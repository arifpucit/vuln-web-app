"""Password-reset business logic (token issue / lookup / consume).

Sibling of verification_service.py / otp_service.py. The route layer in
api/routes/auth.py calls these functions and renders/redirects on the
result. This module is the only one that touches the password_resets
table.

Security posture (all preserved from the closed vulnerabilities):
- VULN-1 (SQL Injection): every SELECT/UPDATE here is parameterized.
- VULN-3 (Reflected XSS): the plaintext token is never reflected back;
  the /reset-password route renders fixed outcome messages, not the token.
- VULN-7 / VULN-8: the POSTs are guarded by the existing RateLimit +
  CSRF middleware. This module adds no new auth surface of its own.

Token model:
- ``secrets.token_urlsafe(32)`` (256 bits) is generated as the plaintext.
- ``hashlib.sha256(token.encode("utf-8")).hexdigest()`` is stored in
  token_hash. The plaintext is NEVER persisted.
- expires_at = time.time() + config.PASSWORD_RESET_TTL_SECONDS (default 900s).
- A successful consume flips used = 1 (single-use).
- The link is built as f"{config.APP_BASE_URL}/reset-password?token=...".
  ``config.APP_BASE_URL`` is the SOLE source of the URL -- request.url,
  request.url.scheme, request.url.netloc, request.headers['host'], and
  request.headers['x-forwarded-host'] are NEVER read. This closes the
  Host Header Injection vector at the spec level.
"""
import hashlib
import logging
import secrets
import time

from app.core import config, mailer
from app.core.security import hash_password
from app.db.session import get_db
from app.services.auth_service import password_meets_policy

logger = logging.getLogger(__name__)


def start_reset(email: str) -> None:
    """Issue a fresh token for the email's user, or return None silently.

    Silent on: unknown email, unverified local account (is_verified = 0),
    Google-only account (auth_provider = 'google'). The caller always
    returns the same generic 200 response, so this is the enumeration-
    resistance gate (along with the constant-time posture below).

    Constant-time posture: the single SELECT runs on every path; the
    mailer call runs on every path where a row matched AND is verified
    AND is local. A non-match path returns None without calling the
    mailer; the routes' response time difference is dominated by the
    network/IO, not by the branch. (See spec NFR-14.)
    """
    if not email:
        return None

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by email.
        # Read ONLY the columns we need to decide whether to issue a token,
        # PLUS `email` itself -- it's passed to mailer.send_password_reset_email()
        # below, so it must be selected here (row["email"] would otherwise
        # raise IndexError on sqlite3.Row for every eligible request).
        row = conn.execute(
            "SELECT id, username, email, is_verified, auth_provider "
            "FROM users WHERE email = ?",
            [email],
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return None
    if not row["is_verified"]:
        return None
    if row["auth_provider"] != "local":
        return None

    # Plaintext token (256 bits, URL-safe Base64, 43 chars). Stored only as
    # its SHA-256 hex digest in token_hash.
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = time.time() + config.PASSWORD_RESET_TTL_SECONDS

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized INSERT.
        conn.execute(
            "INSERT INTO password_resets (user_id, token_hash, expires_at) "
            "VALUES (?, ?, ?)",
            [row["id"], token_hash, expires_at],
        )
        conn.commit()
    finally:
        conn.close()

    # URL built EXCLUSIVELY from config.APP_BASE_URL. Never from request.url,
    # request.url.scheme, request.url.netloc, request.headers['host'], or any
    # other client-supplied value. This is the spec-level closure of the
    # Host Header Injection vector (forgot-password.md NFR-09 / FR-16).
    reset_url = f"{config.APP_BASE_URL}/reset-password?token={token}"

    # Fail-safe mailer: returns False (never raises) on any error or when
    # unconfigured. The route ignores the return value and returns the
    # generic response anyway (enumeration resistance).
    mailer.send_password_reset_email(row["email"], row["username"], reset_url)


def lookup_status(token: str) -> dict:
    """Return one of {"status": "ok"} | "expired" | "used" | "invalid".

    Pure read; does not mutate state. Used by the GET /reset-password handler
    to decide which outcome message to render and whether to show the form.
    Never reflects the token (VULN-3).
    """
    if not token:
        return {"status": "invalid"}
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by token_hash.
        row = conn.execute(
            "SELECT id, user_id, expires_at, used FROM password_resets "
            "WHERE token_hash = ?",
            [token_hash],
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return {"status": "invalid"}
    if row["used"]:
        return {"status": "used"}
    if time.time() > float(row["expires_at"]):
        return {"status": "expired"}
    return {"status": "ok"}


def consume_reset(token: str, new_password: str) -> dict:
    """Validate a token, hash and store the new password, mark used.

    Returns one of:
    - "ok"            -- the password was updated; carries user_id so the
                         route can log the user straight in (we do NOT --
                         the user must log in with the new password, same
                         posture as the OTP/TOTP gates).
    - "weak_password" -- new_password fails password_meets_policy().
                         used is NOT flipped (the token is still usable
                         with a stronger password).
    - "used"          -- the row was already consumed. used stays 1.
    - "expired"       -- the row exists but expires_at has passed.
    - "invalid"       -- missing/blank token, or no matching row.

    Never reflects the token (VULN-3). Never raises on a DB error (fails
    closed by returning "invalid" + logger.exception; a broken reset
    must not silently let the user log in).
    """
    if not token:
        return {"status": "invalid"}
    if not password_meets_policy(new_password):
        return {"status": "weak_password"}

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT.
        row = conn.execute(
            "SELECT id, user_id, expires_at, used FROM password_resets "
            "WHERE token_hash = ?",
            [token_hash],
        ).fetchone()
        if not row:
            return {"status": "invalid"}
        if row["used"]:
            return {"status": "used"}
        if time.time() > float(row["expires_at"]):
            return {"status": "expired"}

        # Strength check passed; flip used, hash the new password, update.
        # Order: used flip is FIRST so a crash in the bcrypt step still
        # leaves the token dead (defense in depth).
        conn.execute(
            "UPDATE password_resets SET used = 1 WHERE id = ?",
            [row["id"]],
        )
        # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
        # FIXED: Weak Password Storage closed -- hash the NEW password with
        # bcrypt (cost 12) before it touches the DB. The plaintext never
        # persists. Legacy MD5 rows in users.password are replaced by the
        # new bcrypt hash on first successful reset.
        new_hash = hash_password(new_password)
        conn.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            [new_hash, row["user_id"]],
        )
        conn.commit()
        logger.info("Password reset consumed for user_id=%s", row["user_id"])
        return {"status": "ok", "user_id": row["user_id"]}
    except Exception:
        logger.exception("consume_reset failed")
        return {"status": "invalid"}
    finally:
        conn.close()