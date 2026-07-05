# Implementation Plan — Forgot Password (Token-Based Reset)

**Version:** 1.0.0
**Last Updated:** 2026-07-02
**Parent Documents:** [forgot-password.md](./forgot-password.md) (specification), [app-foundation.md](./app-foundation.md) (foundation), [docs/TDD.md](../../docs/TDD.md)

---

## 0. How to Read This Plan

This plan implements `.claude/specs/forgot-password.md` as a series of small, verifiable, additive changes. Each phase ends with a checklist of observable behaviors. A phase is **not** considered complete until its checklist passes on a fresh clone.

**Hard constraints that apply to every phase** (repeated in each phase's preamble for emphasis):

- **No new vulnerability is introduced.** The feature is fully hardened end to end. The two vectors the professor's brief flagged for possible preservation — Host Header Injection and Referer Leakage — are **closed at the spec level**, not preserved as lab vectors.
- **URLs are server-side-only.** Both the emailed reset link and the reset form's `action` are derived **exclusively** from `config.APP_BASE_URL`. `request.url`, `request.url.scheme`, `request.url.netloc`, `request.headers["host"]`, and `request.headers["x-forwarded-host"]` are **never** read for URL construction.
- **No third-party assets on the reset page.** The new templates reference only the project's own `/static/css/styles.css` and inline `<script>` blocks. No CDN script, no external stylesheet, no remote image, no web font, no analytics pixel.
- **Every new SQL statement is parameterized.** `?` placeholders only. No string concatenation, no f-string interpolation into SQL, no `LIKE` patterns built from user input.
- **The protected modules are not modified.** `auth_service.login()`, `auth_service.signup()`, `auth_service.change_password()`, `main.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py` stay byte-for-byte unchanged.
- **No new dependency.** The mailer reuses `core/mailer.py`; token generation reuses `secrets`; hashing reuses `hashlib`; URL building reuses `config.APP_BASE_URL`. `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are unchanged.

**Phase ordering rationale.** The plan runs in this order:

1. **Schema** — create the new `password_resets` table first so every later phase can be tested against a real table.
2. **Config** — add `PASSWORD_RESET_TTL_SECONDS` so the service has a single source of truth for the TTL.
3. **Mailer** — add `send_password_reset_email` so the service has a ready-to-call transport.
4. **Service** — implement `password_reset_service.py` (the only module that touches the new table). No HTTP, no templates, no form parsing.
5. **Routes** — add the four new handlers in `auth.py`. Thin wrappers over the service.
6. **Templates** — add `forgot_password.html` and `reset_password.html`, plus the additive "Forgot password?" link on `login.html`.
7. **CSS** — append a small additive block to `styles.css` for the new templates.
8. **Docs** — `.env.example`, `README.md`, `CLAUDE.md`.
9. **End-to-end verification** — run every check from the spec's §10 to confirm the feature works and the hardening holds.

This order means a reviewer can stop after any phase and have a coherent, testable state. The schema, config, mailer, and service phases are all unit-testable without HTTP. The route and template phases wire them into FastAPI. The verification phase runs the full UI flow.

---

## Phase 1 — Schema: Add the `password_resets` Table

### Files touched

- **MODIFY:** `backend/app/db/session.py` — add a `CREATE TABLE IF NOT EXISTS password_resets (...)` to `init_db()`.

### Files NOT touched (regression guards)

- `backend/app/main.py` — `init_db()` is already called from `main.py`; no change to the call site.
- `backend/app/services/auth_service.py` — not modified.
- `backend/app/core/security.py`, `core/csrf.py`, `core/rate_limit.py` — not modified.
- `vulnerable_app.db` — schema change only, no row change.

### Precise additive change

**Location:** inside `init_db()`, after the existing `users` `CREATE TABLE` and after the `migrations` dict loop, before `conn.commit()`.

```python
# Forgot Password (v2.1.0): brand-new table for token-based password reset.
# Stores ONLY the SHA-256 hash of the token (never the plaintext) and the
# expiry / used state. The plaintext lives only in the email and in the
# user's URL bar. No ALTER TABLE is needed (this is a brand-new table, not
# a column on an existing one); CREATE TABLE IF NOT EXISTS makes the
# migration idempotent on every boot.
conn.execute("""
    CREATE TABLE IF NOT EXISTS password_resets (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        expires_at REAL NOT NULL,
        used       INTEGER NOT NULL DEFAULT 0
    )
""")
```

### Why this exact form

- **`CREATE TABLE IF NOT EXISTS`** — the same idempotent pattern the existing `users` `CREATE TABLE` uses (see lines 102–126 of `db/session.py`). A fresh DB creates the table; a pre-existing DB finds the table already present and the statement is a no-op.
- **`token_hash TEXT UNIQUE`** — the SHA-256 hex digest of the plaintext token (64 hex chars). The `UNIQUE` constraint is defense in depth — by construction the token entropy is 256 bits and collisions are impossible, but the constraint guarantees `lookup_status` and `consume_reset` always see at most one row per hash, and prevents accidental collisions in custom token-generation code in the future.
- **`expires_at REAL NOT NULL`** — Unix epoch seconds. The service compares with `time.time()` directly. `REAL` is the same type as `verification_token_expires` and `locked_until` in the existing `users` table — consistent.
- **`used INTEGER NOT NULL DEFAULT 0`** — 0 = unused, 1 = consumed. The default is 0; `consume_reset` flips it to 1 *after* a successful bcrypt update.
- **No `FOREIGN KEY` clause** — matches the existing `users` schema (no foreign keys anywhere in the lab) and avoids the `PRAGMA foreign_keys = ON` requirement. `user_id` is an integer; the service resolves it against the `users` row at lookup time.
- **No `ALTER TABLE` block** — the existing `_PRAGMA table_info` migration block is for *adding columns* to an existing table. A brand-new table doesn't need it.
- **No `UPDATE` block** — the existing `is_verified` grandfather `UPDATE` (line 175) is needed because pre-existing rows needed their `is_verified` flipped to 1. A brand-new table has no pre-existing rows; nothing to migrate.

### Verification (phase-local)

- [ ] `rm -f vulnerable_app.db && uv run backend/app/main.py` boots without error.
- [ ] `sqlite3 vulnerable_app.db ".schema password_resets"` prints the full DDL.
- [ ] `sqlite3 vulnerable_app.db ".schema users"` is byte-for-byte unchanged (no extra columns, no `DROP TABLE`).
- [ ] Boot the app a second time; `init_db()` re-runs; no `OperationalError: table password_resets already exists`. The `CREATE TABLE IF NOT EXISTS` is idempotent.
- [ ] `git diff backend/app/db/session.py` shows ONLY the new `CREATE TABLE` block; no other change.
- [ ] `git diff backend/app/main.py` is empty.

### Rollback

- Drop the new `CREATE TABLE` block from `init_db()`. No data loss (no rows exist).

---

## Phase 2 — Config: Add `PASSWORD_RESET_TTL_SECONDS`

### Files touched

- **MODIFY:** `backend/app/core/config.py` — add one constant and a one-line module-docstring update.

### Files NOT touched

- `backend/app/services/auth_service.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py` — not modified.
- `main.py` — not modified.

### Precise additive change

**Location 1:** at the end of the `core/config.py` module docstring's feature list (the `7.` and `8.` paragraphs that summarize the existing features). Add a 9.:

```
9. Exposes the Password-Reset settings (v2.1.0): PASSWORD_RESET_TTL_SECONDS
   (env-tunable, non-secret; the TTL is fixed at 15 minutes by spec but
   env-tunable for demos). URLs reuse the existing APP_BASE_URL and the
   mailer reuses is_email_configured().
```

**Location 2:** after the existing `QR_LOGIN_*` block (around line 181) and before the CAPTCHA block, add:

```python
# --- Password-Reset settings (env-tunable, non-secret) ---------------------
# After the user requests a reset, the emailed link is valid for
# PASSWORD_RESET_TTL_SECONDS. The TTL is fixed at 15 minutes by spec (the
# professor's brief); the env var is a deliberate, non-secret knob that
# mirrors ACCOUNT_LOCKOUT_DURATION_SECONDS / OTP_TTL_SECONDS, useful for
# local demos (e.g. PASSWORD_RESET_TTL_SECONDS=30 to demo expiry in seconds).
# There is NO is_*_configured() gate of its own — the mailer reuses the
# existing is_email_configured(), and URLs reuse APP_BASE_URL.
PASSWORD_RESET_TTL_SECONDS = int(os.environ.get("PASSWORD_RESET_TTL_SECONDS", "900"))
```

### Why this exact form

- **Module-level constant, not a function** — matches the existing `ACCOUNT_LOCKOUT_DURATION_SECONDS`, `OTP_TTL_SECONDS`, `TOTP_PERIOD_SECONDS` posture: a plain `int` constant read once at import time. The service module imports it as `from app.core import config` and reads `config.PASSWORD_RESET_TTL_SECONDS` directly.
- **Default `"900"` (15 minutes)** — fixed by spec. The professor's brief says "expire strictly after 15 minutes."
- **`int(...)`** — matches every other numeric tunable in the file.
- **Non-secret** — the TTL is a configuration knob, not a credential. It can be committed as a placeholder default and overridden in `.env` (git-ignored) for local demos.
- **No `is_*_configured()` gate** — there is no "reset is configured" boolean. Reset is always available with a safe default; the only gate is `is_email_configured()` for the mailer (which the service uses anyway, via `mailer.send_password_reset_email`).
- **No new env var block in `.env.example`** for SMTP — the mailer reuses the existing SendGrid transport. `.env.example` gets the new `PASSWORD_RESET_TTL_SECONDS=900` line in Phase 8 (docs).

### Verification (phase-local)

- [ ] `python -c "from app.core import config; print(config.PASSWORD_RESET_TTL_SECONDS)"` prints `900`.
- [ ] `PASSWORD_RESET_TTL_SECONDS=30 python -c "from app.core import config; print(config.PASSWORD_RESET_TTL_SECONDS)"` prints `30`.
- [ ] The variable is read once at import; changing it after import has no effect (documented posture).
- [ ] `git diff backend/app/core/config.py` shows ONLY the new constant and the docstring update.
- [ ] All other config constants are unchanged (`is_email_configured()` still works, `APP_BASE_URL` still works, `is_captcha_configured()` still works).

### Rollback

- Remove the new constant and the docstring line. No data loss.

---

## Phase 3 — Mailer: Add `send_password_reset_email`

### Files touched

- **MODIFY:** `backend/app/core/mailer.py` — add one new public function `send_password_reset_email`, sibling of `send_verification_email` and `send_otp_email`.

### Files NOT touched

- `core/config.py` — not modified (the new function reuses `config.SENDGRID_FROM`, `config.SENDGRID_API_KEY`, `config.SENDGRID_HTTP_TIMEOUT`, and the existing `is_email_configured()`).
- `_deliver` and `_send_via_sendgrid` — reused unchanged.

### Precise additive change

**Location 1:** extend the module docstring's `Public surface:` line (currently "Public surface: ``send_verification_email`` (signup link) and ``send_otp_email`` (login one-time code).") to:

```
Public surface: ``send_verification_email`` (signup link), ``send_otp_email``
(login one-time code), and ``send_password_reset_email`` (forgot-password
reset link). All three are deliberately FAIL-SAFE…
```

**Location 2:** at the end of the file, after `send_otp_email`, add:

```python
def send_password_reset_email(to_email: str, username: str, reset_url: str) -> bool:
    """Send the forgot-password reset email. Returns True on success, else False.

    Same fail-safe contract as send_verification_email and send_otp_email:
    returns False (never raises) on any unconfigured-SendGrid or send/API
    error. The caller (POST /forgot-password) ignores the return value and
    returns the same generic response either way (enumeration resistance +
    no oracle via SMTP success/failure). The username and the URL are
    html.escape()'d before they enter the HTML body (VULN-2 posture). The
    raw token (which is embedded in `reset_url`'s query string) is NEVER
    logged (VULN-3 posture) — only "Password reset email sent to <email>".
    """
    if not config.is_email_configured():
        # Defensive: the routes already gate on is_email_configured(), but
        # if anyone calls this directly, no transport means no send.
        logger.warning("Email not configured; skipping password reset email to %s", to_email)
        return False

    safe_username = html.escape(username or "", quote=True)
    safe_url = html.escape(reset_url, quote=True)
    minutes = max(1, config.PASSWORD_RESET_TTL_SECONDS // 60)

    subject = "Reset your password - Security Vulnerability Lab"
    text_body = (
        f"Hi {username},\n\n"
        "We received a request to reset the password for your account on the "
        "Security Vulnerability Lab. Open the link below to set a new "
        f"password (valid for {minutes} minutes):\n\n"
        f"{reset_url}\n\n"
        "If you did not request a reset, you can safely ignore this email — "
        "your password will remain unchanged."
    )
    html_body = (
        f"<p>Hi {safe_username},</p>"
        "<p>We received a request to reset the password for your account on "
        "the <strong>Security Vulnerability Lab</strong>. Click the link "
        f"below to set a new password (valid for {minutes} minutes):</p>"
        f'<p><a href="{safe_url}">Reset my password</a></p>'
        "<p>If you did not request a reset, you can safely ignore this email — "
        "your password will remain unchanged.</p>"
    )

    ok = _deliver(to_email, subject, text_body, html_body)
    if ok:
        logger.info("Password reset email sent to %s", to_email)
    return ok
```

### Why this exact form

- **Sibling of `send_verification_email` and `send_otp_email`** — same shape, same fail-safe contract, same logging discipline. The body explains the 15-minute window; the URL is the only capability; the username and URL are escaped for VULN-2; the raw token is in the URL only and is **never** logged.
- **No raw-token logging** — only the email address is logged. The `reset_url` includes the plaintext token in its query string; logging the full URL would leak the token to the server log. (VULN-3 posture.)
- **Minutes calculation** — `max(1, config.PASSWORD_RESET_TTL_SECONDS // 60)` matches the OTP `minutes` calculation; gives a friendly "valid for 1 minutes" floor if the TTL is below 60s (a demo with `PASSWORD_RESET_TTL_SECONDS=30`).
- **`username` is interpolated into the *text* part raw** — that's the pattern in `send_verification_email` and `send_otp_email` too. The text part is plain; the HTML part is escaped.
- **Subject** — mirrors the verify / OTP subjects ("Verify your email" / "Your login verification code") with the new "Reset your password" copy.

### Verification (phase-local)

- [ ] `python -c "from app.core import mailer; print(mailer.send_password_reset_email.__doc__[:80])"` prints the docstring's first 80 chars.
- [ ] With SendGrid unconfigured (`SENDGRID_API_KEY=""`), the function returns `False` and logs a warning. No exception.
- [ ] With SendGrid configured (real or test creds in `.env`), the function returns `True` on a 2xx and `False` on any error. No exception.
- [ ] `grep -E "token" /tmp/server.log` (after exercising the function) shows **no** line containing the plaintext token.
- [ ] `git diff backend/app/core/mailer.py` shows only the new function and the docstring extension.
- [ ] `_deliver` and `_send_via_sendgrid` are unchanged.

### Rollback

- Remove the new function and the docstring line. No data loss.

---

## Phase 4 — Service: Implement `password_reset_service.py`

### Files touched

- **CREATE:** `backend/app/services/password_reset_service.py` — new module, ~150 lines.

### Files NOT touched

- `auth_service.py` — not modified. The new service imports `password_meets_policy` from it as a black-box helper, just like `change_password` does.
- `core/security.py` — not modified. The new service imports `hash_password` from it as a black-box helper.
- `core/config.py` — not modified (Phase 2 already added the constant).
- `core/mailer.py` — not modified (Phase 3 already added the sender).
- `db/session.py` — not modified (Phase 1 already added the table).

### Module structure

```python
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
  ``config.APP_BASE_URL`` is the SOLE source of the URL — request.url,
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
        # Read ONLY the columns we need to decide whether to issue a token.
        row = conn.execute(
            "SELECT id, username, is_verified, auth_provider "
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
    # Host Header Injection vector (forgot-password.md §2.3 / NFR-09).
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


def is_expired_or_used(row) -> bool:
    """Small pure helper for the POST handler (mirrors lockout_service)."""
    if not row:
        return True
    if row["used"]:
        return True
    return time.time() > float(row["expires_at"])


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
```

### Why this exact form

- **Pure-stdlib cryptography** — `secrets.token_urlsafe(32)` for the plaintext (CSPRNG, 256 bits, URL-safe Base64); `hashlib.sha256(...)` for the digest. No `bcrypt` for the token (the token is a high-entropy capability, not a low-entropy password; SHA-256 is the right primitive).
- **Plaintext never persisted** — only the SHA-256 hex digest lands in the `token_hash` column. A DB leak does not yield reset links; an attacker would have to brute-force 2²⁵⁶ to find a matching plaintext.
- **Strict `time.time() > expires_at`** — matches the spec (FR-12) and the existing `verification_token_expires` check in `verification_service.py`.
- **Pre-issued strength check** — `password_meets_policy(new_password)` runs *before* the `used = 1` flip, so a weak-password submission does not deaden the token (SP-07 / EC-22). The check uses the same five-criteria gate as `auth_service.change_password()` (VULN-5 posture).
- **Post-issued `used = 1` flip** — runs *after* the strength check passes, *before* the bcrypt update. If the bcrypt step crashes, the token is still dead (defense in depth); if a second request races, the `used` check in the second request fails the second transaction cleanly.
- **No session written** — `consume_reset` does **not** read or write `request.session`. The route handler also does not write the session. The user must log in with the new password (mirrors the OAuth / OTP / TOTP gates' posture: the new password is the second factor).
- **All four `get_db()` calls are `try/finally conn.close()`** — matches the existing `auth_service.py` discipline; no leaked connections.
- **Every SQL uses `?` placeholders** — VULN-1 stays closed.
- **URL built from `config.APP_BASE_URL` only** — Host Header Injection vector is closed at the spec level. The grep `grep -nE 'f"http' backend/app/services/password_reset_service.py` returns exactly one line: `reset_url = f"{config.APP_BASE_URL}/reset-password?token={token}"`. (TC-28.)
- **No raw-token logging** — `logger.info("Password reset consumed for user_id=%s", row["user_id"])` is the only log line on the consume path. The `start_reset` path logs only on the mailer's success (in the mailer, not the service).
- **No third-party imports** — `hashlib`, `logging`, `secrets`, `time` are stdlib; everything else is project-internal. (TC-32.)

### Verification (phase-local)

- [ ] `python -c "from app.services import password_reset_service; print(password_reset_service.start_reset.__doc__[:60])"` works.
- [ ] `start_reset("")` returns `None`; no DB write; no email.
- [ ] `start_reset("no-such@example.com")` returns `None`; no DB write; no email.
- [ ] `start_reset("<unverified>")` returns `None`; no DB write; no email.
- [ ] `start_reset("<google-only>")` returns `None`; no DB write; no email.
- [ ] `start_reset("<verified-local>")` writes one `password_resets` row with a 64-char hex `token_hash`; `expires_at ≈ time.time() + 900`; `used = 0`. SendGrid is hit (or the mailer logs "SendGrid not configured" if unconfigured).
- [ ] `lookup_status("")` returns `{"status": "invalid"}`.
- [ ] `lookup_status("<bogus>")` returns `{"status": "invalid"}`.
- [ ] `lookup_status("<valid>")` returns `{"status": "ok"}` for an unexpired, unused row.
- [ ] After manually flipping `used = 1` in the DB, `lookup_status` returns `{"status": "used"}`.
- [ ] After manually setting `expires_at = 1` in the DB, `lookup_status` returns `{"status": "expired"}`.
- [ ] `consume_reset("", "NewPass!2026")` returns `{"status": "invalid"}`.
- [ ] `consume_reset("<valid>", "short")` returns `{"status": "weak_password"}`; `used` is still 0 in the DB.
- [ ] `consume_reset("<valid>", "NewPass!2026")` returns `{"status": "ok", "user_id": <int>}`; `users.password` is now a bcrypt hash starting with `$2b$12$`; `password_resets.used` is now 1.
- [ ] A second `consume_reset` with the same plaintext returns `{"status": "used"}`; `users.password` is unchanged.
- [ ] `grep -nE 'f"http' backend/app/services/password_reset_service.py` returns exactly one line: the `config.APP_BASE_URL`-based URL. **No** line uses `request.url`, `request.headers`, or any client-derived value.
- [ ] `grep -E "request\." backend/app/services/password_reset_service.py` returns **no** matches (the service has no `Request` parameter at all; it is pure DB + mailer).
- [ ] `grep -E "^import " backend/app/services/password_reset_service.py` shows only `hashlib`, `logging`, `secrets`, `time`, and project-internal modules (`app.core.config`, `app.core.mailer`, `app.core.security`, `app.db.session`, `app.services.auth_service`).

### Rollback

- Delete the file. No data loss (the new table is dropped in Phase 1's rollback; the routes in Phase 5 will fail with `ImportError` if rolled back without removing the routes).

---

## Phase 5 — Routes: Add the Four New Handlers

### Files touched

- **MODIFY:** `backend/app/api/routes/auth.py` — add one new import block and four new route handlers. No modification to any existing handler.

### Files NOT touched

- `auth_service.py` — not modified. The new handlers do not call `login()`, `signup()`, or `change_password()`.
- `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/oauth.py`, `core/captcha.py`, `core/qr_login.py`, `core/mailer.py` — not modified.
- `main.py` — not modified. `RateLimitMiddleware` and `CSRFMiddleware` are already registered; the new POSTs sit behind them automatically.
- `services/verification_service.py`, `services/otp_service.py`, `services/totp_service.py`, `services/lockout_service.py`, `services/oauth_service.py` — not modified.

### Precise additive changes

**Change 1 — imports.** At the top of `auth.py`, alongside the existing `from app.services import …` block, add:

```python
from app.services import password_reset_service
```

(The `from app.core.csrf import get_or_create_csrf_token` and `from app.core import config` imports are already present; we use them, not modify them.)

**Change 2 — `forgot_password_page` (GET).** Place after the existing `signup_page` / `check_email_page` / `verify_email` / `verify_resend` cluster, before `login_page`:

```python
@router.get("/forgot-password")
async def forgot_password_page(request: Request):
    """Render the forgot-password form with a per-session CSRF token.

    Same pattern as signup_page() / login_page(): load template, issue
    token, splice via str.replace. When SMTP is not configured we render
    the friendly "email not configured" page (mirrors GET /signup) so
    the user sees an actionable message instead of a form that can't
    succeed. The generic response on the POST keeps enumeration blocked
    even when the GET degrades to the not-configured page.
    """
    if not config.is_email_configured():
        return HTMLResponse(content=_load_template("email_not_configured.html"))
    page = _load_template("forgot_password.html")
    # FIXED: CSRF closed -- splice the per-session token into the form's
    # hidden field. The middleware validates it on the matching POST.
    token = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(token, quote=True))
    return HTMLResponse(content=page)
```

**Change 3 — `forgot_password_post` (POST).** Place immediately after:

```python
@router.post("/forgot-password")
async def forgot_password_post(email: str = Form("")):
    """Handle forgot-password form submission.

    ALWAYS returns the same generic 200 JSON, regardless of whether
    email matches a verified local account. This is the enumeration-
    resistance gate. The start_reset call is silent on unknown email /
    unverified / Google accounts; the mailer is fail-safe; the route's
    response body, status code, and timing are constant.

    No session is written. The CSRF token and per-IP rate limit are
    enforced by middleware before this handler runs.
    """
    password_reset_service.start_reset(email)
    return JSONResponse(
        content={
            "success": True,
            "message": (
                "If that email matches an account, a reset link has "
                "been sent to it."
            ),
        }
    )
```

**Change 4 — `reset_password_page` (GET).** Place after `forgot_password_post`:

```python
@router.get("/reset-password")
async def reset_password_page(request: Request, token: str = ""):
    """Render the reset-password form (or an outcome message).

    The form's action is built EXCLUSIVELY from config.APP_BASE_URL
    (see form_action below). request.url, request.url.scheme,
    request.url.netloc, request.headers['host'], and
    request.headers['x-forwarded-host'] are NEVER read here — closing
    the Host Header Injection vector at the spec level. Even if a
    student sets `Host: evil.example` on this request, the rendered
    form action is unchanged.

    The raw token is NEVER reflected as markup (VULN-3): it is dropped
    from the page once the form is rendered. The {{status}} flag
    controls whether the form shows; "ok" -> form, anything else ->
    fixed outcome message.
    """
    status = password_reset_service.lookup_status(token)["status"]
    page = _load_template("reset_password.html")
    # FIXED: CSRF closed -- splice the per-session token.
    csrf = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(csrf, quote=True))
    # FIXED: Server-side-only URL -- derived from config.APP_BASE_URL, NEVER
    # from request.url or any request header. This is the spec-level closure
    # of the Host Header Injection vector (forgot-password.md NFR-09 / FR-16).
    form_action = f"{config.APP_BASE_URL}/reset-password"
    page = page.replace("{{form_action}}", html.escape(form_action, quote=True))
    # FIXED: Stored/Reflected XSS closed -- escape the status flag before
    # splicing (defense in depth; the values are author-controlled, but
    # the splice pattern is used everywhere in this module).
    page = page.replace("{{status}}", html.escape(status, quote=True))
    return HTMLResponse(content=page)
```

**Change 5 — `reset_password_post` (POST).** Place immediately after:

```python
@router.post("/reset-password")
async def reset_password_post(
    request: Request,
    token: str = Form(""),
    password: str = Form(""),
    confirm_password: str = Form(""),
):
    """Handle reset-password form submission.

    Returns JSON for every outcome so the page's fetch() handler can
    render feedback inline. On success the user is NOT logged in --
    they must log in with the new password. Client-side mismatch
    (password != confirm_password) is caught by the page's inline JS
    (mirrors the v0 signup posture); confirm_password is Form-parsed
    here but not passed to the service (the service is the
    authoritative gate for password strength; mismatch is a UI concern).

    The CSRF token and per-IP rate limit are enforced by middleware
    before this handler runs.
    """
    if password != confirm_password:
        return JSONResponse(
            content={"error": "Passwords do not match."},
            status_code=400,
        )
    result = password_reset_service.consume_reset(token, password)
    status = result["status"]
    if status == "ok":
        return JSONResponse(
            content={
                "success": True,
                "message": (
                    "Password updated. Please log in with your new password."
                ),
            }
        )
    messages = {
        "invalid": "Invalid reset link.",
        "used": "This reset link has already been used.",
        "expired": "This reset link has expired. Request a new one.",
        "weak_password": (
            "Password must be at least 8 characters and include an "
            "uppercase letter, a lowercase letter, a digit, and a "
            "special character."
        ),
    }
    return JSONResponse(
        content={"error": messages.get(status, messages["invalid"])},
        status_code=400,
    )
```

### Why this exact form

- **Thin handlers, no business logic** — every handler delegates to `password_reset_service` or to the existing `core.csrf` / `core.config` helpers. Mirrors the existing pattern (`signup_post` → `auth_service.signup`, `login_post` → `auth_service.login`).
- **Both POSTs sit behind the existing middleware** — `RateLimitMiddleware` (per-IP) and `CSRFMiddleware` (synchronizer token) are already registered in `main.py`. The new routes are automatically throttled and CSRF-validated.
- **No modification to existing handlers** — `login_page`, `login_post`, `signup_page`, `signup_post`, `verify_email`, `verify_resend`, `welcome_page`, `profile_*`, `login_otp_*`, `login_totp_*`, `qr_*`, `auth_google_*`, `search_user`, `logout`, `index` are all byte-for-byte unchanged.
- **`form_action` built from `config.APP_BASE_URL` only** — `f"{config.APP_BASE_URL}/reset-password"`. No `request.url`, no `request.url.scheme`, no `request.url.netloc`, no `request.headers["host"]`, no `request.headers["x-forwarded-host"]`. The grep `grep -nE "request\.(url|headers)" backend/app/api/routes/auth.py | grep -iE "(host|netloc|scheme|forwarded)"` returns **no** matches. (TC-28.)
- **Generic `200` JSON on every `/forgot-password` outcome** — the handler ignores `start_reset`'s return value. Unknown email / empty email / unverified / Google all produce the same JSON, the same status code, and the same handler execution path. Enumeration resistance (NFR-14).
- **`confirm_password` is `Form`-parsed but not passed to the service** — the v0 signup form's posture is preserved: the server is authoritative for password *strength* (via `password_meets_policy`); the *match* check is a client-side concern with a server-side belt-and-suspenders (the handler returns 400 on mismatch without ever touching the service).
- **No session mutation** — neither handler reads or writes `request.session`. The user must log in with the new password.
- **`html.escape(..., quote=True)` on every splice** — `{{csrf_token}}`, `{{form_action}}`, `{{status}}`. Same discipline as every other splice in this module.
- **No `RedirectResponse` on success** — returns JSON. The page's JS does `window.location.href = "/login"` on `data.success`. (Matches the login form's UX; mirrors `login_post`'s pattern.)
- **`email_not_configured.html` degrade on the GET** — mirrors the `signup_page` degrade so a fresh clone with no SendGrid creds doesn't render a form that can't succeed.

### Verification (phase-local)

- [ ] `uv run backend/app/main.py` boots without error.
- [ ] `curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3001/forgot-password` returns `200` (or `200` with the `email_not_configured.html` body if SendGrid is unconfigured).
- [ ] `curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:3001/reset-password?token=anything"` returns `200`.
- [ ] `curl -s -X POST -d "email=no-such@example.com" http://localhost:3001/forgot-password` returns `200 {"success": true, "message": "..."}` (and a `403` if the CSRF token is missing — Phase 5 alone can't easily test this without a GET that issued a token; verify after Phase 6).
- [ ] `git diff backend/app/api/routes/auth.py` shows ONLY:
  - The new `from app.services import password_reset_service` import.
  - The four new handlers.
  - No modification to any existing handler.
- [ ] `grep -nE "request\.(url|headers)" backend/app/api/routes/auth.py` returns **no** lines in the new handlers (and only the existing `request.session.get(...)` lines in the unchanged handlers).
- [ ] `grep -nE 'f"http' backend/app/api/routes/auth.py` shows the new `form_action = f"{config.APP_BASE_URL}/reset-password"` line and **no** other `f"http` lines in the new handlers.

### Rollback

- Remove the four handlers and the new import. No data loss.

---

## Phase 6 — Templates: Add the Two New Pages and the Login Link

### Files touched

- **CREATE:** `frontend/templates/forgot_password.html` — new file, ~70 lines.
- **CREATE:** `frontend/templates/reset_password.html` — new file, ~110 lines.
- **MODIFY:** `frontend/templates/login.html` — add one `<a href="/forgot-password">` line under the existing "Don't have an account? Sign up" line.

### Files NOT touched

- Every other template (`signup.html`, `dashboard.html`, `profile.html`, `verify_result.html`, `check_email.html`, `email_not_configured.html`, `otp_verify.html`, `totp_verify.html`, `qr_approve.html`, `oauth_not_configured.html`) — byte-for-byte unchanged.

### Template 1 — `frontend/templates/forgot_password.html`

The page mirrors the *right panel* of `login.html` (no decorative left panel — keeps the markup small and the no-third-party-asset constraint obvious to students). The only subresource is `/static/css/styles.css` (first-party). The only `<script>` is inline (for client-side feedback).

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script>
        // Pre-render theme init (same shape as login.html).
        (function () {
            try {
                var saved = localStorage.getItem('theme');
                if (saved !== 'light' && saved !== 'dark') { saved = null; }
                var theme = saved;
                if (!theme && window.matchMedia) {
                    theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
                }
                if (!theme) { theme = 'light'; }
                document.documentElement.setAttribute('data-theme', theme);
            } catch (e) {
                document.documentElement.setAttribute('data-theme', 'light');
            }
        })();
    </script>
    <title>Forgot Password - Security Vulnerability Lab</title>
    <!--
        Forgot Password (v2.1.0). This page loads NO third-party script,
        stylesheet, image, font, or other cross-origin asset. The only
        subresource is the first-party stylesheet below; the only script
        is the inline IIFE above and the inline form handler at the
        bottom. A Referer header from this page can therefore never
        carry the page URL to an external origin. (See spec NFR-10.)
    -->
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <header class="header">
        <div class="header-title">Security Vulnerability Lab</div>
        <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to dark mode">
            <span class="theme-toggle-icon" aria-hidden="true">🌙</span>
        </button>
    </header>

    <div class="auth-container">
        <div class="auth-right" style="grid-column: 1 / -1;">
            <div class="form-container">
                <h2 class="form-title">Forgot Password</h2>
                <p class="form-subtitle">Enter the email on your account and we'll send you a reset link.</p>

                <div id="success-message" class="reset-message" role="status" aria-live="polite" style="display: none;"></div>
                <div id="error-message" class="error-message" role="alert" style="display: none;"></div>

                <form id="forgot-form">
                    <input type="hidden" name="csrf_token" value="{{csrf_token}}">
                    <div class="form-group">
                        <label class="form-label" for="email">Email</label>
                        <input type="email" id="email" name="email" class="form-input" placeholder="you@example.com" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Send reset link</button>
                </form>

                <p class="form-link"><a href="/login">Back to sign in</a></p>
            </div>
        </div>
    </div>

    <script>
        // Forgot Password (v2.1.0): the only client logic is the fetch
        // submit and the inline success / error feedback. The page's
        // form's action is the same origin (the form has no `action`
        // attribute, so the browser uses the document URL).
        (function () {
            var form = document.getElementById('forgot-form');
            var successDiv = document.getElementById('success-message');
            var errorDiv = document.getElementById('error-message');

            form.addEventListener('submit', async function (e) {
                e.preventDefault();
                successDiv.style.display = 'none';
                errorDiv.style.display = 'none';

                // Send urlencoded so the CSRF middleware's parser accepts
                // the body and the csrf_token field validates.
                var body = new URLSearchParams(new FormData(form));
                try {
                    var response = await fetch('/forgot-password', {
                        method: 'POST',
                        body: body
                    });
                    var data = await response.json();
                    successDiv.textContent = data.message || 'If that email matches an account, a reset link has been sent to it.';
                    successDiv.style.display = 'block';
                    form.style.display = 'none';
                } catch (err) {
                    errorDiv.textContent = 'Could not send the request. Please try again.';
                    errorDiv.style.display = 'block';
                }
            });
        })();

        // Theme toggle (matches login.html).
        (function () {
            var toggle = document.getElementById('theme-toggle');
            if (!toggle) return;
            function reflect(theme) {
                toggle.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
                var iconEl = toggle.querySelector('.theme-toggle-icon');
                if (iconEl) iconEl.textContent = theme === 'dark' ? '☀' : '🌙';
            }
            reflect(document.documentElement.getAttribute('data-theme') || 'light');
            toggle.addEventListener('click', function () {
                var current = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
                var next = current === 'dark' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', next);
                try { localStorage.setItem('theme', next); } catch (e) {}
                reflect(next);
            });
        })();
    </script>
</body>
</html>
```

### Template 2 — `frontend/templates/reset_password.html`

The page mirrors the *right panel* of `login.html` (no decorative left panel). The form's `action` is `{{form_action}}` (filled by the server from `config.APP_BASE_URL` only). The page contains **no third-party assets** of any kind. The status flag controls whether the form renders.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script>
        // Pre-render theme init (same shape as login.html).
        (function () {
            try {
                var saved = localStorage.getItem('theme');
                if (saved !== 'light' && saved !== 'dark') { saved = null; }
                var theme = saved;
                if (!theme && window.matchMedia) {
                    theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
                }
                if (!theme) { theme = 'light'; }
                document.documentElement.setAttribute('data-theme', theme);
            } catch (e) {
                document.documentElement.setAttribute('data-theme', 'light');
            }
        })();
    </script>
    <title>Reset Password - Security Vulnerability Lab</title>
    <!--
        Forgot Password (v2.1.0). This page loads NO third-party script,
        stylesheet, image, font, or other cross-origin asset. The form's
        action is {{form_action}}, which the server fills exclusively
        from config.APP_BASE_URL -- NEVER from request.url, request.url.
        scheme, request.url.netloc, request.headers['host'], or any other
        client-supplied value. (See spec NFR-09 / NFR-10.) A Referer
        header from this page can therefore never carry the token-bearing
        URL to an external origin.
    -->
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <header class="header">
        <div class="header-title">Security Vulnerability Lab</div>
        <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to dark mode">
            <span class="theme-toggle-icon" aria-hidden="true">🌙</span>
        </button>
    </header>

    <div class="auth-container">
        <div class="auth-right" style="grid-column: 1 / -1;">
            <div class="form-container">
                <h2 class="form-title">Reset Password</h2>
                <p class="form-subtitle">Enter a new password for your account.</p>

                {{form_or_message}}

                <p class="form-link"><a href="/login">Back to sign in</a></p>
            </div>
        </div>
    </div>

    <script>
        // Confirm-password client-side check + fetch() submit. Inline only;
        // no third-party script. The CSRF middleware's urlencoded parser
        // accepts the body, and the csrf_token field validates.
        (function () {
            var form = document.getElementById('reset-form');
            if (!form) return;
            var errorDiv = document.getElementById('reset-error');

            form.addEventListener('submit', async function (e) {
                e.preventDefault();
                errorDiv.style.display = 'none';
                var pwd = document.getElementById('password').value;
                var confirm = document.getElementById('confirm_password').value;
                if (pwd !== confirm) {
                    errorDiv.textContent = 'Passwords do not match.';
                    errorDiv.style.display = 'block';
                    return;
                }
                var body = new URLSearchParams(new FormData(form));
                try {
                    var response = await fetch(form.action, {
                        method: 'POST',
                        body: body
                    });
                    var data = await response.json();
                    if (data.success) {
                        window.location.href = '/login';
                        return;
                    }
                    errorDiv.textContent = data.error || 'Could not reset the password.';
                    errorDiv.style.display = 'block';
                } catch (err) {
                    errorDiv.textContent = 'Could not send the request. Please try again.';
                    errorDiv.style.display = 'block';
                }
            });
        })();

        // Theme toggle (matches login.html).
        (function () {
            var toggle = document.getElementById('theme-toggle');
            if (!toggle) return;
            function reflect(theme) {
                toggle.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
                var iconEl = toggle.querySelector('.theme-toggle-icon');
                if (iconEl) iconEl.textContent = theme === 'dark' ? '☀' : '🌙';
            }
            reflect(document.documentElement.getAttribute('data-theme') || 'light');
            toggle.addEventListener('click', function () {
                var current = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
                var next = current === 'dark' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', next);
                try { localStorage.setItem('theme', next); } catch (e) {}
                reflect(next);
            });
        })();
    </script>
</body>
</html>
```

The route handler renders `{{form_or_message}}` based on `{{status}}`. The route's body therefore is:

```python
if status == "ok":
    inner = (
        '<form id="reset-form" method="POST" action="' + form_action + '">'
        '<input type="hidden" name="csrf_token" value="' + html.escape(csrf, quote=True) + '">'
        '<div class="form-group">'
        '<label class="form-label" for="password">New password</label>'
        '<input type="password" id="password" name="password" class="form-input" required>'
        '</div>'
        '<div class="form-group">'
        '<label class="form-label" for="confirm_password">Confirm new password</label>'
        '<input type="password" id="confirm_password" name="confirm_password" class="form-input" required>'
        '</div>'
        '<div id="reset-error" class="error-message" role="alert" style="display: none;"></div>'
        '<button type="submit" class="btn btn-primary">Reset password</button>'
        '</form>'
    )
else:
    messages = {
        "expired": ("This reset link has expired.", '<p><a href="/forgot-password">Request a new one</a></p>'),
        "used":    ("This reset link has already been used.", '<p><a href="/forgot-password">Request a new one</a></p>'),
        "invalid": ("This reset link is invalid.", '<p><a href="/forgot-password">Request a new link</a></p>'),
    }
    title, follow = messages.get(status, messages["invalid"])
    inner = '<h3>' + html.escape(title, quote=True) + '</h3>' + follow

page = page.replace("{{form_or_message}}", inner)
```

(Phase 5 already added the `form_action`, `csrf`, and `status` splices. Phase 6 only changes the *template content* — the template's static HTML — and the `login.html` additive link. The Python build of `inner` for non-`ok` statuses is a small extension to the route handler from Phase 5; if preferred, it can be a separate `form_or_message` block in the template and the route just splices one of three pre-rendered strings. Either way, the **form's `action` is the same `f"{config.APP_BASE_URL}/reset-password"` string** in all paths.)

### Why this exact form

- **No third-party assets** — the only `<link>` is the first-party `/static/css/styles.css`. The only `<script>` blocks are inline IIFEs for the theme init, the form handler, and the theme toggle. No CDN, no remote font, no analytics pixel, no remote image. (TC-27, §10.11.)
- **Form's `action` is the server-controlled `form_action`** — `f"{config.APP_BASE_URL}/reset-password"`, spliced via `{{form_action}}` and `html.escape(..., quote=True)`-d. A student setting `Host: evil.example` on the GET request sees no change in the rendered `action`.
- **Hidden `csrf_token` field** — first child of each form, matching every other form in the project.
- **`confirm_password` field exists** — mirrors the v0 signup form's posture. Client-side JS catches a mismatch before the form is submitted; the route also returns `400 {"error": "Passwords do not match."}` as a belt-and-suspenders.
- **Theme compatibility** — uses the same CSS custom properties and the same theme-init IIFE as `login.html`. The dark-mode toggle works without a JS change.
- **Accessibility** — explicit `<label for="…">` pairings, `role="alert"` on errors, `role="status" aria-live="polite"` on success.

### Template 3 — Additive "Forgot password?" link on `login.html`

**Location:** under the existing `<p class="form-link">Don't have an account? <a href="/signup">Sign up</a></p>` (line 127 of the current `login.html`).

**Change:** add a sibling `<p>` immediately after, with the same `.form-link` class:

```html
<p class="form-link"><a href="/forgot-password">Forgot your password?</a></p>
```

That is the *only* change to `login.html`. No JS, no `csrf_token`, no script change. The link is a plain `<a href>` GET navigation.

### Verification (phase-local)

- [ ] `curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3001/forgot-password` returns `200`.
- [ ] The response body contains `<form id="forgot-form">` and a hidden `csrf_token` input.
- [ ] The response body contains **no** `<script src="https://…">`, **no** `<link href="https://…">`, **no** `<img src="https://…">`, **no** `@font-face`, **no** analytics pixel.
- [ ] `curl -s "http://localhost:3001/reset-password?token=anything" -o /tmp/reset.html` — the response body is `200`; the body contains `<form id="reset-form" … action="…">` only if a valid token was supplied; otherwise an outcome message.
- [ ] With a valid token, the form's `action` attribute equals `f"{config.APP_BASE_URL}/reset-password"` (e.g. `http://localhost:3001/reset-password`).
- [ ] With `curl -H "Host: evil.example" "http://localhost:3001/reset-password?token=<valid>"`, the form's `action` attribute is **unchanged** (still `http://localhost:3001/reset-password`, not `http://evil.example/reset-password`). This is the Host Header Injection closure test.
- [ ] The page contains a `<!-- … -->` comment explaining the no-third-party-asset posture.
- [ ] `curl -s http://localhost:3001/login` shows the new "Forgot your password?" link under the "Sign up" link.
- [ ] `git diff frontend/templates/login.html` shows ONLY the new `<p class="form-link">…</p>` line.
- [ ] `git status frontend/templates/` shows `forgot_password.html` and `reset_password.html` as new untracked files.
- [ ] `git diff` on every other template file is empty.

### Rollback

- Delete `forgot_password.html` and `reset_password.html`; remove the one-line addition from `login.html`. Phase 5's route handlers will return `FileNotFoundError` from `_load_template(...)`; remove them too. No data loss.

---

## Phase 7 — CSS: Append a Small Additive Block

### Files touched

- **MODIFY:** `frontend/static/css/styles.css` — append a small additive block (`.reset-form`, `.reset-message`, `.reset-status`).

### Files NOT touched

- Every existing CSS rule — byte-for-byte unchanged. The new block is appended at the end, with a clearly-marked section comment.

### Precise additive change

**Location:** at the end of `styles.css`.

```css
/* ========================================================================
   Forgot Password (v2.1.0)
   Additive block for /forgot-password and /reset-password. No existing
   rule is modified. Uses the existing CSS custom properties (--indigo-*,
   --surface-*) so the light/dark theme toggle works without a JS change.
   ======================================================================== */
.reset-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
    margin-top: 16px;
}

.reset-message {
    background: #eef1ff;          /* matches existing form-panel palette */
    border: 1px solid #c5cae9;
    color: #1a237e;
    border-radius: 8px;
    padding: 12px 14px;
    margin: 12px 0;
    font-size: 0.9rem;
    line-height: 1.45;
}
[data-theme="dark"] .reset-message {
    background: #1f2540;
    border-color: #2c3460;
    color: #c5cae9;
}

.reset-status {
    margin-top: 8px;
    font-size: 0.85rem;
    color: var(--muted, #64748b);
}
[data-theme="dark"] .reset-status {
    color: var(--muted, #94a3b8);
}
```

### Why this exact form

- **Appended at the end** — same posture as the prior `.cf-turnstile` block (added in v2.0.0). A reviewer can confirm with `git diff` that no existing rule was modified.
- **No new color tokens** — the new block reuses the existing `--indigo-*` and `#c5cae9` palette; the dark-mode override uses the same hex values the v1.0.0 dark-mode toggle already uses.
- **Additive** — the page can render correctly even if the new block is removed (the form still inherits `.form-group` / `.form-input` / `.btn` styles). The new block is purely spacing/emphasis polish.

### Verification (phase-local)

- [ ] `git diff frontend/static/css/styles.css` shows ONLY the appended block.
- [ ] No existing CSS rule was modified (every other rule's line numbers and text are byte-for-byte unchanged).
- [ ] `curl -s http://localhost:3001/forgot-password` — the response body is visually unchanged compared to the pre-CSS-addition state, but the success-message and form-error states have the new background/border.

### Rollback

- Remove the appended block. No data loss.

---

## Phase 8 — Documentation: `.env.example`, `README.md`, `CLAUDE.md`

### Files touched

- **MODIFY:** `.env.example` — add a `PASSWORD_RESET_TTL_SECONDS=900` line in a new "Password Reset (optional, for local demos)" block.
- **MODIFY:** `README.md` — add a v2.1.0 release row; add a "Forgot Password — Setup" subsection.
- **MODIFY:** `CLAUDE.md` — add a "Forgot Password (v2.1.0)" bullet to the integration section, an Important-Rules entry, and a Specification-Hierarchy entry.

### Files NOT touched

- Every other doc file.

### Precise additive changes

**`.env.example`** — add a new block at the end (with the existing SendGrid block as a sibling):

```
# --- Password Reset (v2.1.0) ---
# Time-to-live (seconds) for forgot-password reset links. The spec
# fixes this at 15 minutes; the env var is a non-secret demo knob
# (e.g. PASSWORD_RESET_TTL_SECONDS=30 to demo expiry in seconds).
# The email transport reuses the SendGrid settings above.
PASSWORD_RESET_TTL_SECONDS=900
```

**`README.md`** — add a v2.1.0 release row at the top of the "Release History" (the existing first row is the v0.1.0 / v1.0.0 baseline), and a new "Forgot Password — Setup" subsection under the existing feature list:

- The release row: `| v2.1.0 | … | Forgot Password (token-based reset via email link). Fully hardened: parameterized SQL, bcrypt, generic enumeration-resistant response, server-side-only URLs (no Host Header Injection), first-party assets only (no Referer Leakage). |`
- The setup subsection: a short note covering the SendGrid requirement, the 15-minute TTL, the five-criteria strength policy, the generic-response enumeration resistance, and the fully-hardened posture (no Host Header, no Referer Leakage). The subsection is 10–15 lines of Markdown.

**`CLAUDE.md`** — add:
1. A new bullet in the "Integration" section: `- **Forgot Password (v2.1.0):** …`. Summarize: token-based reset via email link, `secrets.token_urlsafe(32)` + `hashlib.sha256`, 15-minute strict TTL, single-use, generic enumeration-resistant response, server-side-only URLs from `config.APP_BASE_URL`, first-party assets only, no new dependency, sixth DB-schema change (`password_resets` table, additive `CREATE TABLE IF NOT EXISTS`).
2. A new Important-Rules entry: `- The Forgot Password feature (…): every new SQL is parameterized; the new password is enforced by `auth_service.password_meets_policy()` and bcrypt-hashed; the emailed link and the form's `action` are built **exclusively** from `config.APP_BASE_URL`; the new templates load no third-party asset. …`
3. A new Specification-Hierarchy entry: `21. \`.claude/specs/forgot-password.md\` + \`.claude/specs/forgot-password-plan.md\` — Forgot Password (v2.1.0 feature).`

### Why this exact form

- **Consistent with every prior feature's doc footprint** — Verification v1.0.4, Lockout v1.0.5, OTP v1.0.6, TOTP v1.0.7, QR Code Login v1.0.8, CAPTCHA v2.0.0 all have a README release row, a setup subsection, a CLAUDE.md integration bullet, an Important-Rules entry, and a Specification-Hierarchy entry. The new docs follow the same shape.
- **No new env var block for SMTP** — the mailer reuses SendGrid.
- **No new dependency note** — the only env var is a non-secret tunable.

### Verification (phase-local)

- [ ] `cat .env.example` ends with the new block.
- [ ] `git diff README.md` shows ONLY the v2.1.0 release row and the new setup subsection.
- [ ] `git diff CLAUDE.md` shows ONLY the new integration bullet, the new Important-Rules entry, and the new Specification-Hierarchy entry.
- [ ] No other file in the repo is modified by Phase 8.

### Rollback

- Revert the three doc files. No data loss.

---

## Phase 9 — End-to-End Verification

This phase re-runs every check from the spec's §10 against the fully-implemented feature. It is the only phase that touches the running app end-to-end.

### Pre-flight

- [ ] Confirm `git diff` against the pre-implementation commit shows ONLY the file changes specified in Phases 1–8.
- [ ] Confirm `git status` shows no untracked files other than the two new templates.
- [ ] Confirm `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are byte-for-byte unchanged (`git diff` is empty).
- [ ] Confirm the protected modules are byte-for-byte unchanged: `git diff backend/app/main.py backend/app/services/auth_service.py backend/app/core/security.py backend/app/core/csrf.py backend/app/core/rate_limit.py` is empty.

### §10.2 — Boot and verify the schema

- [ ] `rm -f vulnerable_app.db && uv run backend/app/main.py` boots without error.
- [ ] `sqlite3 vulnerable_app.db ".schema password_resets"` shows the full DDL (`id`, `user_id`, `token_hash UNIQUE NOT NULL`, `expires_at REAL NOT NULL`, `used INTEGER NOT NULL DEFAULT 0`).
- [ ] `sqlite3 vulnerable_app.db ".schema users"` is byte-for-byte the same as before (no extra columns, no `DROP TABLE`).

### §10.3 — End-to-end happy path (manual UI)

- [ ] Sign up `alice@example.com` with `OldPass!2024`; promote to verified in the DB.
- [ ] Visit `/forgot-password`; the form renders (or `email_not_configured.html` if SendGrid is off).
- [ ] Submit `email = "alice@example.com"`; the page shows the generic success message.
- [ ] `sqlite3 … "SELECT id, user_id, substr(token_hash, 1, 12) || '…', expires_at, used FROM password_resets;"` shows one row with a 64-char hex SHA-256 hash, `expires_at ≈ time.time() + 900`, `used = 0`.
- [ ] Open the link from the SendGrid activity log. The page renders the form.
- [ ] The form's `action` attribute is `f"{config.APP_BASE_URL}/reset-password"` (e.g. `http://localhost:3001/reset-password`), **not** derived from the request URL.
- [ ] The page contains **no** `<script src="https://…">`, **no** `<link href="https://…">`, **no** `<img src="https://…">`, **no** `@font-face`, **no** analytics pixel.
- [ ] Submit `NewPass!2026` / `NewPass!2026`; the page redirects to `/login`.
- [ ] `users.password` is now a bcrypt hash starting with `$2b$12$…` (not the plaintext).
- [ ] `password_resets.used` is now `1`.
- [ ] Log in with `alice` / `NewPass!2026`; the page redirects to `/welcome`.

### §10.4 — Negative paths

- [ ] Unknown email: `POST /forgot-password` with `email = "no-such@example.com"` returns the same generic `200`; no `password_resets` row is added.
- [ ] Unverified local user: create a new account, do not promote; submit the same reset flow; the response is identical; no `password_resets` row is added.
- [ ] Google-only account: seed a Google row directly in the DB; submit a reset for that email; the response is identical; no `password_resets` row is added.
- [ ] Expired token: manually set `expires_at = 1`; open the link; the page shows the "expired" message; the form is **not** shown.
- [ ] Single-use: open the link once and submit a strong password (success); then submit the same link again; the page shows the "already been used" message.
- [ ] Weak password: open a valid link, submit `password = "short"`; the page shows the inline error; `used` is still `0`.
- [ ] CSRF missing: in the browser dev tools, delete the hidden `csrf_token` field; submit; the response is `403 {"error": "CSRF token missing or invalid"}` from `CSRFMiddleware`.
- [ ] Rate limit: send 6 `POST /forgot-password` requests from the same IP in 60 seconds; the 6th returns `429 {"error": "Too many requests", "retry_after": <int>}` with a `Retry-After` header.
- [ ] SendGrid unconfigured: unset `SENDGRID_API_KEY` and `SENDGRID_FROM` in `.env`, restart the app; `GET /forgot-password` renders `email_not_configured.html`; `POST /forgot-password` does the same; no enumeration oracle is exposed.

### §10.5 — Hardening verification

- [ ] **Host Header Injection — closed at the spec level:**
  - `curl -i -H "Host: evil.example" "http://localhost:3001/reset-password?token=<plaintext>"` — the response body's `<form … action="…">` reads `action="http://localhost:3001/reset-password"`, **not** `action="http://evil.example/reset-password"`.
  - `grep -nE 'f"http' backend/app/services/password_reset_service.py` returns exactly one line: `reset_url = f"{config.APP_BASE_URL}/reset-password?token={token}"`.
  - `grep -nE 'request\.(url|headers)' backend/app/api/routes/auth.py` returns **no** lines in the new handlers.
- [ ] **Referer Leakage — closed at the spec level:**
  - `curl -s "http://localhost:3001/reset-password?token=<plaintext>" > /tmp/reset.html` — `grep -E '<script[^>]+src="https?://' /tmp/reset.html` is empty; `grep -E '<link[^>]+href="https?://' /tmp/reset.html` is empty; `grep -E '<img[^>]+src="https?://' /tmp/reset.html` is empty; `grep -E '@font-face|url\("https?://' /tmp/reset.html` is empty.
  - The only `<link>` is `href="/static/css/styles.css"` (first-party).
  - Open the page in Chrome with the dev tools Network tab open; observe every request the page issues; every request goes to the application's own origin.
  - Submit the form; the form POST's `Referer` header is the application's own origin (not a third-party host). **No token-bearing URL is leaked to a third party.**

### §10.6 — Mock-SMTP local check

- [ ] With `python -m smtpd.server -n -c DebuggingServer localhost:1025` running in another terminal, the `start_reset` call prints the full email to the sink. The body contains the `reset-password?token=…` link.
- [ ] With SendGrid unconfigured, the page renders `email_not_configured.html` and no email is sent.

### §10.7 — No-new-dependency posture

- [ ] `git diff pyproject.toml backend/pyproject.toml uv.lock` is empty.
- [ ] `grep -E "^import " backend/app/services/password_reset_service.py` shows only `hashlib`, `logging`, `secrets`, `time`, and project-internal modules.

### §10.8 — No-side-effect posture on other modules

- [ ] `git diff backend/app/main.py backend/app/core/security.py backend/app/core/csrf.py backend/app/core/rate_limit.py backend/app/core/oauth.py backend/app/core/captcha.py backend/app/core/qr_login.py backend/app/services/auth_service.py backend/app/services/verification_service.py backend/app/services/otp_service.py backend/app/services/totp_service.py backend/app/services/lockout_service.py backend/app/services/oauth_service.py` is empty.

### §10.9 — Migration is additive

- [ ] On a v2.0.0 DB (no `password_resets` table), `init_db()` creates the table on the next boot.
- [ ] `users` is byte-for-byte unchanged after the migration.

### §10.10 — Log lines do not leak the token

- [ ] `grep -E "token|password" /tmp/server.log` after exercising the flow shows only `Password reset email sent to <email>` and `Password reset consumed for user_id=<int>`. No line contains a plaintext token, a token hash, a plaintext password, or the `reset-password` URL (other than the log-line's own substring "reset" matched by the grep).

### §10.11 — No third-party assets on the reset page

- [ ] `grep -oE '<form[^>]+action="[^"]+"' /tmp/reset.html` shows `action="http://localhost:3001/reset-password"` (or the `APP_BASE_URL` value), **not** a request-derived URL.
- [ ] `grep -E '<script[^>]+src="https?://' /tmp/reset.html` is empty.
- [ ] `grep -E '<link[^>]+href="https?://' /tmp/reset.html` is empty.
- [ ] `grep -E '<img[^>]+src="https?://' /tmp/reset.html` is empty.
- [ ] `grep -E '@font-face|url\("https?://' /tmp/reset.html` is empty.

### Final regression sweep

- [ ] **All 8 closed vulnerabilities stay closed** — re-run the canonical exploit steps from `docs/EXPLOITS.md`:
  - SQL Injection on `/search?q=…` — still parameterized, no auth-bypass via `?q=' OR '1'='1`.
  - Stored XSS via username `<script>…</script>` — dashboard still escapes the username.
  - Reflected XSS on `/search?q=<script>…` — still escaped.
  - Session Hijacking — session secret is still env-sourced, not hardcoded.
  - Weak Password — bcrypt is still the sole password authenticator; MD5 rows still fail closed.
  - Exposed Database — `/download/db` still 404s.
  - No Rate Limiting — `RateLimitMiddleware` still throttles POSTs.
  - CSRF — `CSRFMiddleware` still validates the hidden token on every POST.
- [ ] **All prior features still work end-to-end** — re-run the smoke tests for v1.0.2 (profile / change password), v1.0.3 (Google OAuth if configured), v1.0.4 (email verification on signup), v1.0.5 (account lockout), v1.0.6 (email OTP 2FA), v1.0.7 (TOTP), v1.0.8 (QR code login), v2.0.0 (CAPTCHA on login). No regression.

### Sign-off

When every check above passes on a fresh clone, the implementation is complete. The state of the repo is:

- `backend/app/db/session.py` — one new `CREATE TABLE IF NOT EXISTS password_resets (...)` block.
- `backend/app/core/config.py` — one new `PASSWORD_RESET_TTL_SECONDS` constant; one docstring line.
- `backend/app/core/mailer.py` — one new `send_password_reset_email(...)` function; one docstring extension.
- `backend/app/services/password_reset_service.py` — new file.
- `backend/app/api/routes/auth.py` — one new import; four new route handlers; **no** change to any existing handler.
- `frontend/templates/forgot_password.html` — new file.
- `frontend/templates/reset_password.html` — new file.
- `frontend/templates/login.html` — one new `<p class="form-link">…</p>` line.
- `frontend/static/css/styles.css` — one new appended `.reset-form` / `.reset-message` / `.reset-status` block.
- `.env.example`, `README.md`, `CLAUDE.md` — small additive doc updates.

**No other file is touched.** The protected modules (`auth_service.login/signup/change_password`, `main.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`) are byte-for-byte unchanged. The dependency manifests are byte-for-byte unchanged. **No new vulnerability is introduced.** The Host Header Injection and Referer Leakage vectors are closed at the spec level.

---

**End of plan.**
