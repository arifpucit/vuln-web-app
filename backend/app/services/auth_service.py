"""Authentication business logic for signup and login.

The HTTP route handlers in api/routes/auth.py are thin wrappers around the
two functions defined here. Keeping the business logic separate from the
transport layer means the SQL + password-verification flow can be unit-
tested without spinning up FastAPI, and the route handler stays a one-liner
that just forwards form fields to the service.

Closed vulnerabilities relevant to this file:
- VULN-1 (SQL Injection): every SQL statement uses parameterized `?`
  placeholders. Never reintroduce string concatenation here.
- VULN-5 (Weak Password Storage): passwords are hashed with bcrypt via
  core/security.hash_password() before insert, and checked with
  core/security.verify_password() in Python (NOT inside SQL -- bcrypt's
  per-call salt makes SQL equality matching impossible).
"""

import re
import sqlite3

from starlette.requests import Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse

from app.db.session import get_db
from app.core import config
from app.core.security import hash_password, verify_password
from app.services import verification_service
from app.services import lockout_service
from app.services import otp_service
from app.services import totp_service
from app.core import hibp


def password_meets_policy(password: str) -> bool:
    """Return True when `password` satisfies the same five criteria the
    signup page's strength meter checks: length >= 8 plus at least one
    lowercase letter, one uppercase letter, one digit, and one special
    (non-alphanumeric) character.

    On signup the meter is advisory only (the server accepts any non-empty
    password). The change-password flow, by contrast, ENFORCES this policy
    server-side so a weak new password is rejected regardless of the client
    -- the profile form runs the identical check in JS for inline feedback,
    but this function is the authoritative gate.
    """
    return (
        len(password) >= 8
        and re.search(r"[a-z]", password) is not None
        and re.search(r"[A-Z]", password) is not None
        and re.search(r"[0-9]", password) is not None
        and re.search(r"[^A-Za-z0-9]", password) is not None
    )


def signup(username: str, email: str, password: str):
    """Create a new user account.

    Returns (one of):
    - RedirectResponse(302, /login) on success -- the browser then follows
      to the login page, where the user authenticates with the credentials
      they just chose.
    - HTMLResponse(400, ...) if any field is empty, if the username already
      exists, or on any other DB error. The 400 responses are tiny HTML
      snippets with a "Go back" link -- intentional for the lab's no-JS
      signup flow.

    Note that the CSRF middleware has already validated the request before
    this function runs, so we do not need to re-check any csrf_token here.
    """
    # Trivial input validation. The HTML form's `required` attribute catches
    # most cases client-side, but a hand-crafted POST can still skip it, so
    # we re-validate server-side.
    if not username or not email or not password:
        return HTMLResponse(
            content="<h3>All fields are required</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )

    # Check for compromised password (if HIBP configured)
    if config.is_hibp_configured() and hibp.is_password_compromised(password):
        return HTMLResponse(
            content="<h3>This password has been exposed in a data breach. "
                    "Please choose a different password.</h3>"
                    "<a href='/signup'>Go back</a>",
            status_code=400,
        )

    # Hash before insert. The plaintext password never touches the DB.
    hashed = hash_password(password)

    # FIXED: SQL Injection closed by using parameterized query.
    # The `?` placeholders are passed as a separate argument list, so the
    # SQLite driver binds the values without any string interpolation --
    # crafted input like `'); DROP TABLE users; --` is treated as data,
    # not as SQL.
    #
    # is_verified is listed explicitly as 0: a brand-new local account starts
    # UNVERIFIED until the user clicks the link in the verification email
    # (Email-Verification feature, v1.0.4). Google/OAuth accounts are created
    # as 1 in oauth_service.py instead.
    query = "INSERT INTO users (username, email, password, is_verified) VALUES (?, ?, ?, 0)"

    conn = get_db()
    try:
        cursor = conn.execute(query, [username, email, hashed])
        conn.commit()
        # Capture the new row id BEFORE closing the connection so we can issue
        # the verification token against it.
        user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        # Triggered by the `UNIQUE` constraint on `username`. Distinct from
        # the generic Exception branch below so the user gets a precise
        # error message instead of a generic "Error: ...".
        return HTMLResponse(
            content="<h3>Username already exists</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )
    except Exception as e:
        # Catch-all for unexpected DB errors (disk full, schema mismatch,
        # etc.). The error message is reflected back to the user; for a
        # production app you would log this server-side and show a
        # generic error instead.
        return HTMLResponse(
            content=f"<h3>Error: {str(e)}</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )
    finally:
        conn.close()

    # Account created. Now that the row exists (and the connection is closed),
    # issue a verification token and email the link. background=True hands the
    # SMTP send to a daemon thread so the signup response (the "check your
    # inbox" page) returns immediately instead of waiting on the Gmail
    # handshake. A failed/unconfigured send is NOT fatal -- the account stands
    # and the user can resend from the login page (Email-Verification, v1.0.4).
    # The signup routes already gate on is_email_configured(), so this is only
    # reached when SMTP is configured.
    verification_service.start_verification(user_id, username, email, background=True)

    # 302 to the "check your inbox" page instead of straight to /login: the
    # account is unverified and the user must confirm via the emailed link.
    return RedirectResponse(url="/check-email", status_code=302)


def login(request: Request, username: str, password: str):
    """Authenticate a user and populate the session on success.

    Returns:
    - JSONResponse(200, {"success": True, "redirect": "/welcome"}) on a
      valid credential pair. The session cookie is written by
      SessionMiddleware on the way out because we mutate request.session.
    - JSONResponse(401, {"error": "..."}) on bad credentials, missing
      fields, or DB errors.
    - JSONResponse(401, {"error": "...", "locked": True, "retry_after": <int>})
      when the account is temporarily locked after too many consecutive failed
      attempts (Account-Lockout feature, v1.0.5). Checked BEFORE bcrypt, so a
      locked account is refused even with the correct password and no session
      is written.

    The HTML login page uses fetch() instead of a normal form submit so it
    can read the JSON response and redirect (or display the error inline)
    without a full page reload. That is why this function returns JSON
    instead of a redirect, in contrast to signup() above.

    Note: the same generic 401 body is used for "no such username", "bcrypt
    mismatch", and "legacy MD5 hash" cases. That intentional uniformity
    prevents username-enumeration via timing or message-text differences.
    """
    if not username or not password:
        return JSONResponse(
            content={"error": "Username and password are required"},
            status_code=401,
        )

    # FIXED: SQL Injection closed by using parameterized query.
    # We fetch the row by username, then compare passwords in Python.
    # Pre-fix versions of this code put the password equality test inside
    # the SQL (`WHERE username = ? AND password = ?`); that no longer
    # works because bcrypt produces a different hash each time (random
    # salt), so SQL equality would never match. Doing the bcrypt
    # comparison in Python via verify_password() is the correct primitive.
    query = "SELECT * FROM users WHERE username = ?"

    conn = get_db()
    try:
        cursor = conn.execute(query, [username])
        user = cursor.fetchone()
    except Exception:
        # Treat any DB error as a failed login. We do not surface the
        # underlying exception (avoid leaking schema details to an
        # attacker probing the endpoint).
        return JSONResponse(
            content={"error": "Invalid username or password"},
            status_code=401,
        )
    finally:
        conn.close()

    # Account-lockout gate (v1.0.5): if the account is currently locked, refuse
    # immediately -- BEFORE bcrypt -- even if the password is correct. Only an
    # existing account can be locked; a missing row falls through to the generic
    # 401 below (lockout protects real accounts only). Checking before
    # verify_password() means a locked account never burns a bcrypt hash and
    # cannot be used as a bcrypt-CPU oracle. This per-account control layers on
    # top of the unchanged per-IP rate limiter (VULN-7); it does not replace it.
    #
    # Trade-off (deliberate): the lock message reveals that this username exists,
    # a bounded relaxation of the otherwise-strict enumeration resistance --
    # every OTHER failure still returns the identical generic 401 below.
    if user:
        remaining = lockout_service.seconds_remaining(user)
        if remaining > 0:
            return JSONResponse(
                content={
                    "error": lockout_service.lock_message(remaining),
                    "locked": True,
                    "retry_after": remaining,
                },
                status_code=401,
            )

    # verify_password() returns False rather than raising on a malformed
    # hash, so legacy MD5 rows fail closed here -- they cannot log in.
    if user and verify_password(password, user["password"]):
        # Correct password: clear any accumulated failure count / stale lock
        # BEFORE the verification gate, so a correct-but-unverified login also
        # resets the chain (it is not a brute-force attempt).
        lockout_service.reset(user["id"])
        # Email-Verification gate (v1.0.4): a correct password is NOT enough --
        # the account must be verified before a session is created. Google
        # accounts and grandfathered legacy accounts are is_verified=1, so they
        # pass straight through. The `unverified` flag lets the login page
        # reveal a "Resend verification email" affordance. No session is
        # written, so an unverified user cannot reach /welcome.
        if not user["is_verified"]:
            return JSONResponse(
                content={
                    "error": (
                        "Please verify your email before logging in. "
                        "Check your inbox for the verification link."
                    ),
                    "unverified": True,
                },
                status_code=401,
            )
        # Second factor #1 -- Authenticator App TOTP (v1.0.7): if the user
        # enrolled an authenticator app, do NOT create the session yet. Stash the
        # pending marker (NOT user_id, so /welcome and /profile stay gated) and
        # send them to the TOTP screen. This runs AFTER bcrypt + the verified gate
        # (a true second factor) and BEFORE the Email-OTP branch below, so TOTP
        # takes PRECEDENCE and NO email is sent. The code comes from the user's
        # authenticator app -- nothing is delivered, so this works even with SMTP
        # unconfigured. Auth stays session-only (no JWT): the session is promoted
        # to a full login only after the code is verified at POST /login/totp.
        if user["totp_enabled"]:
            request.session["pending_2fa_user_id"] = user["id"]
            request.session["pending_2fa_username"] = user["username"]
            request.session["pending_2fa_method"] = "totp"
            return JSONResponse(
                content={"otp_required": True, "redirect": "/login/totp"}
            )

        # Second factor #2 -- Email OTP 2FA (v1.0.6): if the user opted in, do NOT
        # create the session yet. Stash a short-lived pending marker (NOT
        # user_id, so /welcome and /profile stay gated), email a 6-digit code,
        # and tell the page to go to the OTP screen. This runs AFTER bcrypt +
        # the verified gate, so only a fully password-authenticated, verified
        # user ever reaches it -- the OTP is a true second factor, not a weaker
        # first one. Auth stays session-only (no JWT): the session is promoted
        # to a full login only after the code is verified at POST /login/otp.
        if user["two_factor_enabled"]:
            if not config.is_email_configured():
                # Fail closed: 2FA is on but we cannot deliver the code. Never
                # bypass the second factor by silently completing login.
                return JSONResponse(
                    content={
                        "error": (
                            "Two-factor authentication is enabled but email "
                            "delivery is unavailable. Please contact the "
                            "administrator."
                        )
                    },
                    status_code=401,
                )
            request.session["pending_2fa_user_id"] = user["id"]
            request.session["pending_2fa_username"] = user["username"]
            # Disambiguate which verify screen the login page should open (TOTP vs
            # email) -- the TOTP branch above sets "totp".
            request.session["pending_2fa_method"] = "email"
            # background=True: the daemon-thread SMTP send does not block this
            # response; the code is already persisted, so a slow/failed send is
            # recoverable via the OTP screen's resend button.
            otp_service.start_challenge(
                user["id"], user["username"], user["email"], background=True
            )
            return JSONResponse(
                content={"otp_required": True, "redirect": "/login/otp"}
            )

        # No 2FA: populate the session and complete the login. SessionMiddleware
        # serializes this dict and writes it back as a signed cookie on the
        # response. The CSRF token (already in the session from the prior GET
        # /login page render) is preserved -- we are merging keys, not replacing
        # the whole session.
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        return JSONResponse(content={"success": True, "redirect": "/welcome"})
    else:
        # Wrong password. For an EXISTING account, count this toward the lockout
        # threshold (v1.0.5); a non-existent username has no row to touch. If
        # this miss trips the lock, surface the locked 401 with a countdown.
        if user:
            remaining = lockout_service.register_failure(
                user["id"], user["failed_login_attempts"]
            )
            if remaining > 0:
                return JSONResponse(
                    content={
                        "error": lockout_service.lock_message(remaining),
                        "locked": True,
                        "retry_after": remaining,
                    },
                    status_code=401,
                )
        # Same JSON body for "no such user" and "wrong-but-not-yet-locked
        # password". See the docstring's note on enumeration resistance.
        return JSONResponse(
            content={"error": "Invalid username or password"},
            status_code=401,
        )


def change_password(request: Request, current_password: str, new_password: str):
    """Change the logged-in user's password.

    Returns JSON for every outcome (mirrors login()) so the profile page's
    fetch() handler can render feedback inline without a reload:
    - 200 {"success": True, "message": "Password updated successfully"}
    - 401 {"error": "Not authenticated"}              (no session user_id / row gone)
    - 400 {"error": "Current and new password are required"}  (empty input)
    - 401 {"error": "Current password is incorrect"}  (bad/legacy current pw)
    - 400 {"error": "Could not update password"}       (unexpected DB error)

    Security posture (all preserved from the closed vulnerabilities):
    - VULN-1: the SELECT and UPDATE are parameterized -- never concatenate.
    - VULN-5: the current password is checked with verify_password() (bcrypt,
      fails closed on legacy MD5) and the new password is hashed with
      hash_password() (bcrypt) before storage.
    The CSRF token and per-IP rate limit are enforced by middleware before
    this function ever runs.
    """
    # Auth gate. The route also renders /profile only for sessions, and the
    # CSRF middleware already blocks a session-less POST at 403 -- this is
    # defense in depth so the service is safe to call directly.
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    if not current_password or not new_password:
        return JSONResponse(
            content={"error": "Current and new password are required"},
            status_code=400,
        )

    # Enforce the same strength policy the signup page advertises (length >= 8
    # plus lower/upper/digit/special). Unlike signup -- where the meter is
    # advisory and the server accepts anything -- the change-password flow
    # rejects a weak new password server-side. The profile form runs the
    # identical check in JS, but this is the authoritative gate.
    if not password_meets_policy(new_password):
        return JSONResponse(
            content={
                "error": (
                    "New password must be at least 8 characters and include an "
                    "uppercase letter, a lowercase letter, a digit, and a special "
                    "character"
                )
            },
            status_code=400,
        )

    # Check for compromised password (if HIBP configured)
    if config.is_hibp_configured() and hibp.is_password_compromised(new_password):
        return JSONResponse(
            content={
                "error": "This password has been exposed in a data breach. "
                         "Please choose a different password."
            },
            status_code=400,
        )

    # FIXED: SQL Injection closed -- parameterized SELECT by primary key.
    select_query = "SELECT * FROM users WHERE id = ?"
    # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
    update_query = "UPDATE users SET password = ? WHERE id = ?"

    conn = get_db()
    try:
        cursor = conn.execute(select_query, [user_id])
        user = cursor.fetchone()
        if not user:
            # Session references a row that no longer exists (no delete flow
            # exists, so this is defensive only).
            return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

        # FIXED: Weak Password Storage closed -- verify the CURRENT password
        # with bcrypt in Python. Returns False (never raises) on a legacy MD5
        # row, so such accounts cannot change their password here; they must
        # re-register, exactly like the login flow.
        if not verify_password(current_password, user["password"]):
            return JSONResponse(
                content={"error": "Current password is incorrect"},
                status_code=401,
            )

        # FIXED: Weak Password Storage closed -- hash the NEW password with
        # bcrypt before it touches the DB. The plaintext never persists.
        hashed = hash_password(new_password)
        conn.execute(update_query, [hashed, user_id])
        conn.commit()
        return JSONResponse(
            content={"success": True, "message": "Password updated successfully"}
        )
    except Exception:
        # Generic error -- never reflect the underlying DB exception text.
        return JSONResponse(
            content={"error": "Could not update password"},
            status_code=400,
        )
    finally:
        conn.close()
