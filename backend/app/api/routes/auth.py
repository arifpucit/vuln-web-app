"""HTTP route handlers.

All eight endpoints of the lab app live here. The handlers are
deliberately thin: they parse request inputs, call into the service layer
(`auth_service`) or directly query the DB for read-only routes, render or
escape any HTML, and return a Response. No business logic, no SQL string
construction, and no password hashing happens in this module.

Route summary:
- GET  /         redirect to /signup (default landing page)
- GET  /signup   render signup form (issues CSRF token)
- POST /signup   create account, redirect to /login
- GET  /login    render login form (issues CSRF token)
- POST /login    authenticate, write session, return JSON
- GET  /search   case-insensitive search across users (intentionally public)
- GET  /welcome  protected dashboard (requires session)
- GET  /logout   clear session, redirect to /login

Closed vulnerabilities relevant to this file:
- VULN-1 (SQL Injection): `/search` uses parameterized `LIKE ?`.
- VULN-2 (Stored XSS): `/welcome` escapes the username before splicing
  into the dashboard template.
- VULN-3 (Reflected XSS): `/search` escapes q, every row column, and the
  exception text before splicing into the response HTML.
- VULN-6 (Exposed Database): the pre-fix `/download/db` route is gone.
- VULN-8 (CSRF): GET /signup and GET /login splice a per-session token
  into a hidden form field; the CSRFMiddleware validates it on POST.
"""

import os
import html
import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from app.core.csrf import get_or_create_csrf_token
from app.core import config
from app.core import qr_login
from app.core import captcha
from app.core.oauth import oauth
from app.services import auth_service
from app.services import oauth_service
from app.services import verification_service
from app.services import otp_service
from app.services import totp_service
from app.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter()

# Absolute path to frontend/templates. The four `..` segments climb from
# this file (backend/app/api/routes/auth.py) back up to the repo root.
# Resolved at import time so the path is stable regardless of CWD.
BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
TEMPLATE_DIR = os.path.join(BASE_DIR, "frontend", "templates")


def _load_template(name: str) -> str:
    """Read a template file from disk on every call (no caching, no engine).

    Mirrors the inline `with open(...)` pattern used elsewhere in this module,
    factored out so the new routes that just render a static page (and the
    email-not-configured gate used in two places) stay one-liners.
    """
    with open(os.path.join(TEMPLATE_DIR, name), "r") as f:
        return f.read()


@router.get("/")
async def index():
    """Default landing page -- send first-time visitors straight to signup."""
    return RedirectResponse(url="/signup", status_code=302)


@router.get("/signup")
async def signup_page(request: Request):
    """Render the signup HTML form with a per-session CSRF token spliced in.

    Templates are loaded from disk on every request (no caching, no
    template engine) so live edits to the HTML files take effect on
    refresh. The CSRF token splice uses the same str.replace pattern as
    /welcome -- minimal infrastructure, easy for students to read.

    Email-verification gate (v1.0.4): signup creates an UNVERIFIED account and
    emails a confirmation link, so it cannot work without SMTP. When email is
    not configured we render the friendly setup page instead of a form that
    can't succeed -- mirrors the Continue-with-Google "not configured" degrade.
    """
    if not config.is_email_configured():
        return HTMLResponse(content=_load_template("email_not_configured.html"))

    with open(os.path.join(TEMPLATE_DIR, "signup.html"), "r") as f:
        page = f.read()
    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    # get_or_create_csrf_token() is idempotent: it returns the existing
    # token if one is already in the session, or generates one if not.
    # html.escape is defensive only -- the token alphabet (URL-safe Base64)
    # contains no HTML-significant characters today, but escaping keeps the
    # splice safe under future token-format changes.
    token = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(token, quote=True))
    hibp_info = '<div class="hibp-notice">Your password is checked against the Have I Been Pwned breach database to prevent use of compromised credentials.</div>' if config.HIBP_ENABLED else ''
    page = page.replace('{{hibp_info}}', hibp_info)
    secure_indicator = '🔒' if request.url.scheme == "https" else '🌐'
    page = page.replace('{{secure_indicator}}', secure_indicator)
    return HTMLResponse(content=page)


@router.post("/signup")
async def signup_post(
    username: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
):
    """Handle signup form submission.

    Defaults of `Form("")` mean missing fields become empty strings rather
    than raising 422 -- the service layer handles the "all fields required"
    case with a user-friendly HTML error.

    The hidden `csrf_token` field is also POSTed but is consumed and
    validated by CSRFMiddleware before this handler runs; FastAPI's
    Form() ignores unknown form fields, so it transparently disappears.

    Email-verification gate (v1.0.4): refuse to create an account that could
    never be verified. Defense in depth against a direct POST that skips the
    gated GET /signup page -- same not-configured page, no row inserted.
    """
    if not config.is_email_configured():
        return HTMLResponse(content=_load_template("email_not_configured.html"))

    return auth_service.signup(username, email, password)


@router.get("/check-email")
async def check_email_page():
    """Static "we sent you a verification link" page shown right after signup.

    No user input is reflected here (intentionally generic -- it does not name
    the address), so there is no sink to escape. Loaded fresh from disk like
    every other template.
    """
    return HTMLResponse(content=_load_template("check_email.html"))


@router.get("/verify")
async def verify_email(request: Request):
    """Consume an email-verification link.

    Reads the high-entropy token from the query string and asks the service to
    validate it. Renders a fixed, server-controlled outcome message -- the raw
    token is NEVER reflected back into the page (VULN-3 posture). This is a GET
    because the capability is the unguessable token in the link itself, exactly
    like the OAuth GET callback; the POST-only CSRF/rate-limit middleware
    correctly ignore it.
    """
    token = request.query_params.get("token", "")
    result = verification_service.verify_email_token(token)

    # On success, log the user straight in (clicking the emailed link proves
    # control of the address) by writing the SAME session keys as
    # auth_service.login(), then send them to their dashboard. This mutation is
    # what makes SessionMiddleware emit the signed Set-Cookie.
    if result["status"] == "ok":
        user = result["user"]
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        return RedirectResponse(url="/welcome", status_code=302)

    # Expired / invalid: render a fixed, HTML-escaped outcome message. These
    # strings are author-controlled, but we still html.escape() them before
    # splicing -- same defensive output-encoding discipline used throughout
    # this module. The raw token is never reflected (VULN-3 posture).
    outcomes = {
        "expired": (
            "Link expired",
            "This verification link has expired. Go to the login page, enter "
            "your username and password, and use “Resend verification email”.",
        ),
        "invalid": (
            "Invalid link",
            "This verification link is invalid or has already been used.",
        ),
    }
    title, message = outcomes.get(result["status"], outcomes["invalid"])

    page = _load_template("verify_result.html")
    page = page.replace("{{title}}", html.escape(title, quote=True))
    page = page.replace("{{message}}", html.escape(message, quote=True))
    return HTMLResponse(content=page)


@router.post("/verify/resend")
async def verify_resend(
    username: str = Form(""),
    password: str = Form(""),
):
    """Re-send the verification email, gated on valid credentials.

    Login is blocked until verification, so an unverified user has no session
    to gate on. The login page calls this with the username + password the user
    just entered; verification_service.resend_for_credentials() re-checks them
    with bcrypt (the password is the authorization) and re-issues the link.
    Thin handler -- same shape as login_post(). The hidden csrf_token and the
    per-IP rate limit are enforced by middleware before this runs (it is a
    POST); FastAPI's Form() ignores the extra csrf_token field.
    """
    return verification_service.resend_for_credentials(username, password)


@router.get("/login")
async def login_page(request: Request):
    """Render the login HTML form with a per-session CSRF token spliced in.

    Same pattern as signup_page(): load template, issue/read token,
    splice via str.replace.
    """
    with open(os.path.join(TEMPLATE_DIR, "login.html"), "r") as f:
        page = f.read()
    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    token = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(token, quote=True))
    hibp_info = '<div class="hibp-notice">Your password is checked against the Have I Been Pwned breach database to prevent use of compromised credentials.</div>' if config.HIBP_ENABLED else ''
    page = page.replace('{{hibp_info}}', hibp_info)
    secure_indicator = '🔒' if request.url.scheme == "https" else '🌐'
    page = page.replace('{{secure_indicator}}', secure_indicator)
    # CAPTCHA on Login (v2.0.0): render the Cloudflare Turnstile widget + script
    # only when both keys are configured; otherwise both placeholders collapse to
    # "" and the login page is byte-for-byte the pre-CAPTCHA page (graceful degrade).
    if config.is_captcha_configured():
        head = (
            '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"'
            " async defer></script>"
        )
        widget = (
            '<div class="cf-turnstile" data-sitekey="'
            + html.escape(config.TURNSTILE_SITE_KEY, quote=True)
            + '"></div>'
        )
    else:
        head = widget = ""
    page = page.replace("{{turnstile_head}}", head).replace(
        "{{turnstile_widget}}", widget
    )
    return HTMLResponse(content=page)


@router.post("/login")
async def login_post(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    cf_turnstile_response: str = Form("", alias="cf-turnstile-response"),
):
    """Handle login form submission.

    CAPTCHA on Login (v2.0.0): when Turnstile is configured, the token is
    verified BEFORE auth_service.login() -- a request that fails the CAPTCHA
    never reaches the lockout gate, bcrypt, or the DB, and writes no session.
    A failed check returns 400 with a fixed message (the raw token is never
    reflected or logged -- VULN-3). When Turnstile is unconfigured the check is
    skipped entirely (graceful degrade). The Form alias is required because the
    Turnstile field name (`cf-turnstile-response`) contains hyphens.

    The Request parameter is forwarded to the service layer so it can
    write user_id/username/email into `request.session` on success --
    that mutation is what triggers SessionMiddleware to write the
    Set-Cookie header on the response.
    """
    if config.is_captcha_configured() and not captcha.verify(cf_turnstile_response):
        return JSONResponse(
            {"error": "CAPTCHA verification failed. Please try again."},
            status_code=400,
        )
    return auth_service.login(request, username, password)


@router.get("/search")
async def search_user(q: str = ""):
    """Public, unauthenticated user search by partial username or email.

    Intentionally accessible without a session -- exists for students to
    practice reflected-XSS and SQLi against. Both classes of attack are
    now closed (see FIXED comments below), but the endpoint itself stays.
    """
    if not q:
        return HTMLResponse(content="<h3>No search query provided</h3>")

    # FIXED: SQL Injection closed by using parameterized query
    # FIXED: Reflected XSS closed -- q, row columns, and exception text are HTML-escaped before splicing.
    # The raw values remain in the URL and in the database (output-encoding fix, not input filtering).
    #
    # Why parameterize the LIKE wildcards too? The `?` binds the WHOLE
    # value including the surrounding `%`, so `q = '%foo'` would not let
    # an attacker break out of the LIKE clause -- the `%` is data, not
    # syntax. This is the canonical safe LIKE pattern.
    query = "SELECT username, email FROM users WHERE username LIKE ? OR email LIKE ?"

    conn = get_db()
    try:
        cursor = conn.execute(query, [f"%{q}%", f"%{q}%"])
        rows = cursor.fetchall()

        # Every sink that gets spliced back into HTML gets html.escape()'d
        # with quote=True. quote=True is essential because the values flow
        # into an HTML body -- if any of them later move into an attribute
        # context, the quoted form prevents attribute-injection too.
        safe_q = html.escape(q, quote=True)
        results = ""
        for row in rows:
            safe_username = html.escape(row[0], quote=True)
            safe_email = html.escape(row[1], quote=True)
            results += f"<li>{safe_username} ({safe_email})</li>"

        page = f"<h3>Search results for: {safe_q}</h3><ul>{results}</ul>"
        return HTMLResponse(content=page)
    except Exception as e:
        # Even the exception text is escaped before being reflected --
        # sqlite3 occasionally surfaces user-controlled bytes in its
        # error messages, so this is a real sink, not a paranoia escape.
        safe_error = html.escape(str(e), quote=True)
        return HTMLResponse(content=f"<h3>Error: {safe_error}</h3>")
    finally:
        conn.close()


@router.get("/welcome")
async def welcome_page(request: Request):
    """Render the post-login dashboard.

    Auth check happens here, not in middleware: the only protected route
    is /welcome, so a per-route check is simpler than a route-table or
    decorator-based scheme.
    """
    # If no session cookie or the cookie's payload doesn't carry user_id,
    # the user has not logged in -- bounce them to /login. This is the
    # only authorization gate in the app.
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    # Username is written into the session by auth_service.login(). The
    # "" default lets the template render with an empty <strong> tag if
    # the session was somehow torn (shouldn't happen, defensive only).
    #
    # Note: only verified users ever reach here -- login() refuses to create a
    # session for an unverified account (Email-Verification, v1.0.4) -- so the
    # dashboard needs no verification check or banner.
    username = request.session.get("username", "")

    with open(os.path.join(TEMPLATE_DIR, "dashboard.html"), "r") as f:
        page = f.read()

    # FIXED: Stored XSS closed -- username escaped before substitution.
    # The raw value remains in the session/database (output-encoding fix, not input filtering).
    #
    # The raw username can contain `<script>` from a malicious signup --
    # we do NOT sanitize on the way in (that would lose information and
    # is famously fragile). Instead we escape on the way out, so the
    # rendered HTML treats the username as text, never as markup.
    safe_username = html.escape(username, quote=True)
    page = page.replace("{{username}}", safe_username)

    return HTMLResponse(content=page)


@router.get("/profile")
async def profile_page(request: Request):
    """Render the authenticated profile page.

    Same auth gate as /welcome: no user_id in the session -> bounce to
    /login. Splices the per-session CSRF token (for the change-password
    form) plus the HTML-escaped username and email read from the session.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    username = request.session.get("username", "")
    email = request.session.get("email", "")

    # 2FA cards (Email OTP v1.0.6 + Authenticator-App TOTP v1.0.7): the session
    # does not carry either flag, so read both for the cards' initial state
    # (parameterized SELECT -- VULN-1).
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT two_factor_enabled, totp_enabled FROM users WHERE id = ?",
            [user_id],
        ).fetchone()
    finally:
        conn.close()
    twofa_enabled = bool(row["two_factor_enabled"]) if row else False
    totp_enabled = bool(row["totp_enabled"]) if row else False



    with open(os.path.join(TEMPLATE_DIR, "profile.html"), "r") as f:
        page = f.read()

    # FIXED: CSRF closed -- issue/splice the per-session token for the form.
    token = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(token, quote=True))
    hibp_info = '<div class="hibp-notice">Your password is checked against the Have I Been Pwned breach database to prevent use of compromised credentials.</div>' if config.HIBP_ENABLED else ''
    page = page.replace('{{hibp_info}}', hibp_info)
    secure_indicator = '🔒' if request.url.scheme == "https" else '🌐'
    page = page.replace('{{secure_indicator}}', secure_indicator)

    # FIXED: Stored XSS closed -- escape every user-controlled value before
    # splicing (output encoding, same posture as the dashboard username).
    page = page.replace("{{username}}", html.escape(username, quote=True))
    page = page.replace("{{email}}", html.escape(email, quote=True))

    # Server-controlled "0"/"1" flags for the 2FA cards (not user input).
    page = page.replace("{{twofa_enabled}}", "1" if twofa_enabled else "0")
    page = page.replace(
        "{{email_configured}}", "1" if config.is_email_configured() else "0"
    )
    page = page.replace("{{totp_enabled}}", "1" if totp_enabled else "0")

    return HTMLResponse(content=page)


@router.post("/profile/2fa")
async def profile_2fa_post(request: Request, enable: str = Form("")):
    """Enable/disable Email OTP 2FA for the logged-in user (v1.0.6).

    Session-gated only -- no current-password re-prompt (a deliberate product
    choice favouring UX; see the spec's NFR-09). The hidden csrf_token and the
    per-IP rate limit are enforced by middleware before this runs; FastAPI's
    Form() ignores the extra csrf_token field. Enabling is refused when SMTP is
    not configured, because a future login could not deliver the OTP.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    want_enable = enable == "1"
    if want_enable and not config.is_email_configured():
        return JSONResponse(
            content={
                "error": "Email delivery is not configured, so OTP 2FA can't be enabled."
            },
            status_code=400,
        )
    if not otp_service.set_two_factor(user_id, want_enable):
        return JSONResponse(
            content={"error": "Could not update the 2FA setting."}, status_code=400
        )
    return JSONResponse(
        content={
            "success": True,
            "two_factor_enabled": want_enable,
            "message": "Two-factor authentication "
            + ("enabled." if want_enable else "disabled."),
        }
    )


@router.get("/login/otp")
async def login_otp_page(request: Request):
    """Render the OTP entry screen -- only mid-2FA-login (pending marker set).

    Gated on request.session["pending_2fa_user_id"], which auth_service.login()
    writes after a correct password + verified gate when 2FA is on. With no
    pending marker (deep link, or after logout) we bounce to /login. The screen
    reflects NO user input (no email, no code) -- a fixed prompt only (VULN-3).
    """
    if not request.session.get("pending_2fa_user_id"):
        return RedirectResponse(url="/login", status_code=302)
    page = _load_template("otp_verify.html")
    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    token = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(token, quote=True))
    hibp_info = '<div class="hibp-notice">Your password is checked against the Have I Been Pwned breach database to prevent use of compromised credentials.</div>' if config.HIBP_ENABLED else ''
    page = page.replace('{{hibp_info}}', hibp_info)
    secure_indicator = '🔒' if request.url.scheme == "https" else '🌐'
    page = page.replace('{{secure_indicator}}', secure_indicator)
    return HTMLResponse(content=page)


@router.post("/login/otp")
async def login_otp_post(request: Request, otp: str = Form("")):
    """Verify the OTP and complete the login by writing the full session.

    Reads the pending user id from the session (set by login()) and the submitted
    code. On success it clears the pending keys, writes the SAME session keys as
    a normal login (user_id/username/email) -- this mutation is what makes
    SessionMiddleware emit the signed Set-Cookie -- and 302-able-redirects to
    /welcome. Every other outcome returns a fixed JSON error and no session
    (the raw code is never echoed -- VULN-3).
    """
    user_id = request.session.get("pending_2fa_user_id")
    if not user_id:
        return JSONResponse(
            content={"error": "Your login session expired. Please sign in again."},
            status_code=401,
        )

    result = otp_service.verify(user_id, otp)
    if result["status"] == "ok":
        user = result["user"]
        request.session.pop("pending_2fa_user_id", None)
        request.session.pop("pending_2fa_username", None)
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        return JSONResponse(content={"success": True, "redirect": "/welcome"})

    messages = {
        "invalid": "Incorrect code. Please try again.",
        "too_many": "Too many incorrect attempts. Request a new code.",
        "expired": "This code has expired. Request a new one.",
        "no_challenge": "No active code. Please sign in again.",
    }
    return JSONResponse(
        content={"error": messages.get(result["status"], messages["invalid"])},
        status_code=401,
    )


@router.post("/login/otp/resend")
async def login_otp_resend(request: Request):
    """Re-send the OTP during a pending 2FA login, honouring the cooldown.

    Identified by the session's pending marker (no credentials re-submitted). The
    per-account resend cooldown is enforced via seconds_until_resend; the hidden
    csrf_token and per-IP rate limit are enforced by middleware (it is a POST).
    """
    user_id = request.session.get("pending_2fa_user_id")
    username = request.session.get("pending_2fa_username", "")
    if not user_id:
        return JSONResponse(
            content={"error": "Your login session expired. Please sign in again."},
            status_code=401,
        )

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by primary key.
        row = conn.execute(
            "SELECT email, otp_last_sent FROM users WHERE id = ?", [user_id]
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return JSONResponse(content={"error": "Please sign in again."}, status_code=401)

    wait = otp_service.seconds_until_resend(row)
    if wait > 0:
        return JSONResponse(
            content={
                "error": f"Please wait {wait} seconds before requesting another code."
            },
            status_code=429,
        )
    if otp_service.start_challenge(user_id, username, row["email"], background=False):
        return JSONResponse(
            content={
                "success": True,
                "message": "Verification code sent. Check your inbox.",
            }
        )
    return JSONResponse(
        content={"error": "Could not send the code. Please try again later."},
        status_code=400,
    )


@router.post("/profile/totp/setup")
async def profile_totp_setup(request: Request):
    """Begin authenticator-app (TOTP) enrollment for the logged-in user (v1.0.7).

    Session-gated only -- no current-password re-prompt (same deliberate product
    choice as the Email-OTP toggle; see the spec's NFR-09). Generates a fresh
    PENDING secret and returns the QR + manual-entry key for the user to scan; the
    secret is not active until POST /profile/totp/confirm validates a code.
    Refused when TOTP is already enabled, so an active secret is never overwritten
    mid-use (the user must disable first to re-enroll). The hidden csrf_token and
    per-IP rate limit are enforced by middleware before this runs.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    username = request.session.get("username", "")
    # Re-enroll only after disabling, so an active secret is never overwritten.
    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by primary key.
        row = conn.execute(
            "SELECT totp_enabled FROM users WHERE id = ?", [user_id]
        ).fetchone()
    finally:
        conn.close()
    if row and row["totp_enabled"]:
        return JSONResponse(
            content={
                "error": "Authenticator 2FA is already enabled. Disable it first to re-enroll."
            },
            status_code=400,
        )

    data = totp_service.start_enrollment(user_id, username)
    if not data:
        return JSONResponse(
            content={"error": "Could not start enrollment. Please try again."},
            status_code=400,
        )
    # The secret/QR go ONLY to the authenticated owner (VULN-3): this is the
    # enrollment payload, not a reflection of attacker input.
    return JSONResponse(content={"success": True, **data})


@router.post("/profile/totp/confirm")
async def profile_totp_confirm(request: Request, code: str = Form("")):
    """Confirm enrollment by validating a current code, then activate TOTP (v1.0.7).

    Session-gated. Requiring a valid code proves the authenticator was provisioned
    correctly (prevents self-lockout from a mis-scanned QR). The raw code is never
    reflected back (VULN-3). On success totp_enabled flips to 1.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    result = totp_service.confirm(user_id, code)
    if result["status"] == "ok":
        return JSONResponse(
            content={"success": True, "message": "Authenticator app enabled."}
        )
    messages = {
        "invalid": (
            "That code didn't match. Make sure your authenticator is set up and "
            "enter the current code."
        ),
        "no_pending": "Start setup first, then enter the code from your authenticator app.",
    }
    return JSONResponse(
        content={"error": messages.get(result["status"], messages["invalid"])},
        status_code=400,
    )


@router.post("/profile/totp/disable")
async def profile_totp_disable(request: Request):
    """Disable authenticator-app (TOTP) 2FA for the logged-in user (v1.0.7).

    Session-gated (no password re-prompt; see NFR-09). Clears the secret, the
    flag, and the replay-guard step. The hidden csrf_token and per-IP rate limit
    are enforced by middleware before this runs.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)
    if not totp_service.disable(user_id):
        return JSONResponse(
            content={"error": "Could not update the setting."}, status_code=400
        )
    return JSONResponse(
        content={"success": True, "message": "Authenticator app disabled."}
    )


@router.get("/login/totp")
async def login_totp_page(request: Request):
    """Render the authenticator-code screen -- only mid-2FA-login via TOTP (v1.0.7).

    Gated on request.session["pending_2fa_user_id"] AND a "totp" method marker,
    both written by auth_service.login() after a correct password + verified gate
    when TOTP is enrolled. With no/other pending marker (deep link, after logout,
    or an email-OTP login) we bounce to /login. The screen reflects NO user input
    (no secret, no code) -- a fixed prompt only (VULN-3).
    """
    if (
        not request.session.get("pending_2fa_user_id")
        or request.session.get("pending_2fa_method") != "totp"
    ):
        return RedirectResponse(url="/login", status_code=302)
    page = _load_template("totp_verify.html")
    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    token = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(token, quote=True))
    hibp_info = '<div class="hibp-notice">Your password is checked against the Have I Been Pwned breach database to prevent use of compromised credentials.</div>' if config.HIBP_ENABLED else ''
    page = page.replace('{{hibp_info}}', hibp_info)
    secure_indicator = '🔒' if request.url.scheme == "https" else '🌐'
    page = page.replace('{{secure_indicator}}', secure_indicator)
    return HTMLResponse(content=page)


@router.post("/login/totp")
async def login_totp_post(request: Request, code: str = Form("")):
    """Verify the authenticator code and complete the login by writing the session.

    Reads the pending user id from the session (set by login()) and the submitted
    code. On success it clears the pending keys, writes the SAME session keys as a
    normal login (user_id/username/email) -- this mutation is what makes
    SessionMiddleware emit the signed Set-Cookie -- and redirects to /welcome.
    Every other outcome returns a fixed JSON error and no session (the raw code is
    never echoed -- VULN-3).
    """
    user_id = request.session.get("pending_2fa_user_id")
    if not user_id:
        return JSONResponse(
            content={"error": "Your login session expired. Please sign in again."},
            status_code=401,
        )

    result = totp_service.verify(user_id, code)
    if result["status"] == "ok":
        user = result["user"]
        request.session.pop("pending_2fa_user_id", None)
        request.session.pop("pending_2fa_username", None)
        request.session.pop("pending_2fa_method", None)
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        return JSONResponse(content={"success": True, "redirect": "/welcome"})

    messages = {
        "invalid": "Incorrect code. Open your authenticator app and try again.",
        "no_challenge": "No active authenticator challenge. Please sign in again.",
    }
    return JSONResponse(
        content={"error": messages.get(result["status"], messages["invalid"])},
        status_code=401,
    )


@router.post("/profile/password")
async def profile_password_post(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
):
    """Handle a change-password submission.

    Thin wrapper over auth_service.change_password() -- same shape as
    login_post(). The Request is forwarded so the service can read
    request.session["user_id"]. The CSRF token and per-IP rate limit are
    enforced by middleware before this handler runs; FastAPI's Form()
    ignores the extra csrf_token field.
    """
    return auth_service.change_password(request, current_password, new_password)


@router.get("/auth/google/login")
async def google_login(request: Request):
    """Start the Google OAuth 2.0 Authorization Code flow.

    Worker endpoint (no page of its own): when Google is configured it 302-
    redirects the browser to Google's consent screen; Authlib stashes the
    anti-CSRF `state` and anti-replay `nonce` in the session on the way out.

    If Google is NOT configured, we render a friendly setup page (HTTP 200)
    instead of crashing or redirecting nowhere -- a fresh clone stays usable
    and the password flow is unaffected.
    """
    if not config.is_google_configured():
        with open(os.path.join(TEMPLATE_DIR, "oauth_not_configured.html"), "r") as f:
            return HTMLResponse(content=f.read())
    return await oauth.google.authorize_redirect(request, config.GOOGLE_REDIRECT_URI)


@router.get("/auth/google/callback")
async def google_callback(request: Request):
    """Handle Google's redirect back to the app (the registered redirect URI).

    Worker endpoint (no page of its own): it verifies the response, logs the
    user in via the SAME signed session cookie the password flow uses, and
    302s to /welcome. There is no JWT and no extra cookie -- the session is
    the single auth mechanism.

    Every failure mode degrades to /login WITHOUT leaking any detail to the
    client (the specifics are logged server-side):
      - user denied consent / provider error (`?error=...`)
      - invalid token / state mismatch / expired session (Authlib raises)
      - missing user information (no email/sub from Google)
    """
    # 1) User denied consent, or Google reported an error on the redirect.
    error = request.query_params.get("error")
    if error:
        logger.warning("Google OAuth callback returned error=%s", error)
        return RedirectResponse(url="/login", status_code=302)

    # 2) Exchange the code + verify the ID token. authorize_access_token()
    #    validates `state` (anti-CSRF), swaps the code for tokens, and verifies
    #    the ID token signature + iss/aud/exp/nonce. It raises on any mismatch
    #    or when the session (holding `state`/`nonce`) has expired.
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception:
        logger.warning("Google OAuth token exchange/verification failed", exc_info=True)
        return RedirectResponse(url="/login", status_code=302)

    # 3) Pull the verified profile claims.
    userinfo = token.get("userinfo") or {}
    google_id = userinfo.get("sub")
    email = userinfo.get("email")
    name = userinfo.get("name", "")
    picture = userinfo.get("picture", "")

    # 4) Resolve to a user row (create / link / return). None => missing info.
    user = oauth_service.find_or_create_google_user(google_id, email, name, picture)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    # 5) Log in by writing the SAME session keys as auth_service.login(). This
    #    mutation is what makes SessionMiddleware emit the signed Set-Cookie.
    #    Existing keys (e.g. csrf_token) are preserved -- we merge, not replace.
    request.session["user_id"] = user["id"]
    request.session["username"] = user["username"]
    request.session["email"] = user["email"]
    return RedirectResponse(url="/welcome", status_code=302)


@router.get("/qr/create")
async def qr_create(request: Request):
    """Vend a fresh QR-login token, bound to THIS browser's session (v1.0.8).

    Worker endpoint (returns JSON, no page): mint a token, render the QR for
    ``{APP_BASE_URL}/qr/scan/{token}``, and return both to the login page, which
    shows the QR and polls ``GET /qr/status``.

    GET on purpose: it vends an UNAUTHENTICATED capability that is useless until an
    already-authenticated device approves it -- there is nothing CSRF-sensitive to
    protect (mirrors the OAuth GET login). The crucial step is recording the token
    in ``request.session["qr_login_token"]``: this **owner-binding** is what later
    lets ONLY this browser be logged in by the token (see ``qr_status`` -- it closes
    the login-CSRF / session-fixation vector).
    """
    token = qr_login.create_token()
    request.session["qr_login_token"] = token
    qr_url = f"{config.APP_BASE_URL}/qr/scan/{token}"
    return JSONResponse(
        content={
            "token": token,
            "qr_url": qr_url,
            "qr_data_uri": qr_login.render_qr(qr_url),
            "poll_interval": config.QR_LOGIN_POLL_INTERVAL_SECONDS,
            "expires_in": config.QR_LOGIN_TTL_SECONDS,
        }
    )


@router.get("/qr/status")
async def qr_status(request: Request, token: str = ""):
    """Desktop poll. Owner-bound: only the browser that created ``token`` is promoted.

    Returns ``{"status": ...}`` where status is ``pending`` / ``rejected`` /
    ``expired`` / ``invalid``, or ``approved`` plus a ``redirect``. On ``approved``
    it claims the (single-use) token and writes the SAME session keys as
    ``auth_service.login()`` (``user_id`` / ``username`` / ``email``) -- this
    mutation is what makes SessionMiddleware emit the signed Set-Cookie, completing
    the login on this device with no password/2FA entered here.

    This is a GET that promotes the session -- justified exactly like the OAuth /
    verify GET callbacks, and ADDITIONALLY gated two ways: the unguessable token,
    and **owner-binding** (the polling browser's signed session must already own
    this token). A cross-site ``GET /qr/status`` forced into a victim's browser
    carries no matching ``qr_login_token`` and is ignored -- closing login-CSRF.
    """
    if not token or request.session.get("qr_login_token") != token:
        return JSONResponse(content={"status": "invalid"})

    st = qr_login.status(token)
    if st == "approved":
        identity = qr_login.claim(token)
        if not identity:
            return JSONResponse(content={"status": "expired"})
        request.session.pop("qr_login_token", None)
        request.session["user_id"] = identity["user_id"]
        request.session["username"] = identity["username"]
        request.session["email"] = identity["email"]
        return JSONResponse(content={"status": "approved", "redirect": "/welcome"})
    return JSONResponse(content={"status": st})


@router.get("/qr/scan/{token}")
async def qr_scan(request: Request, token: str):
    """Phone landing page the QR encodes (v1.0.8).

    **Session-gated:** you must be logged in to approve a new device. With no
    session we 302 to ``/login`` (the phone logs in, then re-scans). Logged in, we
    render ``qr_approve.html`` with the HTML-escaped approver ``{{username}}``, the
    ``{{token}}``, and a CSRF token. An unknown / expired / already-acted-on token
    renders a fixed "no longer valid" state (buttons hidden) -- the raw token is
    never reflected as markup (VULN-3 posture; the token is escaped on splice).
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    username = request.session.get("username", "")
    entry = qr_login.get(token)
    valid = bool(entry and entry["status"] == "pending")

    page = _load_template("qr_approve.html")
    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    csrf = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(csrf, quote=True))
    # FIXED: Stored/Reflected XSS closed -- escape every value before splicing.
    page = page.replace("{{token}}", html.escape(token, quote=True))
    page = page.replace("{{username}}", html.escape(username, quote=True))
    # Server-controlled "0"/"1" flag (not user input).
    page = page.replace("{{valid}}", "1" if valid else "0")
    return HTMLResponse(content=page)


@router.post("/qr/approve")
async def qr_approve_post(request: Request, token: str = Form("")):
    """Approve a pending QR-login as the logged-in user (v1.0.8).

    Session-gated (no password re-prompt; see the spec's NFR-09). The approver's
    identity is read from THIS device's signed session -- the desktop inherits it
    on its next poll. The hidden csrf_token and per-IP rate limit are enforced by
    middleware before this runs.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)
    ok = qr_login.approve(
        token,
        user_id,
        request.session.get("username", ""),
        request.session.get("email", ""),
    )
    if ok:
        return JSONResponse(
            content={
                "success": True,
                "message": "Login approved. Return to the other device.",
            }
        )
    return JSONResponse(
        content={"error": "This QR code has expired or was already used."},
        status_code=400,
    )


@router.post("/qr/reject")
async def qr_reject_post(request: Request, token: str = Form("")):
    """Reject a pending QR-login (v1.0.8). Session-gated; CSRF + rate-limit apply."""
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)
    qr_login.reject(token)
    return JSONResponse(content={"success": True, "message": "Login request denied."})


@router.get("/logout")
async def logout(request: Request):
    """Destroy the session and redirect to the login page.

    request.session.clear() wipes every key (user_id, username, email,
    AND csrf_token). That last point is intentional -- a new GET /login
    will re-issue a fresh CSRF token tied to the new session, so any
    forms cached in the browser from before logout cannot be replayed.
    """
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)
