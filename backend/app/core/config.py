"""Configuration + .env loading for the Continue-with-Google, Email
Verification, Account-Lockout, Email-OTP-2FA, Authenticator-App-TOTP-2FA,
QR-Code-Login, and CAPTCHA-on-Login features.

Stdlib only -- no python-dotenv dependency. This module:

1. Loads a repo-root `.env` file (if present) into ``os.environ`` so a local
   developer can keep their Google credentials AND SMTP credentials in one
   git-ignored file.
2. Exposes the Google OAuth settings and an ``is_google_configured()`` gate.
3. Exposes the SendGrid / email-verification settings and an
   ``is_email_configured()`` gate.
4. Exposes the account-lockout thresholds (env-tunable, non-secret; no gate --
   the feature is always on with safe defaults).
5. Exposes the Email-OTP-2FA settings (env-tunable, non-secret; no gate of their
   own -- OTP delivery reuses ``is_email_configured()``).
6. Exposes the Authenticator-App-TOTP settings (env-tunable, non-secret; no gate
   -- TOTP needs neither SMTP nor Google, so the feature is always available).

Design notes (production posture):
- **Real environment variables always win** over ``.env`` values. A container,
  CI runner, or hosting platform injects config through the real environment;
  we never let a stale committed-by-mistake ``.env`` override it.
- **Importing this module is non-fatal.** A missing or unreadable ``.env`` is
  ignored, and absent credentials simply make ``is_google_configured()`` return
  ``False`` -- the app still boots and the password flow is unaffected.
- **No secret is hardcoded here.** Everything comes from the environment.
"""

import logging
import os

logger = logging.getLogger(__name__)

# Repo root: climb from backend/app/core/config.py up three levels to the
# directory that holds `.env` (resolved at import time, CWD-independent).
_BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..")
_ENV_PATH = os.path.join(_BASE_DIR, ".env")


def _load_dotenv(path: str) -> None:
    """Seed ``os.environ`` from a minimal ``KEY=VALUE`` ``.env`` file.

    Ignores blank lines and ``#`` comments, strips surrounding quotes, and only
    sets keys that are NOT already present in the environment (real env vars
    take precedence). A missing or unreadable file is silently skipped so a
    fresh clone with no ``.env`` still starts cleanly.
    """
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError as exc:
        # A broken/unreadable .env must never crash startup -- log and move on.
        logger.warning("Could not read .env at %s: %s", path, exc)


_load_dotenv(_ENV_PATH)

# --- Google OAuth settings (all sourced from the environment) ----------------
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.environ.get(
    "GOOGLE_REDIRECT_URI", "http://localhost:3001/auth/google/callback"
)

# Network timeout (seconds) for the OIDC discovery + token-exchange calls, so a
# slow/hung Google endpoint cannot pin a worker indefinitely.
OAUTH_HTTP_TIMEOUT = float(os.environ.get("OAUTH_HTTP_TIMEOUT", "10"))


def is_google_configured() -> bool:
    """Return True only when both the client id and secret are present.

    The login route uses this to decide whether to start the real OAuth flow
    or render the friendly "not configured" page.
    """
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


# --- Email-verification settings (all sourced from the environment) ----------
# Public base URL used to build the verification link spliced into the email
# body. Trailing slash trimmed so f"{APP_BASE_URL}/verify?..." is always clean.
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:3001").rstrip("/")

# Verification-token lifetime in seconds. Default 1 hour.
EMAIL_VERIFICATION_TTL_SECONDS = int(
    os.environ.get("EMAIL_VERIFICATION_TTL_SECONDS", "3600")
)


# --- SendGrid HTTP API (the only email transport) ----------------------------
# Email is delivered exclusively over SendGrid's HTTPS API (port 443) via stdlib
# urllib -- no new dependency. This avoids the outbound-SMTP ports that some PaaS
# hosts (e.g. Render's free plan) block. SENDGRID_FROM MUST be an address (or
# domain) verified in SendGrid. The API key is a real secret -- env/.env only,
# never committed, never logged.
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")
SENDGRID_FROM = os.environ.get("SENDGRID_FROM", "")
SENDGRID_HTTP_TIMEOUT = float(os.environ.get("SENDGRID_HTTP_TIMEOUT", "10"))


def is_sendgrid_configured() -> bool:
    """True only when a SendGrid API key AND a verified sender are present."""
    return bool(SENDGRID_API_KEY and SENDGRID_FROM)


def is_email_configured() -> bool:
    """Return True when email can be sent (SendGrid is the only transport).

    The signup routes use this to decide whether to run the real verification
    flow or render the friendly "email not configured" setup page.
    """
    return is_sendgrid_configured()


# --- Account-lockout settings (env-tunable, non-secret) ----------------------
# After ACCOUNT_LOCKOUT_MAX_ATTEMPTS consecutive failed credential checks against
# a single account, it is locked for ACCOUNT_LOCKOUT_DURATION_SECONDS. These are
# NOT secrets -- there is no is_*_configured() gate; the feature is always on
# with safe defaults and can be lowered for demos, e.g.
#   ACCOUNT_LOCKOUT_MAX_ATTEMPTS=3 ACCOUNT_LOCKOUT_DURATION_SECONDS=30
# This per-ACCOUNT control complements (does not replace) the per-IP
# RateLimitMiddleware (VULN-7), which stays registered and unchanged.
ACCOUNT_LOCKOUT_MAX_ATTEMPTS = int(os.environ.get("ACCOUNT_LOCKOUT_MAX_ATTEMPTS", "6"))
ACCOUNT_LOCKOUT_DURATION_SECONDS = int(
    os.environ.get("ACCOUNT_LOCKOUT_DURATION_SECONDS", "3600")
)


# --- Email OTP 2FA settings (env-tunable, non-secret) ------------------------
# When a user enables Email OTP 2FA on their profile, a correct password issues a
# 6-digit code emailed to them; login completes only after the code is verified.
# These are NOT secrets and have no is_*_configured() gate of their own -- OTP
# delivery reuses is_email_configured() (the same SMTP settings above). They have
# safe defaults and can be lowered for demos, e.g.
#   OTP_TTL_SECONDS=30 OTP_RESEND_COOLDOWN_SECONDS=5
OTP_LENGTH = 6  # fixed: the feature is specified as a 6-digit code (not env-tunable).
OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", "300"))
OTP_MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", "5"))
OTP_RESEND_COOLDOWN_SECONDS = int(os.environ.get("OTP_RESEND_COOLDOWN_SECONDS", "60"))


# --- MFA via Authenticator App (TOTP) settings (env-tunable, non-secret) ------
# When a user enrolls an authenticator app (Google Authenticator, Authy, ...), a
# correct password issues a TOTP challenge instead of completing login. These are
# NOT secrets and have NO is_*_configured() gate -- TOTP needs neither SMTP nor
# Google, so the feature is always available with safe defaults. The per-user
# shared secret is generated at enrollment (secrets.token_bytes) and stored on the
# users row. TOTP math is RFC 4226/6238 in pure stdlib; only the QR image uses the
# `segno` dependency. At login TOTP takes precedence over Email OTP (v1.0.6).
TOTP_ISSUER = os.environ.get("TOTP_ISSUER", "Security Vulnerability Lab")
TOTP_PERIOD_SECONDS = int(os.environ.get("TOTP_PERIOD_SECONDS", "30"))
TOTP_SKEW_STEPS = int(os.environ.get("TOTP_SKEW_STEPS", "1"))
TOTP_DIGITS = 6        # fixed: authenticator-app default (not env-tunable).
TOTP_SECRET_BYTES = 20  # fixed: 160-bit secret (RFC 6238 norm), base32 in the QR.


# --- QR Code Login settings (env-tunable, non-secret) ------------------------
# An unauthenticated browser is shown a QR on /login; an already-authenticated
# device scans it and approves, logging the first browser in (the WhatsApp-Web
# pattern). State is in-memory (core/qr_login.py) and the signed session -- there
# is NO DB schema change and NO new dependency (the QR image reuses `segno`, added
# for TOTP in v1.0.7). These are NOT secrets and have NO is_*_configured() gate --
# QR login needs neither SMTP nor Google. The scannable URL is built from the
# existing APP_BASE_URL above: for a real cross-device scan set APP_BASE_URL to an
# address the scanning device can reach (LAN IP / public origin); on localhost
# "scan" by opening the URL in a second, already-logged-in browser.
QR_LOGIN_TTL_SECONDS = int(os.environ.get("QR_LOGIN_TTL_SECONDS", "120"))
QR_LOGIN_POLL_INTERVAL_SECONDS = int(
    os.environ.get("QR_LOGIN_POLL_INTERVAL_SECONDS", "2")
)


# --- Cloudflare Turnstile CAPTCHA settings (site key public; secret key IS a secret) ---
# An always-on CAPTCHA on POST /login: the login page shows a Turnstile widget and
# the POST is verified server-side (core/captcha.py, stdlib urllib -- no new
# dependency) BEFORE any password check. With BOTH keys unset the login page renders
# no widget and the POST performs no check, so login works exactly as today (graceful
# degrade, mirroring the Google/SMTP blocks above). The SITE key is public; the SECRET
# key is a real secret -- env/.env only, never committed, never logged. A configured-
# but-unreachable verify endpoint FAILS OPEN (allows login + logs a warning) -- a bot
# filter must not lock out every legitimate user during a provider outage (same posture
# as the rate limiter / account lockout; the opposite of CSRFMiddleware's fail-closed).
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")

# Network timeout (seconds) for the siteverify call, so a slow/hung Cloudflare
# endpoint cannot pin a worker indefinitely (mirrors OAUTH_HTTP_TIMEOUT/SMTP_TIMEOUT).
TURNSTILE_HTTP_TIMEOUT = float(os.environ.get("TURNSTILE_HTTP_TIMEOUT", "10"))


def is_captcha_configured() -> bool:
    """Return True only when both the site and secret keys are present.

    The login route uses this to decide whether to render + enforce the Turnstile
    widget or skip it entirely. Mirrors is_google_configured() / is_email_configured().
    """
    return bool(TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY)


# --- Have I Been Pwned (HIBP) settings (env-tunable, non-secret) ----------------
# When enabled, checks new passwords during signup and password change against
# the Have I Been Pwned password breach database using k-anonymity (only first 5
# chars of SHA-1 hash sent to API). This helps prevent use of known compromised
# passwords. Not a secret and has no is_*_configured() gate of its own -- defaults
# to disabled but can be enabled via environment variable.
HIBP_ENABLED = os.environ.get("HIBP_ENABLED", "false").lower() == "true"


def is_hibp_configured() -> bool:
    """Return True when HIBP breach checking is enabled via environment variable.

    This feature checks passwords against the Have I Been Pwned database during
    signup and password changes to prevent use of known compromised credentials.
    """
    return HIBP_ENABLED
