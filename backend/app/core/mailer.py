"""Transactional email senders for the Email-Verification and Email-OTP-2FA
features.

Stdlib only -- ``urllib`` + ``json`` for the SendGrid HTTP-API transport -- so
the features add no new dependency, mirroring the stdlib-only posture of
``core/csrf.py`` and ``core/rate_limit.py``. All settings come from
``core/config.py`` (env / git-ignored ``.env``); no secret is hardcoded here
(VULN-4 posture).

Single transport: the **SendGrid HTTPS API**. Some hosts (e.g. Render's free
plan) block outbound SMTP ports, so an ``smtplib`` path cannot connect there;
SendGrid's ``/v3/mail/send`` endpoint is reached over HTTPS (port 443, not
blocked) via stdlib ``urllib``. The API key is sent in the ``Authorization``
header and is NEVER logged. (The earlier SMTP/Gmail transport has been removed --
SendGrid is the only sender.)

Public surface: ``send_verification_email`` (signup link) and ``send_otp_email``
(login one-time code). Both are deliberately FAIL-SAFE -- they return ``False``
(never raise) when email is unconfigured or any send/API error occurs, logging
the cause server-side. A failed send must never crash a request handler nor
change auth state: the caller treats ``False`` as "couldn't send" and the user
can resend.

Security note: the HTML alternative part splices the username and the
verification URL with ``html.escape(..., quote=True)`` before they enter the
markup (VULN-2 posture -- output encoding), so a username containing HTML
cannot inject into the email body. The raw OTP code is NEVER logged (VULN-3).
"""

import html
import json
import logging
import urllib.request

from app.core import config

logger = logging.getLogger(__name__)

SENDGRID_API_URL = "https://api.sendgrid.com/v3/mail/send"


def _send_via_sendgrid(to_email: str, subject: str, text_body: str, html_body: str) -> bool:
    """Deliver one message through SendGrid's HTTPS API. Returns True/False.

    Never raises; the API key is never logged. SendGrid returns 202 on success.
    The content array MUST list text/plain before text/html (SendGrid requirement).
    """
    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": config.SENDGRID_FROM},
        "subject": subject,
        "content": [
            {"type": "text/plain", "value": text_body},
            {"type": "text/html", "value": html_body},
        ],
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        SENDGRID_API_URL,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {config.SENDGRID_API_KEY}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=config.SENDGRID_HTTP_TIMEOUT) as resp:
            return 200 <= resp.status < 300
    except Exception:
        # Do not log the API key. Surface only that the send failed.
        logger.exception("SendGrid API send failed to %s", to_email)
        return False


def _deliver(to_email: str, subject: str, text_body: str, html_body: str) -> bool:
    """Dispatch one message via SendGrid. Returns False (never raises) when unconfigured."""
    if config.is_sendgrid_configured():
        return _send_via_sendgrid(to_email, subject, text_body, html_body)
    logger.warning("SendGrid not configured; cannot send to %s", to_email)
    return False


def send_verification_email(to_email: str, username: str, verify_url: str) -> bool:
    """Send the signup verification email. Returns True on success, else False.

    Delivers via SendGrid. Never raises -- every failure path returns False so
    signup/resend stay robust.
    """
    if not config.is_email_configured():
        # Should not happen (the signup routes gate on this), but stay safe if
        # called directly: no transport means no send.
        logger.warning("Email not configured; skipping verification email to %s", to_email)
        return False

    # Output-encode the two attacker-influenced values before they enter HTML.
    safe_username = html.escape(username or "", quote=True)
    safe_url = html.escape(verify_url, quote=True)

    subject = "Verify your email - Security Vulnerability Lab"
    text_body = (
        f"Hi {username},\n\n"
        "Confirm your email address for the Security Vulnerability Lab by "
        "opening the link below (valid for 1 hour):\n\n"
        f"{verify_url}\n\n"
        "If you did not sign up, you can safely ignore this email."
    )
    html_body = (
        f"<p>Hi {safe_username},</p>"
        "<p>Confirm your email address for the <strong>Security Vulnerability "
        "Lab</strong> by clicking the link below (valid for 1 hour):</p>"
        f'<p><a href="{safe_url}">Verify my email</a></p>'
        "<p>If you did not sign up, you can safely ignore this email.</p>"
    )

    ok = _deliver(to_email, subject, text_body, html_body)
    if ok:
        logger.info("Verification email sent to %s", to_email)
    return ok


def send_otp_email(to_email: str, username: str, code: str) -> bool:
    """Send a one-time login passcode (Email OTP 2FA). Returns True/False.

    Same fail-safe contract as send_verification_email -- never raises; every
    failure path returns False so the login / resend flow stays robust. The
    6-digit ``code`` is server-generated (no escaping concern); the username is
    html.escape()'d before entering the HTML part (VULN-2 posture). The raw code
    is NEVER logged (VULN-3 posture) -- only "OTP email sent to <email>".
    """
    if not config.is_email_configured():
        # Should not happen (login fails closed and the toggle gates on this),
        # but stay safe if called directly: no transport means no send.
        logger.warning("Email not configured; skipping OTP email to %s", to_email)
        return False

    safe_username = html.escape(username or "", quote=True)
    minutes = max(1, config.OTP_TTL_SECONDS // 60)

    subject = "Your login verification code - Security Vulnerability Lab"
    text_body = (
        f"Hi {username},\n\n"
        f"Your one-time login code is: {code}\n\n"
        f"It is valid for {minutes} minutes. If you did not try to log in, "
        "you can safely ignore this email."
    )
    html_body = (
        f"<p>Hi {safe_username},</p>"
        "<p>Your one-time login code for the <strong>Security Vulnerability "
        "Lab</strong> is:</p>"
        f'<p style="font-size:24px;font-weight:bold;letter-spacing:3px;">{code}</p>'
        f"<p>It is valid for {minutes} minutes. If you did not try to log in, "
        "you can safely ignore this email.</p>"
    )

    ok = _deliver(to_email, subject, text_body, html_body)
    if ok:
        logger.info("OTP email sent to %s", to_email)
    return ok


def send_email_change_verification(to_email: str, username: str, verify_url: str) -> bool:
    """Send a verification link when the user changes their email address.

    Reuses the same SendGrid transport as send_verification_email(). Subject and
    body are different so the user's inbox makes the context clear. Returns False
    on any failure (including when email is not configured); never raises.
    """
    if not config.is_email_configured():
        logger.warning("Email not configured; cannot send email change verification.")
        return False

    safe_username = html.escape(username or "", quote=True)
    safe_url = html.escape(verify_url, quote=True)

    subject = "Verify your new email address"
    text_body = (
        f"Hi {username},\n\n"
        "You requested to change your email address. Please verify your new "
        "address by clicking the link below:\n\n"
        f"{verify_url}\n\n"
        "If you did not request this change, please ignore this email."
    )
    html_body = (
        f"<p>Hi {safe_username},</p>"
        "<p>You requested to change your email address. Please verify your new "
        "address by clicking the link below:</p>"
        f'<p><a href="{safe_url}">Verify Email</a></p>'
        "<p>If you did not request this change, please ignore this email.</p>"
        "<p>— The Vuln Web App Team</p>"
    )

    ok = _deliver(to_email, subject, text_body, html_body)
    if ok:
        logger.info("Email change verification sent to %s", to_email)
    return ok
