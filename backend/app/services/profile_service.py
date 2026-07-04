"""Profile editing service — display name and email change.

All SQL uses parameterized ? placeholders (VULN-1 closure). The display_name
column is read and written by primary key (WHERE id = ?). Email changes trigger
re-verification via verification_service (same model as signup).

Exports:
- update_display_name(user_id, display_name) -> dict (success/message)
- update_email(user_id, new_email) -> dict (success/message/email_verification)
- validate_email_format(email) -> bool
- validate_display_name(name) -> bool (len <= 60, trimmed)
"""
import html
import logging

from app.db import session
from app.services import verification_service

logger = logging.getLogger(__name__)


# --- Validation helpers ---
def validate_email_format(email: str) -> bool:
    """Validate email format: basic regex ^[^@\s]+@[^@\s]+\.[^@\s]+$, length <= 254."""
    import re
    if not email or len(email) > 254:
        return False
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def validate_display_name(name: str) -> bool:
    """Validate display name: max 60 chars, trimmed length > 0."""
    if name is None:
        return True  # NULL/empty is allowed
    trimmed = name.strip()
    return 0 < len(trimmed) <= 60


# --- Core operations ---
def update_display_name(user_id: int, display_name: str) -> dict:
    """Update the user's display name. display_name=None/empty stores as NULL."""
    trimmed = display_name.strip() if display_name else None
    if not validate_display_name(trimmed):
        return {"success": False, "message": "Display name must be 1-60 characters."}

    conn = session.get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE users SET display_name = ? WHERE id = ?",
            (trimmed, user_id),
        )
        conn.commit()
        # Update the session cache if it exists (done by the route handler)
        return {"success": True, "message": "Display name updated."}
    except Exception as e:
        logger.error(f"Failed to update display_name: {e}")
        return {"success": False, "message": "Database error."}


def update_email(user_id: int, new_email: str) -> dict:
    """Update the user's email and trigger re-verification.

    Sets is_verified=0, writes a new verification token, emails the link.
    Returns success/message and an email_verification flag for the UI.
    """
    new_email = new_email.strip()
    if not validate_email_format(new_email):
        return {"success": False, "message": "Invalid email format."}

    conn = session.get_db()
    cursor = conn.cursor()
    try:
        # Fetch current email to check for no-change
        cursor.execute("SELECT email, is_verified FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return {"success": False, "message": "User not found."}

        current_email = row["email"]
        if current_email == new_email:
            return {"success": False, "message": "New email is the same as current email."}

        # Fetch username for the verification email
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        username = cursor.fetchone()["username"]

        # Update email and trigger re-verification (same model as signup)
        success = verification_service.start_verification(user_id, username, new_email)
        if not success:
            return {"success": False, "message": "Failed to send verification email."}

        return {
            "success": True,
            "message": "Verification email sent. Please check your inbox.",
            "email_verification": True,
        }
    except Exception as e:
        logger.error(f"Failed to update email: {e}")
        return {"success": False, "message": "Database error."}