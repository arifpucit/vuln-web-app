# Implementation Plan — Profile Editing (Display Name + Email)

**Spec:** [display-name-and-email-edit.md](./display-name-and-email-edit.md)
**Target Release Tag:** v2.1.0
**Feature #:** 1 (README "User Account Management Enhancements" — first slice)

This plan turns the spec into ordered, surgical steps. It adds **one** new service (`profile_service.py`), **one** new mailer function, **one** new database column (`display_name`), **two** new routes (`POST /profile`, `POST /profile/email/resend`), **one** extended route (`GET /profile`), **one** dashboard splice update, **one** new card in `profile.html`, and the project's **first** test suite (`pytest` + `pytest-asyncio`). **No** edit to `main.py`, `auth_service.py`, or any middleware module.

Key facts grounding this plan (verified against the current tree):
- `GET /profile` = `profile_page` (`auth.py`) loads `profile.html`, splices `{{username}}`, `{{email}}`, `{{csrf_token}}`, `{{twofa_enabled}}`, `{{totp_enabled}}`, `{{email_configured}}` via `html.escape(..., quote=True)`.
- `POST /profile/password` = `change_password_post` (`auth.py`) calls `auth_service.change_password()`, returns JSON.
- `profile.html` has two cards: "Account Information" (read-only) and "Change Password" (form with hidden `csrf_token`).
- `core/mailer.py` has `send_verification_email()` — the template for `send_email_change_verification()`.
- `services/verification_service.py` has `start_verification()` — reused for email-change re-verification.
- `db/session.py` ends at the TOTP columns (line ~75); the `ALTER TABLE` block is the template for the `display_name` migration.

---

## Step 0 — Branch & preconditions
- Work on `feature/display-name-and-email-edit` (already checked out).
- Confirm the dev dependencies (`pytest`, `pytest-asyncio`) will be added via `pyproject.toml` `[dependency-groups] dev`.

## Step 1 — `backend/app/db/session.py` (additive column migration)
- Locate the idempotent `ALTER TABLE` block (around line 95-115).
- Add a new idempotent migration after the existing ones:
```python
# --- Profile Editing: display_name column (v2.1.0) ---
if "display_name" not in existing:
    cursor.execute("ALTER TABLE users ADD COLUMN display_name TEXT")
    existing.add("display_name")
```
- Update the module docstring's schema notes to document the new column and its fallback semantics (NULL = use username).

## Step 2 — `backend/app/core/config.py` (docstring update only)
- Add "Profile Editing — Display Name + Email (v2.1.0)" to the module docstring's numbered feature list (point 10).
- No new env tunables — the feature reuses existing settings.

## Step 3 — `backend/app/core/mailer.py` (new email-change function)
- Append after `send_verification_email()`:
```python
def send_email_change_verification(to_email: str, username: str, verify_url: str) -> bool:
    """Send a verification link when the user changes their email address.

    Reuses the same SendGrid transport as send_verification_email(). Subject and
    body are different so the user's inbox makes the context clear. Returns False
    on any failure (including when email is not configured); never raises.
    """
    if not is_email_configured():
        logger.warning("Email not configured; cannot send email change verification.")
        return False

    subject = "Verify your new email address"
    text_body = f"""Hi {username},

You requested to change your email address. Please verify your new address by clicking the link below:

{verify_url}

If you did not request this change, please ignore this email.

— The Vuln Web App Team
"""
    html_body = f"""<p>Hi {html.escape(username, quote=True)},</p>
<p>You requested to change your email address. Please verify your new address by clicking the link below:</p>
<p><a href="{html.escape(verify_url, quote=True)}">Verify Email</a></p>
<p>If you did not request this change, please ignore this email.</p>
<p>— The Vuln Web App Team</p>
"""
    return _send_email(to_email, subject, text_body, html_body)
```
- Confirm `_send_email()` and `is_email_configured()` are already imported at the top.

## Step 4 — `backend/app/services/profile_service.py` (new; parameterized SQL + validation)
Create the new file with:
```python
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
from app.core import config
from app.core.mailer import send_email_change_verification
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
```

## Step 5 — `backend/app/api/routes/auth.py` (new routes + extended profile + dashboard)
- Add to imports: `from app.services import profile_service`.
- **Extend `profile_page` (GET /profile):**
  - After loading `username`/`email` from session, add:
    ```python
    display_name = request.session.get("display_name", "")
    email_verified = request.session.get("email_verified", True)
    ```
  - Add splices: `page = page.replace("{{display_name}}", html.escape(display_name or "", quote=True))` and `page = page.replace("{{email_verified}}", "true" if email_verified else "false")`.
  - Ensure the session is updated after profile edits (see Step 6).
- **Add `POST /profile` (update account details):**
  ```python
  @router.post("/profile")
  async def profile_post(
      request: Request,
      display_name: str = Form(""),
      email: str = Form(""),
  ):
      user_id = request.session.get("user_id")
      if not user_id:
          return JSONResponse({"error": "Not authenticated"}, status_code=401)

      # Update display name
      dn_result = profile_service.update_display_name(user_id, display_name)
      if not dn_result.get("success"):
          return JSONResponse({"error": dn_result.get("message")}, status_code=400)

      # Update email if changed
      email_result = {"success": True}  # default - no change
      email_verification = False
      if email:
          email_result = profile_service.update_email(user_id, email)
          if not email_result.get("success"):
              return JSONResponse({"error": email_result.get("message")}, status_code=400)
          email_verification = email_result.get("email_verification", False)

      # Refresh session cache
      conn = session.get_db()
      cursor = conn.cursor()
      cursor.execute("SELECT username, email, display_name, is_verified FROM users WHERE id = ?", (user_id,))
      row = cursor.fetchone()
      request.session["username"] = row["username"]
      request.session["email"] = row["email"]
      request.session["display_name"] = row["display_name"] or ""
      request.session["email_verified"] = bool(row["is_verified"])

      return JSONResponse({
          "success": True,
          "message": "Account updated.",
          "email_verification": email_verification,
      })
  ```
- **Add `POST /profile/email/resend` (session-gated resend):**
  ```python
  @router.post("/profile/email/resend")
  async def profile_email_resend(request: Request):
      user_id = request.session.get("user_id")
      if not user_id:
          return JSONResponse({"error": "Not authenticated"}, status_code=401)

      conn = session.get_db()
      cursor = conn.cursor()
      cursor.execute("SELECT username, email FROM users WHERE id = ?", (user_id,))
      row = cursor.fetchone()
      if not row:
          return JSONResponse({"error": "User not found"}, status_code=404)

      success = verification_service.start_verification(user_id, row["username"], row["email"])
      if not success:
          return JSONResponse({"error": "Failed to send verification email."}, status_code=400)

      return JSONResponse({"success": True, "message": "Verification email resent."})
  ```
- **Update `welcome_page` (GET /welcome):**
  - Change the username splice to use display_name fallback:
    ```python
    display_name = request.session.get("display_name") or request.session.get("username")
    page = page.replace("{{username}}", html.escape(display_name, quote=True))
    ```
  - The template's `{{username}}` token stays unchanged.

## Step 6 — `frontend/templates/profile.html` (additive Account Details card)
- Add a new "Account Details" card **above** the existing "Change Password" card:
```html
<div class="profile-card">
    <h2 class="section-title">Account Details</h2>
    <form id="account-details-form">
        <input type="hidden" name="csrf_token" value="{{csrf_token}}">
        <div class="form-group">
            <label class="form-label" for="display_name">Display Name</label>
            <input type="text" id="display_name" name="display_name" class="form-input"
                   value="{{display_name}}" maxlength="60" placeholder="Optional, shown on dashboard">
        </div>
        <div class="form-group">
            <label class="form-label" for="email">Email Address</label>
            <input type="email" id="email" name="email" class="form-input"
                   value="{{email}}" maxlength="254">
            {% if email_verified == "false" %}
            <span class="pending-pill">Pending verification</span>
            {% endif %}
        </div>
        <button type="submit" class="btn btn-primary">Save Changes</button>
        {% if email_verified == "false" %}
        <button type="button" class="btn btn-secondary" id="resend-verification">Resend Verification Email</button>
        {% endif %}
        <div class="profile-message" aria-live="polite"></div>
    </form>
</div>
```
- Add the submit JS (inline `<script>`) for the new form:
```javascript
document.getElementById('account-details-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    const form = e.target;
    const msgDiv = form.querySelector('.profile-message');
    msgDiv.textContent = 'Saving...';
    msgDiv.className = 'profile-message';

    const formData = new FormData(form);
    const params = new URLSearchParams(formData);

    try {
        const resp = await fetch('/profile', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: params.toString()
        });
        const data = await resp.json();
        if (data.success) {
            msgDiv.textContent = data.message;
            msgDiv.className = 'profile-message is-success';
            if (data.email_verification) {
                // Reload to show pending pill
                setTimeout(() => window.location.reload(), 1500);
            }
        } else {
            msgDiv.textContent = data.error || 'Error saving changes';
            msgDiv.className = 'profile-message is-error';
        }
    } catch (err) {
        msgDiv.textContent = 'Network error';
        msgDiv.className = 'profile-message is-error';
    }
});

// Resend verification button
const resendBtn = document.getElementById('resend-verification');
if (resendBtn) {
    resendBtn.addEventListener('click', async function() {
        const msgDiv = document.querySelector('.profile-message');
        msgDiv.textContent = 'Sending...';
        msgDiv.className = 'profile-message';
        try {
            const resp = await fetch('/profile/email/resend', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'csrf_token=' + encodeURIComponent(form.querySelector('input[name=csrf_token]').value)
            });
            const data = await resp.json();
            if (data.success) {
                msgDiv.textContent = data.message;
                msgDiv.className = 'profile-message is-success';
            } else {
                msgDiv.textContent = data.error || 'Failed to resend';
                msgDiv.className = 'profile-message is-error';
            }
        } catch (err) {
            msgDiv.textContent = 'Network error';
            msgDiv.className = 'profile-message is-error';
        }
    });
}
```
- Add placeholder splices in the template (at the top, after the existing ones):
  - `{{display_name}}` → empty string
  - `{{email_verified}}` → "true"
- Add `.pending-pill` CSS (see Step 7).

## Step 7 — `frontend/static/css/styles.css` (additive blocks)
Append:
```css
/* Profile: Account Details card (v2.1.0) — additive */
.profile-card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 24px;
}

.profile-card .section-title {
    margin: 0 0 16px;
    font-size: 1.25rem;
    color: var(--text-primary);
}

.profile-message {
    margin-top: 12px;
    padding: 8px 12px;
    border-radius: 4px;
    font-size: 0.875rem;
}

.profile-message.is-success {
    background: var(--success-bg, #d4edda);
    color: var(--success-text, #155724);
}

.profile-message.is-error {
    background: var(--error-bg, #f8d7da);
    color: var(--error-text, #721c24);
}

/* Pending verification pill */
.pending-pill {
    display: inline-block;
    margin-top: 4px;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.75rem;
    background: var(--warning-bg, #fff3cd);
    color: var(--warning-text, #856404);
}
```

## Step 8 — `pyproject.toml` (dev dependencies)
- Add a new `[dependency-groups]` section at the end:
```toml
[dependency-groups]
dev = [
    "pytest>=7.0.0",
    "pytest-asyncio>=0.21.0",
]
```

## Step 9 — Test infrastructure (`backend/tests/`)
Create the directory and files:

**`backend/tests/__init__.py`**: empty.

**`backend/tests/conftest.py`**:
```python
"""Pytest fixtures for the vuln-web-app test suite."""
import os
import tempfile
import pytest
from fastapi.testclient import TestClient

# Patch config BEFORE importing app
os.environ["TURNSTILE_SITE_KEY"] = ""
os.environ["TURNSTILE_SECRET_KEY"] = ""

from app.main import app
from app.db import session as db_session

@pytest.fixture
def tmp_db(monkeypatch):
    """Create a temporary SQLite database for each test."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    monkeypatch.setattr(db_session, "DB_PATH", path)
    db_session.init_db()
    yield path
    os.unlink(path)

@pytest.fixture
def client(tmp_db):
    """Create a TestClient with a fresh temp DB."""
    return TestClient(app)

@pytest.fixture
def csrf_session(client):
    """Return a logged-in session dict with CSRF token from /login."""
    # Simple user for testing
    client.post("/signup", data={
        "username": "testuser",
        "email": "test@example.com",
        "password": "Test1234!",
        "csrf_token": "dummy",  # Will be replaced
    })
    # Extract CSRF token from login page
    resp = client.get("/login")
    import re
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    csrf = match.group(1) if match else "dummy"
    # Login
    resp = client.post("/login", data={
        "username": "testuser",
        "password": "Test1234!",
        "csrf_token": csrf,
    })
    return {"client": client, "csrf": csrf}
```

**`backend/tests/test_profile_edit.py`** (14 test cases):
| Test Case | Description |
|----------|-------------|
| `test_display_name_update` | Valid display name (≤60 chars) updates successfully |
| `test_display_name_too_long` | Display name >60 chars returns 400 |
| `test_display_name_optional` | Empty display name allowed (stored as NULL) |
| `test_email_update_triggers_verification` | Changing email sets is_verified=0, sends token |
| `test_email_invalid_format` | Invalid email format returns 400 |
| `test_email_same_as_current` | Same email returns 400 |
| `test_email_resend` | Resend verification email works when logged in |
| `test_profile_requires_session` | POST /profile without session returns 401 |
| `test_display_name_rendered_on_dashboard` | Display name shows on /welcome instead of username |
| `test_username_fallback_when_display_name_null` | NULL display_name falls back to username |
| `test_pending_pill_shows_when_unverified` | Email verification pill shows when is_verified=0 |
| `test_email_verified_session_update` | Session updated after email change |
| `test_display_name_html_escaped` | XSS payload in display_name renders as text |
| `test_email_change_preserves_username` | Changing email does not change username |

**`backend/tests/test_vuln_closures.py`** (8 regression tests):
| Test | Tests |
|------|-------|
| `test_vuln_1_sql_injection` | Parameterized SQL in profile_service |
| `test_vuln_2_stored_xss` | display_name escaped on output |
| `test_vuln_3_reflected_xss` | No user input reflected in responses |
| `test_vuln_4_session_hijacking` | SECRET_KEY unchanged |
| `test_vuln_5_weak_password` | No password handling in profile_service |
| `test_vuln_6_exposed_database` | No /download/db route |
| `test_vuln_7_no_rate_limiting` | POST /profile is rate-limited |
| `test_vuln_8_csrf` | POST /profile requires csrf_token |

**`backend/tests/test_auth_service.py`** and **`backend/tests/test_verification.py`**: Basic sanity tests for existing services (importable, no crash).

## Step 10 — `README.md`
- **Feature Enhancements table:** add a new row "Profile Editing (Display Name + Email)" with status **Done** and tag **v2.1.0**.
- Add a **v2.1.0 release row** to the Releases table.
- Update the "X are done … remaining are planned" prose.
- Add a **"Profile Editing — Setup"** section (no new env vars, no API changes, same profile page).

## Step 11 — `CLAUDE.md`
- **Frontend-Backend Integration:** add a **"Profile Editing (v2.1.0)"** bullet — display_name column, `profile_service.py`, email-change re-verification, session-gated resend, display-name fallback on dashboard.
- **Important Rules:** add an entry pinning the invariants — parameterized SQL only; display_name validation (≤60 chars); email uses existing verification_service; all splices use `html.escape()`; session stays valid throughout; do **not** modify `main.py`/`auth_service.py`/`security.py`/`csrf.py`/`rate_limit.py`/`oauth.py`/`mailer.py`/`qr_login.py`/`captcha.py`.
- **Specification Hierarchy:** add item **21. `.claude/specs/display-name-and-email-edit.md` + `-plan.md`**.

---

## Verification (per spec §9)

### Automated
1. `uv sync --dev` succeeds; pytest and pytest-asyncio installed.
2. `uv run pytest -q` is GREEN — all 14 profile-edit tests pass, all 8 VULN regression tests pass.
3. `uv run backend/app/main.py` boots with no traceback.

### Manual smoke tests
1. **Account Details card visible:** `GET /profile` shows the new card above Change Password.
2. **Display name update:** Edit display name → DB updated, session updated, dashboard shows new name.
3. **Email change triggers verification:** Change email → is_verified=0, verification email sent, pending pill shows.
4. **Verify link works:** Click emailed link → is_verified=1, token cleared, auto-login to dashboard.
5. **Display-name fallback:** User with display_name="Alice" sees "Alice"; user with NULL sees username.
6. **Resend works:** Click "Resend Verification Email" → new token issued, email sent.

### Security spot-check
- `git diff --stat` empty for MUST-NOT files (main.py, auth_service.py, etc.)
- `PRAGMA table_info(users)` shows exactly ONE new column: display_name.
- `pyproject.toml` `dependencies` array unchanged; only `[dependency-groups]` added.
- All 8 VULN regression tests pass.

---

## Out of scope (deferred to a future slice)
- Username change (requires its own spec)
- Avatar / profile picture upload
- Activity log / "last edited" timestamp
- 2FA re-prompt on email change

---

## Risk notes
- **Sync DB call in async handler:** `profile_service` uses sync `sqlite3` (same as `auth_service`). Bounded by DB latency; consistent with the existing pattern.
- **Session update on every profile edit:** The route refreshes the session from the DB after every edit — ensures consistency but adds one extra query.
- **Email-change token reuse:** The same `verification_service.start_verification()` is used — the token columns are reused, so a pending signup token is overwritten by an email-change token (and vice versa). This is the same model as signup and is acceptable for the lab.