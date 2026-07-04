# Software Specification Document — Profile Editing (Display Name + Email)

**Version:** 1.0.0
**Last Updated:** 2026-07-04
**Target Release Tag:** v2.1.0
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md), [user-profile-page.md](./user-profile-page.md), [email-verification-on-signup.md](./email-verification-on-signup.md)
**Tracking Issue:** [User Account Management Enhancements — Profile](https://github.com/arifpucit/vuln-web-app/issues)

---

## 1. Overview / Purpose

This document specifies the **Profile Editing — Display Name + Email** enhancement. It is the first slice of the "User Account Management Enhancements" feature group identified in the README's "Feature Enhancements" table (the items the team has not yet shipped). It upgrades the existing `/profile` page — shipped in **v1.0.2** as view-and-change-password only — so a logged-in user can also **edit their display name** and **change their email address** (with re-verification).

**This slice is additive, schema-migrating, and middleware-respecting.** It does not modify `main.py`, `auth_service.login()`, the lockout/CSRF/rate-limit middleware, the session secret, or any of the eight previously-closed vulnerabilities. It composes cleanly with every shipped feature (Email Verification v1.0.4, Account Lockout v1.0.5, Email-OTP 2FA v1.0.6, TOTP v1.0.7, QR Login v1.0.8, CAPTCHA v2.0.0) and is the first feature since v1.0.7 to ship a brand-new test suite alongside itself.

### 1.1 Why now, and what the user sees

Today's `/profile` page (`frontend/templates/profile.html`) shows the user's username and email as read-only text. The `name` and `picture` columns that Continue-with-Google (v1.0.3) added to the `users` row are stored but never rendered. There is no way for a user to fix a typo in their email, no way to update their email after a domain migration, and no way to set a friendly name on the dashboard beyond their login identifier.

This slice adds an **Account Details** card on `/profile` with two editable fields:

- **Display name** — a free-text label (≤ 60 chars, optional, trimmed). Renders on the dashboard in place of the raw username when set; falls back to the username when NULL.
- **Email** — the same field the signup flow already collects. Changes flip `is_verified` back to `0` and email a single-use, 1-hour re-verification link (same token model as v1.0.4). The session stays valid throughout; the next login after confirmation passes the `is_verified` gate.

The dashboard's "Logged in as **alice**" line is replaced with "Logged in as **Alice**" when a display name is set, and continues to show the username otherwise.

### 1.2 Design Decisions (product-owner choices)

These decisions were made explicitly before writing this spec and shape everything below:

1. **Username is immutable in this slice.** The login identifier stays the user's `username` for life. Changing it would cascade into: Google account linking by email (v1.0.3), email-verification resend (v1.0.4), account-lockout counters (v1.0.5), and the future password-reset flow. That cascade is a separate spec; it is explicitly listed as a non-goal here and as a candidate for a future v2.x.0 slice.
2. **The existing `verification_token` / `verification_token_expires` / `is_verified` columns are reused.** No new token columns. The email-change flow calls `verification_service.start_verification` exactly as `auth_service.signup` does, on the same row, with the same `EMAIL_VERIFICATION_TTL_SECONDS` (default 3600 s) and the same single-use contract. The only new column on `users` is `display_name`.
3. **The OAuth `name` column is NOT consulted in this slice.** When Continue-with-Google (v1.0.3) creates a user it stores Google's profile `name` in `users.name`, but that field is intentionally not rendered anywhere yet (per the v1.0.3 spec: *"The Google name/picture are stored but not rendered this release."*). A future slice can layer "prefer `name` when `auth_provider='google'`" without a migration. For v2.1.0 the dashboard falls back to `username` when `display_name` is NULL — identical behaviour to today.
4. **An email change re-verifies; a display-name change does not.** Same posture as v1.0.4: a new email is untrusted until the user proves control by clicking the link. The display name is just a label; no trust claim is being made.
5. **The session stays valid throughout the email-change process.** A user can edit their email, see the pending-verification pill, change their mind, and edit it again — all without re-logging in. The `is_verified=0` gate fires only on the *next login from a different device*; the in-flight session on the editing device is not invalidated. (This matches the existing semantics where a verified user who later gets `is_verified=0` flipped by an admin would still hold their session — there is no session-revocation hook today, and adding one is out of scope.)
6. **No 2FA re-prompt on email change.** A 2FA re-prompt would be a stricter posture; it is rejected for v2.1.0 because the `is_verified=0` gate is the trust-revocation lever — until the new address is verified, no new device can log in via the password flow, and the editing device is already trusted by virtue of holding the session. A future hardening slice can add the 2FA re-prompt behind a feature flag.
7. **The "Resend verification email" affordance is session-gated, not credential-gated.** The signup path uses credential-gated resend (v1.0.4) because an unverified signup has no session. A profile-page email change is different: the user is already logged in, so the resend is a simple `POST /profile/email/resend` that re-issues the token without prompting for the password. The same `secrets.token_urlsafe(32)` token and the same TTL are reused.
8. **Tests ship with this slice.** Per the user's preference, this PR introduces the project's first test suite (pytest, fastapi `TestClient`, per-test temp SQLite). It also adds explicit regression tests for all eight previously-closed vulnerabilities so that future features cannot silently regress them. The test suite is structured so v2.2.0 (session management), v2.3.0 (account deletion), and v2.4.0 (search history) can add new files without restructuring.

### 1.3 Built on existing primitives

This slice is deliberately **surgical**: it adds one column, one service module, one mailer function, three routes (one is an existing route, two are new), one new card in `profile.html`, two `replace()` calls in the route handlers, ~14 new tests, and the test infrastructure. Nothing else changes.

- **All SQL lives in a new `profile_service.py`** — sibling of `auth_service.py`, `verification_service.py`, `oauth_service.py`. Parameterized `?` placeholders throughout, mirroring the project's VULN-1 closure posture.
- **The new mailer function is a parallel of `send_verification_email`** — same SendGrid HTTPS transport (`core/mailer.py`), same `urllib`-only contract, same `html.escape(username, quote=True)` VULN-2 discipline, same fail-safe `return False` contract. The subject and body are different so the user's inbox makes the context clear, but the transport, retries, and timeout are identical.
- **The new route handlers follow the same `def_post` / `def_page` split as every other route in `api/routes/auth.py`** — thin wrappers over the service layer that splice CSRF tokens, parse `Form(...)` inputs, and return JSON for `fetch()`-based submits.
- **The new "Account Details" card follows the same `profile-card > section-title + form + profile-message` pattern** as every other card on `/profile`. The submit script uses the same `URLSearchParams(new FormData(form))` + `fetch()` shape as the change-password and 2FA forms. The same theme-toggle script. The same hidden `csrf_token` field. The same `aria-live="polite"` feedback `<div>`.
- **The new test suite uses the same `get_db()` factory as the production code** — `conftest.py` monkey-patches `app.db.session.DB_PATH` to a per-test temp file, runs `init_db()`, and tears down on test exit. No SQLite-in-memory-only shortcuts; the suite exercises the real `init_db()` migration path that production uses.
- **The existing middleware stack is unchanged.** The new POST routes (`/profile`, `/profile/email/resend`) automatically inherit the same CSRF, rate-limit, and signed-session protections because they are POSTs. The middleware order in `main.py` (RateLimit → Session → CSRF → handler) is preserved.

### 1.4 The implementation touches

- **One new backend module**: `backend/app/services/profile_service.py` (parameterized `UPDATE`, validation, email-change re-verification orchestration).
- **One new backend test module**: `backend/tests/conftest.py` + `backend/tests/test_profile_edit.py` + `backend/tests/test_vuln_closures.py` + `backend/tests/test_auth_service.py` + `backend/tests/test_verification.py` (the project's first pytest suite).
- **Existing files**: `backend/app/db/session.py` (one idempotent `ALTER TABLE`), `backend/app/api/routes/auth.py` (two new routes + one extended route + one dashboard splice), `backend/app/core/mailer.py` (one new function), `backend/app/core/config.py` (docstring update), `frontend/templates/profile.html` (additive Account Details card), `frontend/templates/dashboard.html` is **not** touched (the `welcome_page` handler in `auth.py` does the splicing), `frontend/static/css/styles.css` (small additive blocks), `pyproject.toml` (`[dependency-groups] dev = [...]`).
- **Documentation**: `.env.example` (no change — no new tunables), `README.md` (Feature Enhancements row, release row, setup section), `CLAUDE.md` (integration paragraph, Important Rule, hierarchy entry).
- **Spec/plan docs**: `.claude/specs/display-name-and-email-edit.md` (this file), `.claude/specs/display-name-and-email-edit-plan.md`, the three `docs/prompts/display-name-and-email-edit-*-prompt.txt` files.

**No other file is touched.** In particular, `backend/app/main.py`, `backend/app/services/auth_service.py` (and every other existing service), `backend/app/core/security.py`, `backend/app/core/csrf.py`, `backend/app/core/rate_limit.py`, `backend/app/core/oauth.py`, `backend/app/core/qr_login.py`, `backend/app/core/captcha.py`, `backend/app/db/session.py`'s existing schema (only the new column migration is added — no rewrite), the dependency manifests' runtime `dependencies` arrays (only `[dependency-groups]` is added), and every other template remain unchanged.

This feature introduces **one database-schema change** — the seventh since v0.1.0, all additive, all idempotent, all column-level `ALTER TABLE`s with no row drops or rewrites — and **no new runtime dependency**. The only dependency changes are dev-only (`pytest`, `pytest-asyncio`), grouped under `[dependency-groups] dev = [...]` so they do not bloat the production install.

### 1.5 What this slice does NOT do

- Does **not** allow changing the **username** (the login identifier). That requires its own spec.
- Does **not** render the OAuth `name` column. A future slice can layer "prefer `name` when `auth_provider='google'`" without a migration.
- Does **not** upload or render an avatar. No file storage, no upload UI.
- Does **not** add a generic activity log. The v2.4.0 search-history slice will make that call when it lands.
- Does **not** change the `welcome_page` template's `{{username}}` token. The handler in `auth.py` does the splice; the template stays byte-for-byte identical.
- Does **not** touch the change-password card or any 2FA card on `/profile`. The new Account Details card sits above them and is fully independent.
- Does **not** require any new env var. The TTL reuses `EMAIL_VERIFICATION_TTL_SECONDS`; the mailer reuses `SENDGRID_*`. `.env.example` is unchanged.

### 1.6 Explicit Preservation Note — All Eight Closed Vulnerabilities Stay Closed

The full closure tests for these are added in `backend/tests/test_vuln_closures.py` as part of this slice; the rationale is in each service/route file's docstring.

- **VULN-1 (SQL Injection):** every SELECT, INSERT, UPDATE in `profile_service.py` uses parameterized `?` placeholders. The new `display_name` column is read and written by primary key (`WHERE id = ?`). `auth_service.signup` / `login` / `change_password` are not modified. The full login / search / change-password / lockout paths remain parameterized.
- **VULN-2 (Stored XSS):** `display_name` is `html.escape(..., quote=True)`-d before being spliced into `profile.html` (the field value, the success message, and the pending-verification pill all go through the same escape). The dashboard splice in `welcome_page` does the same. A `<script>` payload entered as a display name renders as text, never as markup.
- **VULN-3 (Reflected XSS):** the new `POST /profile` does not reflect the submitted email or display name into the response body. The JSON success payload is a fixed set of keys (`success`, `message`, `email_verification`); the user-controlled values are stored in the DB and re-rendered on the next GET, where they go through the VULN-2 escape. The verification token is **never** reflected into any response, log, or email body — the same posture as v1.0.4.
- **VULN-4 (Session Hijacking):** `main.py` is not modified; the env-sourced `SECRET_KEY` is untouched. The new routes write to `request.session` (signed by the existing `SessionMiddleware`) just like every other route.
- **VULN-5 (Weak Password Storage):** `core/security.py` is not modified; bcrypt is unchanged. The new Account Details card does not touch passwords at all (the existing Change Password card handles that with the same bcrypt path).
- **VULN-6 (Exposed Database):** no `/download/db` or `/db` route is added. The new routes do not serve the SQLite file.
- **VULN-7 (No Rate Limiting):** `RateLimitMiddleware` stays registered and unchanged; the new `POST /profile` and `POST /profile/email/resend` are POSTs, so they inherit the same per-IP throttle.
- **VULN-8 (CSRF):** the new `POST /profile` and `POST /profile/email/resend` carry the hidden `csrf_token` field; `CSRFMiddleware` validates it. The same synchronizer-token contract as every other POST in the app.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- **Database migration (idempotent, additive).** `backend/app/db/session.py`:
  - Add `display_name TEXT` to the `CREATE TABLE IF NOT EXISTS users (...)` statement (one new column, no constraints, NULL by default). Fresh DBs get the column automatically.
  - Add an idempotent `ALTER TABLE users ADD COLUMN display_name TEXT` to the existing migration block, guarded by the `existing` set so it runs only on pre-v2.1.0 databases. No grandfather `UPDATE` (NULL is the correct default — it means "use the username as the dashboard label").
  - Update the module docstring's schema notes to document the new column and its fallback semantics.
  - The migration is the project's **seventh DB-schema change** since v0.1.0. Like every previous one, it is additive and never drops or rewrites existing rows.
- **Configuration.** `backend/app/core/config.py`:
  - **No new env tunables.** The feature reuses `EMAIL_VERIFICATION_TTL_SECONDS` (default 3600 s) and the existing `SENDGRID_*` / `APP_BASE_URL` settings.
  - Update the module docstring's feature list to include "Profile Editing — Display Name + Email (v2.1.0)".
- **New service module.** `backend/app/services/profile_service.py` (sibling of `auth_service.py`, `verification_service.py`):
  - `validate_email_format(email: str) -> bool` — returns `True` only for `^[^@\s]+@[^@\s]+\.[^@\s]+$` AND length ≤ 254 (RFC 5321 mailbox limit). Mirrors the JS validation the profile form does for inline feedback.
  - `update_account(user_id: int, display_name: str, new_email: str, current_email: str) -> dict` — the workhorse:
    1. SELECT the row by primary key (parameterized).
    2. Validate `display_name`: trim, length 0–60 (empty → store NULL).
    3. Validate `new_email`: must equal `current_email` OR pass the format check; on a changed value, flip `is_verified=0`, set the new email, and call `verification_service.start_verification(..., background=True)`. On an unchanged value, skip the verification re-issue.
    4. UPDATE the row (parameterized). On email change, the UPDATE writes `display_name`, `email`, `is_verified=0`, `verification_token=NULL`, `verification_token_expires=NULL` (the old token is cleared; `start_verification` writes a fresh one immediately after).
    5. Return a dict `{"status": "ok" | "invalid_email" | "display_name_too_long" | "not_found", "email_verification": "pending" | "none", "row": {...}}`. The route translates this into JSON.
  - `resend_email_verification(user_id: int) -> dict` — re-issues the token by calling `verification_service.start_verification(user_id, row["username"], row["email"], background=False)` so the resend returns a synchronous success/failure to the page (matching the v1.0.4 resend contract). Returns `{"status": "ok" | "not_found" | "already_verified", "message": "..."}`.
  - **All SQL is parameterized.** No string concatenation. No LIKE wildcards. No dynamic column names.
- **Email change mailer.** `backend/app/core/mailer.py`:
  - Add `send_email_change_verification(to_email, username, verify_url) -> bool` — same SendGrid transport (`_send_via_sendgrid`), same `html.escape(username, quote=True)` VULN-2 discipline, same fail-safe `return False` contract, same `_deliver` wrapper. Different subject ("Confirm your new email address - Security Vulnerability Lab") and a body that explicitly tells the user *this is a change request, not a new sign-up*, with a "If you did not request this change, secure your account" line. The verify URL token is never logged (VULN-3 posture).
- **Profile route changes.** `backend/app/api/routes/auth.py`:
  - `GET /profile` (`profile_page`, currently at `auth.py:362`): extend the splice set to include `{{display_name}}` and `{{email_verified}}`. The `display_name` value is read from the session (set on login by a small additive change — see below) OR from a fresh `SELECT display_name FROM users WHERE id = ?` (whichever is cheaper; the SELECT path is used to handle the case where the session was issued before this feature shipped). `email_verified` is `1` if `is_verified=1` and `0` otherwise. The template is the source of truth for what to render; this handler just provides the values.
  - **Add `POST /profile`**: thin wrapper over `profile_service.update_account`. Session-gated. CSRF + rate-limit are enforced by middleware before this runs. Returns JSON: `{"success": true, "message": "Account updated.", "email_verification": "pending" | "none", "display_name": "...", "email": "..."}` on success; `{"error": "..."}` on validation failure with the appropriate status code. On success, the route also updates the signed session: `request.session["display_name"]` and `request.session["email"]` are set so the dashboard's next render uses the new values without a re-login.
  - **Add `POST /profile/email/resend`**: thin wrapper over `profile_service.resend_email_verification`. Session-gated. Returns JSON: `{"success": true, "message": "Verification email sent. Check your inbox."}` or `{"error": "Email is already verified."}` with the appropriate status code. CSRF + rate-limit middleware applies.
  - **Extend `GET /welcome` (`welcome_page`, currently at `auth.py:322`)**: replace the `{{username}}` splice with a `{{display_name}}` splice that uses `request.session.get("display_name") or username` as the source. The handler does the fallback; the template stays a single `{{display_name}}` token. The `safe_username = html.escape(username, quote=True)` line moves to `safe_display_name = html.escape(display_name, quote=True)` with the same `quote=True` posture. (The template still has the `{{username}}` token in the audit trail — but it is now a 100% server-controlled value derived from the row's `username` column, escaped identically.)
  - **Extend the login success path** in `auth_service.login()` is **out of scope**; the dashboard's `welcome_page` reads `display_name` from a fresh SELECT if the session lacks it (the v1.0.2 dashboard already does a `SELECT * FROM users WHERE id = ?` for the 2FA flags, so this fits the existing pattern). The session will be populated for the current user on the very first `POST /profile` call (which writes the new keys), and existing sessions work transparently.
- **Profile template.** `frontend/templates/profile.html`:
  - **Additive** Account Details card, placed above the existing Change Password card. Mirrors the existing card structure verbatim: `<div class="profile-card">` > `<h2 class="section-title">Account Details</h2>` > `<form id="account-details-form">` (with hidden `csrf_token`) > two `<div class="form-group">` fields > a `<div id="account-details-message">` feedback > a "Save changes" button. The display_name field has a 60-char `maxlength`; the email field has a 254-char `maxlength` and `type="email"`.
  - A small inline `<script>` at the bottom of the card (matches the change-password / 2FA / TOTP scripts' style) does the JS-side format check (same regex as the server) for inline feedback, then submits via `URLSearchParams(new FormData(form))` and a `fetch('/profile', { method: 'POST', body })`. The success path hides the form, shows the message, and re-renders the page in the new state. The error path reuses the same `is-success` / `is-error` styling as the other cards.
  - A small **pending-verification pill** is rendered above the email field when `{{email_verified}}` is `0` (a styled `<span class="pill pill-pending">Pending verification</span>`). When `email_verified` is `1`, no pill is shown. When the email has been changed but not yet verified, a "Resend verification email" link appears next to the pill, posting to `/profile/email/resend` and toggling to "Sent — check your inbox." on success.
  - The card's title says "Account Details" and the section subtitle says "Update your display name and email address. Email changes require re-verification."
- **CSS.** `frontend/static/css/styles.css`:
  - Append a small additive `.profile-field-edit` block for the editable-field state (matches the existing `.profile-field` and `.profile-field-value` blocks but is the input variant).
  - Append a `.pill` base + `.pill-pending` modifier (a small rounded badge).
  - Append a `.field-feedback` block for the inline format-check error text (smaller, red in light mode, lighter red in dark mode).
  - **No existing rule is modified.** The new blocks live at the end of the file and only add new selectors.
- **Dashboard template.** `frontend/templates/dashboard.html`: **not modified**. The `welcome_page` handler in `auth.py` does the splicing; the template's `{{username}}` token is now substituted with the display-name-or-fallback value (server-controlled, escaped identically).
- **Test infrastructure.** `backend/tests/`:
  - `__init__.py` — empty file to make it a package.
  - `conftest.py` — fixtures (`tmp_db`, `client`, `csrf_session`, `captcha_disabled`, `app_module`).
  - `test_vuln_closures.py` — 8 regression tests, one per closed vulnerability.
  - `test_auth_service.py` — coverage for `signup`, `login`, `change_password`, lockout gate.
  - `test_verification.py` — coverage for the existing `verification_service.start_verification` / `verify_email_token` / `resend_for_credentials` (the profile-edit flow reuses these, so they get their own tests).
  - `test_profile_edit.py` — 14 v2.1.0-specific cases (see §5.3 of the plan).
- **Dev dependencies.** `pyproject.toml`:
  - Append `[dependency-groups] dev = ["pytest", "pytest-asyncio"]` (matching the PEP 735 standard that `uv` already understands). Run `uv sync --dev` to regenerate `uv.lock`. No runtime dep changes.
- **Documentation.** `README.md`:
  - Add the v2.1.0 row to the Feature Enhancements table (next ID after #8, which was CAPTCHA; this is #10 in PRD ordering).
  - Add a v2.1.0 release row to the release-history table.
  - Add a "Profile Editing — Display Name + Email" subsection under a new "Optional Features" heading, with a one-paragraph overview, a screenshot placeholder, and a "No setup required" note.
  - `CLAUDE.md`:
    - Add the v2.1.0 integration paragraph to the existing "Frontend-Backend Integration" block, mirroring the per-feature paragraph style.
    - Append the new Important Rule for v2.1.0.
    - Add a new entry to the Specification Hierarchy (item 21).

### 2.2 Out of Scope (Intentionally)

- **Username change.** A separate spec. Cascades into OAuth linking, verification resend, lockout counters, future password reset. Explicitly deferred.
- **Avatar / profile picture.** No file storage, no upload UI. The OAuth `picture` column stays unrendered.
- **OAuth `name` rendering on `/welcome`.** Stored, not rendered. A future slice can layer it without a migration.
- **2FA re-prompt on email change.** The `is_verified=0` gate is the trust-revocation lever. Future hardening can add this behind a flag.
- **Generic activity log.** Search-history (v2.4.0) will make that call.
- **No CAPTCHA on `POST /profile` or `POST /profile/email/resend`.** These are session-gated; only the password login carries bot-filter risk. A future slice can extend the Turnstile pattern to the profile form if abuse appears.
- **No new dependency.** `pyproject.toml`'s runtime `dependencies` array is unchanged; only `[dependency-groups]` is added.
- **No new env var.** `EMAIL_VERIFICATION_TTL_SECONDS` and `SENDGRID_*` are reused; `.env.example` is unchanged.
- **No new template engine / JS framework.** The card uses the same `str.replace('{{csrf_token}}', ...)` pattern as every other template; the JS uses the same `URLSearchParams(new FormData(form))` + `fetch()` shape.
- **No audit log of profile changes.** Defer to v2.4.0 (search-history can double as activity log).
- **No `PATCH /profile` (partial update).** The form sends both fields atomically. Future hardening if needed.

### 2.3 Files that MUST NOT be modified

This is the explicit-allowlist discipline every prior feature in this repo has used. The diff is small and reviewable precisely because of this list.

- `backend/app/main.py` — middleware wiring / `SECRET_KEY` / `RATE_LIMIT_*` / port (VULN-4 / VULN-7 / VULN-8 closures). The new routes are core/route-layer; no middleware is added.
- `backend/app/services/auth_service.py` — every existing function (`signup`, `login`, `change_password`, `password_meets_policy`) stays byte-for-byte unchanged. The dashboard's new `display_name` read happens in `welcome_page`, not in `auth_service`.
- `backend/app/services/lockout_service.py`, `verification_service.py`, `oauth_service.py`, `otp_service.py`, `totp_service.py` — unchanged. `profile_service` imports `verification_service` to start the token; it does not modify it.
- `backend/app/core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/oauth.py`, `core/mailer.py` (except the one new function), `core/qr_login.py`, `core/captcha.py`.
- `frontend/templates/login.html`, `signup.html`, `dashboard.html` (the welcome handler does the splicing — the template's `{{username}}` token now receives the display-name-or-fallback, but the file is not edited), all the verify/otp/totp templates, `check_email.html`, `verify_result.html`, `email_not_configured.html`, `oauth_not_configured.html`, `qr_approve.html`.
- `pyproject.toml`'s runtime `dependencies` array — only the `[dependency-groups]` dev block is added. The runtime install (`uv sync` without `--dev`) is unchanged.
- `uv.lock` — regenerated by `uv sync --dev`; no manual edit.
- `.env.example` — no new tunable.

---

## 3. Affected Files

The change MUST touch only the following files (beyond this spec/plan pair, the three prompt docs, and the implementation).

| Path | Change Type | Purpose |
|------|-------------|---------|
| `.claude/specs/display-name-and-email-edit.md` | **New** | This spec doc. |
| `.claude/specs/display-name-and-email-edit-plan.md` | **New** | Per-file task list mirroring `captcha-on-login-plan.md`. |
| `docs/prompts/display-name-and-email-edit-spec-prompt.txt` | **New** | The spec-generation prompt. |
| `docs/prompts/display-name-and-email-edit-plan-prompt.txt` | **New** | The plan-generation prompt. |
| `docs/prompts/display-name-and-email-edit-execution-prompt.txt` | **New** | The implementation prompt. |
| `backend/app/db/session.py` | Modified | One new `display_name TEXT` column + idempotent ALTER TABLE. |
| `backend/app/core/mailer.py` | Modified | One new function `send_email_change_verification`. |
| `backend/app/core/config.py` | Modified | Docstring feature list update (no new tunables). |
| `backend/app/services/profile_service.py` | **New** | The workhorse service: `validate_email_format`, `update_account`, `resend_email_verification`. |
| `backend/app/api/routes/auth.py` | Modified | Two new routes (`POST /profile`, `POST /profile/email/resend`); `GET /profile` extended with two extra splices; `GET /welcome` extended with display-name-or-fallback splice. |
| `frontend/templates/profile.html` | Modified | Additive Account Details card. |
| `frontend/static/css/styles.css` | Modified | Small additive blocks (`.profile-field-edit`, `.pill`, `.pill-pending`, `.field-feedback`). |
| `pyproject.toml` | Modified | `[dependency-groups] dev = [...]`. |
| `backend/tests/__init__.py` | **New** | Empty package marker. |
| `backend/tests/conftest.py` | **New** | Test fixtures. |
| `backend/tests/test_vuln_closures.py` | **New** | 8 VULN regression tests. |
| `backend/tests/test_auth_service.py` | **New** | Signup / login / change_password / lockout. |
| `backend/tests/test_verification.py` | **New** | Verification service coverage. |
| `backend/tests/test_profile_edit.py` | **New** | 14 v2.1.0 cases. |
| `README.md` | Modified | Feature Enhancements row + release row + setup section. |
| `CLAUDE.md` | Modified | Integration paragraph + Important Rule + hierarchy entry. |

**Files that MUST NOT be modified by this change:**

- `backend/app/main.py`
- `backend/app/services/auth_service.py`, `lockout_service.py`, `verification_service.py`, `oauth_service.py`, `otp_service.py`, `totp_service.py`
- `backend/app/core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/oauth.py`, `core/qr_login.py`, `core/captcha.py`
- `frontend/templates/login.html`, `signup.html`, `dashboard.html`, `check_email.html`, `verify_result.html`, `email_not_configured.html`, `oauth_not_configured.html`, `qr_approve.html`, `otp_verify.html`, `totp_verify.html`
- `pyproject.toml`'s `dependencies` array (only `[dependency-groups]` is added)
- `.env.example`
- `uv.lock` (regenerated by `uv sync --dev`)

---

## 4. Functional Requirements

### FR-01: Database Migration — `display_name` Column
- `backend/app/db/session.py` MUST add `display_name TEXT` to the `CREATE TABLE IF NOT EXISTS users (...)` statement.
- `init_db()` MUST add an idempotent `ALTER TABLE users ADD COLUMN display_name TEXT` to the existing migration block, guarded by the `existing` set so it runs exactly once on pre-v2.1.0 databases.
- There MUST be **no** grandfather `UPDATE` (NULL is the correct default; it means "use the username as the dashboard label").
- The migration MUST NOT modify or drop any existing column. The new column is the project's seventh DB-schema change; it follows the same additive, idempotent, row-preserving pattern as the previous six.
- The schema-notes docstring MUST be updated to document the new column and its fallback semantics.

### FR-02: No New Configuration Tunables
- `backend/app/core/config.py` MUST NOT introduce any new env-tunable values.
- The TTL reuses the existing `EMAIL_VERIFICATION_TTL_SECONDS` (default 3600 s).
- The mailer reuses the existing `SENDGRID_API_KEY` / `SENDGRID_FROM` / `SENDGRID_HTTP_TIMEOUT` / `APP_BASE_URL` settings.
- The module docstring's feature list MUST be updated to include "Profile Editing — Display Name + Email (v2.1.0)".

### FR-03: New Service Module — `profile_service.py`
- `validate_email_format(email: str) -> bool` MUST return `True` only for strings matching `^[^@\s]+@[^@\s]+\.[^@\s]+$` AND length ≤ 254. False otherwise.
- `update_account(user_id, display_name, new_email, current_email) -> dict` MUST:
  1. Open a fresh `get_db()` connection.
  2. SELECT the row by primary key (parameterized) — if not found, return `{"status": "not_found"}`.
  3. Validate `display_name`: trim the value, reject if length > 60 (return `{"status": "display_name_too_long"}`), accept empty as NULL.
  4. Detect email change: `new_email != current_email`. If unchanged, skip steps 5-6.
  5. On change, validate `new_email` via `validate_email_format` (return `{"status": "invalid_email"}` on failure), then UPDATE the row to set `email=new_email`, `is_verified=0`, and clear `verification_token`/`verification_token_expires`.
  6. Call `verification_service.start_verification(user_id, row["username"], new_email, background=True)`. Failures are logged and surfaced as `{"status": "ok", "email_verification": "send_failed"}` — the row update has already committed, so the user can resend from the page.
  7. UPDATE `display_name` (always; an unchanged display name is a no-op write).
  8. Return `{"status": "ok", "email_verification": "pending" | "none", "row": {...}, "display_name": "...", "email": "..."}`.
- `resend_email_verification(user_id) -> dict` MUST:
  1. SELECT the row (parameterized) — if not found, return `{"status": "not_found"}`.
  2. If `is_verified=1`, return `{"status": "already_verified", "message": "Your email is already verified."}`.
  3. Call `verification_service.start_verification(user_id, row["username"], row["email"], background=False)` and return its boolean as `{"status": "ok"}` or `{"status": "send_failed"}`.
- Every SQL statement MUST be parameterized (`?` placeholders, bound values as a separate list). No string concatenation. No dynamic column names. No `LIKE` queries.

### FR-04: New Mailer Function
- `core/mailer.send_email_change_verification(to_email, username, verify_url) -> bool` MUST:
  1. Return `False` (never raise) when SendGrid is unconfigured.
  2. Use the existing `_send_via_sendgrid` transport with `to_email`, subject ("Confirm your new email address - Security Vulnerability Lab"), text body, and HTML body.
  3. `html.escape(username or "", quote=True)` and `html.escape(verify_url, quote=True)` the attacker-influenced values before they enter the HTML part (VULN-2 posture).
  4. The HTML body MUST include a line like "If you did not request this change, please secure your account immediately by changing your password." (VULN-3 / phishing-resistance posture).
  5. The raw verify URL token MUST NOT be logged.
  6. On any send / API error, return `False` and log a warning server-side.
  7. Be a sibling of the existing `send_verification_email` — same SendGrid-only transport, same fail-safe contract.

### FR-05: `GET /profile` — Extended Splices
- `profile_page` MUST continue to require a session (no `user_id` → 302 `/login`).
- `profile_page` MUST splice `{{display_name}}` (HTML-escaped, `quote=True`) — read from the session if present, else from a fresh `SELECT display_name FROM users WHERE id = ?` (parameterized), else `""` (the template's `{{display_name}}` falls back to the username in the JS).
- `profile_page` MUST splice `{{email_verified}}` — `"1"` if the row's `is_verified=1`, else `"0"`.
- `profile_page` MUST splice `{{email}}` (unchanged), `{{username}}` (unchanged), `{{csrf_token}}` (unchanged), `{{twofa_enabled}}` (unchanged), `{{email_configured}}` (unchanged), `{{totp_enabled}}` (unchanged).
- The page MUST remain a single `HTMLResponse` rendered from `profile.html` with `str.replace`; no template engine is introduced.

### FR-06: `POST /profile` — New Route
- The route MUST be a thin wrapper over `profile_service.update_account`. Session-gated (no `user_id` → 401 JSON). CSRF + rate-limit are enforced by middleware before this runs.
- The route MUST read `display_name: str = Form("")` and `email: str = Form("")` (matching the field names in the HTML).
- On success, the route MUST update the signed session: `request.session["display_name"] = result["display_name"]`, `request.session["email"] = result["email"]`. This mutation is what causes `SessionMiddleware` to emit the new signed cookie.
- The route MUST return JSON for every outcome so the page's `fetch()` handler can render feedback inline without a reload:
  - `200 {"success": true, "message": "Account updated.", "email_verification": "pending" | "none", "display_name": "...", "email": "..."}` on success.
  - `400 {"error": "Display name must be 60 characters or fewer."}` on too-long display name.
  - `400 {"error": "Please enter a valid email address."}` on invalid email format.
  - `401 {"error": "Not authenticated."}` on no session.
  - `500 {"error": "Could not update account."}` on unexpected DB error (generic, no exception text reflected).

### FR-07: `POST /profile/email/resend` — New Route
- The route MUST be a thin wrapper over `profile_service.resend_email_verification`. Session-gated (no `user_id` → 401 JSON). CSRF + rate-limit are enforced by middleware before this runs.
- The route MUST return JSON for every outcome:
  - `200 {"success": true, "message": "Verification email sent. Check your inbox."}` on success.
  - `200 {"success": true, "message": "Your email is already verified."}` on already-verified (treated as a soft success — no email sent, but the user is told the truth).
  - `401 {"error": "Not authenticated."}` on no session.
  - `500 {"error": "Could not send the email. Please try again later."}` on mailer failure.

### FR-08: `GET /welcome` — Display Name or Fallback
- `welcome_page` MUST continue to require a session (no `user_id` → 302 `/login`).
- `welcome_page` MUST compute `display_name = request.session.get("display_name") or username` (where `username` is the existing read from `request.session.get("username", "")`). The session value is preferred; the fallback is the immutable username.
- `welcome_page` MUST splice the **same** `{{username}}` token in the `dashboard.html` template (the template is not modified), but the value passed in is `display_name`. The `safe_username = html.escape(username, quote=True)` line becomes `safe_display_name = html.escape(display_name, quote=True)` with identical `quote=True` posture.
- This is the **only** behavioural change to `welcome_page`. The auth gate, the verification gate (which is in `auth_service.login()`, unchanged), and the template remain identical.

### FR-09: `auth_service.login()` — Unchanged
- `auth_service.login()` and every other function in `auth_service.py` MUST remain byte-for-byte unchanged. The dashboard's `display_name` is read in `welcome_page` (which does the SELECT), not in `login()`. This is the same pattern the v1.0.2 profile page already uses for the 2FA flags.

### FR-10: Profile Template — Additive Card
- `frontend/templates/profile.html` MUST add an Account Details card above the existing Change Password card. The card MUST follow the same `profile-card > section-title + form + profile-message` structure as every other card on the page.
- The card MUST contain:
  - A hidden `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` field (first child of the form, per the project's CSRF convention).
  - A `<div class="form-group">` with label "Display name" and an `<input type="text" id="display_name" name="display_name" maxlength="60" class="form-input">`. The value is the current `{{display_name}}` (or empty if NULL).
  - A `<div class="form-group">` with label "Email" and an `<input type="email" id="email" name="email" maxlength="254" required class="form-input">`. The value is the current `{{email}}`. A `.pill-pending` element appears next to the label when `{{email_verified}}` is `0`.
  - A "Save changes" button (`<button type="submit" class="btn btn-primary">Save changes</button>`).
  - A feedback `<div id="account-details-message" role="status" aria-live="polite" style="display: none;">` (hidden by default, shown by JS on response).
  - When `{{email_verified}}` is `0`, a "Resend verification email" link next to the pill, wired to `POST /profile/email/resend` and styled like the existing 2FA card's secondary actions.
- The card's title MUST be "Account Details" with subtitle "Update your display name and email address. Email changes require re-verification."
- The card MUST have an inline `<script>` block at the bottom that:
  1. Listens to the form's `submit` event with `e.preventDefault()`.
  2. Mirrors the server-side validation (display name max 60, email format) for inline feedback before submitting.
  3. Submits via `URLSearchParams(new FormData(form))` (so the Content-Type is `application/x-www-form-urlencoded` and the CSRF middleware's parser accepts it) and `fetch('/profile', { method: 'POST', body })`.
  4. On `200`, displays the success message, updates the form values, and re-renders the pending-verification state if `email_verification === "pending"`.
  5. On `400`, displays the error in the feedback div with `is-error` styling (matches the change-password / 2FA / TOTP scripts' style).
- The existing Account Information card (currently showing username + email as read-only spans) MUST remain in place and unchanged. The new Account Details card is **in addition to** it; the existing card provides read-only context, the new card provides the edit form. (A future cleanup PR can merge them; for v2.1.0 the additive approach is the lowest-risk path.)

### FR-11: CSS — Additive Blocks
- `frontend/static/css/styles.css` MUST append:
  - A `.profile-field-edit` block: a flex container that aligns the input + label, with the same vertical rhythm as the existing `.profile-field` block.
  - A `.pill` base + `.pill-pending` modifier: a small rounded badge with the same colour palette (warning yellow in light mode, amber in dark mode, drawn from the existing CSS custom properties).
  - A `.field-feedback` block: a small red text under an input, with `data-theme="dark"` overrides for the dark variant.
- **No existing rule MUST be modified.** The new blocks live at the end of the file and only add new selectors.

### FR-12: Dashboard Template — Unchanged
- `frontend/templates/dashboard.html` MUST NOT be modified. The `{{username}}` token in the template continues to be a single `replace()` call in `welcome_page`; the value passed in is the display-name-or-fallback. The HTML escaping is identical. The audit posture is identical.

### FR-13: `auth_service.login()` Continues to Write the Session Without `display_name`
- Existing sessions (issued before v2.1.0) lack the `display_name` session key. The dashboard's `welcome_page` handles this transparently by falling back to the username. New sessions issued by v2.1.0 (or sessions refreshed by `POST /profile`) include the key. There is no migration path needed for old sessions; the fallback is sufficient.
- This is the same pattern v1.0.2 used for the `is_verified` / `two_factor_enabled` flags (read from the row, not the session, in `profile_page`).

### FR-14: Test Suite — Project's First
- `backend/tests/__init__.py` MUST be empty.
- `backend/tests/conftest.py` MUST provide:
  - `tmp_db` fixture — autouse; monkey-patches `app.db.session.DB_PATH` to a `tmp_path / "test.db"` file, calls `init_db()`, yields, then deletes the file on test exit. Every test gets a fresh DB.
  - `client` fixture — `from fastapi.testclient import TestClient`; returns a `TestClient(app)` instance. A per-test session secret is set via `os.environ["SECRET_KEY"]` in the fixture so cookies don't leak across tests.
  - `csrf_session(client)` fixture — calls `GET /login`, captures the `csrf_token` from the rendered form (regex against the HTML), and exposes it as a string for POSTs.
  - `captcha_disabled` fixture — autouse; sets `os.environ["TURNSTILE_SITE_KEY"] = ""` and `os.environ["TURNSTILE_SECRET_KEY"] = ""` (or re-imports `app.core.config` with the override) so the login POST does not try to hit Cloudflare.
- `backend/tests/test_vuln_closures.py` MUST contain exactly eight tests, one per closed vulnerability, named `test_vuln{1..8}_<short_description>`. Each test asserts the closure's invariant: parameterized SQL (no auth bypass on `' OR '1'='1`), HTML escaping on `/welcome` and `/search`, env-sourced session secret, bcrypt-hashed passwords, no `/download/db` route, 429 on the 6th POST, 403 on missing CSRF token.
- `backend/tests/test_auth_service.py` MUST cover `signup` (success, duplicate username, missing fields), `login` (correct creds, wrong password, no such user, locked account), and `change_password` (correct current, wrong current, weak new, success).
- `backend/tests/test_verification.py` MUST cover `verification_service.start_verification` (writes token), `verify_email_token` (success clears token, expired, invalid), and `resend_for_credentials` (correct creds, wrong creds, already verified).
- `backend/tests/test_profile_edit.py` MUST contain exactly the 14 cases enumerated in §5.3 of the plan.

### FR-15: No New Runtime Dependency
- `pyproject.toml`'s `dependencies` array MUST remain unchanged.
- `pyproject.toml` MUST add `[dependency-groups] dev = ["pytest", "pytest-asyncio"]` (PEP 735).
- The dev install (`uv sync --dev`) MUST add `pytest` and `pytest-asyncio`; the production install (`uv sync` without `--dev`) MUST be unchanged.

### FR-16: `auth_service.login()` Signature Unchanged
- The login service's signature, return type, and behaviour MUST remain byte-for-byte identical. The new profile routes do not call `login()`; they call `profile_service.update_account` / `resend_email_verification`.

### FR-17: Verification Token Behaviour Preserved
- The email-change flow MUST call `verification_service.start_verification` with the same `secrets.token_urlsafe(32)` token, the same `EMAIL_VERIFICATION_TTL_SECONDS` TTL, the same single-use contract (success clears both columns), and the same `html.escape(username, quote=True)` mailer discipline. The token MUST be stored in the existing `verification_token` / `verification_token_expires` columns; no new token columns are added.
- `verification_service.verify_email_token` MUST work unchanged on a token issued by the profile flow (the existing function looks up by token value and clears both columns on success; nothing in the profile flow alters the column semantics).

### FR-18: Lockout Counter Preserved
- `POST /profile` and `POST /profile/email/resend` MUST NOT increment the account-lockout counter (v1.0.5). The lockout counter is a property of the password-login credential check, not the profile-edit flow. This is consistent with the v1.0.6 / v1.0.7 / v1.0.8 design choices.

### FR-19: Display Name Never Reflected Unescaped (VULN-2 / VULN-3)
- The display name submitted to `POST /profile` MUST NOT appear in the JSON response body, the success message, the error message, the next `GET /profile` HTML, or the next `GET /welcome` HTML without first being processed by `html.escape(..., quote=True)`.
- The email submitted to `POST /profile` MUST NOT appear in the JSON response body, the success message, the error message, or any subsequent response without first being processed by `html.escape(..., quote=True)`.
- The verification token (the `secrets.token_urlsafe(32)` value) MUST NOT appear in any response body, URL, template, log line, or email body. The mailer renders the URL with `html.escape(verify_url, quote=True)` on the HTML alternative part; the URL is also URL-encoded by SendGrid's body parser.

### FR-20: Token Never Logged
- The verification token (both at issue time and at verify time) MUST NOT be logged at any log level. The `verification_service.start_verification` and `verify_email_token` functions already enforce this; `profile_service` inherits the contract by calling those functions directly.

### FR-21: Rate Limit + CSRF Apply to New POSTs
- The new `POST /profile` and `POST /profile/email/resend` are POSTs, so they MUST inherit the existing `RateLimitMiddleware` (5 POSTs per 60 s per IP by default, tunable via `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_SECONDS`) and the existing `CSRFMiddleware` (synchronizer-token check, fail-closed) without any modification to either middleware.
- A POST without a valid `csrf_token` form field MUST be rejected with 403 by the CSRF middleware before the handler runs.
- The 6th POST in a 60-second window MUST be rejected with 429 by the rate limiter before the handler runs.

### FR-22: `.env.example` Unchanged
- The feature reuses the existing `EMAIL_VERIFICATION_TTL_SECONDS` and `SENDGRID_*` settings. No new tunable is added. `.env.example` MUST NOT be modified.

### FR-23: `welcome_page` Reads the Same Row, Same Field
- The new `display_name` read in `welcome_page` MUST reuse the row already SELECTed for the 2FA flags. Specifically, `welcome_page` does NOT issue a fresh SELECT — the existing 2FA-flag SELECT in v1.0.2 / v1.0.6 is extended by one column. The parameter binding list grows from `[user_id]` to `[user_id]` (the column is added to the SELECT list; the parameter list is unchanged).
- The session `display_name` key is preferred when present; the row is the source of truth for the fallback. The session's `display_name` is updated on `POST /profile` success.

---

## 5. Non-Functional Requirements

### NFR-01: Surgical Scope
- The change MUST touch only the files in §3.1. `main.py`, the existing services (except the new `profile_service.py`), the existing core modules (except the one new mailer function), and every other template MUST remain unchanged.

### NFR-02: No Regressions to Closed Vulnerabilities
- All eight previously-closed vulnerabilities MUST remain closed. The new `test_vuln_closures.py` suite is the machine-verifiable assertion of this requirement; running `uv run pytest -q` MUST be green.

### NFR-03: Backwards-Compatible Sessions
- Sessions issued before v2.1.0 (which lack the `display_name` key) MUST continue to work. The dashboard's `welcome_page` falls back to the username transparently; the profile page's `profile_page` reads from the row when the session key is absent.

### NFR-04: Performance
- The new `POST /profile` MUST complete in well under 100 ms on a warm SQLite (the existing password change takes ~150 ms due to bcrypt; the profile update does no bcrypt and is faster).
- The new `display_name` read in `welcome_page` MUST be a column add to the existing SELECT, not a new query.
- No N+1 patterns are introduced.

### NFR-05: Observability
- The `profile_service` MUST log a `logger.info` line on every successful update (with the user_id and a one-line summary — no PII, no token). The mailer already logs "Email sent to <address>" on success; the resend path inherits that.

### NFR-06: Idempotency
- A second `POST /profile` with the same `display_name` and `email` MUST succeed (no-op update) and return `{"email_verification": "none"}`. The route does not assume the user is changing values; an empty-form submit is a valid "save the current state" action.
- `POST /profile/email/resend` called twice in a row MUST issue two distinct tokens (the second overwrites the first, same as v1.0.4 resend).

### NFR-07: No Hardcoded Secrets
- No new secret is introduced. The verification token is `secrets.token_urlsafe(32)` (already imported by `verification_service`). The display name is user input; the email is user input. Nothing else is stored.

### NFR-08: Documentation Discipline
- `README.md` and `CLAUDE.md` MUST be updated to reflect the v2.1.0 feature. The CLAUDE.md "Important Rules" section MUST gain a new entry that captures the security posture of this feature. The Specification Hierarchy MUST gain item #21.

### NFR-09: Test Coverage
- The 14 v2.1.0 cases in §5.3 of the plan MUST all pass. The 8 VULN regression cases MUST all pass. The auth-service and verification-service cases MUST all pass. The total test count MUST be at least 30 cases.

### NFR-10: Diff Size Budget
- The PR diff SHOULD be under 1500 lines of new code (excluding tests, which are a separate ~600-line block) and under 500 lines of modified code. This is a soft budget, not a hard cap — if a real bug requires a longer diff, the spec wins.

---

## 6. Open Questions (resolved before merge)

1. **Display name max length: 60 chars.** Resolved: 60. Matches Google OAuth's `name` column.
2. **Email change while unverified: keep the change, show pending pill.** Resolved: yes, keep the change.
3. **Display name change re-issue session/logout event: no.** Resolved: no audit row.
4. **VULN regression tests bundled in v2.1.0 PR.** Resolved: yes, bundled.

---

## 7. Out of Scope (Future Slices)

- **Username change** — separate spec, cascades through OAuth linking and verification resend.
- **OAuth `name` rendering on `/welcome`** — a one-line change in `welcome_page`; deferred.
- **Avatar / profile photo** — no file storage in this project.
- **2FA re-prompt on email change** — future hardening, behind a feature flag.
- **Generic activity log** — v2.4.0 search-history will make that call.
- **CAPTCHA on `POST /profile`** — session-gated; no bot-filter risk today.
- **Audit log of profile changes** — v2.4.0 could double as activity log with one extra `kind` column.
- **`PATCH /profile` partial updates** — the form is atomic; the service is already idempotent so the migration is trivial when needed.

---

## 8. Verification

### 8.1 Automated tests
```bash
uv sync --dev
uv run pytest -q          # all tests green
uv run pytest -q -k profile  # v2.1.0 tests only
uv run pytest -q -k vuln  # VULN regression tests only
```

### 8.2 Manual smoke test
```bash
uv run backend/app/main.py    # boot the app on :3001
# 1. Sign up (uses SendGrid if configured; otherwise the page
#    degrades -- use a different DB and a local mailer for the demo).
# 2. Visit /profile; the new Account Details card is visible above
#    Change Password. Both fields are pre-filled.
# 3. Edit the display name to "Alice"; click Save changes. The page
#    shows "Account updated." inline. The dashboard at /welcome now
#    shows "Logged in as Alice" instead of the username.
# 4. Edit the email to a new address; click Save changes. The page
#    shows "Account updated. Check your inbox to confirm the new
#    address." and a "Pending verification" pill appears next to the
#    email field with a "Resend verification email" link.
# 5. Check the inbox; click the verification link. The /verify page
#    shows the success outcome; the dashboard's email field updates.
# 6. Visit /profile again; the pill is gone; the email is verified.
```

### 8.3 Security spot-check
```bash
# VULN-1: try SQLi on the new POST /profile
curl -X POST -d "csrf_token=$TOKEN&display_name=' OR 1=1--&email=victim@example.com" \
  -b cookies.txt http://localhost:3001/profile
# Expected: 400 with the JS-mirrored validation error; the row is unchanged.

# VULN-2: sign up with a display name of "<script>alert(1)</script>"
# (manually set via the form), then visit /welcome. Expected: the
# browser shows the literal text; no alert.

# VULN-3: submit a profile update with an email of
# "<img onerror=alert(1) src=x>". Expected: 400 (invalid email
# format); no XSS.

# VULN-8: POST /profile without csrf_token. Expected: 403 from
# CSRFMiddleware; the handler does not run.
```

---

## 9. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Existing `welcome_page` change subtly alters dashboard rendering | Low | Medium | The change is a single `replace()` swap; the template's `{{username}}` token is unchanged. Manual smoke + `test_dashboard_renders_display_name_or_fallback`. |
| New column migration fails on a pre-v2.1.0 DB with a different `users` schema | Very low | Medium | The migration follows the exact same idempotent pattern as the previous six; `existing` set guards every ALTER. `test_vuln_closures.py::test_vuln6_no_db_download_route` plus a new migration test. |
| `POST /profile` allows an XSS via the display name | Low | High | `html.escape(quote=True)` on every splice; `test_post_profile_html_escapes_display_name`. |
| Email change re-issue confuses the v1.0.4 signup flow | Very low | Medium | The same `verification_service.start_verification` function is called; same columns, same TTL, same single-use contract. The signup flow is unchanged. |
| Test suite runs against the user's real `vulnerable_app.db` | Medium | High | `conftest.py` uses `monkeypatch` to redirect `DB_PATH` to a per-test temp file. The real DB is never touched. |
| `pyproject.toml` change breaks the production install | Low | High | Only `[dependency-groups]` is added; the runtime `dependencies` array is unchanged. `uv sync` (no `--dev`) installs the same set as before. |

---

## 10. References

- v1.0.2 spec: `.claude/specs/user-profile-page.md` — the existing `/profile` page (view + change password).
- v1.0.3 spec: `.claude/specs/continue-with-google.md` — the `name` / `picture` columns (stored, not rendered).
- v1.0.4 spec: `.claude/specs/email-verification-on-signup.md` — the verification token model that this feature reuses.
- v2.0.0 spec: `.claude/specs/captcha-on-login.md` — the format template mirrored for this document.
- v2.0.0 plan: `.claude/specs/captcha-on-login-plan.md` — the per-file task list template mirrored for the v2.1.0 plan.
- `CLAUDE.md` — the project-wide rules this slice must honour.
