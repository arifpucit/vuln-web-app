# Software Specification Document — Forgot Password (Token-Based Reset)

**Version:** 1.0.0
**Last Updated:** 2026-07-02
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)

---

## 1. Overview / Purpose

This document specifies a **fully hardened, token-based Forgot Password** flow. The application currently has no recovery mechanism — `auth_service.login()` accepts bcrypt-verified credentials only, and `auth_service.change_password()` requires the *current* password (v1.0.2). This spec adds an email-delivered reset link that lets a user who has forgotten their password set a new one without a session.

A user submits their email on a new `GET /forgot-password` page → `POST /forgot-password` mints a single-use, 15-minute `secrets.token_urlsafe(32)` token, stores **only the SHA-256 hash of the token** in a new `password_resets` table, and emails a one-shot `{config.APP_BASE_URL}/reset-password?token=<plaintext>` link via the existing `core/mailer.py` (SendGrid transport). Clicking the link loads `GET /reset-password?token=…`, where the user picks a new password. `POST /reset-password` re-hashes the submitted token, looks it up in `password_resets`, enforces the existing five-criteria strength policy (`password_meets_policy()` — length ≥ 8 plus lower, upper, digit, special), bcrypt-hashes the new password, updates the `users.password` column, and **marks the row `used = 1` immediately** so the link cannot be replayed. No session is written — the user logs in with the new password.

**Hardening posture — no new vulnerability is introduced by this feature.** Every other spec in this lab closes one tracked OWASP vulnerability while deliberately leaving others open for study; this spec is **fully hardened end to end**. Every URL the server emits — the emailed reset link *and* the reset form's `action` target — is built exclusively from the trusted server-side `config.APP_BASE_URL` setting; the reset page loads **no third-party asset of any kind** (no CDN script, no external stylesheet, no remote image, no web font, no analytics pixel) so no `Referer` header carrying the token-bearing URL can ever be sent to an external origin. Host Header Injection and Referer Leakage vectors are therefore *not* demonstrable against this feature; the production-grade fix is applied at the spec level.

This is the project's **sixth DB-schema change**: a brand-new `password_resets` table is added by the same idempotent, additive `CREATE TABLE IF NOT EXISTS` pattern used by every prior feature (Verification v1.0.4, Lockout v1.0.5, OTP v1.0.6, TOTP v1.0.7). **No row is ever dropped or rewritten; the `users` table is unchanged.**

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- **New `password_resets` table** added by `init_db()` (idempotent `CREATE TABLE IF NOT EXISTS`):
  - `id INTEGER PRIMARY KEY AUTOINCREMENT`
  - `user_id INTEGER NOT NULL` — FK to `users.id`; resolved at lookup time
  - `token_hash TEXT UNIQUE NOT NULL` — SHA-256 hex digest of the plaintext token (64 chars); the plaintext is **never** stored
  - `expires_at REAL NOT NULL` — Unix epoch seconds (`time.time() + 900`); compared against `time.time()` on lookup with strict `>`
  - `used INTEGER NOT NULL DEFAULT 0` — `1` once the link has been consumed (single-use)
- **New service module `backend/app/services/password_reset_service.py`** (sibling of `verification_service.py`, `otp_service.py`):
  - `start_reset(email: str) -> None` — mints a `secrets.token_urlsafe(32)` token, stores its SHA-256 hash with `expires_at = time.time() + 900`, emails the `{config.APP_BASE_URL}/reset-password?token=<plaintext>` link via `core/mailer.send_password_reset_email()`. **Silent on unknown email / unverified / Google accounts** (returns `None`; the route returns the same generic response — enumeration resistance, see §2.2).
  - `consume_reset(token: str, new_password: str) -> dict` — returns `{"status": "ok" | "invalid" | "expired" | "used" | "weak_password", "user_id": int|None}`. Re-hashes the supplied token, looks it up, refuses if `used = 1` or `time.time() > expires_at`, refuses if `password_meets_policy(new_password)` is false. On success: marks `used = 1` (single-use), bcrypt-hashes the new password, runs a parameterized `UPDATE users SET password = ? WHERE id = ?`. **No session is written** — the user must log in with the new password.
  - `lookup_status(token: str) -> dict` — pure lookup helper for the GET handler; returns one of `{"status": "ok"}` / `{"status": "expired"}` / `{"status": "used"}` / `{"status": "invalid"}`. Does **not** mutate state.
  - `is_expired_or_used(row) -> bool` — small pure helper.
- **New `core/mailer.send_password_reset_email(to_email, username, reset_url)`** — sibling of `send_verification_email` / `send_otp_email`; same fail-safe contract (returns `False`, never raises). Subject: "Reset your password — Security Vulnerability Lab". `html.escape(username, quote=True)` on the username; `html.escape(reset_url, quote=True)` on the URL. **The raw token is never logged** (VULN-3).
- **Four new routes in `backend/app/api/routes/auth.py`** (thin handlers, delegate to the service):
  - `GET /forgot-password` — renders `forgot_password.html` with the `csrf_token` spliced. No session required.
  - `POST /forgot-password` — single `Form` param `email`. Calls `password_reset_service.start_reset(email)` and **always** returns `200 {"success": true, "message": "If that email matches an account, a reset link has been sent to it."}` regardless of whether the email exists, is empty, belongs to an unverified local account, or belongs to a Google account. **No difference in response body, status code, or timing based on whether the email matched.**
  - `GET /reset-password?token=…` — calls `password_reset_service.lookup_status(token)`, renders `reset_password.html` with the `csrf_token` spliced and a `{{status}}` flag controlling whether the password form is shown. The form's `action` attribute is the literal `{{form_action}}` placeholder, which the server fills **exclusively from `config.APP_BASE_URL`** — never from `request.url.scheme`, `request.url.netloc`, `request.headers["host"]`, or any other client-supplied value. **The raw token is never reflected as markup** (VULN-3); it is `html.escape(..., quote=True)`-d on splice, and it is dropped from the page once the form is rendered.
  - `POST /reset-password` — `Form` params `token`, `password`, `confirm_password`. Calls `password_reset_service.consume_reset(token, password)`. Returns JSON for every outcome so a `fetch()`-driven UI can render inline feedback. On success: `200 {"success": true, "message": "Password updated. Please log in with your new password."}` and a 302 to `/login` (the user is NOT logged in).
- **Two new templates in `frontend/templates/`**:
  - `forgot_password.html` — single `email` field, "Send reset link" button, hidden `csrf_token`, the generic "if that email matches…" success message after submit. Loads **no** third-party script, stylesheet, image, font, or any other cross-origin asset. The only `<link>` / `<script>` references are first-party (the project's own `/static/css/styles.css` and a small inline `<script>` for client-side confirm-password validation).
  - `reset_password.html` — `password` + `confirm_password` fields, hidden `csrf_token`, the `{{status}}` flag controls whether the form renders. The form's `action="{{form_action}}"` is filled by the server with a string derived **exclusively from `config.APP_BASE_URL`** (e.g. `http://localhost:3001/reset-password`). The page loads **no** third-party script, stylesheet, image, font, analytics pixel, or any other cross-origin asset. The only `<link>` / `<script>` references are first-party. **No `Referer` header from this page can carry the token-bearing URL to an external origin.**
- **Reset-page hardening (host-header-trust and Referer-leakage vectors are eliminated at the spec level):**
  - **URLs are server-side-only.** Both the emailed link and the reset form's `action` are built from `f"{config.APP_BASE_URL}/reset-password?token={...}"` (or, for the form action, the same prefix without the token). **`request.url.scheme`, `request.url.netloc`, `request.headers["host"]`, the `Host` header, and the `X-Forwarded-Host` header are NEVER used to construct a URL the user is asked to click or submit to.** This closes the Host Header Injection vector at the spec level — there is no way for an attacker to coerce a victim into POSTing the reset form to a different origin by manipulating headers, because the action URL is static and server-controlled.
  - **No third-party assets.** The reset page's `<head>` and `<body>` contain only first-party resources: the project's `/static/css/styles.css`, the inline JS for confirm-password validation, and form fields. **No `<script src="https://…">`, no `<link href="https://…">`, no `<img src="https://…">`, no `@font-face` URL, no analytics pixel.** A `Referer` header on the form POST (or on any other request originating from the page) is therefore sent only to the same origin (the app's own host), which is the production-grade posture.
  - **The form's `action` does not embed the token in the URL.** The token is POSTed in the urlencoded body (alongside `csrf_token` and `password`), not as a query parameter. The `Referer` header on the form POST is the *page's* URL (which *does* carry the token in the query string of the GET that rendered the form), but since the form POSTs to the same first-party origin, that `Referer` stays inside the application's own trust boundary.
- **`init_db()` migration** — additive, idempotent. A new block in `db/session.py`:
  ```python
  conn.execute("""
      CREATE TABLE IF NOT EXISTS password_resets (
          id          INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id     INTEGER NOT NULL,
          token_hash  TEXT UNIQUE NOT NULL,
          expires_at  REAL NOT NULL,
          used        INTEGER NOT NULL DEFAULT 0
      )
  """)
  ```
  No `ALTER TABLE` is needed (it's a brand-new table); no `UPDATE` is needed (no rows exist on a fresh DB). The same `_PRAGMA table_info` check pattern is used to be consistent with the prior features.
- **One new constant in `core/config.py`** (env-tunable, non-secret; no `is_*_configured()` gate of its own — the mailer reuses the existing `is_email_configured()`):
  - `PASSWORD_RESET_TTL_SECONDS = 900` (15 minutes) — read from env with `PASSWORD_RESET_TTL_SECONDS` (default `"900"`). The TTL is fixed at 15 minutes by spec, but env-tunable for local demos (`PASSWORD_RESET_TTL_SECONDS=30` to demo expiry in seconds). Hard-coded as 900 by the implementation; the env var is a deliberate non-secret knob that mirrors the account-lockout / OTP / TOTP tunables.
  - Update the module docstring's feature list to mention the new constant.
- **`.env.example`, `README.md`, `CLAUDE.md`** — add the new feature; document the hardening posture (Host Header / Referer are *closed*, not preserved as lab vectors); note the **No new dependency** posture.

### 2.2 Out of Scope (Intentionally)

- **No password reset for Google (OAuth) accounts.** The `users` table has rows with `auth_provider = 'google'` and `password IS NULL`. The reset flow's `start_reset` SELECTs by `email` and refuses (silently — enumeration resistance) when the matched row is a Google account. This is the right product behavior: Google users reset through Google, not by setting a local password. (An alternative — linking a local password to a Google account — is out of scope.)
- **No reset for the `is_verified = 0` account.** Same posture as Login: an unverified local user is told to verify first. The reset flow's `start_reset` refuses (silently) when the matched row's `is_verified = 0`. The user is told to use the verification-email flow.
- **No reset when SMTP is unconfigured.** `POST /forgot-password` and `GET /forgot-password` both gate on `config.is_email_configured()` (mirroring the `email_not_configured.html` degrade used by `GET /signup`); when SMTP is off, the page is not rendered and the POST returns the *same* generic response (so the unconfigured path is not an enumeration oracle).
- **No "I forgot my username" recovery.** The reset link is keyed on the user's *email*; the user must remember the address they signed up with.
- **No session-gated password reset.** The reset link IS the capability (mirrors the OAuth GET callback and `/verify`); the POST is gated only by CSRF + rate-limit middleware. This is the standard password-reset pattern.
- **No rate-limit on the *token lookup* itself.** Lookup throttling is a known future hardening (would compose with the existing per-IP rate limit). Not in scope for this slice.
- **No notification email on success.** The user already received the reset email; sending a second "your password was changed" email is nice-to-have and is not in scope.
- **No "expired/used/invalid" reveal beyond a fixed page.** All three negative outcomes render a fixed, server-controlled, `html.escape(..., quote=True)`-d message; no `error_code` is reflected that would help an attacker enumerate.
- **No lab vectors — the feature is fully hardened.** Unlike the QR-Code-Login spec (v1.0.8), which intentionally keeps an owner-binding exploit demonstrable, this spec is hardened end to end. There is no preserved Host Header Injection vector, no preserved Referer Leakage vector, no preserved XSS sink, no preserved SQL-injection string-concat path. This is a deliberate, spec-level choice for this feature (see §2.3).

### 2.3 Explicit Hardening Note — No New Vulnerability Introduced

**This feature is fully hardened end to end.** Every other spec in this lab (VULN-1 … VULN-8 fixes, v1.0.2 profile, v1.0.3 Google OAuth, v1.0.4 email verification, v1.0.5 account lockout, v1.0.6 email OTP, v1.0.7 TOTP, v1.0.8 QR code login, v2.0.0 CAPTCHA) closes one tracked OWASP vulnerability while deliberately leaving other vectors demonstrable for study. This spec is different: it introduces **no new vulnerability of any kind**.

Concretely, the vectors that are **closed by construction** (not "preserved as lab vectors"):

- **Host Header Injection (CWE-644):** the emailed link and the form's `action` are both built from `config.APP_BASE_URL`. `request.url`, `request.url.scheme`, `request.url.netloc`, `request.headers["host"]`, `request.headers["x-forwarded-host"]`, and any other client-supplied value are NEVER used to construct a URL. Even if a student sets `Host: evil.example` on the request, the server-rendered `action` attribute is unchanged. A form-submit-by-victim to `evil.example` is therefore *not* demonstrable. The README and the inline code comments call this out as a **deliberate, spec-level closure** (contrast with the QR-code-login spec, which keeps the `qr_login_token` in the URL by design).
- **Referer Leakage (CWE-598):** the reset page contains no third-party script, stylesheet, image, font, analytics pixel, or any other cross-origin asset. A `Referer` header on the form POST (or on any other request originating from the page) is therefore sent **only to the same origin** — the application's own host, which is the trust boundary. There is no external host to leak the token-bearing URL to. (Contrast with a hypothetical v2.0.x enhancement that adds Google Analytics: that would be a deliberate, separately-specified addition with `referrerpolicy="no-referrer"` enforced — not in scope here.)
- **Cross-origin form-action vector:** the form's `action` is the application's own `/reset-password` endpoint on the application's own origin. Even though the `<form>` element has no `action` attribute, the browser uses the form's document URL by default — and both the document URL and the form action are derived from `config.APP_BASE_URL` (set to the same value for both the GET and the POST). There is no opportunity for an attacker to coerce a cross-origin submission by manipulating the rendered HTML.
- **All eight closed vulnerabilities stay closed** (see §2.4 for the per-vulnerability note).

### 2.4 Explicit Preservation Note — All Eight Closed Vulnerabilities Stay Closed

- **VULN-1 (SQL Injection):** the new `password_resets` table is touched only with parameterized `?` placeholders (SELECT by email, SELECT by token_hash, UPDATE by id, INSERT by user_id/token_hash/expires_at). `auth_service.login()` and `auth_service.change_password()` are not modified. **No string concatenation, no f-string interpolation into SQL, no `LIKE` patterns built from user input** — every new query is parameterized.
- **VULN-2 (Stored XSS):** the reset page's `{{status}}` placeholder is `html.escape(..., quote=True)`-d before substitution. The reset page's `{{form_action}}` is the literal string `f"{config.APP_BASE_URL}/reset-password"` — server-controlled, no user input, but `html.escape(..., quote=True)`-d on splice for defense in depth (mirrors the dashboard username splice). The new `core/mailer.send_password_reset_email` escapes the username and the URL. The "generic response" JSON is fixed. The "ok / expired / used / invalid" outcome strings are author-controlled; they are also `html.escape(..., quote=True)`-d before splicing.
- **VULN-3 (Reflected XSS):** the plaintext token is **never** reflected into any page, log, or URL (other than the email's link, which is the trusted channel). The reset form's `action` URL does **not** include the token (it is POSTed in the body, alongside `csrf_token` and `password`). The "ok / expired / used / invalid" outcome pages render fixed, author-controlled text. The `{{token}}` placeholder, if it is ever spliced for debugging, is `html.escape(..., quote=True)`-d.
- **VULN-4 (Session Hijacking):** `main.py` is not modified. The reset flow writes **no session keys** on success; the user must log in with the new password, which is the cleanest possible posture. The reset email URL is built from `config.APP_BASE_URL` (env-tunable, not hardcoded) — *not* from any request header.
- **VULN-5 (Weak Password Storage):** the new password is checked against `auth_service.password_meets_policy()` (the same five-criteria gate used by the v1.0.2 change-password flow) — length ≥ 8, lower, upper, digit, special. It is then bcrypt-hashed via `core/security.hash_password()` (cost 12) before it touches the DB. **The plaintext never persists.** Legacy MD5 rows in `users.password` (if any) are replaced by the new bcrypt hash on first successful reset.
- **VULN-6 (Exposed Database):** no `/download/db` route exists; none is added. The `password_resets` table is not exposed.
- **VULN-7 (No Rate Limiting):** `RateLimitMiddleware` stays registered and unchanged; **both** new POSTs (`/forgot-password`, `/reset-password`) sit behind it. The reset flow is also defended by the **generic response** on `/forgot-password` (so a burst of unknown-email submits doesn't reveal which addresses exist) and the **single-use, 15-minute token** (so a leaked link ages out fast).
- **VULN-8 (CSRF):** `CSRFMiddleware` stays registered and unchanged; **both** new POSTs sit behind it. `forgot_password.html` and `reset_password.html` carry a hidden `csrf_token` (issued by `get_or_create_csrf_token` on GET); the `URLSearchParams(new FormData(form))` submit sends it as a urlencoded form field, matching the existing pattern. **Fail-closed** (a missing/invalid token returns 403 from middleware before the handler runs).

### 2.5 Explicit Non-Goals / Minimal Touch

- This feature does **not** modify `auth_service.login()` / `signup()` / `change_password()`, `main.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/oauth.py`, `core/captcha.py`, `core/qr_login.py`, or any existing template except by adding a "Forgot password?" link on `login.html` (purely additive — a single `<a href="/forgot-password">` line under the existing "Don't have an account? Sign up" link; no JS, no `csrf_token`, just a GET navigation).
- The new service depends on the existing `core/mailer.py` — no SMTP code is duplicated.
- No dependency manifest change. `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are unchanged.

---

## 3. Affected Files

| Path | Type | Change |
|------|------|--------|
| `backend/app/db/session.py` | Schema | Add `CREATE TABLE IF NOT EXISTS password_resets (...)` to `init_db()` (additive; same `CREATE TABLE IF NOT EXISTS` pattern as the `users` table). |
| `backend/app/services/password_reset_service.py` | Service | **New file.** `start_reset`, `consume_reset`, `lookup_status`, `is_expired_or_used`. Depends on `core.security.hash_password`, `auth_service.password_meets_policy`, `core.mailer.send_password_reset_email`, `db.session.get_db`, `core.config.APP_BASE_URL` and `core.config.PASSWORD_RESET_TTL_SECONDS`. |
| `backend/app/api/routes/auth.py` | Routes | Add `forgot_password_page` (GET), `forgot_password_post` (POST), `reset_password_page` (GET, path with `?token=…`), `reset_password_post` (POST). All four are thin handlers that delegate to the service. The `form_action` is built **exclusively** from `config.APP_BASE_URL`: `form_action = f"{config.APP_BASE_URL}/reset-password"`. **`request.url`, `request.url.scheme`, `request.url.netloc`, and `request.headers` are not read for URL construction.** |
| `backend/app/core/mailer.py` | Mailer | Add `send_password_reset_email(to_email, username, reset_url) -> bool`. Reuses `_deliver` and `_send_via_sendgrid`. Fail-safe (returns `False`, never raises). |
| `backend/app/core/config.py` | Config | Add `PASSWORD_RESET_TTL_SECONDS = int(os.environ.get("PASSWORD_RESET_TTL_SECONDS", "900"))`. Update the module docstring's feature list. **No other setting is added** — the mailer reuses the existing `is_email_configured()` and the URLs reuse the existing `APP_BASE_URL`. |
| `frontend/templates/forgot_password.html` | Template | **New file.** Single `email` field, hidden `csrf_token`, "Send reset link" submit. Renders the generic success message via `{{message}}` after submit. **No third-party assets** — only the project's own `/static/css/styles.css` and a small inline `<script>` for client-side feedback. |
| `frontend/templates/reset_password.html` | Template | **New file.** `password` + `confirm_password` fields, hidden `csrf_token`, conditional render on `{{status}}`. The form's `action` is `{{form_action}}`, which the server fills with `f"{config.APP_BASE_URL}/reset-password"`. **No third-party assets** — only the project's own `/static/css/styles.css` and a small inline `<script>` for client-side confirm-password validation. No analytics, no CDN, no remote font, no remote image. |
| `frontend/templates/login.html` | Template | **Additive.** Add a "Forgot password?" link under the existing "Don't have an account? Sign up" link, pointing to `/forgot-password`. No other change. |
| `frontend/static/css/styles.css` | CSS | Append a small `.reset-form`, `.reset-message`, `.reset-status` block (styling only; matches the existing indigo theme). No existing rule is modified. |
| `.env.example` | Docs | Add a `PASSWORD_RESET_TTL_SECONDS=900` line in a "Password Reset (optional, for local demos)" block, with a short note that the default is 15 minutes. |
| `README.md` | Docs | Add a v2.1.0 release row to the "Release History"; add a "Forgot Password — Setup" subsection (notes the SendGrid requirement, the 15-minute TTL, the five-criteria strength policy, the generic-response enumeration resistance, and the **fully hardened** posture — no Host Header, no Referer Leakage). |
| `CLAUDE.md` | Docs | Add a "Forgot Password (v2.1.0)" bullet to the integration section, an Important-Rules entry, and a Specification-Hierarchy entry. |

**No other file is touched.** In particular, `backend/app/main.py`, `backend/app/services/auth_service.py`, `backend/app/services/verification_service.py`, `backend/app/services/otp_service.py`, `backend/app/services/totp_service.py`, `backend/app/services/lockout_service.py`, `backend/app/services/oauth_service.py`, `backend/app/core/security.py`, `backend/app/core/csrf.py`, `backend/app/core/rate_limit.py`, `backend/app/core/oauth.py`, `backend/app/core/captcha.py`, `backend/app/core/qr_login.py`, every existing template other than `login.html`, and the dependency manifests (`pyproject.toml`, `backend/pyproject.toml`, `uv.lock`) remain unchanged.

---

## 4. Functional Requirements (FR)

| ID | Requirement |
|----|-------------|
| FR-01 | `GET /forgot-password` returns `200` with `forgot_password.html` containing a single `email` input and a hidden `csrf_token`, **or** (when `config.is_email_configured()` is `False`) renders `email_not_configured.html`. |
| FR-02 | `POST /forgot-password` accepts `email` (string, may be empty). It calls `password_reset_service.start_reset(email)` and **always** responds `200 {"success": true, "message": "If that email matches an account, a reset link has been sent to it."}` — whether the email matched a row, was empty, did not exist, belonged to an unverified local account, or belonged to a Google account. **No difference in response body, status code, or timing based on whether the email is registered.** |
| FR-03 | `start_reset(email)` mints a token with `secrets.token_urlsafe(32)`, computes `hashlib.sha256(token.encode("utf-8")).hexdigest()` for the `token_hash` column, sets `expires_at = time.time() + config.PASSWORD_RESET_TTL_SECONDS` (default 900), and writes the row with a parameterized `INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)` after a parameterized `SELECT id, username, is_verified, auth_provider FROM users WHERE email = ?`. |
| FR-04 | `start_reset` refuses to issue a token (silent no-op) when the matched row has `is_verified = 0` *or* `auth_provider = 'google'`. Both branches still produce the same generic response on the route. |
| FR-05 | `start_reset` builds the emailed link as `f"{config.APP_BASE_URL}/reset-password?token={token}"` — **always from `config.APP_BASE_URL`, never from `request.url`, `request.url.scheme`, `request.url.netloc`, `request.headers['host']`, `request.headers['x-forwarded-host']`, or any other client-supplied value** — and calls `core/mailer.send_password_reset_email(email, username, reset_url)`. |
| FR-06 | `GET /reset-password?token=<plaintext>` calls `password_reset_service.lookup_status(token)`, which: re-hashes the token with SHA-256, runs a parameterized `SELECT user_id, expires_at, used FROM password_resets WHERE token_hash = ?`, and returns one of `{"status": "ok"}`, `{"status": "expired"}`, `{"status": "used"}`, `{"status": "invalid"}`. The handler renders `reset_password.html` with the `csrf_token` spliced, the `{{status}}` flag set, and the `{{form_action}}` set to `f"{config.APP_BASE_URL}/reset-password"` — **derived exclusively from `config.APP_BASE_URL`, not from `request.url` or any request header**. **The raw token is never spliced as markup** (VULN-3); if shown for debugging, it is `html.escape(..., quote=True)`-d. |
| FR-07 | `POST /reset-password` accepts `token` (string), `password` (string), `confirm_password` (string). It calls `password_reset_service.consume_reset(token, password)`. |
| FR-08 | `consume_reset` re-hashes the supplied token with SHA-256 and runs a parameterized `SELECT id, user_id, expires_at, used FROM password_resets WHERE token_hash = ?`. It returns `{"status": "invalid"}` for a missing/blank token or a row that does not exist. It returns `{"status": "used"}` when `used = 1`. It returns `{"status": "expired"}` when `time.time() > expires_at` (strict `>`, not `>=`). It returns `{"status": "weak_password"}` when `auth_service.password_meets_policy(password)` is `False`. Client-side `password != confirm_password` is caught by the page's inline JS (mirrors the v0 signup form's posture); the `confirm_password` field is `Form`-parsed by the route but **not** passed to the service. |
| FR-09 | On `consume_reset` success: parameterized `UPDATE password_resets SET used = 1 WHERE id = ?`, parameterized `UPDATE users SET password = ? WHERE id = ?` (the new password is `core.security.hash_password(password)` first — bcrypt, cost 12). The response is `200 {"success": true, "message": "Password updated. Please log in with your new password."}`. **No session is written**; the user must log in. |
| FR-10 | All four new routes sit behind the existing `CSRFMiddleware` and `RateLimitMiddleware` (already registered in `main.py`; no middleware change). The hidden `csrf_token` field is the first child of each `<form>` in `forgot_password.html` and `reset_password.html`, mirroring every other form in the project. |
| FR-11 | The reset link is **single-use**: a second `POST /reset-password` with the same plaintext token returns `{"status": "used"}` and writes no password. |
| FR-12 | The reset link **expires strictly after 15 minutes** (`expires_at = time.time() + config.PASSWORD_RESET_TTL_SECONDS`; `time.time() > expires_at` is the check, strict `>`). Tokens issued at `T=0` are dead by `T=900.0`. The TTL is env-tunable for local demos (`PASSWORD_RESET_TTL_SECONDS=30` to demo expiry in seconds) but defaults to 900. |
| FR-13 | `core/mailer.send_password_reset_email` is fail-safe: returns `False` (never raises) when `config.is_email_configured()` is `False` or when SendGrid errors. **The route does not depend on the return value** (the generic response is identical with or without a successful send). |
| FR-14 | The plaintext token is **never** persisted, **never** logged, and **never** reflected into any response body, URL (other than the email's link), template, or log. `logger.info("Password reset email sent to %s", to_email)` is the only log line on the mailer path; it does not include the token or its hash. |
| FR-15 | The new `password_resets` table is created by `init_db()` in `db/session.py` via `CREATE TABLE IF NOT EXISTS password_resets (...)`. The migration is idempotent: a fresh DB gets the table from `CREATE TABLE`; a pre-existing DB finds the table already present. No `ALTER TABLE` is needed (this is a brand-new table, not a column on an existing one). No `UPDATE` is needed (no rows exist on a fresh DB; no existing rows are migrated). |
| FR-16 | **The reset form's `action="{{form_action}}"` is filled with `f"{config.APP_BASE_URL}/reset-password"`** — derived exclusively from `config.APP_BASE_URL`. **`request.url.scheme`, `request.url.netloc`, `request.headers["host"]`, `request.headers["x-forwarded-host"]`, and any other client-supplied value are NEVER used to construct this URL.** Even if a student sets `Host: evil.example` on the GET request, the server-rendered `action` attribute is unchanged. This is the **spec-level closure of the Host Header Injection vector** (see §2.3). |
| FR-17 | **The reset page loads no third-party script, stylesheet, image, font, analytics pixel, or any other cross-origin asset.** The page's `<head>` and `<body>` reference only first-party resources: the project's own `/static/css/styles.css` and a small inline `<script>` for client-side confirm-password validation. **No `Referer` header from this page can carry the token-bearing URL to an external origin.** This is the **spec-level closure of the Referer Leakage vector** (see §2.3). |
| FR-18 | `start_reset` returns `None` silently for an unknown email; the route's generic response is identical (FR-02). The timing of the response is dominated by the single SELECT in `start_reset` (which runs the same query regardless of whether the email matched) and the mailer call (which runs on every path); there is no per-match branch that would surface a timing oracle. |
| FR-19 | `consume_reset` is idempotent in the sense that a second call on a used token returns `{"status": "used"}` and does **not** revert the `used = 1` flag. (Once consumed, the row is dead — the schema makes this structural.) |
| FR-20 | The new `login.html` "Forgot password?" link is a plain `<a href="/forgot-password">`; no JS, no `csrf_token` (it's a GET navigation). |
| FR-21 | **Every new SQL statement is parameterized.** The `INSERT INTO password_resets`, the `SELECT … WHERE email = ?`, the `SELECT … WHERE token_hash = ?`, the `UPDATE password_resets SET used = 1 WHERE id = ?`, and the `UPDATE users SET password = ? WHERE id = ?` all use `?` placeholders and pass values as a separate argument list. **No string concatenation, no f-string interpolation, no `LIKE` patterns built from user input.** |
| FR-22 | `auth_service.login()`, `auth_service.signup()`, `auth_service.change_password()`, `main.py`, `core/security.py`, `core/csrf.py`, and `core/rate_limit.py` are **not** modified by this feature. The reset flow reuses `auth_service.password_meets_policy()` and `core.security.hash_password()` as black-box helpers. |

---

## 5. Non-Functional Requirements (NFR)

| ID | Requirement |
|----|-------------|
| NFR-01 | **Security: VULN-1 closed.** Every SQL statement in `password_reset_service.py` and `db/session.py` uses parameterized `?` placeholders. No string concatenation, no f-string interpolation into SQL, no `LIKE` patterns built from user input. |
| NFR-02 | **Security: VULN-2 closed.** All `html.escape(..., quote=True)` discipline is applied to every value spliced into the new templates: `{{csrf_token}}`, `{{status}}`, `{{form_action}}` (the URL is `config.APP_BASE_URL`-derived, no user-controlled bytes, but escaped on splice for defense in depth), `{{token}}` (when shown for debugging — escaped), and the `{{message}}` text after submit. The mailer escapes the username and the URL. |
| NFR-03 | **Security: VULN-3 closed.** The plaintext token is never reflected into any page, log, or URL other than the email's link. The reset form's `action` URL does **not** include the token (it is POSTed in the body). The "ok / expired / used / invalid" outcome pages render fixed, author-controlled text. |
| NFR-04 | **Security: VULN-4 posture preserved.** `main.py` is not modified. The reset email URL and the form's `action` are both built from `config.APP_BASE_URL` (env-tunable, never hardcoded) — never from any request header. |
| NFR-05 | **Security: VULN-5 closed.** The new password is enforced by `auth_service.password_meets_policy()` (length ≥ 8 + lower + upper + digit + special) and is bcrypt-hashed by `core/security.hash_password()` (cost 12) before it touches the DB. **The plaintext never persists.** Legacy MD5 rows in `users.password` (if any) are replaced by the new bcrypt hash on first successful reset. |
| NFR-06 | **Security: VULN-6 posture preserved.** No `/download/db` route is added. The `password_resets` table is not exposed. |
| NFR-07 | **Security: VULN-7 posture preserved.** `RateLimitMiddleware` is unchanged; both new POSTs sit behind it. The default 5 POSTs / 60 s per IP is sufficient to deter a single-IP flood; the *generic response* on `POST /forgot-password` makes a multi-IP credential-enumeration attack a non-starter (no oracle). |
| NFR-08 | **Security: VULN-8 posture preserved.** `CSRFMiddleware` is unchanged; both new POSTs sit behind it. Both new forms carry the hidden `csrf_token` and submit urlencoded via `URLSearchParams(new FormData(form))`, matching every other form in the project. The middleware is fail-closed (a missing/invalid token returns 403 before the handler runs). |
| NFR-09 | **Hardening: Host Header Injection (CWE-644) closed by spec.** The emailed link and the form's `action` are both built from `config.APP_BASE_URL`; `request.url`, `request.url.scheme`, `request.url.netloc`, `request.headers["host"]`, `request.headers["x-forwarded-host"]`, and any other client-supplied value are NEVER used to construct a URL the user is asked to click or submit to. A `Host: evil.example` header on the request does not change the rendered `action` attribute. The README and inline code comments call this out as a **deliberate, spec-level closure** (contrast with v1.0.8 QR code login, which keeps the token in the URL by design). |
| NFR-10 | **Hardening: Referer Leakage (CWE-598) closed by spec.** The reset page contains no third-party script, stylesheet, image, font, analytics pixel, or any other cross-origin asset. A `Referer` header on the form POST (or on any other request originating from the page) is sent **only to the same origin** — the application's own host, which is the trust boundary. There is no external host to leak the token-bearing URL to. The README and inline code comments call this out as a **deliberate, spec-level closure**. |
| NFR-11 | **No new dependency.** The mailer reuses the existing `core/mailer.py` (stdlib `urllib` / SendGrid). Token generation reuses `secrets.token_urlsafe` (stdlib). Hashing reuses `hashlib.sha256` (stdlib). `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are unchanged. |
| NFR-12 | **No new session field.** The reset flow writes **no** session keys. The user must log in with the new password (mirrors the `change_password` flow's posture — that flow keeps the session, but only because the user was already logged in; a reset has no session to keep). |
| NFR-13 | **Schema additive / idempotent.** `init_db()` adds the `password_resets` table with `CREATE TABLE IF NOT EXISTS`; a fresh DB and a pre-existing DB both end up with the same schema. No `UPDATE` is run; no row in `users` is ever touched by the migration. |
| NFR-14 | **Enumeration resistance.** `POST /forgot-password` returns the same response for `email = ""`, `email = "no-such@example.com"`, `email = "verified-local@example.com"`, `email = "unverified-local@example.com"`, and `email = "google-only@example.com"`. The route's response time is dominated by the single SELECT in `start_reset` (which runs the same query regardless of match) and the mailer call (which runs on every path); there is no per-match branch that would surface a timing oracle. |
| NFR-15 | **Single-use, time-boxed tokens.** A successful reset flips `used = 1`; a second submission with the same plaintext returns `{"status": "used"}`. The 15-minute window is **strict** (`time.time() > expires_at`, not `>=`). |
| NFR-16 | **Fail-safe mailer.** `core/mailer.send_password_reset_email` returns `False` (never raises) when SendGrid is unconfigured or the API call errors. The route ignores the return value; the generic response is identical. |
| NFR-17 | **Stdlib-only service code.** `password_reset_service.py` uses only `hashlib`, `secrets`, `time`, `logging`, and the project's own modules — no third-party imports. |
| NFR-18 | **No email enumeration via SMTP errors.** When SendGrid is unconfigured, `POST /forgot-password` still returns the generic `200` (the mailer returns `False` silently). When SendGrid is configured but the address is unknown, `start_reset` does not even call the mailer (no row matched). Both paths return the same JSON. |
| NFR-19 | **Audit log surface.** `logger.info("Password reset email sent to %s", to_email)` is the only log line on the mailer path. `logger.info("Password reset consumed for user_id=%s", user_id)` is the only log line on the consume path. **Neither log line includes the token, its hash, the password, the new password, the form `action` URL, or the request IP** (the IP is already handled by `RateLimitMiddleware`'s own log). |
| NFR-20 | **Theme compatibility.** The new templates' CSS uses the existing CSS custom properties (`--indigo-*`, `--surface-*`), so the light/dark toggle works without a JS change. |
| NFR-21 | **Accessibility.** Both new forms have explicit `<label for="…">` pairings, the submit button has a clear `type="submit"`, the error text is in a `<div role="alert">`, and the `forgot_password.html` success message uses `<div role="status" aria-live="polite">` so screen readers announce it. |
| NFR-22 | **No third-party assets on the reset page — verified by code review.** The reset page's `<head>` and `<body>` contain no `<script src="https://…">`, no `<link href="https://…">`, no `<img src="https://…">`, no `@font-face` URL, and no analytics pixel. The only `<link>` is `href="/static/css/styles.css"` (first-party). The only `<script>` is inline (for confirm-password validation) or absent. This is a hard requirement of the spec, not a style preference (see §2.3 / NFR-10 / FR-17). |

---

## 6. Success Paths (SP)

### SP-01 — User requests a reset link (unknown email)

1. User navigates to `/forgot-password`.
2. Server renders `forgot_password.html` with the `csrf_token` spliced (200 OK).
3. User submits `email = "no-such@example.com"`.
4. CSRFMiddleware validates the token (passes).
5. RateLimitMiddleware admits the request (under the threshold).
6. Route calls `password_reset_service.start_reset("no-such@example.com")`.
7. `start_reset` runs a parameterized `SELECT id, username, is_verified, auth_provider FROM users WHERE email = ?` — no row.
8. `start_reset` returns `None` silently.
9. Route returns `200 {"success": true, "message": "If that email matches an account, a reset link has been sent to it."}`.
10. User sees the same success message they would see for a known email (enumeration resistance).

### SP-02 — User requests a reset link (known verified local email)

1. User navigates to `/forgot-password`.
2. Server renders `forgot_password.html` (200 OK).
3. User submits `email = "alice@example.com"`.
4. CSRFMiddleware validates, RateLimitMiddleware admits.
5. Route calls `start_reset("alice@example.com")`.
6. `start_reset` runs a parameterized `SELECT … WHERE email = ?` — row found, `is_verified = 1`, `auth_provider = 'local'`.
7. `start_reset` mints `token = secrets.token_urlsafe(32)`, computes `token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()`, `expires_at = time.time() + config.PASSWORD_RESET_TTL_SECONDS` (default 900).
8. `start_reset` runs a parameterized `INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)`.
9. `start_reset` builds `reset_url = f"{config.APP_BASE_URL}/reset-password?token={token}"` — **derived exclusively from `config.APP_BASE_URL`**.
10. `start_reset` calls `core/mailer.send_password_reset_email("alice@example.com", "alice", reset_url)`.
11. Mailer posts to SendGrid; on 2xx returns `True`. **The plaintext token is in the email only.**
12. Route returns `200 {"success": true, "message": "If that email matches an account, a reset link has been sent to it."}`.
13. Alice opens her inbox, clicks the link → browser GETs `http://localhost:3001/reset-password?token=<plaintext>`.

### SP-03 — User opens the reset link (valid, unused, unexpired)

1. Alice's browser sends `GET /reset-password?token=<plaintext>` (link from email).
2. RateLimitMiddleware admits (it's a GET, so the per-IP POST limiter ignores it).
3. Route calls `password_reset_service.lookup_status(token)`.
4. `lookup_status` re-hashes the token with SHA-256, runs a parameterized `SELECT user_id, expires_at, used FROM password_resets WHERE token_hash = ?`.
5. Row found: `used = 0`, `expires_at > time.time()`. Returns `{"status": "ok"}`.
6. Route renders `reset_password.html` with `{{status}} = "ok"`, `{{csrf_token}}` set, and `{{form_action}}` set to `f"{config.APP_BASE_URL}/reset-password"` — **derived exclusively from `config.APP_BASE_URL`, not from `request.url` or any request header**. Even if the GET request had `Host: evil.example`, the `{{form_action}}` is unchanged.
7. The HTML references **only first-party assets** (the project's own `/static/css/styles.css` and an inline `<script>` for confirm-password validation). **No third-party script, stylesheet, image, font, or analytics pixel is loaded.** A `Referer` header on the form POST (or on any other request originating from the page) is sent only to the same origin.
8. Alice sees the form: New password, Confirm password, Reset Password button.

### SP-04 — User submits a valid new password

1. Alice types `NewPass!2026` and `NewPass!2026` (matching).
2. JS reads `URLSearchParams(new FormData(form))` and POSTs urlencoded to the form's `action` — `f"{config.APP_BASE_URL}/reset-password"` (i.e. `http://localhost:3001/reset-password` in local dev). The token is in the POST **body**, not the URL.
3. CSRFMiddleware validates, RateLimitMiddleware admits.
4. Route calls `password_reset_service.consume_reset(token, "NewPass!2026")`.
5. `consume_reset` re-hashes the token, runs a parameterized `SELECT … WHERE token_hash = ?`. Row found, `used = 0`, not expired.
6. `consume_reset` calls `auth_service.password_meets_policy("NewPass!2026")` → `True`.
7. `consume_reset` runs a parameterized `UPDATE password_resets SET used = 1 WHERE id = ?` and a parameterized `UPDATE users SET password = ? WHERE id = ?` with the bcrypt hash of `NewPass!2026`.
8. `consume_reset` returns `{"status": "ok", "user_id": <int>}`.
9. Route returns `200 {"success": true, "message": "Password updated. Please log in with your new password."}`.
10. JS `window.location.href = "/login"`. Alice logs in with the new password.

### SP-05 — User submits the same link a second time

1. Alice (or an attacker) re-POSTs the same plaintext token to `/reset-password`.
2. `consume_reset` re-hashes, runs the SELECT. Row found, `used = 1`.
3. Returns `{"status": "used"}`.
4. Route renders `reset_password.html` with `{{status}} = "used"` — the form is **not** rendered; a fixed, escaped message "This reset link has already been used." is shown.

### SP-06 — User waits > 15 minutes and clicks the link

1. `lookup_status` (on GET) or `consume_reset` (on POST) finds the row but `time.time() > expires_at`.
2. Returns `{"status": "expired"}`.
3. Route renders `reset_password.html` with `{{status}} = "expired"` — a fixed message "This reset link has expired. Request a new one." with a link back to `/forgot-password`.

### SP-07 — User submits a weak new password

1. `consume_reset` validates `auth_service.password_meets_policy("short")` → `False`.
2. Returns `{"status": "weak_password"}`. **The `used` flag is NOT flipped** — the token is still usable with a stronger password.
3. Route returns `200 {"error": "Password must be at least 8 characters and include an uppercase letter, a lowercase letter, a digit, and a special character."}`.
4. JS shows the error inline (no page reload); Alice tries again with a stronger password.

### SP-08 — User submits mismatched confirm password

1. JS validation (`password.value !== confirm_password.value`) catches it client-side and shows the same red error used by the v0 signup page.
2. The form is **not** submitted.
3. The plaintext token is **not** consumed.

---

## 7. Edge Cases (EC)

| ID | Case | Expected Behavior |
|----|------|-------------------|
| EC-01 | `POST /forgot-password` with `email = ""` | `start_reset("")` runs a SELECT that returns no row; returns `None`; route returns the generic `200` response. |
| EC-02 | `POST /forgot-password` with an email belonging to an unverified local account (`is_verified = 0`) | `start_reset` returns `None` silently (no token issued, no email sent). The route's generic response is identical to the unknown-email case. **No signal that the account exists but is unverified.** |
| EC-03 | `POST /forgot-password` with an email belonging to a Google account (`auth_provider = 'google'`, `password IS NULL`) | `start_reset` returns `None` silently. The route's generic response is identical. **No signal that the account is Google-only.** |
| EC-04 | `GET /reset-password` with `?token=` (empty token) | `lookup_status("")` returns `{"status": "invalid"}`. Route renders `reset_password.html` with `{{status}} = "invalid"` and a fixed "Invalid reset link" message. |
| EC-05 | `GET /reset-password` with a bogus `?token=<garbage>` | `lookup_status` re-hashes, SELECT finds no row, returns `{"status": "invalid"}`. Same as EC-04. |
| EC-06 | `GET /reset-password` with a token whose row exists but `used = 1` | Returns `{"status": "used"}`. Renders the "already been used" message; the form is **not** shown. |
| EC-07 | `GET /reset-password` with a token whose row exists but `time.time() > expires_at` | Returns `{"status": "expired"}`. Renders the "expired" message with a link to `/forgot-password`. |
| EC-08 | `POST /reset-password` with `token = ""` or `password = ""` | `consume_reset` returns `{"status": "invalid"}` (empty token) or `{"status": "weak_password"}` (empty password fails `password_meets_policy`). The route returns the appropriate JSON. |
| EC-09 | `POST /reset-password` with mismatched `password` vs `confirm_password` | Caught client-side by the JS check (mirrors the v0 signup form's posture); the form is never submitted. The `confirm_password` field is `Form`-parsed by the route but **not** passed to the service. |
| EC-10 | A user requests two reset links in quick succession | The second `INSERT` writes a second `password_resets` row (different `token_hash`). The first link still works until consumed or 15 minutes elapse. There is **no** "invalidate prior tokens" behavior in this slice — a single user can have multiple valid reset links at once. (Documented as future hardening.) |
| EC-11 | The reset email is opened on a different device than the one requesting it | That's the *intended* use case — the link is the capability. The link works from any device with a browser. |
| EC-12 | The user requests a reset for an email they do not own | The attacker would receive the response "If that email matches…" but would **not** receive the email (only the registered owner would). They could not enumerate accounts from the response. |
| EC-13 | A user requests a reset for an email they do own but is mid-`POST /login` (locked out by v1.0.5) | `start_reset` is **not** gated by `lockout_service` (it does not check credentials). The reset link is delivered and consumed normally. After the reset, the user logs in with the new password; the new login goes through the unchanged `login()` and `reset()`s the lockout counter. |
| EC-14 | A user with Email-OTP 2FA enabled (v1.0.6) resets their password | After the reset, the new password triggers an OTP challenge at next login — 2FA is unchanged. |
| EC-15 | A user with TOTP enabled (v1.0.7) resets their password | Same as EC-14 — TOTP is unchanged. |
| EC-16 | The reset email is sent but SendGrid returns 5xx | `core/mailer.send_password_reset_email` returns `False`. The route ignores the return value and returns the generic `200`. The user does not know the send failed; they can request another link. The token row is still in the DB (it will expire in 15 minutes). |
| EC-17 | SendGrid is unconfigured (`SENDGRID_API_KEY` or `SENDGRID_FROM` empty) | `GET /forgot-password` renders `email_not_configured.html` (200 OK). `POST /forgot-password` does the same (defense in depth). The user sees the friendly "Email is not configured" page — no enumeration oracle. |
| EC-18 | The user opens the reset link in a browser whose `Host` header is set to `evil.example` | The form's `action` is **unchanged**: it is `f"{config.APP_BASE_URL}/reset-password"`, derived from the env var, not from `request.url` or any request header. The POST goes to the application's own origin, not to `evil.example`. **The Host Header Injection vector is closed at the spec level** (see §2.3 / NFR-09 / FR-16). |
| EC-19 | The reset page is loaded and the browser issues subresource requests | The page contains only first-party resources (`/static/css/styles.css`, inline `<script>`, form fields). All subresource requests go to the application's own origin. **No `Referer` header is sent to any external host.** The Referer Leakage vector is closed at the spec level (see §2.3 / NFR-10 / FR-17). |
| EC-20 | The user is mid-2FA-login (has `pending_2fa_user_id` in session) and requests a reset | The reset flow is unauthenticated; the `pending_2fa_*` keys in the session are not read or written by the reset service. The user could complete the reset on a separate tab and log in with the new password — the 2FA challenge still applies on the new login. |
| EC-21 | The `password_resets` table is missing on a pre-existing DB | The next `init_db()` call (on the next `main.py` boot) runs `CREATE TABLE IF NOT EXISTS password_resets (...)` and creates it. **No `ALTER TABLE` is needed** (it's a brand-new table). |
| EC-22 | The user resets their password, the row's `used` flips to 1, but the new password fails `password_meets_policy` | The `used` flag is only flipped **after** the strength check passes (SP-07 shows the strength check runs first). EC-22 is therefore unreachable in the current design — the strength check is the gate. |
| EC-23 | The `users.password` row contains a legacy MD5 hex digest (from the pre-v1.0.5 era) | The reset flow does not care — it runs `UPDATE users SET password = ? WHERE id = ?` with the new bcrypt hash. The next `auth_service.login()` runs `verify_password` against the new hash, which now succeeds. (Pre-existing MD5 rows are explicitly handled by the bcrypt fix; the reset is a clean override path.) |
| EC-24 | Two users with the same email request a reset at the same time | The `users.email` column is **not** `UNIQUE` in the current schema (it's `TEXT`, no `UNIQUE`). The `start_reset` SELECT would return the first matching row; only that row gets a token. The lab does not address duplicate-email handling in this slice. (Documented as a known limitation; production hardening would add a `UNIQUE` constraint on `email`.) |

---

## 8. Acceptance Criteria (AC)

| ID | Criterion |
|----|-----------|
| AC-01 | A new user can `POST /forgot-password` with their verified-local email and receive a reset link in their inbox within 10 seconds (SendGrid latency). |
| AC-02 | The reset link is a single-use, 256-bit `secrets.token_urlsafe(32)` token, scoped to expire at `time.time() + config.PASSWORD_RESET_TTL_SECONDS` seconds (default 900) from issuance. |
| AC-03 | The plaintext token is never stored in any column of any table, never logged, and never reflected into any response body, URL (other than the email's link), template, or log line. |
| AC-04 | `POST /forgot-password` returns the same `200 {"success": true, "message": "…"}` for `email = ""`, `email = "no-such@example.com"`, `email = "<verified-local>"`, `email = "<unverified-local>"`, and `email = "<google-only>"`. |
| AC-05 | `GET /reset-password?token=<plaintext>` (with a valid, unused, unexpired token) renders the password form; the form's `action` attribute is `f"{config.APP_BASE_URL}/reset-password"` (derived exclusively from `config.APP_BASE_URL`, **not** from `request.url` or any request header). |
| AC-06 | `POST /reset-password` with a valid token and a password that satisfies `password_meets_policy` updates `users.password` (bcrypt, cost 12) and sets `password_resets.used = 1` in the same request. The `users.password` column contains only the bcrypt hash; the plaintext is never persisted. |
| AC-07 | A second `POST /reset-password` with the same plaintext token returns `{"status": "used"}` and does not update `users.password`. |
| AC-08 | A `POST /reset-password` with a token whose `time.time() > expires_at` returns `{"status": "expired"}`. The `used` flag is **not** flipped (the token is dead, not consumed). |
| AC-09 | A `POST /reset-password` with a token whose row is missing returns `{"status": "invalid"}`. |
| AC-10 | A `POST /reset-password` with a password that fails `password_meets_policy` returns `{"status": "weak_password"}`. The `used` flag is **not** flipped. |
| AC-11 | A user can log in with their newly-reset password immediately after the reset; `auth_service.login()` accepts the new bcrypt hash. |
| AC-12 | The two POST routes sit behind the existing `CSRFMiddleware` and `RateLimitMiddleware`; a missing/invalid `csrf_token` returns 403 before the handler runs; a flood of POSTs from one IP gets 429s. |
| AC-13 | The new `password_resets` table is created by `init_db()` in `db/session.py` via `CREATE TABLE IF NOT EXISTS`; re-running `init_db()` on a DB that already has the table is a no-op. |
| AC-14 | The `core/mailer.send_password_reset_email` function never raises; it returns `False` on a SendGrid error or when SendGrid is unconfigured. The route ignores the return value. |
| AC-15 | The new templates are styled with the existing CSS custom properties (light/dark theme); the dark-mode toggle works on `/forgot-password` and `/reset-password` without any JS change. |
| AC-16 | No new dependency is added. `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are unchanged. |
| AC-17 | The `auth_service.login()`, `signup()`, `change_password()`, `verification_service.*`, `otp_service.*`, `totp_service.*`, `lockout_service.*`, and `oauth_service.*` modules are **not** modified. `main.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/oauth.py`, `core/captcha.py`, `core/qr_login.py` are not modified. |
| AC-18 | **The reset form's `action` attribute is `f"{config.APP_BASE_URL}/reset-password"`** — derived exclusively from `config.APP_BASE_URL`. **`request.url.scheme`, `request.url.netloc`, `request.headers["host"]`, `request.headers["x-forwarded-host"]`, and any other client-supplied value are NEVER used to construct this URL.** A request with `Host: evil.example` does **not** change the rendered `action` attribute. (Host Header Injection vector is closed at the spec level.) |
| AC-19 | **The reset page loads no third-party asset of any kind.** The page's `<head>` and `<body>` contain no `<script src="https://…">`, no `<link href="https://…">`, no `<img src="https://…">`, no `@font-face` URL, and no analytics pixel. The only `<link>` is `href="/static/css/styles.css"` (first-party). **No `Referer` header from this page can carry the token-bearing URL to an external origin.** (Referer Leakage vector is closed at the spec level.) |
| AC-20 | The reset page does **not** reflect the raw token as markup (VULN-3). The token is `html.escape(..., quote=True)`-d if it is ever spliced for debugging. |
| AC-21 | A user who resets their password can still log in even if they had Email-OTP-2FA (v1.0.6) or TOTP (v1.0.7) enabled — the 2FA challenge is presented on the new login, exactly as before. |
| AC-22 | **Every new SQL statement is parameterized.** The `INSERT INTO password_resets`, the `SELECT … WHERE email = ?`, the `SELECT … WHERE token_hash = ?`, the `UPDATE password_resets SET used = 1 WHERE id = ?`, and the `UPDATE users SET password = ? WHERE id = ?` all use `?` placeholders and pass values as a separate argument list. No string concatenation, no f-string interpolation. |
| AC-23 | The `start_reset` and `consume_reset` services do **not** read `request.url`, `request.url.scheme`, `request.url.netloc`, `request.headers`, or any other client-supplied value to construct a URL. A `grep` of the source confirms the only `f"http` string in `password_reset_service.py` is `f"{config.APP_BASE_URL}/reset-password?token={token}"` (i.e. uses `config.APP_BASE_URL` only). |

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | Unknown email submits `/forgot-password` | `users` table has no row with `email = "ghost@example.com"` | `200 {"success": true, "message": "If that email matches an account, a reset link has been sent to it."}`; no `password_resets` row inserted; no email sent. |
| TC-02 | Verified local email submits `/forgot-password` | `users` row exists: `username = "alice"`, `email = "alice@example.com"`, `is_verified = 1`, `auth_provider = 'local'`; SendGrid is configured | `200` with the generic message; one row in `password_resets` with `user_id = alice.id`; one reset email in SendGrid's outbound log carrying a `{config.APP_BASE_URL}/reset-password?token=<plaintext>` link. |
| TC-03 | Unverified local email submits `/forgot-password` | `users` row exists, `is_verified = 0` | `200` with the generic message; **no** row in `password_resets`; no email sent. |
| TC-04 | Google-only email submits `/forgot-password` | `users` row exists, `auth_provider = 'google'`, `password IS NULL` | `200` with the generic message; **no** row in `password_resets`; no email sent. |
| TC-05 | Empty email submits `/forgot-password` | (no precondition) | `200` with the generic message; no DB write; no email sent. |
| TC-06 | Valid, unused, unexpired token opens `/reset-password` | `password_resets` row: `used = 0`, `expires_at = time.time() + 600` | `200 OK` with the form rendered; `{{status}} = "ok"`; `{{csrf_token}}` spliced; `{{form_action}}` set to `f"{config.APP_BASE_URL}/reset-password"`. |
| TC-07 | Used token opens `/reset-password` | `password_resets` row: `used = 1` | `200 OK` with the "already been used" message; form **not** rendered. |
| TC-08 | Expired token opens `/reset-password` | `password_resets` row: `expires_at = time.time() - 1` | `200 OK` with the "expired" message; form **not** rendered; link back to `/forgot-password`. |
| TC-09 | Bogus token opens `/reset-password` | No `password_resets` row matches the SHA-256 hash | `200 OK` with the "invalid" message; form **not** rendered. |
| TC-10 | Valid token + strong password POSTs `/reset-password` | `password_resets` row: `used = 0`, `expires_at` in the future; `password = "NewPass!2026"` (satisfies policy) | `200 {"success": true, "message": "Password updated. Please log in with your new password."}`; `users.password` is now a bcrypt hash of `"NewPass!2026"`; `password_resets.used` is now `1`. |
| TC-11 | Same token POSTs `/reset-password` a second time | (continuation of TC-10) | `200 {"error": "This reset link has already been used."}`; `users.password` is unchanged. |
| TC-12 | Valid token + weak password POSTs `/reset-password` | `password = "short"` | `200 {"error": "Password must be at least 8 characters and include an uppercase letter, a lowercase letter, a digit, and a special character."}`; `users.password` is unchanged; `password_resets.used` remains `0`. |
| TC-13 | Valid token + mismatched confirm password | `password = "NewPass!2026"`, `confirm_password = "different"` | Client-side JS catches the mismatch; the form is **not** submitted. The `password_resets.used` flag is unchanged. |
| TC-14 | Expired token POSTs `/reset-password` | `password_resets` row: `expires_at` in the past | `200 {"error": "This reset link has expired. Request a new one."}`; `users.password` is unchanged. |
| TC-15 | Bogus token POSTs `/reset-password` | No matching `password_resets` row | `200 {"error": "Invalid reset link."}`; `users.password` is unchanged. |
| TC-16 | Empty token POSTs `/reset-password` | `token = ""` | `200 {"error": "Invalid reset link."}`; `users.password` is unchanged. |
| TC-17 | Empty password POSTs `/reset-password` | `token` is valid; `password = ""` | `200 {"error": "Password must be at least 8 characters…"}`; `users.password` is unchanged; `password_resets.used` remains `0`. |
| TC-18 | SendGrid is unconfigured — `GET /forgot-password` | `SENDGRID_API_KEY` or `SENDGRID_FROM` is empty | `200 OK` with `email_not_configured.html` rendered. |
| TC-19 | SendGrid is unconfigured — `POST /forgot-password` | (same) | `200 OK` with `email_not_configured.html` rendered. **The response is not the generic JSON** (the GET-page degrade is the contract; the POST is defense in depth). |
| TC-20 | `POST /forgot-password` with a missing `csrf_token` | (no precondition) | `403 {"error": "CSRF token missing or invalid"}` from `CSRFMiddleware`; the handler is not invoked. |
| TC-21 | `POST /reset-password` with a missing `csrf_token` | (no precondition) | Same as TC-20. |
| TC-22 | Burst of 6 `POST /forgot-password` from one IP in 60 s | `RATE_LIMIT_MAX = 5`, `RATE_LIMIT_WINDOW_SECONDS = 60` (defaults) | The 6th request returns `429 {"error": "Too many requests", "retry_after": <int>}` with a `Retry-After` header. |
| TC-23 | A user resets their password and logs in with the new one | Alice has just completed TC-10 | `POST /login` with `username = "alice"` and `password = "NewPass!2026"` returns `200 {"success": true, "redirect": "/welcome"}`; `request.session` carries `user_id`, `username`, `email`. |
| TC-24 | A user with 2FA enabled resets their password | Alice has `two_factor_enabled = 1`; she just completed TC-10 | The new login returns `200 {"otp_required": true, "redirect": "/login/otp"}`; the OTP gate is unchanged. |
| TC-25 | A user with TOTP enabled resets their password | Alice has `totp_enabled = 1`; she just completed TC-10 | The new login returns `200 {"otp_required": true, "redirect": "/login/totp"}`; the TOTP gate is unchanged. |
| TC-26 | **`Host: evil.example` on `GET /reset-password?token=…`** | A valid token; the request sets `Host: evil.example` | The form's `action` attribute is **unchanged**: it is `f"{config.APP_BASE_URL}/reset-password"` (e.g. `http://localhost:3001/reset-password`), **not** `http://evil.example/reset-password`. The Host Header Injection vector is closed at the spec level. |
| TC-27 | **Reset page contains no third-party assets** | (any test above) | Inspect the HTML body of `/reset-password`. The only `<link>` is `href="/static/css/styles.css"` (first-party). The only `<script>` is inline (for confirm-password validation) or absent. There is no `<script src="https://…">`, no `<link href="https://…">`, no `<img src="https://…">`, no `@font-face` URL, no analytics pixel. The Referer Leakage vector is closed at the spec level. |
| TC-28 | **The form's `action` URL is built from `config.APP_BASE_URL` only** | (any test above) | Inspect the source of `password_reset_service.py` and `auth.py`. The only `f"http` string in `password_reset_service.py` is `f"{config.APP_BASE_URL}/reset-password?token={token}"` (uses `config.APP_BASE_URL` only). The route handler's `form_action` is `f"{config.APP_BASE_URL}/reset-password"`. There is no `f"{request.url.scheme}://{request.url.netloc}"`, no `f"http://{request.headers['host']}"`, and no other client-derived URL construction. |
| TC-29 | The plaintext token is never reflected in any response | (any test above) | Inspect the HTML body of every response (login, signup, forgot-password, reset-password, welcome, profile, dashboard, search, verify). The plaintext token does not appear except in the `action` URL of a same-origin POST on `/reset-password` (the form posts the token in the body, not the URL). |
| TC-30 | The `password_resets` table is created on a fresh DB | `vulnerable_app.db` does not exist; the app starts | After `main.py` boot, `sqlite3 vulnerable_app.db ".schema password_resets"` shows the full DDL. |
| TC-31 | The `password_resets` table is created on a pre-existing DB that has `users` but not `password_resets` | `vulnerable_app.db` exists from v2.0.0 (no `password_resets` table) | After `main.py` boot, `.schema password_resets` shows the table. The `users` table is byte-for-byte unchanged. |
| TC-32 | No new dependency is added | (compare `pyproject.toml` and `uv.lock` before/after) | `git diff pyproject.toml uv.lock` is empty. `grep -E "^import " backend/app/services/password_reset_service.py` shows only `hashlib`, `secrets`, `time`, `logging`, and project-internal modules. |
| TC-33 | The reset mailer is fail-safe | Mock SendGrid with a 500 response | `core/mailer.send_password_reset_email` returns `False`; no exception propagates to the route; the route still returns the generic `200` response. |
| TC-34 | The reset mailer fails safe on unconfigured SendGrid | `SENDGRID_API_KEY = ""` | `core/mailer.send_password_reset_email` returns `False` (and logs a warning); no exception. |
| TC-35 | A second reset link can be issued before the first is consumed | Alice requests a reset; 60 s later requests a second reset | Two `password_resets` rows exist for Alice. The first link still works; the second works too (each is independent). |
| TC-36 | Logout + request a reset + log in with the new password | Alice is logged in; logs out; resets her password; logs in | The reset succeeds; the new login is independent of any prior session. The signed session cookie is fresh after `/logout` (same posture as every other endpoint). |
| TC-37 | **`APP_BASE_URL` is the only URL source for the email link and the form action** | Set `APP_BASE_URL=https://lab.example.com:8443` in the environment; restart the app | The emailed reset link is `https://lab.example.com:8443/reset-password?token=…` (derived from `APP_BASE_URL`). The form's `action` is `https://lab.example.com:8443/reset-password`. **Even if the request has `Host: localhost:3001` or `Host: evil.example`, the URLs in the response are unchanged.** |
| TC-38 | **TTL is env-tunable** | Set `PASSWORD_RESET_TTL_SECONDS=30` in the environment; restart the app | A reset issued at `T=0` is dead by `T=30.5` (strict `time.time() > expires_at`). Useful for demos. |

---

## 10. Verification Steps

These are the exact UI steps, commands, and local mock-SMTP checks to run by hand to verify the feature in a fresh clone.

### 10.1 One-time environment

```bash
# From the project root, with the spec implemented:
cd backend && uv sync
cd ..
# Add the SendGrid creds to .env (git-ignored) so mailer.send_password_reset_email
# has a real transport. Without these, the flow degrades to email_not_configured.html
# and the reset pages are not rendered (NFR-16 / EC-17/18/19).
echo "SENDGRID_API_KEY=<your-real-key>" >> .env
echo "SENDGRID_FROM=<your-verified-sender@example.com>" >> .env
# Optionally set APP_BASE_URL to the origin the scanning device can reach:
echo "APP_BASE_URL=http://localhost:3001" >> .env
# Optionally tune the TTL for demos:
echo "PASSWORD_RESET_TTL_SECONDS=900" >> .env
```

### 10.2 Boot and verify the schema

```bash
# 1. Wipe any pre-existing DB so the migration is observable.
rm -f vulnerable_app.db

# 2. Start the app.
uv run backend/app/main.py

# 3. Confirm the new table is present.
sqlite3 vulnerable_app.db ".schema password_resets"
# Expected:
# CREATE TABLE password_resets (
#     id          INTEGER PRIMARY KEY AUTOINCREMENT,
#     user_id     INTEGER NOT NULL,
#     token_hash  TEXT UNIQUE NOT NULL,
#     expires_at  REAL NOT NULL,
#     used        INTEGER NOT NULL DEFAULT 0
# );
```

### 10.3 End-to-end happy path (manual UI)

1. **Sign up a verified local user** so the reset has a target.
   - Browse to `http://localhost:3001/signup`.
   - Submit `username = "alice"`, `email = "alice@example.com"`, `password = "OldPass!2024"` (any non-empty value).
   - The page 302s to `/check-email`. (The account is `is_verified = 0`.)
   - **Promote the account to verified** for the lab (the verification-email flow is the v1.0.4 mechanism, but for the reset lab we just need Alice to be a real, verified user):
     ```bash
     sqlite3 vulnerable_app.db "UPDATE users SET is_verified = 1 WHERE username = 'alice';"
     ```
2. **Request a reset link.**
   - Browse to `http://localhost:3001/forgot-password`.
   - Confirm the form renders (no `email_not_configured.html`).
   - Submit `email = "alice@example.com"`.
   - Confirm the success message: "If that email matches an account, a reset link has been sent to it."
3. **Inspect the database.**
   ```bash
   sqlite3 vulnerable_app.db "SELECT id, user_id, substr(token_hash, 1, 12) || '…', expires_at, used FROM password_resets;"
   # Expected: one row, used = 0, expires_at ≈ time.time() + 900, token_hash is a 64-char hex SHA-256.
   ```
4. **Open the reset link** from the SendGrid activity log (or from your inbox).
   - The URL is `{APP_BASE_URL}/reset-password?token=<plaintext>` (e.g. `http://localhost:3001/reset-password?token=…`).
   - The page renders the form. Inspect the page source:
     - The form has a hidden `csrf_token` input.
     - The form's `action` attribute is `http://localhost:3001/reset-password` (or whatever `APP_BASE_URL` is). It is **not** derived from `request.url` or any request header.
     - The HTML contains **no** `<script src="https://…">`, **no** `<link href="https://…">`, **no** `<img src="https://…">`, **no** `@font-face` URL, **no** analytics pixel. The only `<link>` is the first-party `/static/css/styles.css`.
5. **Submit a strong new password.**
   - Type `NewPass!2026` and `NewPass!2026` (matching).
   - Submit. The page redirects to `/login`.
6. **Inspect the database again.**
   ```bash
   sqlite3 vulnerable_app.db "SELECT password FROM users WHERE username = 'alice';"
   # Expected: a bcrypt hash starting with $2b$12$… (NOT the plaintext).

   sqlite3 vulnerable_app.db "SELECT used FROM password_resets ORDER BY id DESC LIMIT 1;"
   # Expected: 1 (the row was marked used = 1).
   ```
7. **Log in with the new password.**
   - Browse to `http://localhost:3001/login`.
   - Submit `username = "alice"`, `password = "NewPass!2026"`.
   - The page redirects to `/welcome`. Alice is in.

### 10.4 Negative paths

- **Unknown email:** repeat §10.3 step 2 with `email = "no-such@example.com"`. Confirm the response is the same generic `200 {"success": true, "message": "If that email matches an account, a reset link has been sent to it."}`. Confirm no `password_resets` row was added (`SELECT COUNT(*) FROM password_resets` is unchanged).
- **Unverified local user:** create a new account via `/signup` (do **not** promote to verified). Submit the same reset flow. Confirm the response is identical and no `password_resets` row is added.
- **Google-only account:** seed a Google row directly:
  ```bash
  sqlite3 vulnerable_app.db "INSERT INTO users (username, email, google_id, auth_provider, is_verified) VALUES ('bob', 'bob@example.com', 'g-12345', 'google', 1);"
  ```
  Submit a reset for `bob@example.com`. Confirm the response is identical and no `password_resets` row is added.
- **Expired token:** request a reset, then manually expire it:
  ```bash
  sqlite3 vulnerable_app.db "UPDATE password_resets SET expires_at = 1 WHERE id = (SELECT MAX(id) FROM password_resets);"
  ```
  Open the link. The page renders the "expired" message; the form is **not** shown.
- **Single-use:** open the link once and submit a strong password (success). Then submit the same link again. The page renders the "already been used" message.
- **Weak password:** open a valid link, submit `password = "short"`, `confirm_password = "short"`. The page renders the inline error; the `used` flag remains `0` (the token is still usable).
- **CSRF missing:** in the browser dev tools, delete the hidden `csrf_token` field from the form. Submit. The response is `403 {"error": "CSRF token missing or invalid"}` from `CSRFMiddleware` (the handler does not run).
- **Rate limit:** send 6 `POST /forgot-password` requests from the same IP in 60 seconds. The 6th returns `429 {"error": "Too many requests", "retry_after": <int>}` with a `Retry-After` header.
- **SendGrid unconfigured:** unset `SENDGRID_API_KEY` and `SENDGRID_FROM` in `.env`, restart the app. `GET /forgot-password` renders `email_not_configured.html`. `POST /forgot-password` does the same. The reset flow is fully blocked; no enumeration oracle is exposed.

### 10.5 Hardening verification (the two closed vectors)

These checks confirm the **spec-level closures** of Host Header Injection and Referer Leakage. They are not lab vectors — the feature is fully hardened — so the expected outcome of every check is "the attack is not demonstrable."

- **Host Header Injection — `Host: evil.example` does not change the form action.**
  ```bash
  # Send a GET to /reset-password?token=<plaintext> with a doctored Host header.
  curl -i -H "Host: evil.example" "http://localhost:3001/reset-password?token=<plaintext>"
  # Inspect the response body's <form action="…">.
  # Expected: action="http://localhost:3001/reset-password" (or whatever APP_BASE_URL is).
  # NOT action="http://evil.example/reset-password".
  # The Host Header Injection vector is closed at the spec level — the action URL
  # is server-controlled, not request-derived.
  ```
- **Referer Leakage — the reset page makes no third-party requests.**
  1. Open the reset page in Chrome with the dev tools Network tab open.
  2. Observe every request the page issues. **Expected:** every request goes to the application's own origin (`http://localhost:3001/...`). **No** request goes to `cdn.example.com`, `cdnjs.cloudflare.com`, `fonts.googleapis.com`, `googletagmanager.com`, or any other external host.
  3. Inspect the page source. **Expected:** no `<script src="https://…">`, no `<link href="https://…">`, no `<img src="https://…">`, no `@font-face` URL, no analytics pixel. The only `<link>` is the first-party `/static/css/styles.css`.
  4. Submit the form (to the same origin). Inspect the form POST's `Referer` header — it points to the application's own origin, not to any external host. **No token-bearing URL is leaked to a third party.**

- **Source-code review — no `request.url` or `request.headers` in URL construction.**
  ```bash
  # The only f"http string in password_reset_service.py must be config.APP_BASE_URL-based.
  grep -nE 'f"http' backend/app/services/password_reset_service.py
  # Expected: a single line like:
  #   f"{config.APP_BASE_URL}/reset-password?token={token}"
  # (No f"{request.url.scheme}://…", no f"http://{request.headers['host']}…", etc.)

  # The route handler's form_action must be config.APP_BASE_URL-based.
  grep -nE 'form_action' backend/app/api/routes/auth.py
  # Expected: form_action = f"{config.APP_BASE_URL}/reset-password"
  # (No f"{request.url.scheme}://{request.url.netloc}…", no f"http://{request.headers['host']}…".)
  ```

### 10.6 Mock-SMTP local check (no SendGrid)

If you want to exercise the mailer without hitting SendGrid, run a local stdlib SMTP sink:

```bash
# In one terminal: start a local SMTP sink on port 1025.
python -m smtpd.server -n -c DebuggingServer localhost:1025
```

Then point the app at it by setting `SMTP_HOST = localhost` and `SMTP_PORT = 1025` in the `core/mailer.py` constants (for the local lab only — this is a verification convenience; the production transport is SendGrid). On `POST /forgot-password`, the sink prints the full `Subject:` / `To:` / body, and you can copy the `reset-password?token=…` link from the body to your browser.

If you do not want to modify `core/mailer.py`, leave SendGrid unconfigured and rely on the `email_not_configured.html` degrade (§10.4 last bullet).

### 10.7 Verifying the no-new-dependency posture

```bash
git diff pyproject.toml backend/pyproject.toml uv.lock
# Expected: empty.

grep -E "^import " backend/app/services/password_reset_service.py
# Expected: hashlib, secrets, time, logging, plus project-internal imports
# (app.core.config, app.core.mailer, app.core.security, app.db.session,
#  app.services.auth_service).

grep -E "^import " backend/app/api/routes/auth.py | head -40
# Expected: no new third-party imports (the file's import list is unchanged).
```

### 10.8 Verifying the no-side-effect posture on other modules

```bash
git diff backend/app/main.py \
         backend/app/core/security.py \
         backend/app/core/csrf.py \
         backend/app/core/rate_limit.py \
         backend/app/core/oauth.py \
         backend/app/core/captcha.py \
         backend/app/core/qr_login.py \
         backend/app/services/auth_service.py \
         backend/app/services/verification_service.py \
         backend/app/services/otp_service.py \
         backend/app/services/totp_service.py \
         backend/app/services/lockout_service.py \
         backend/app/services/oauth_service.py
# Expected: empty.
```

### 10.9 Verifying the migration is additive

```bash
# On a v2.0.0 DB (no password_resets table):
rm -f vulnerable_app.db
# Recreate a v2.0.0 state by booting from a checkout without the new spec
# (e.g. `git stash`), signing up + promoting alice, then `git stash pop`
# and rebooting. (This step is for the schema-evolution check; for normal
# verification, §10.2 is sufficient.)

# Confirm the table is created on reboot:
sqlite3 vulnerable_app.db ".schema password_resets"
# Expected: the full DDL.

# Confirm the users table is unchanged:
sqlite3 vulnerable_app.db ".schema users"
# Expected: same as v2.0.0; no new columns, no rewrites.

# Confirm Alice still has her old password hash (the migration did not
# touch the users table):
sqlite3 vulnerable_app.db "SELECT password FROM users WHERE username = 'alice';"
# Expected: a bcrypt hash from v2.0.0 (not a reset flow output).
```

### 10.10 Spot-check the log lines (no token leakage)

```bash
# Trigger a reset and a consumption, then grep the server log.
uv run backend/app/main.py 2>&1 | tee /tmp/server.log &
SERVER_PID=$!
# ... exercise the flow ...
kill $SERVER_PID
grep -E "(reset|password)" /tmp/server.log
# Expected: only lines like "Password reset email sent to <email>" and
# "Password reset consumed for user_id=<int>". NO line should contain a
# token, a token hash, a plaintext password, a form action URL, or
# the /reset-password URL (other than the log line itself, which is
# grep-matching the substring "reset").
```

### 10.11 Verifying no third-party assets on the reset page

```bash
# Fetch the reset page and inspect its <head> and <body>.
curl -s "http://localhost:3000/reset-password?token=<any-plaintext>" > /tmp/reset.html

# 1. Confirm the form's action is the application's own origin.
grep -oE '<form[^>]+action="[^"]+"' /tmp/reset.html
# Expected: <form … action="http://localhost:3001/reset-password" …>
# (or whatever APP_BASE_URL is — NOT a request-derived URL)

# 2. Confirm there are no third-party scripts.
grep -E '<script[^>]+src="https?://' /tmp/reset.html
# Expected: empty.

# 3. Confirm there are no third-party stylesheets.
grep -E '<link[^>]+href="https?://' /tmp/reset.html
# Expected: empty (the page's only <link> is to /static/css/styles.css).

# 4. Confirm there are no third-party images.
grep -E '<img[^>]+src="https?://' /tmp/reset.html
# Expected: empty.

# 5. Confirm there are no @font-face URLs.
grep -E '@font-face|url\("https?://' /tmp/reset.html
# Expected: empty.
```

---

**End of specification.**
