# Vulnerable Web Application Build via Claude Code

An intentionally vulnerable web application designed to teach common security vulnerabilities through hands-on exploitation. Rather than studying vulnerabilities in theory, you'll exploit them in a working application to understand how real attacks work.

Built with FastAPI and SQLite — simple enough to read in one sitting, realistic enough to demonstrate actual attack techniques.

**Live Demo of v0.1.0:** https://vuln-web-app.onrender.com

> **WARNING:** This application is deliberately insecure. It is designed for educational use only and should never be deployed to production or used on systems you do not own.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | FastAPI, Uvicorn |
| Database | SQLite3 |
| Frontend | Vanilla HTML5, CSS3, JavaScript |
| Session Management | Starlette SessionMiddleware |
| Package Manager | uv |
| Python | 3.12+ |

## Project Structure

```
vuln-web-app/
├── backend/
│   ├── app/
│   │   ├── main.py                  # Entry point — starts the server
│   │   ├── core/
│   │   │   └── security.py          # Password hashing (bcrypt, work factor 12)
│   │   ├── db/
│   │   │   └── session.py           # Database connection and schema setup
│   │   ├── services/
│   │   │   └── auth_service.py      # Business logic for signup and login
│   │   └── api/routes/
│   │       └── auth.py              # All HTTP route handlers
│   └── pyproject.toml               # Backend package config
├── frontend/
│   ├── templates/
│   │   ├── login.html               # Login page (fetch-based, theme toggle)
│   │   ├── signup.html              # Registration page (form POST, theme toggle)
│   │   └── dashboard.html           # Protected dashboard (theme toggle)
│   └── static/
│       ├── css/styles.css           # Application styling (light/dark themes)
│       └── images/                  # Organization logos (PUCIT, Excaliat, FCCU)
├── docs/
│   ├── PRD.md                       # Product requirements
│   ├── TDD.md                       # Technical design
│   └── prompts/                     # Prompts used to generate specs & plans
├── .claude/specs/                   # Feature specs and implementation plans
├── pyproject.toml                   # Root project config
└── vulnerable_app.db                # SQLite database (auto-created)
```

---

## Releases & Versions

This repository ships in several tagged releases. The versions below are the main anchors — pick the one that matches how you want to learn:

| Version | Who it's for | What you get |
|---------|--------------|--------------|
| **v0.1.0** | Students who want to fix the vulnerabilities **from scratch** | The baseline vulnerable app with **all 8 intentional vulnerabilities open** (including the MD5 weak password storage). Your job is to find and patch each one yourself. |
| **v0.1.1** | Students who want a **partial reference implementation** | Adds the **dark mode toggle** and replaces MD5 with **bcrypt** (VULN-5 fixed). A good starting point for comparing your own early fixes. |
| **v1.0.0** | Students who want the **complete reference implementation** | All **8 vulnerabilities fixed** (SQLi, stored & reflected XSS, session hijacking, weak passwords, exposed DB, no rate limiting, CSRF). Study it to see how every patch was implemented. |
| **v1.0.1** | Students who want the complete reference **plus the first feature enhancement** | Everything in v1.0.0 plus the **password strength meter** on the signup form (real-time bar + live 5-criterion checklist, advisory only — the backend gate is unchanged). |
| **v1.0.2** | Students who want the reference **plus the user profile page** | Everything in v1.0.1 plus the authenticated **User Profile Page** (`/profile`): view your username/email and change your password (current-password check + bcrypt, with a server-enforced strength policy). CSRF-protected, rate-limited, no schema change. |
| **v1.0.3** | Students who want the reference **plus social login** | Everything in v1.0.2 plus **Continue with Google** (OAuth 2.0 Authorization Code flow via Authlib + OpenID Connect): new accounts are auto-created and matching emails linked, and login reuses the existing signed session. The project's **first database-schema change**; the app still runs (and the button shows a setup page) when Google isn't configured. |
| **v1.0.4** | Students who want the reference **plus email verification** | Everything in v1.0.3 plus **Email Verification on Signup**: registration sends a single-use, 1-hour confirmation link over SMTP (stdlib only, no new dependency); accounts are created *unverified* and **cannot log in until the link is clicked**, with a credential-checked **Resend** button on the login page. Google accounts are auto-verified; the signup page shows a friendly setup page when SMTP isn't configured. Second DB-schema change (3 columns on `users`). |
| **v1.0.5** | Students who want the reference **plus account lockout** | Everything in v1.0.4 plus **Account Lockout**: after a configurable number of consecutive failed logins (default **6**) a single account is temporarily locked (default **1 hour**, then auto-unlocks), refusing authentication even with the correct password and showing a countdown. The lock is checked *before* bcrypt and shared between login and the verification-resend endpoint. A per-**account** layer that **complements — does not replace — the per-IP rate limiter (VULN-7)**. Third DB-schema change (2 columns on `users`); stdlib only, no new dependency. |
| **v1.0.6** | Students who want the reference **plus email OTP 2FA** | Everything in v1.0.5 plus **Email OTP Two-Factor Authentication**: a user can opt in from their profile, after which a correct password no longer logs them in directly — the app emails a **6-digit one-time code** (5-min expiry, 5-attempt cap, 60-s resend cooldown — all env-tunable) and completes login only after the code is verified on a dedicated screen. The challenge runs *after* bcrypt + the email-verified gate; the session is promoted only post-OTP (**session-only, no JWT**). Fourth DB-schema change (5 columns on `users`); stdlib only, no new dependency. |
| **v1.0.7** | Students who want the reference **plus authenticator-app 2FA** | Everything in v1.0.6 plus **MFA via Authenticator App (TOTP)**: a user enrolls Google Authenticator / Authy by scanning a **QR code** on their profile and confirming one code; thereafter a correct password issues a **TOTP challenge** on a dedicated `/login/totp` screen instead of completing login. **Independent of Email OTP and takes precedence** when both are on (no email sent); it needs **no SMTP and no Google**, so it works on a fresh clone. TOTP math is pure stdlib; the **only new dependency is `segno`** (pure-Python QR). Session-only (no JWT); replay-guarded. Fifth DB-schema change (3 columns on `users`). |
| **v1.0.8** | Students who want the reference **plus QR-code login** | Everything in v1.0.7 plus **QR Code Login**: an unauthenticated browser is shown a **QR code** on the login page and an already-signed-in device scans it, confirms on an **Approve / Reject** page, and logs the first browser in — the WhatsApp-Web pattern. The desktop **polls** for approval; pairing state is held in an **in-memory store** (like the rate limiter), so there is **no database-schema change** and **no new dependency** (the QR image reuses `segno`). Tokens are single-use and short-lived, and an **owner-binding** check (only the browser that generated a QR can be logged in by it) closes the login-CSRF vector. Login stays **session-only (no JWT)**; the trust comes from the already-authenticated device (its second factor was already satisfied). |
| **v2.0.0** | Students who want the reference **plus CAPTCHA on login** | Everything in v1.0.8 plus **CAPTCHA on Login** (**Cloudflare Turnstile**): the login form shows a Turnstile widget and **`POST /login` is verified server-side before any password check**, blocking automated/bot login attempts. Verification is a stdlib-`urllib` call to Cloudflare's `siteverify` — **no new dependency** and **no database-schema change**. With no keys set the widget isn't shown and login works exactly as before (graceful, like the Google/SMTP setup pages); a configured-but-unreachable Cloudflare **fails open** so an outage can't lock everyone out. Keys come from a git-ignored `.env`; the check runs **before** the account-lockout/bcrypt logic, which is otherwise unchanged. |
| **v2.1.0** | Students who want the reference **plus impossible-travel detection** | Everything in v2.0.0 plus **Geolocation & Impossible Travel Detection**: on successful password login the app compares the current IP's coordinates with the user's prior login location and time, and if the movement implies travel faster than 1000 km/h it treats the account as potentially compromised — clears `is_verified`, re-issues a verification email, and forces the user back through the existing email-verification flow. Local/private IPs, missing config, and provider outages degrade safely (the login still proceeds and the last-login metadata is updated without geolocation). No new dependency; the lookup uses stdlib `urllib` / `math` only. Sixth DB-schema change (4 columns on `users`). |

The incremental tags between them (**v0.1.2 – v0.1.7**) each close one additional vulnerability — see the [Bug Fixes](#bug-fixes) table for the version-by-version mapping. The feature-enhancement tags build on top of v1.0.0: **v1.0.1** adds the password strength meter, **v1.0.2** the User Profile Page, **v1.0.3** Continue with Google, **v1.0.4** Email Verification on Signup, **v1.0.5** Account Lockout, **v1.0.6** Email OTP 2FA, **v1.0.7** MFA via Authenticator App (TOTP), **v1.0.8** QR Code Login, **v2.0.0** CAPTCHA on Login, and **v2.1.0** Geolocation & Impossible Travel Detection.

### Download the version you want

**Option A — Download a release archive (no Git required)**

- v0.1.0 (all vulnerabilities open): https://github.com/arifpucit/vuln-web-app/releases/tag/v0.1.0
- v0.1.1 (dark mode + bcrypt): https://github.com/arifpucit/vuln-web-app/releases/tag/v0.1.1
- v1.0.0 (all vulnerabilities fixed): https://github.com/arifpucit/vuln-web-app/releases/tag/v1.0.0

Download the `Source code (zip)` or `Source code (tar.gz)` asset for the version you want and extract it.

**Option B — Clone the repo and check out the tag**

```bash
git clone https://github.com/arifpucit/vuln-web-app.git
cd vuln-web-app

# Work on the fully vulnerable baseline from scratch
git checkout v0.1.0

# Or study the partial reference (dark mode + bcrypt)
git checkout v0.1.1

# Or study the complete reference (all 8 vulnerabilities fixed)
git checkout v1.0.0
```

---

## Getting Started

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/arifpucit/vuln-web-app.git
cd vuln-web-app

# Check out the version you want (see "Releases & Versions" above)
git checkout v0.1.0   # baseline (all open) — or v0.1.1 (partial) / v1.0.0 (all fixed)

# Install dependencies
uv sync
```

### Running the Application

From the project root:
```bash
uv run backend/app/main.py
```

The app starts at **http://localhost:3001**. The database file (`vulnerable_app.db`) is created automatically on first run.

---

## Continue with Google — Setup (optional)

The app runs fine **without** any Google setup: username/password login works as
always, and the "Continue with Google" button simply shows a friendly
"not configured" page. To actually enable Google sign-in, give the app a Google
OAuth client:

1. **Create a project** — open the [Google Cloud Console](https://console.cloud.google.com/), create a new project, then **select/open it** (it must be the active project).
2. **Configure the consent screen** — in **Google Auth Platform** (older UI: *APIs & Services → OAuth consent screen*), work through the horizontal steps **App information → Audience → Contact → Finish**. Google blocks client creation until this is done.
3. **Make it usable** — either **Publish app** (Audience page → *In production*) so any Google account can sign in, or keep it in *Testing* and add your Google email under **Audience → Test users**. (Only basic `openid`/`email`/`profile` scopes are used, so no Google verification is required.)
4. **Create the OAuth client** — **Clients → Create client → Web application**. Under **Authorized redirect URIs** add this **exact** value (scheme, host, port, path — no trailing slash):
   ```
   http://localhost:3001/auth/google/callback
   ```
5. **Add the credentials locally** — copy the template and fill in your values:
   ```bash
   cp .env.example .env
   # then edit .env:
   #   GOOGLE_CLIENT_ID=...apps.googleusercontent.com
   #   GOOGLE_CLIENT_SECRET=...
   ```
6. **Restart** — `uv run backend/app/main.py`. The Google button now works.

---

## Email Verification — Setup (required for sign-up)

As of **v1.0.4**, creating a username/password account sends a confirmation
email, and the account **cannot log in until the link is clicked** (the login
page then offers a credential-checked "Resend verification email" button).
Because sign-up depends on email, the signup page shows a friendly **"sign-up
isn't available yet"** page until email is configured. (Login for
already-verified accounts and **Continue with Google** still work without email;
Google accounts are auto-verified.)

Email is delivered through the **SendGrid HTTPS API** (stdlib `urllib` — **no
extra dependency**). SendGrid is used instead of SMTP because many hosts (e.g.
Render's free plan) **block outbound SMTP ports**, whereas SendGrid's API works
over HTTPS (port 443). You need a SendGrid API key and a verified sender:

1. **Create a SendGrid account** (free tier is enough) at https://sendgrid.com.
2. **Verify a sender** — *Settings → Sender Authentication* → either verify a
   **Single Sender** email address or authenticate a domain. This address is
   what `SENDGRID_FROM` must be set to.
3. **Create an API key** — *Settings → API Keys → Create API Key* with the
   **Mail Send** permission. SendGrid shows the key (starting `SG.`) **once** —
   copy it.
4. **Add the credentials** — either locally in `.env`, or as environment
   variables on your host (e.g. Render):
   ```bash
   cp .env.example .env
   # then edit .env:
   #   SENDGRID_API_KEY=SG.your-sendgrid-api-key
   #   SENDGRID_FROM=your-verified-sender@example.com
   #   APP_BASE_URL=http://localhost:3001     # your public origin in production
   ```
5. **Restart** — `uv run backend/app/main.py`. Sign-up now sends verification
   emails, and the link in the email (valid 1 hour) confirms the account.

> **Deploying (e.g. Render):** the real `.env` is git-ignored and **not**
> deployed — set `SENDGRID_API_KEY`, `SENDGRID_FROM`, and `APP_BASE_URL` as
> environment variables in your host's dashboard, and set `APP_BASE_URL` to your
> public `https://` origin (no port). Without these the signup page shows the
> "not configured" notice.

The verification token is a single-use, 1-hour `secrets.token_urlsafe(32)`
value stored on the user's row; `APP_BASE_URL` is the public origin used to
build the link. `SENDGRID_FROM` must be an address (or domain) **verified in
SendGrid**, or the send is rejected. The real `.env` is **git-ignored** — never
commit your API key; `.env.example` holds placeholders only.

---

## CAPTCHA on Login — Setup (optional)

As of **v2.0.0**, the login form can show a **Cloudflare Turnstile** CAPTCHA, and
`POST /login` is verified server-side **before** any password check — blocking
automated/bot login attempts. The app runs fine **without** any setup: with no
keys configured the widget isn't shown and login behaves exactly as before
(graceful degrade, like the Google / Email setup pages). Verification uses
Python's standard-library `urllib` — **no extra dependency** — and there is **no
database change**.

To enable it, give the app a Turnstile widget (free, no domain required):

1. **Create a Cloudflare account** — https://dash.cloudflare.com/sign-up (free,
   no credit card, no domain needed).
2. **Add a Turnstile widget** — dashboard → **Turnstile** → **Add widget**.
   - **Hostname:** `localhost` (add `127.0.0.1` too if you like).
   - **Widget mode:** **Managed** (recommended).
3. **Copy the keys** — Cloudflare shows a **Site Key** (public) and a **Secret
   Key** (private).
4. **Add the credentials locally** — copy the template and fill in your values:
   ```bash
   cp .env.example .env
   # then edit .env:
   #   TURNSTILE_SITE_KEY=...
   #   TURNSTILE_SECRET_KEY=...
   ```
5. **Restart** — `uv run backend/app/main.py`. The login page now shows the
   widget and rejects logins that fail the CAPTCHA.

**Production note:** use a **separate** widget whose hostname is your real domain
(serve the app over HTTPS), and provide the keys through your host's environment
variables / secrets rather than a committed `.env`. Both keys are required
together; the **Site Key is public** but the **Secret Key is a real secret** —
the real `.env` is **git-ignored**, and `.env.example` holds placeholders only. A
configured-but-unreachable Cloudflare **fails open** (login still proceeds, gated
by password + lockout + rate-limit) so an outage can't lock everyone out.

*(This feature adds no new API endpoints — `POST /login` is unchanged in path and
method; only its request now carries the Turnstile token.)*

---
## Geolocation & Impossible Travel Detection — Setup (optional)

As of **v2.1.0**, password logins can consult a free geolocation provider and
compare the new location with the user's previous login coordinates. The feature
degrades safely when the IP is localhost/private, when no provider is configured,
or when the provider is unreachable. No new dependency is added; the lookup uses
Python's standard-library `urllib` and `math` only.

1. Add a free geolocation endpoint in `.env` (for example,
   `GEO_API_URL=https://ip-api.com/json/{ip}`).
2. Optionally set `GEO_HTTP_TIMEOUT` to a small value (for example `5`) if you
   want to bound the lookup latency.
3. Restart the app; if the endpoint is missing or unreachable the app still
   allows login and updates the last-login metadata.

---
## API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|:---:|
| GET | `/` | Redirect to signup | No |
| GET | `/signup` | Display signup form | No |
| POST | `/signup` | Create user account | No |
| GET | `/login` | Display login form | No |
| POST | `/login` | Authenticate user (returns JSON) | No |
| GET | `/welcome` | Protected dashboard | Yes |
| GET | `/profile` | Authenticated profile page (view info + change password + 2FA toggle) | Yes |
| POST | `/profile/password` | Change the logged-in user's password (returns JSON) | Yes |
| POST | `/profile/2fa` | Enable/disable Email OTP 2FA for the logged-in user (returns JSON) | Yes |
| POST | `/profile/totp/setup` | Begin authenticator-app (TOTP) enrollment; returns QR + manual key (JSON) | Yes |
| POST | `/profile/totp/confirm` | Confirm enrollment with a current code, activating TOTP (returns JSON) | Yes |
| POST | `/profile/totp/disable` | Disable authenticator-app (TOTP) 2FA (returns JSON) | Yes |
| GET | `/login/otp` | OTP entry screen shown mid-login when Email OTP 2FA is on (pending session) | Pending 2FA |
| POST | `/login/otp` | Verify the 6-digit email OTP and complete the login (returns JSON) | Pending 2FA |
| POST | `/login/otp/resend` | Re-send the login OTP (honours the per-account cooldown; returns JSON) | Pending 2FA |
| GET | `/login/totp` | Authenticator-code entry screen shown mid-login when TOTP is on (pending session) | Pending 2FA |
| POST | `/login/totp` | Verify the 6-digit TOTP code and complete the login (returns JSON) | Pending 2FA |
| GET | `/check-email` | "Check your inbox" page shown right after signup | No |
| GET | `/verify?token=` | Confirm an email-verification link (single-use, 1-hour token) | No |
| POST | `/verify/resend` | Re-send the verification email to the logged-in user (returns JSON) | Yes |
| GET | `/auth/google/login` | Start Google OAuth (or show the setup page when unconfigured) | No |
| GET | `/auth/google/callback` | Google OAuth redirect URI: verify, create/link the user, log in via session | No |
| GET | `/qr/create` | Issue a QR-login token + image, bound to the calling browser's session (returns JSON) | No |
| GET | `/qr/status?token=` | Poll a QR-login token; on approval writes the session and returns a redirect (returns JSON) | No |
| GET | `/qr/scan/{token}` | Approve/Reject page shown when a signed-in device scans the QR | Yes |
| POST | `/qr/approve` | Approve a pending QR login as the signed-in user (returns JSON) | Yes |
| POST | `/qr/reject` | Reject a pending QR login (returns JSON) | Yes |
| GET | `/logout` | Terminate session | No |
| GET | `/search?q=` | Search users | No |

---

## Intentional Vulnerabilities

| # | Vulnerability | OWASP Category | Location | Status |
|---|---------------|----------------|----------|--------|
| 1 | SQL Injection | A03:2021 - Injection | `auth_service.py` — string concatenation in queries | **Closed** |
| 2 | Stored XSS | A03:2021 - Injection | `auth.py` — was unescaped username on dashboard; now HTML-escaped before output | **Closed** |
| 3 | Reflected XSS | A03:2021 - Injection | `auth.py` — was unescaped query param in search; now HTML-escaped before output | **Closed** |
| 4 | Session Hijacking | A07:2021 - Auth Failures | `main.py` — was a hardcoded secret key; now sourced from `SECRET_KEY` env var with a strong random fallback | **Closed** |
| 5 | Weak Password Storage | A02:2021 - Crypto Failures | `security.py` — was MD5 (no salt); now bcrypt (cost 12) | **Closed** |
| 6 | Exposed Database | A01:2021 - Access Control | `auth.py` — unauthenticated `/download/db` (route removed) | **Closed** |
| 7 | No Rate Limiting | A07:2021 - Auth Failures | `core/rate_limit.py` + `main.py` — was no throttling; now per-IP sliding-window limit on every POST (HTTP 429 when exceeded). The v1.0.5 Account Lockout adds a complementary per-**account** layer on top; this middleware is unchanged. | **Closed** |
| 8 | CSRF | A01:2021 - Access Control | `core/csrf.py` + `main.py` + form templates — was no CSRF tokens on forms; now per-session synchronizer token validated on every POST (HTTP 403 when missing or mismatched) | **Closed** |

---

## Learning Path

1. **Explore the app** — Sign up, log in, and navigate the dashboard to understand normal functionality.
2. **Read the source code** — Each vulnerability is commented in the code with its vulnerability number.
3. **Exploit each flaw** — Use the vulnerability table above to locate and exploit each one.
4. **Fix it** — Patch each vulnerability using secure coding practices: parameterized queries, output escaping, strong password hashing, rate limiting, and CSRF tokens.

---

## Useful Commands

Check the database contents:
```bash
sqlite3 vulnerable_app.db "SELECT * FROM users;"
```

Reset the database (delete and restart):
```bash
rm vulnerable_app.db
uv run backend/app/main.py
```

Free port 3001 if already in use:
```bash
# macOS / Linux
lsof -ti:3001 | xargs kill

# Windows (PowerShell)
Get-NetTCPConnection -LocalPort 3001 | Select-Object OwningProcess
Stop-Process -Id <PID> -Force
```

---

## Bug Fixes
The **weak password storage** bug (VULN-5: MD5 → bcrypt) is **fixed** as of **v0.1.1**, the **SQL injection** vulnerability (VULN-1: string concatenation → parameterized queries) is **fixed** as of **v0.1.2**, the **exposed database** endpoint (VULN-6: unauthenticated `/download/db` → route removed) is **fixed** as of **v0.1.3**, the **session hijacking** vulnerability (VULN-4: hardcoded session secret → env-sourced secret with a strong random fallback) is **fixed** as of **v0.1.4**, the **stored XSS** vulnerability (VULN-2: unescaped dashboard username → HTML-escaped output) is **fixed** as of **v0.1.5**, the **reflected XSS** vulnerability (VULN-3: unescaped `/search` reflection → HTML-escaped output) is **fixed** as of **v0.1.6**, the **no rate limiting** vulnerability (VULN-7: no throttling → per-IP sliding-window POST rate limit returning HTTP 429) is **fixed** as of **v0.1.7**, and the **CSRF** vulnerability (VULN-8: no CSRF tokens → per-session synchronizer-token middleware returning HTTP 403) is **fixed** as of **v1.0.0**. **All 8 vulnerabilities are now closed**; the current codebase is a complete reference implementation. To study the original vulnerabilities, check out the `v0.1.0` tag (fully vulnerable baseline) and patch them yourself.

| # | Vulnerability | Description | Status |
|---|---------------|-------------|--------|
| 1 | Weak Password Storage | Passwords were hashed with unsalted MD5; replaced with bcrypt (cost 12). Login now verifies the hash in Python instead of matching it in the SQL query. | **Fixed (v0.1.1)** |
| 2 | SQL Injection | `auth_service.py` builds queries with raw string concatenation; crafted input can read data or bypass authentication. Fix with parameterized/prepared queries. | **Fixed (v0.1.2)** |
| 3 | Stored XSS | `auth.py` rendered the username on the dashboard without escaping, so a malicious script persisted in the database and executed for every viewer. Fixed by HTML-escaping the username (`html.escape(..., quote=True)`) before output; the raw value still lives in the DB (output-encoding fix, not input filtering). | **Fixed (v0.1.5)** |
| 4 | Reflected XSS | The `/search` endpoint echoed the `q` parameter (and result rows / error text) back unescaped, executing injected scripts in the victim's browser. Fixed by HTML-escaping every reflected sink (`html.escape(..., quote=True)`); the raw values still live in the URL/DB (output-encoding fix, not input filtering). | **Fixed (v0.1.6)** |
| 5 | Session Hijacking | `main.py` used a hardcoded session secret key, making session cookies guessable/forgeable. Fixed by loading `SECRET_KEY` from the environment with a strong `secrets.token_hex(32)` random fallback, so a fresh checkout never ships a known key. | **Fixed (v0.1.4)** |
| 6 | Exposed Database | `/download/db` served the entire SQLite file with no authentication or authorization. Fixed by removing the route entirely. | **Fixed (v0.1.3)** |
| 7 | No Rate Limiting | There was no throttling middleware, leaving login open to brute-force and credential-stuffing attacks. Fixed by adding a stdlib `RateLimitMiddleware` that enforces a per-IP sliding window on every POST (default 5 requests / 60 s), returning HTTP 429 with a `Retry-After` header before the handler runs. | **Fixed (v0.1.7)** |
| 8 | CSRF | Forms carried no CSRF tokens, allowing cross-site request forgery against authenticated users. Fixed by adding a stdlib pure-ASGI `CSRFMiddleware` plus a per-session synchronizer token (`secrets.token_urlsafe(32)`) stored in `request.session["csrf_token"]`, spliced into a hidden field in the login and signup forms by the GET handlers, and validated on every POST with `secrets.compare_digest` — mismatches return HTTP 403 before the handler runs. | **Fixed (v1.0.0)** |

---

## Feature Enhancements

The dark mode toggle (v0.1.1), password strength meter (v1.0.1), User Profile Page (v1.0.2), Continue with Google (v1.0.3), Email Verification on Signup (v1.0.4), Account Lockout (v1.0.5), Email OTP 2FA (v1.0.6), MFA via Authenticator App / TOTP (v1.0.7), QR Code Login (v1.0.8), CAPTCHA on Login (v2.0.0), and Geolocation & Impossible Travel Detection (v2.1.0) are **done** — see the Status column. **All planned feature enhancements are now complete.**

Rows are listed in **release order** (by tag); the `#` column is the original
feature id from the PRD (kept stable so cross-references like "Email OTP (#6)"
still resolve). Planned items have no tag yet.

| Tag | # | Feature | Description | Status |
|-----|---|---------|-------------|--------|
| **v0.1.1** | 0 | Dark Mode Toggle | Light/dark theme toggle on login, signup, and dashboard pages; preference saved in `localStorage`, restored before first paint to avoid FOUC, with `prefers-color-scheme` fallback. | **Done** |
| **v1.0.1** | 1 | Password Strength Meter | A real-time, frontend-only indicator on the signup form: a colored bar (Very Weak → Strong), a live checklist of five acceptance criteria (min length 8, lowercase, uppercase, digit, special character), and a `data-theme`-aware color palette. Advisory only — the backend still accepts any non-empty password. | **Done** |
| **v1.0.2** | 2 | User Profile Page | Authenticated `/profile` page: view your username and email (read-only) and change your password (current-password check + bcrypt). The new password must meet the same five-criteria strength policy as signup (length ≥ 8 plus lower/upper/digit/special), enforced client- and server-side (no meter widget shown). CSRF-protected, rate-limited, no schema change. Dark-mode stays per-browser (`localStorage`). | **Done** |
| **v1.0.3** | 4 | Continue with Google (OAuth 2.0) | Sign up / log in with a Google account via the OAuth 2.0 Authorization Code flow (Authlib + OpenID Connect). New users are auto-created and existing emails are linked; login uses the **existing signed session** (no JWT, one cookie). The OAuth `state` param is the flow's CSRF defense. Credentials come from a git-ignored `.env`; with none set, the button shows a friendly setup page and the rest of the app still runs. First DB-schema change (4 nullable columns on `users`). | **Done** |
| **v1.0.4** | 3 | Email Verification on Signup | Registration sends a confirmation email with a single-use, 1-hour `secrets.token_urlsafe(32)` link (stdlib `smtplib`, no new dependency). New accounts are created **unverified** and **cannot log in until the link is clicked** — the login page then offers a CSRF-protected, rate-limited, credential-checked **Resend** button. Google accounts are auto-verified; existing accounts are grandfathered; the signup page degrades to a friendly setup page when SMTP isn't configured. Second DB-schema change (3 columns). | **Done** |
| **v1.0.5** | 9 | Account Lockout | Temporarily lock an account after a configured number of consecutive failed login attempts (default 6), with a cooldown timer before retry (default 1 hour, then auto-unlocks). Per-account state on two new `users` columns; the lock is checked **before** bcrypt and shared between `POST /login` and `POST /verify/resend`, so an attacker can't reset the count by switching endpoints. The lock message shows a countdown (a deliberate, bounded relaxation of login enumeration resistance). A per-account layer that **complements — not replaces — the per-IP rate limiter (VULN-7)**, which stays unchanged. Thresholds are env-tunable; stdlib only, no new dependency. Third DB-schema change (2 columns). | **Done** |
| **v1.0.6** | 6 | OTP via Email | Opt-in **Email OTP two-factor authentication**: a user enables it on `/profile`, after which a correct username + password no longer logs them in directly — the app emails a **6-digit one-time code** and login completes only after the code is verified on a dedicated `/login/otp` screen. The challenge runs **after** bcrypt and the email-verified gate; between the two steps a short-lived `pending_2fa_user_id` (not `user_id`) holds the signed session, so the dashboard stays gated. Bounded by a 5-attempt cap, a 5-minute expiry, and a 60-second resend cooldown (all env-tunable), on top of the unchanged per-IP rate limiter. Session-only (no JWT); delivery reuses the stdlib SMTP mailer. Fourth DB-schema change (5 columns on `users`); stdlib only, no new dependency. | **Done** |
| **v1.0.7** | 5 | MFA via Authenticator App (TOTP) | Opt-in **authenticator-app two-factor authentication** (RFC 6238 TOTP): a user enrolls Google Authenticator / Authy / 1Password by scanning a **QR code** on `/profile`, confirms one code to activate, and thereafter a correct password no longer logs them in directly — it asks for the current **6-digit time-based code** on a dedicated `/login/totp` screen. **Independent of Email OTP (#6); when both are on, TOTP takes precedence** and no email is sent (TOTP needs neither SMTP nor Google, so it works on a fresh clone). The TOTP math is pure stdlib; the only new dependency is **`segno`** (pure-Python QR rendering). Session-only (no JWT); a replay guard + ±skew window + the unchanged per-IP rate limiter bound the code. No backup codes this slice (admin clears the flag in the DB). Fifth DB-schema change (3 columns on `users`). |
| **v1.0.8** | 7 | QR Code Login | Log in by scanning a **QR code** shown on the login page from an already-authenticated device, which confirms on an **Approve / Reject** page — the WhatsApp-Web pattern. The unauthenticated browser **polls** for approval; pairing state lives in an **in-memory store** (`core/qr_login.py`, like the rate limiter), so there is **no database-schema change** and **no new dependency** (the QR image reuses `segno`). Tokens are `secrets.token_urlsafe(32)`, **single-use**, and short-lived; an **owner-binding** check (only the browser that generated a QR can be logged in by it) closes the login-CSRF / session-fixation vector. Approve/Reject are **session-gated POSTs** behind the existing CSRF + rate-limit middleware. Login stays **session-only (no JWT)**; the desktop is not re-challenged for 2FA because the approving device already satisfied it. `auth_service.py`, `main.py`, and the DB schema are unchanged. | **Done** |
| **v2.0.0** | 8 | CAPTCHA on Login | Add a **Cloudflare Turnstile** CAPTCHA to the login form to block automated and bot-driven login attempts. The widget is shown on `/login` and **`POST /login` is verified server-side (stdlib `urllib` → Cloudflare `siteverify`) before any password check** — a failed CAPTCHA never reaches the account-lockout/bcrypt logic. **No new dependency, no database-schema change.** Keys come from a git-ignored `.env`; with none set the widget isn't rendered and login works exactly as today (graceful degrade). A configured-but-unreachable Cloudflare **fails open** (a bot filter must not lock out everyone during an outage). Always-on for the login form only; `auth_service.login()` and all middleware are unchanged. | **Done** |
| **v2.1.0** | 9 | Geolocation & Impossible Travel Detection | On successful password login the app looks up the source IP's coordinates via a free geolocation API (stdlib `urllib`/`json`/`math`, no new dependency) and compares them with the user's prior login location and time. If the movement implies travel faster than 1000 km/h (Haversine formula), the account is treated as potentially compromised: `is_verified` is cleared, a fresh verification email is issued, and the login returns the standard unverified `401`. Local/private IPs, missing config, and provider outages degrade safely (login proceeds; the last-login IP/time are still updated). Fourth-ever additive, idempotent DB-schema change (4 columns on `users`); the check runs after bcrypt but before session creation. | **Done** |

---

## Legal Notice

This application is provided strictly for educational purposes. Unauthorized access to computer systems is illegal. Ensure you have explicit permission before testing security vulnerabilities on any system you do not own. The authors are not responsible for misuse of this project.

---

## Troubleshooting

**`uv command not found`**
Install uv: `pip install uv` or see https://docs.astral.sh/uv/getting-started/installation/

**`Port 3001 already in use`**
Kill the existing process using the commands in "Useful Commands" above.

**`ModuleNotFoundError: No module named 'app'`**
Run the app from the project root with `uv run backend/app/main.py`. The entry point automatically adds `backend/` to `sys.path`.

**Database seems corrupted or stale**
Delete `vulnerable_app.db` from the project root and restart the app. The database is recreated automatically on startup.

---
