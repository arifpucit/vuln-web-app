# Software Specification Document — Geolocation & Impossible Travel Detection

**Version:** 1.0.0
**Last Updated:** 2026-07-08
**Target Release Tag:** v2.1.0
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [Geolocation & Impossible Travel Detection — README "Feature Enhancements" #9](https://github.com/arifpucit/vuln-web-app/issues)

---

## 1. Overview / Purpose

This document specifies the **Geolocation & Impossible Travel Detection** enhancement. It is item #9 in the README's "Feature Enhancements" table. On successful password-based login, the app evaluates the source IP's geolocation against the user's last known login coordinates and timestamp; if the movement is physically implausible, the login is treated as a potential account takeover and the user is forced back through email verification.

This feature is intentionally layered on top of the existing authentication flow. It adds a new detection step after successful password verification but before the session is created, so a suspicious login can be blocked from becoming a real session while preserving the app's current session-only model.

### 1.1 Design Decisions (product-owner choices)

The following decisions are fixed and shape the entire feature:

1. **Provider = A free geolocation API like `ip-api.com/json/{ip}`.**
2. **Trigger = On POST /login, AFTER successful password verification, but BEFORE session creation.**
3. **Logic = Calculate distance (Haversine formula, pure stdlib `math`) between current IP's geo-coordinates and the `last_login_lat` / `last_login_lon`. Calculate speed based on `last_login_time`. If speed > 1000 km/h, flag as impossible travel.**
4. **Action = If flagged, log a security warning, revert the user's `is_verified` status to 0, and issue a new verification email via `verification_service.start_verification()`. Return the standard `401 {"error": "...", "unverified": true}` so the frontend forces them to check their email.**
5. **Unconfigured/Local IP degrade = If the IP is localhost/private, or the Geo API is unconfigured, bypass the check and update the last login time/IP without geo-coordinates.**
6. **Provider unreachable = FAIL-OPEN (allow login, log warning). A geo-service outage must not lock out legitimate users.**

### 1.2 Built on existing primitives

- The new logic lives in a dedicated module, `backend/app/core/geo.py`, alongside the existing `core/` helpers.
- The outbound lookup uses **stdlib** `urllib`, `json`, and `math` only — no new dependency, mirroring the CAPTCHA feature's stdlib posture.
- The schema is additive and idempotent: four new columns on `users` are added in `backend/app/db/session.py` with `ALTER TABLE ... ADD COLUMN ...` and no grandfather `UPDATE`.
- The feature preserves the existing security posture: parameterized SQL, HTML-escaped output, and no new auth cookie/JWT.

This feature does **not** change any of the eight closed vulnerabilities. After this change, all eight remain closed and the app gains its **fourth database-schema change** (the `last_login_*` columns).

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- **Schema (additive, idempotent — fourth-ever schema change).** Add four columns to `users` in `init_db()`:
  - `last_login_ip TEXT`
  - `last_login_time REAL`
  - `last_login_lat REAL`
  - `last_login_lon REAL`
  - The migration adds any missing column with `ALTER TABLE users ADD COLUMN ...` and never rewrites or drops rows. **No grandfather `UPDATE` is needed**: the columns start with `NULL`/no values and are only used after a successful login.
- **Geolocation module (`core/geo.py`, new).** Implement lookup + Haversine math in pure stdlib, with helpers for:
  - IP normalization / localhost / private IP handling
  - outbound geolocation lookup via `urllib` / `json`
  - Haversine distance and speed calculation
  - fail-open error handling and structured logging
- **Login enforcement (`services/auth_service.py`).** After successful password verification, call the new geolocation check before session creation. If the check flags impossible travel, the function must:
  1. log a security warning,
  2. set `is_verified = 0` for that user,
  3. issue a new verification email via `verification_service.start_verification()`,
  4. return the existing standard `401 {"error": "...", "unverified": true}` response.
- **Successful login bookkeeping.** On every successful login (including OAuth and QR-based login paths that reuse the same session-writing semantics), update the `last_login_*` columns with the current IP and time; if geolocation is unavailable or the IP is local/private, persist the IP/time only and leave coordinates null.
- **Configuration.** Read any optional geolocation settings from `core/config.py` (for example, a configurable API URL / timeout) with safe defaults; if unset, the lookup is skipped and the login proceeds as a degrade-safe path.
- **Docs.** Update `.env.example`, `README.md`, and `CLAUDE.md` to describe the feature and its degrade behavior.

### 2.2 Out of Scope (Intentionally)

- **No new dependency.** No `requests`, `httpx`, or other third-party client is introduced. The feature uses stdlib `urllib` and `json` only.
- **No change to the existing login UI.** The feature uses the existing login error path and does not add a new frontend widget or page.
- **No blocking on provider errors.** A geo-service outage is a fail-open event; the user is allowed to log in and the app updates the last-login metadata without coordinates.
- **No extra auth mechanism.** The feature does not add JWTs, extra cookies, or a separate verification prompt beyond the existing email-verification flow.
- **No geolocation on non-password flows.** The feature is triggered on password-based login only; the OAuth / QR login paths inherit the same “update last-login metadata” behavior when their session-creation path is used, but they do not add a separate geo challenge. This is the chosen scope for v2.1.0.

### 2.3 Explicit Preservation Note — All Eight Closed Vulnerabilities Stay Closed

- **VULN-1 (SQL Injection):** every new or modified SQL statement uses parameterized `?` placeholders. No string concatenation.
- **VULN-2 (Stored XSS):** no new unescaped user-controlled values are rendered in templates; the feature only writes to the DB and logs a server-side warning.
- **VULN-3 (Reflected XSS):** the feature never reflects raw IPs, coordinates, or attacker input into the response body; any error message is fixed and server-controlled.
- **VULN-4 (Session Hijacking):** the existing session secret / session middleware remain unchanged; no hardcoded secret is introduced.
- **VULN-5 (Weak Password Storage):** bcrypt remains the authentication primitive and remains the only password verifier on the normal login path.
- **VULN-6 (Exposed DB):** no database-download route is introduced or restored.
- **VULN-7 (No Rate Limiting):** the existing per-IP rate limiter stays in place; geolocation is an additive check, not a replacement.
- **VULN-8 (CSRF):** the existing CSRF middleware and hidden tokens remain unchanged; the geolocation check does not weaken them.

### 2.4 Explicit Non-Goals

- This feature does **not** attempt to infer trust from IP reputation or VPN/proxy heuristics beyond a simple geolocation distance check.
- This feature does **not** require a database table for geolocation history or a new state store; the state is the existing `users` row plus the signed session.
- This feature does **not** add a new UI element or new page flow beyond the existing email verification path already used by the app.

---

## 3. Affected Files

The change MUST touch only the following files (beyond this spec and its prompt docs).

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/core/geo.py` | **New** | Geolocation lookup, private-IP handling, Haversine math, fail-open behavior |
| `backend/app/db/session.py` | Modified | Additive idempotent migration for four `last_login_*` columns; no grandfather `UPDATE` |
| `backend/app/services/auth_service.py` | Modified | Insert the impossible-travel gate after password verification and before session creation; update `last_login_*` on successful login |
| `backend/app/core/config.py` | Modified | Optional geolocation settings / timeout (if introduced) |
| `.env.example` | Modified | Document the optional geolocation settings |
| `README.md` | Modified | Add v2.1.0 release note + feature description |
| `CLAUDE.md` | Modified | Mention the feature, its degrade posture, and its schema change |

Files that MUST NOT be modified by this change:

- `backend/app/main.py` — middleware / session secret / rate-limit wiring remain unchanged.
- `backend/app/core/security.py` — bcrypt remains untouched.
- `backend/app/core/csrf.py` — CSRF middleware remains unchanged.
- `backend/app/core/rate_limit.py` — rate-limit middleware remains unchanged.
- `backend/app/core/oauth.py`, `backend/app/core/mailer.py`, `backend/app/services/oauth_service.py`, `backend/app/services/otp_service.py`, `backend/app/services/totp_service.py` — unrelated auth flows remain unchanged.
- `backend/app/api/routes/auth.py` — the route layer remains thin; the geolocation logic is in the service layer.
- All templates and CSS — the existing login/error flow is reused.
- `pyproject.toml`, `backend/pyproject.toml`, `uv.lock` — no dependency change.

**Expected git status:**

```text
A backend/app/core/geo.py
M backend/app/db/session.py
M backend/app/services/auth_service.py
M backend/app/core/config.py
M .env.example
M README.md
M CLAUDE.md
```

---

## 4. Functional Requirements

### FR-01: Additive, Idempotent Schema Migration
- `init_db()` MUST add `last_login_ip TEXT`, `last_login_time REAL`, `last_login_lat REAL`, and `last_login_lon REAL` to `users` using `ALTER TABLE ... ADD COLUMN ...` when the columns are absent.
- The migration MUST be idempotent and row-preserving; no rows are dropped or rewritten.
- No grandfather `UPDATE` is run for these columns; the feature uses the columns only after a successful login.

### FR-02: Geolocation Configuration
- `config` MUST expose optional geolocation settings (for example: API URL / timeout) with safe defaults and no hardcoded secret.
- If the settings are absent or misconfigured, the feature MUST degrade safely by skipping the external lookup and updating only the time/IP fields.

### FR-03: Geolocation Module (`core/geo.py`)
- `backend/app/core/geo.py` MUST implement IP normalization, localhost/private-IP detection, geolocation lookup via stdlib `urllib`/`json`, Haversine distance calculation using pure stdlib `math`, and fail-open logging.
- The lookup MUST be best-effort and MUST NOT raise to the caller; any exception or provider outage returns a degrade-safe result.
- The module MUST NOT introduce a new dependency or perform any SQL work.

### FR-04: Trigger Point in Login Flow
- The geolocation evaluation MUST run on `POST /login` only after the password has been verified successfully and before any session is created.
- A suspicious login MUST never create a session.

### FR-05: Impossible-Travel Detection Logic
- If a previous login exists (prior `last_login_lat` / `last_login_lon` / `last_login_time` values), the app MUST compute the great-circle distance between the current lookup coordinates and the stored coordinates.
- If a previous login time exists, the app MUST compute a speed estimate from the elapsed time and flag the login when the speed exceeds `1000 km/h`.
- The computation MUST use the Haversine formula with pure stdlib `math`.

### FR-06: Action on Impossible Travel
- When impossible travel is detected, the app MUST log a security warning, set the user's `is_verified` to `0`, and issue a fresh verification email via `verification_service.start_verification()`.
- The login MUST return the standard unverified response shape: `401 {"error": "...", "unverified": true}`.
- No session is created for the suspicious login.

### FR-07: Local / Unconfigured / Private IP Degrade
- If the IP address is localhost/private, or the geolocation API is unconfigured, the app MUST bypass the detection path and update the last-login metadata (`last_login_ip`, `last_login_time`) without coordinates.
- This path MUST still count as a successful login for the purpose of updating the last-login state.

### FR-08: Provider Unreachable / Fail-Open
- If the geolocation provider is unreachable or returns an invalid response, the app MUST allow the login to proceed and log a warning.
- The feature MUST NOT deny legitimate logins due to a transient outage.

### FR-09: Successful Login Metadata Update
- On every successful login, `auth_service.login()` MUST update the `last_login_ip`, `last_login_time`, `last_login_lat`, and `last_login_lon` columns as appropriate.
- This includes the successful session-writing paths that already exist for password login and the session-based flows that reuse the same successful-login semantics (OAuth / QR).

### FR-10: Parameterized SQL and Output Safety
- Every SQL statement added or modified by this feature MUST use parameterized `?` placeholders.
- No attacker-controlled value is rendered into any template or response body; the app uses fixed server-controlled messages for any failure path.

### FR-11: No New Dependency
- The implementation MUST use stdlib `urllib`, `json`, and `math` only. No new Python dependency is introduced.

---

## 5. Non-Functional Requirements

### NFR-01: Surgical Scope
Exactly the files in §3 change (plus the spec/plan/prompt docs). No middleware is added, no route handler is rewritten, and no existing vulnerability fix is weakened.

### NFR-02: Graceful Degrade
The feature MUST be safe when the provider is unavailable, when the IP is local/private, or when configuration is missing. In those cases the login proceeds and the last-login time/IP are still updated.

### NFR-03: Fail-Open for Provider Outage
A temporary geolocation outage MUST NOT lock out legitimate users. The feature accepts the bounded risk that a suspicious login may slip through during a provider outage.

### NFR-04: Defense in Depth
The feature is an additional detection layer on top of existing password verification, rate limiting, CSRF, and email verification. It does not replace them.

### NFR-05: No Information Leakage
The feature MUST not expose raw IPs, lookup errors, or internal state to the client. Any suspicious-login response uses the existing unverified path and a fixed server-controlled message.

### NFR-06: Consistency With Existing Patterns
The implementation should match the lab's existing conventions: thin route handler → service-layer business logic, additive migration in `db/session.py`, stdlib-only network I/O in `core/`, and parameterized SQL everywhere.

---

## 6. Success Paths

### SP-01: Normal Login With No Prior Location
1. A user submits a correct password.
2. The geolocation lookup is skipped or returns no prior coordinates.
3. The app updates `last_login_ip` and `last_login_time` and completes the normal successful login flow.

### SP-02: Normal Login With Prior Location and Plausible Travel
1. A user has a stored prior location from an earlier login.
2. The new lookup returns coordinates that are within a plausible distance and speed threshold.
3. The app updates the last-login metadata and completes the login normally.

### SP-03: Impossible Travel Is Detected
1. The user has a stored prior location and a prior login time.
2. The new lookup returns a distant coordinate pair and the computed speed exceeds `1000 km/h`.
3. The app logs a warning, resets the user's `is_verified` to `0`, re-issues a verification email, and returns the standard unverified `401` response.

### SP-04: Local or Unconfigured IP Degrades Safely
1. The request comes from `127.0.0.1` or a private address, or the API is not configured.
2. The geolocation check is bypassed.
3. The app updates the `last_login_ip` / `last_login_time` columns and allows the login to continue.

### SP-05: Provider Error Is Fail-Open
1. The geolocation provider is unreachable or returns malformed data.
2. The lookup helper logs a warning and returns a degrade-safe result.
3. The login proceeds and the last-login metadata is updated without coordinates.

---

## 7. Edge Cases

- **EC-01 — No prior coordinates:** the feature skips the distance/speed check and updates only the last-login time/IP.
- **EC-02 — Missing or malformed provider response:** the lookup helper treats it as a provider failure and allows login (fail-open).
- **EC-03 — Localhost/private IP:** bypass the check; no geolocation lookup is attempted.
- **EC-04 — Invalid/empty IP string:** treat it as unresolvable and fall back to the degrade-safe path.
- **EC-05 — Existing user already unverified:** the impossible-travel branch still forces `is_verified = 0` and re-issues the verification email; the response remains the existing unverified `401`.
- **EC-06 — DB error while updating login metadata:** the login path must not fail solely because the metadata update did not persist; the core auth result remains the primary outcome.
- **EC-07 — Provider configured but slow:** the call remains bounded by a timeout; on timeout it fails open.
- **EC-08 — Existing account with no prior login history:** the detection uses the current login as the first known location and does not flag it.

---

## 8. Acceptance Criteria

- **AC-01:** A fresh DB's `users` table has `last_login_ip`, `last_login_time`, `last_login_lat`, and `last_login_lon` after startup.
- **AC-02:** A pre-existing DB gains those columns on first boot via `ALTER TABLE` without any row rewrite; the migration is idempotent.
- **AC-03:** A successful password login updates the `last_login_*` columns with the current IP/time and, when available, coordinates.
- **AC-04:** A login with a distant prior location that implies a speed above `1000 km/h` triggers the impossible-travel branch: a warning is logged, `is_verified` becomes `0`, a new verification email is issued, and the response is the standard unverified `401`.
- **AC-05:** Localhost/private IPs, missing config, or provider outages bypass the detection and allow login while updating the last-login time/IP.
- **AC-06:** No new dependency is introduced and all SQL statements remain parameterized.

---

## 9. Test Cases

| ID | Scenario | Steps | Expected Result |
|----|----------|-------|------------------|
| TC-01 | Fresh DB schema | Start the app with a new `vulnerable_app.db` | `users` contains the four `last_login_*` columns with the expected defaults |
| TC-02 | Existing DB migration | Start the app against an older DB file | Columns are added in place; existing rows remain intact |
| TC-03 | Plausible travel | Login twice from nearby coordinates | The second login succeeds and updates the metadata |
| TC-04 | Impossible travel | Login from a far-away location with a short elapsed time | Login returns the unverified `401`, `is_verified` becomes `0`, and a verification email is issued |
| TC-05 | Local/private IP | Login from `127.0.0.1` or a private address | The detection is bypassed; the last-login metadata is updated without coordinates |
| TC-06 | Provider outage | Simulate a provider timeout/error | Login proceeds and the app logs a warning; no session is blocked |
| TC-07 | SQL safety | Inspect the new/modified SQL | All statements use bound parameters (`?`) |
| TC-08 | Output safety | Trigger the suspicious-login path | No raw IP/geo data is reflected into the response body |

---

## 10. Verification Steps

Run the app and verify the feature end to end:

```bash
cd backend && uv sync
cd ..
uv run backend/app/main.py
```

Then verify the behavior at the following URLs:

- `http://localhost:3001/login` — confirm the login page still works and the existing login flow is unchanged.
- `http://localhost:3001/` or `http://localhost:3001/welcome` — verify that a normal successful login still produces a session and reaches the authenticated area.
- `http://localhost:3001/check-email` — verify that a suspicious login that triggers the impossible-travel branch sends the user to the existing verification-email flow.

Optional manual verification commands:

```bash
curl -i http://localhost:3001/login
sqlite3 vulnerable_app.db "PRAGMA table_info(users);"
```

Expected outcome: the new columns exist, a normal login updates the metadata, and an impossible-travel login forces the user back through the existing unverified-email path without weakening any of the closed vulnerabilities.
