# Implementation Plan — Geolocation & Impossible Travel Detection

**Spec:** [impossible-travel.md](./impossible-travel.md)
**Target Release Tag:** v2.1.0
**Feature #:** 9 (README "Feature Enhancements")

This plan turns the spec into ordered, surgical steps. It adds **one** new backend module (`core/geo.py`), edits **three** backend files (`db/session.py`, `core/config.py`, `services/auth_service.py`), and updates **two** documentation files (`README.md`, `CLAUDE.md`). **No** changes are made to `auth.py`, `login.html`, or any middleware modules.

Key facts grounding this plan (verified against the current tree):
- `auth_service.login()` currently performs the lockout gate, password verification, the unverified gate, 2FA branches, and then writes the session keys (`user_id` / `username` / `email`) just before returning success.
- `verification_service.start_verification()` already exists and uses a parameterized UPDATE plus a mailer send path; it is the correct re-verification hook.
- `db/session.py` already uses idempotent `ALTER TABLE ... ADD COLUMN ...` migrations for previous features; the new geolocation columns should follow that exact pattern.
- The current login flow stays thin in `auth.py`; the geolocation logic belongs in the service layer, not in the route handlers.

---

## Step 0 — Branch & preconditions
- Work on a dedicated branch such as `feature/impossible-travel`.
- Confirm the app still runs with the current stack and that the existing login flow is unchanged except for the new gate.
- Keep the hard constraints visible during implementation:
  - **No new dependency** — only `math`, `urllib`, `json`, and the existing stdlib stack.
  - **All SQL updates must be parameterized**.
  - **`auth.py` routes, `login.html`, and middleware modules remain completely untouched.**

## Step 1 — `backend/app/db/session.py` (schema additions, idempotent migration)
Extend the existing `users` migration pattern with four additive columns that mirror the earlier v1.x schema changes.

```python
# In the module docstring / schema notes, add a short note for the new feature:
# - `last_login_ip TEXT`: the most recent successful login IP, or NULL.
# - `last_login_time REAL`: Unix epoch seconds of the most recent successful login.
# - `last_login_lat REAL`: the most recent successful login latitude, or NULL.
# - `last_login_lon REAL`: the most recent successful login longitude, or NULL.
```

```python
# In the CREATE TABLE IF NOT EXISTS users (...) block, append the new columns:
# last_login_ip TEXT,
# last_login_time REAL,
# last_login_lat REAL,
# last_login_lon REAL,
```

```python
# In the migrations dict, append the v2.1.0 columns using the same pattern as
# the earlier additive features. No grandfather UPDATE is needed.
migrations = {
    ...,
    # Geolocation / Impossible Travel feature (v2.1.0)
    "last_login_ip": "ALTER TABLE users ADD COLUMN last_login_ip TEXT",
    "last_login_time": "ALTER TABLE users ADD COLUMN last_login_time REAL",
    "last_login_lat": "ALTER TABLE users ADD COLUMN last_login_lat REAL",
    "last_login_lon": "ALTER TABLE users ADD COLUMN last_login_lon REAL",
}
```

Implementation notes:
- Keep the same `existing = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}` pattern.
- Do not add any `UPDATE users SET ...` for legacy rows; the defaults are simply `NULL` until the next successful login.
- Keep the migration idempotent and row-preserving.

## Step 2 — `backend/app/core/config.py` (optional geolocation settings)
Add a small config block for the external lookup feature, using the same env/`.env` style as the existing feature settings.

```python
# --- Geolocation / Impossible Travel settings (v2.1.0) ---
# Optional: use a free IP-geolocation provider. If unset or misconfigured, the
# feature degrades safely (skip the lookup and update only the last-login time/ip).
GEO_API_URL = os.environ.get("GEO_API_URL", "")
GEO_HTTP_TIMEOUT = float(os.environ.get("GEO_HTTP_TIMEOUT", "5"))


def is_geo_configured() -> bool:
    """Return True when a geolocation endpoint is configured."""
    return bool(GEO_API_URL)
```

Implementation notes:
- Keep the values non-secret and optional.
- The feature must degrade safely when the setting is empty or malformed.

## Step 3 — `backend/app/core/geo.py` (new module; stdlib lookup + Haversine math)
Create a new helper module that owns all geolocation logic, keeps SQL out of the module, and uses only stdlib networking and math.

```python
"""Geolocation helpers for impossible-travel detection.

Uses stdlib urllib/json/math only. The login flow calls this helper after
successful password verification; any provider issue is treated as a fail-open
condition so legitimate users are not blocked by a transient outage.
"""
import ipaddress
import json
import logging
import math
import urllib.parse
import urllib.request

from app.core import config

logger = logging.getLogger(__name__)


def normalize_ip(raw_ip: str) -> str:
    """Normalize/clean an IP string for downstream checks."""
    if not raw_ip:
        return ""
    return raw_ip.strip()


def is_local_or_private(raw_ip: str) -> bool:
    """Return True for localhost/private IPs that should bypass lookup."""
    ip_text = normalize_ip(raw_ip)
    if not ip_text:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return True
    return ip_obj.is_loopback or ip_obj.is_private


def lookup_coordinates(raw_ip: str) -> dict | None:
    """Look up coordinates for a non-private IP using a free geo API.

    Returns {"lat": float, "lon": float} when available, otherwise None.
    Any exception is treated as a fail-open condition."""
    if not config.is_geo_configured() or is_local_or_private(raw_ip):
        return None

    try:
        url = config.GEO_API_URL.format(ip=normalize_ip(raw_ip))
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=config.GEO_HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        lat = data.get("lat")
        lon = data.get("lon")
        if lat is None or lon is None:
            return None
        return {"lat": float(lat), "lon": float(lon)}
    except Exception:
        logger.warning("Geolocation lookup failed; allowing login and updating metadata without coordinates.")
        return None


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return the great-circle distance in kilometers between two points."""
    radius_km = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    a = (
        math.sin(delta_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return radius_km * c


def should_flag_impossible_travel(
    prev_lat: float | None,
    prev_lon: float | None,
    prev_time: float | None,
    curr_lat: float | None,
    curr_lon: float | None,
    curr_time: float | None,
) -> bool:
    """Return True when travel speed exceeds 1000 km/h between two known points."""
    if None in (prev_lat, prev_lon, prev_time, curr_lat, curr_lon, curr_time):
        return False
    if curr_time <= prev_time:
        return False
    distance_km = haversine_km(prev_lat, prev_lon, curr_lat, curr_lon)
    elapsed_hours = (curr_time - prev_time) / 3600.0
    if elapsed_hours <= 0:
        return False
    speed_kmh = distance_km / elapsed_hours
    return speed_kmh > 1000.0
```

Implementation notes:
- The module uses **stdlib only** and never performs SQL.
- `lookup_coordinates()` is intentionally fail-open and returns `None` on any exception or invalid response.
- The function names and logic keep the implementation testable in isolation.

## Step 4 — `backend/app/services/auth_service.py` (integrate geo-check inside `login()`)
Add the geolocation import and wire the check into `login()` immediately after the successful password verification branch and before the existing unverified / 2FA / session-writing logic.

```python
import time

from app.core import config, geo
```

```python
# After the existing lockout reset and before the existing email-verification gate:
if user and verify_password(password, user["password"]):
    lockout_service.reset(user["id"])

    # 1) Determine the current IP and look up coordinates (fail-open on errors).
    current_ip = request.client.host if request.client else ""
    current_time = time.time()
    current_coords = geo.lookup_coordinates(current_ip)

    # 2) Compare against the user's prior location if it exists.
    prev_lat = user["last_login_lat"]
    prev_lon = user["last_login_lon"]
    prev_time = user["last_login_time"]
    suspicious = False
    if current_coords is not None:
        suspicious = geo.should_flag_impossible_travel(
            prev_lat,
            prev_lon,
            prev_time,
            current_coords["lat"],
            current_coords["lon"],
            current_time,
        )

    # 3) If suspicious, log, clear verification, re-issue email, and return the
    #    existing unverified 401 shape without creating a session.
    if suspicious:
        logger.warning("Impossible travel detected for user %s from %s", user["username"], current_ip)
        conn = get_db()
        try:
            conn.execute(
                "UPDATE users SET is_verified = 0 WHERE id = ?",
                [user["id"]],
            )
            conn.commit()
        finally:
            conn.close()
        verification_service.start_verification(user["id"], user["username"], user["email"], background=True)
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

    # 4) On the normal path, update the last-login metadata with parameterized SQL.
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET last_login_ip = ?, last_login_time = ?, last_login_lat = ?, last_login_lon = ? WHERE id = ?",
            [
                current_ip,
                current_time,
                current_coords["lat"] if current_coords else None,
                current_coords["lon"] if current_coords else None,
                user["id"],
            ],
        )
        conn.commit()
    finally:
        conn.close()

    # 5) Continue with the existing unverified / 2FA / session-writing branches.
    if not user["is_verified"]:
        return JSONResponse(...)
    ...
```

Implementation notes:
- The check should run after password verification succeeds and before any session creation.
- The update to `last_login_*` should happen on the successful path and on the degrade-safe branch (local/private/unconfigured provider).
- The suspicious branch returns the existing unverified `401` body so the frontend continues to behave the same way.
- The SQL update is parameterized; do not concatenate user input into SQL.

## Step 5 — `README.md` (release row + feature note)
Add the new release row and a short feature entry in the same style as the existing release table.

```md
| **v2.1.0** | Students who want the reference **plus impossible-travel detection** | Everything in v2.0.0 plus **Geolocation & Impossible Travel Detection**: on successful password login the app checks the current IP against the user's prior login coordinates and time, and if the movement implies travel faster than 1000 km/h it re-verifies the account and forces the user back through the existing email-verification flow. Local/private IPs, missing config, and provider outages degrade safely (the login still proceeds and the last-login metadata is updated). |
```

```md
### Geolocation & Impossible Travel Detection — Setup (optional)

As of **v2.1.0**, password logins can consult a free geolocation provider and compare the new location with the user's previous login coordinates. The feature degrades safely when the IP is localhost/private, when no provider is configured, or when the provider is unreachable. No new dependency is added; the lookup uses Python's standard-library `urllib` and `math` only.

1. Add a free geolocation endpoint in `.env` (for example, `GEO_API_URL=https://ip-api.com/json/{ip}`).
2. Optionally set `GEO_HTTP_TIMEOUT` to a small value (for example `5`) if you want to bound the lookup latency.
3. Restart the app; if the endpoint is missing or unreachable the app still allows login and updates the last-login metadata.
```

Implementation notes:
- Keep the README in the same tone and release-table shape as the existing document.
- Mention that the feature is additive and does not change the existing login route or middleware.

## Step 6 — `CLAUDE.md` (integration note + invariant entry)
Add a concise integration section and one Important-Rules entry that preserves the feature’s constraints.

```md
- **Geolocation & Impossible Travel Detection (shipped in v2.1.0):** on successful password login the app compares the current IP's coordinates with the user's last known location and time; if the movement implies travel faster than 1000 km/h the app logs a warning, clears `is_verified`, re-issues a verification email, and returns the standard unverified `401`. Local/private IPs, missing config, and provider outages degrade safely (allow login and update the last-login metadata without coordinates). The lookup uses stdlib `urllib` / `json` / `math` only, no new dependency, and the schema change is additive (`last_login_ip`, `last_login_time`, `last_login_lat`, `last_login_lon`).
```

```md
- The Geolocation feature must stay additive: `auth.py`, `login.html`, `main.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, and the middleware stack are unchanged; the check lives in `auth_service.login()` + `core/geo.py` and the schema is added in `db/session.py` only. All SQL updates remain parameterized, the provider is fail-open on errors, and local/private IPs bypass the lookup.
```

Implementation notes:
- Place the new bullet in the same “Frontend-Backend Integration” section style as the rest of the file.
- Add the new spec/plan pair to the Specification Hierarchy if the repository’s CLAUDE.md currently enumerates the feature specs in order.

## Step 7 — Verification mapping to the spec
This is the proof checklist after implementation:

1. **AC-01 / AC-02 (schema):** start the app against a fresh DB and an older DB; verify that `PRAGMA table_info(users)` shows the four new columns and that the migration is idempotent.
2. **AC-03 (normal login updates DB):** log in successfully and query the row to confirm `last_login_ip`, `last_login_time`, `last_login_lat`, and `last_login_lon` are updated.
3. **AC-04 (impossible travel branch):** seed a plausible prior location/time and simulate a distant newer lookup; verify that the login returns the expected unverified `401`, `is_verified` becomes `0`, and a verification email is re-issued.
4. **AC-05 (fail-open / degrade):** test local/private IP and an unreachable provider; verify that the login still proceeds and updates the metadata without coordinates.
5. **AC-06 (no new dependency / parameterized SQL):** audit the diff and confirm that only the intended files changed, that `pyproject.toml` / `backend/pyproject.toml` / `uv.lock` are untouched, and that the new/updated SQL uses `?` placeholders.

## Step 8 — Suggested execution order
1. `db/session.py` (schema first so the rest of the code can target real columns).
2. `core/config.py` + `core/geo.py` (core service and dependency-free lookup logic).
3. `services/auth_service.py` (auth flow wiring and DB updates).
4. `README.md` + `CLAUDE.md` (docs last, once the behavior is implemented and verified).

## Ordering rationale
Schema first keeps the implementation grounded in the real DB shape; the core helper comes next because the auth service depends on it; auth logic comes after that so the new behavior can be embedded at the correct trigger point; docs are last because they reflect the finished behavior rather than the intermediate scaffolding. Each step is individually testable and reversible.

## Risk notes
- **Synchronous network call inside the auth flow:** the geo lookup is a blocking `urllib` call inside the login handler. The implementation should use a short timeout and keep the failure mode fail-open so a provider outage cannot lock out legitimate users.
- **Localhost / IPv6 / private addresses:** the helper should treat loopback and private addresses as degrade-safe, and it should not attempt an external lookup for malformed or non-routable IP strings.
- **Fail-open semantics:** the feature is a security signal, not the auth mechanism. A provider outage must never become a denial-of-service path.
- **No route/UI changes:** the flow uses the existing unverified 401 path and remains inside the service layer, which keeps the feature surgical and avoids touching the login template or route handlers.
