"""SQLite connection and schema initialization.

This lab uses a single SQLite file (`vulnerable_app.db` at the repo root) as
its only datastore. The file is auto-created on first launch by init_db(),
which runs once from main.py at startup.

Why SQLite and not Postgres/MySQL? The app is an educational lab meant to be
clonable and runnable with zero infrastructure. SQLite ships with Python,
needs no server, and lets students reset the data layer with a single `rm`.
"""

import sqlite3
import os

# Absolute path to the database file: <repo>/vulnerable_app.db.
# The four `..` segments climb from this file (backend/app/db/session.py)
# back up to the project root. We resolve this at import time so the path
# is stable regardless of which directory uvicorn was launched from.
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "vulnerable_app.db")


def get_db():
    """Open a fresh SQLite connection.

    Callers are responsible for closing the returned connection (use
    try/finally or `with`). Each handler opens its own connection so we
    do not need a connection pool -- SQLite's file-level locking is
    sufficient for a single-process educational lab.

    - check_same_thread=False: required because FastAPI runs handlers on
      an asyncio event loop that may dispatch them across threads. SQLite
      objects are not normally thread-safe; this flag tells sqlite3 to
      trust us to serialize access ourselves (we do, by opening one
      connection per request and never sharing it).
    - row_factory = sqlite3.Row: makes cursor.fetchone() return a Row
      object that supports both `row[0]` and `row["username"]` access,
      so auth_service.login() can read `user["password"]` by column name.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create -- or upgrade -- the users table.

    Called once from main.py at app startup. Idempotent and row-preserving:
    a fresh DB gets the full schema below; a pre-existing DB (e.g. from
    v1.0.2, before Continue-with-Google) is migrated IN PLACE by adding any
    of the four OAuth columns that are missing. No row is ever dropped.

    Schema notes:
    - `username TEXT UNIQUE`: signup relies on this to surface
      "Username already exists" via sqlite3.IntegrityError.
    - `password TEXT` (NULLABLE): local accounts store the bcrypt hash
      string; Google (OAuth-only) accounts store NULL -- there is no weak
      hash to leak, and the unchanged password login() fails closed on a
      NULL hash, so such accounts simply cannot log in with a password.
    - `google_id TEXT UNIQUE`: the user's stable Google subject id, or NULL
      for local accounts. SQLite allows multiple NULLs under UNIQUE, so
      local users coexist freely.
    - `name` / `picture`: the Google profile display name and avatar URL
      (stored, not rendered in this release).
    - `auth_provider TEXT DEFAULT 'local'`: 'local' or 'google'.
    - `is_verified INTEGER DEFAULT 0`: 0 = email not yet confirmed, 1 = verified.
      Google (OAuth) accounts are created as 1; existing rows that predate the
      Email-Verification feature are grandfathered to 1 by the migration below.
    - `verification_token TEXT`: the active single-use email-verification token
      (`secrets.token_urlsafe(32)`), or NULL when none is outstanding.
    - `verification_token_expires REAL`: Unix epoch seconds after which the
      token is dead, or NULL. Compared against `time.time()` on /verify.
    - `failed_login_attempts INTEGER DEFAULT 0`: consecutive failed credential
      checks since the last success / lock (Account-Lockout feature, v1.0.5).
      Reset to 0 on any correct password.
    - `locked_until REAL`: Unix epoch seconds until which the account is locked
      out after too many consecutive failures, or NULL when not locked.
      Compared against `time.time()` on every login / resend.
    - `two_factor_enabled INTEGER DEFAULT 0`: 1 when the user opted into Email
      OTP 2FA (Email-OTP-2FA feature, v1.0.6); a correct password then issues an
      emailed code instead of completing login immediately. Defaults to 0 (off),
      so existing rows are unaffected without a grandfather UPDATE.
    - `otp_code TEXT`: the current outstanding 6-digit login OTP (raw), or NULL
      when no challenge is pending. Single-use: cleared on a successful verify.
    - `otp_expires REAL`: Unix epoch seconds after which the OTP is dead, or NULL.
      Compared against `time.time()` on /login/otp.
    - `otp_attempts INTEGER DEFAULT 0`: wrong-OTP submissions against the current
      code; reset to 0 on each new code, and the code is invalidated when this
      reaches OTP_MAX_ATTEMPTS.
    - `otp_last_sent REAL`: Unix epoch seconds of the most recent OTP send, used
      to enforce the per-account resend cooldown, or NULL.
    - `totp_secret TEXT`: the base32 authenticator-app TOTP shared secret
      (MFA-via-Authenticator-App feature, v1.0.7). Set as *pending* when
      enrollment starts, persists while enrolled, NULL when the user has none.
    - `totp_enabled INTEGER DEFAULT 0`: 1 only after a confirm code validated the
      secret; 0 while disabled or while a secret is pending (generated but not yet
      confirmed). Defaults to 0, so existing rows need no grandfather UPDATE.
    - `totp_last_step INTEGER`: the last accepted TOTP time-step counter, for
      replay protection (a code already used cannot be reused inside its window);
      NULL until the first successful verify.
    """
    conn = get_db()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id                         INTEGER PRIMARY KEY AUTOINCREMENT,
            username                   TEXT UNIQUE,
            email                      TEXT,
            password                   TEXT,
            google_id                  TEXT UNIQUE,
            name                       TEXT,
            picture                    TEXT,
            auth_provider              TEXT DEFAULT 'local',
            is_verified                INTEGER DEFAULT 0,
            verification_token         TEXT,
            verification_token_expires REAL,
            failed_login_attempts      INTEGER DEFAULT 0,
            locked_until               REAL,
            two_factor_enabled         INTEGER DEFAULT 0,
            otp_code                   TEXT,
            otp_expires                REAL,
            otp_attempts               INTEGER DEFAULT 0,
            otp_last_sent              REAL,
            totp_secret                TEXT,
            totp_enabled               INTEGER DEFAULT 0,
            totp_last_step             INTEGER
        )"""
    )

    # Migrate older databases in place: add any missing OAuth columns. Note
    # that ALTER TABLE ADD COLUMN cannot carry a UNIQUE constraint in SQLite,
    # so a migrated `google_id` lacks the table-level UNIQUE; uniqueness is
    # still enforced in practice because the service always SELECTs by
    # google_id before inserting. Fresh DBs get UNIQUE from CREATE TABLE above.
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    migrations = {
        "google_id": "ALTER TABLE users ADD COLUMN google_id TEXT",
        "name": "ALTER TABLE users ADD COLUMN name TEXT",
        "picture": "ALTER TABLE users ADD COLUMN picture TEXT",
        "auth_provider": "ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT 'local'",
        # Email-Verification feature (v1.0.4): three nullable/defaulted columns.
        "is_verified": "ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0",
        "verification_token": "ALTER TABLE users ADD COLUMN verification_token TEXT",
        "verification_token_expires": "ALTER TABLE users ADD COLUMN verification_token_expires REAL",
        # Account-Lockout feature (v1.0.5): two columns. The defaults (0 / NULL)
        # already mean "no failures, not locked", so -- unlike is_verified --
        # NO grandfather UPDATE is needed; existing rows are correct as-is.
        "failed_login_attempts": "ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0",
        "locked_until": "ALTER TABLE users ADD COLUMN locked_until REAL",
        # Email OTP 2FA feature (v1.0.6): five columns. The defaults (0 / NULL)
        # already mean "2FA off, no challenge outstanding", so -- like the
        # lockout columns -- NO grandfather UPDATE is needed.
        "two_factor_enabled": "ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0",
        "otp_code": "ALTER TABLE users ADD COLUMN otp_code TEXT",
        "otp_expires": "ALTER TABLE users ADD COLUMN otp_expires REAL",
        "otp_attempts": "ALTER TABLE users ADD COLUMN otp_attempts INTEGER DEFAULT 0",
        "otp_last_sent": "ALTER TABLE users ADD COLUMN otp_last_sent REAL",
        # MFA via Authenticator App (TOTP) feature (v1.0.7): three columns. The
        # defaults (NULL / 0 / NULL) already mean "no secret, TOTP off, never
        # used", so -- like the lockout/otp columns -- NO grandfather UPDATE is
        # needed; existing rows are correct as-is.
        "totp_secret": "ALTER TABLE users ADD COLUMN totp_secret TEXT",
        "totp_enabled": "ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0",
        "totp_last_step": "ALTER TABLE users ADD COLUMN totp_last_step INTEGER",
    }
    for column, ddl in migrations.items():
        if column not in existing:
            conn.execute(ddl)
            if column == "is_verified":
                # Grandfather: accounts that predate email verification are
                # treated as already verified, so the migration does not
                # retroactively lock them behind the "verify your email"
                # banner. This runs exactly once -- on the boot that first
                # adds the column to a pre-existing database. (On a fresh DB
                # the column comes from CREATE TABLE above and is never in
                # this branch, so new signups keep their explicit 0.)
                conn.execute("UPDATE users SET is_verified = 1")

    # Forgot Password (v2.1.0): brand-new table for token-based password reset.
    # Stores ONLY the SHA-256 hash of the token (never the plaintext) and the
    # expiry / used state. The plaintext lives only in the email and in the
    # user's URL bar. No ALTER TABLE is needed (this is a brand-new table, not
    # a column on an existing one); CREATE TABLE IF NOT EXISTS makes the
    # migration idempotent on every boot.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            expires_at REAL NOT NULL,
            used       INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()
