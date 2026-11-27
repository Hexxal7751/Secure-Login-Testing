import os
import re
import json
import hmac
import base64
import hashlib
import secrets
import logging
import gzip
import threading
import time
import ipaddress
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO

import bcrypt
import psycopg2
import pyotp
import qrcode
from psycopg2 import errors as pg_errors
from psycopg2 import pool as pg_pool
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from flask import (
    Flask, abort, request, render_template, redirect, url_for, session, flash,
    make_response, jsonify, g, has_request_context,
)
from werkzeug.exceptions import HTTPException
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from security_logging import log_security_event
from security_middleware import validate_email

# Load environment variables
load_dotenv()

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s request_id=%(request_id)s %(message)s",
)


class _RequestIdFilter(logging.Filter):
    """Adds request_id=<id> to every log line so one request can be searched in Render."""
    def filter(self, record):
        try:
            record.request_id = g.get("request_id", "-") if has_request_context() else "-"
        except Exception:
            record.request_id = "-"
        return True


for _h in logging.getLogger().handlers:
    _h.addFilter(_RequestIdFilter())
app.secret_key = os.getenv("FLASK_PASS")

# Trust proxy headers (needed on Render)
app.config["PREFERRED_URL_SCHEME"] = "https"
if os.getenv("FLASK_ENV") == "production":
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Session security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_REFRESH_EACH_REQUEST"] = True

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# WebAuthn
RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = "Secure Login Testing"
ORIGIN = os.getenv("ORIGIN", "http://localhost:10000").strip().rstrip("/")

# Google sign-in (OpenID Connect)
def _clean_env(value):
    """Trim spaces and quotes that often get pasted along with a value."""
    return (value or "").strip().strip("\"'").strip()


GOOGLE_CLIENT_ID = _clean_env(os.getenv("GOOGLE_CLIENT_ID"))
GOOGLE_CLIENT_SECRET = _clean_env(os.getenv("GOOGLE_CLIENT_SECRET"))
GOOGLE_REDIRECT_URI = _clean_env(os.getenv("GOOGLE_REDIRECT_URI")) or f"{ORIGIN}/auth/google/callback"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# Email is sent over HTTPS (Render's free tier blocks SMTP). Pick ONE option in .env:
#  A) AgentMail (no domain needed): AGENTMAIL_API_KEY + AGENTMAIL_INBOX (e.g. sltesting@agentmail.to)
#  B) Resend (needs a domain you own): RESEND_API_KEY + MAIL_FROM (e.g. login@yourdomain.com)
AGENTMAIL_API_KEY = os.getenv("AGENTMAIL_API_KEY", "").strip()
AGENTMAIL_INBOX = os.getenv("AGENTMAIL_INBOX", "").strip()
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()
MAIL_FROM = os.getenv("MAIL_FROM", "").strip()
MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME", "Secure Login Testing").strip()
HTTP_UA = "secure-login-testing/1.0"

EMAIL_CODE_TTL = timedelta(minutes=10)
EMAIL_CODE_MAX_ATTEMPTS = 5
DEL_TTL = timedelta(minutes=10)
PENDING_GOOGLE_TTL = timedelta(minutes=15)
RESET_TTL = timedelta(minutes=15)
ACT_TTL = timedelta(minutes=10)
SESSION_IDLE = timedelta(minutes=30)

CLIENT_IP_HEADER = _clean_env(os.getenv("CLIENT_IP_HEADER"))   # e.g. CF-Connecting-IP (optional)
try:
    PROXY_HOPS = max(1, int(os.getenv("PROXY_HOPS", "1")))        # proxies between the internet and the app
except ValueError:
    PROXY_HOPS = 1


def check_config():
    """Log obvious configuration mistakes at startup (values are never printed)."""
    if not os.getenv("FLASK_PASS"):
        app.logger.error("FLASK_PASS is not set: sessions will not work.")
    url = os.getenv("SUPABASE_URL") or ""
    if not url.startswith(("postgresql://", "postgres://")):
        app.logger.error("SUPABASE_URL is missing or doesn't start with postgresql://")
    if os.getenv("FLASK_ENV") == "production" and not (CLIENT_IP_HEADER or os.getenv("PROXY_HOPS")):
        app.logger.warning("Client IP detection uses the default (last X-Forwarded-For entry). "
                           "Open /admin/network after signing in to check it shows YOUR IP.")
    if GOOGLE_CLIENT_ID and not GOOGLE_CLIENT_ID.endswith(".apps.googleusercontent.com"):
        app.logger.warning("GOOGLE_CLIENT_ID doesn't end with .apps.googleusercontent.com")
    if GOOGLE_CLIENT_ID and not (GOOGLE_CLIENT_SECRET.startswith("GOCSPX-") and len(GOOGLE_CLIENT_SECRET) == 35):
        app.logger.warning(
            "GOOGLE_CLIENT_SECRET looks wrong: expected 35 characters starting with GOCSPX-, got %d characters.",
            len(GOOGLE_CLIENT_SECRET))


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
def rate_key():
    """Rate-limit counters are per visitor IP (see client_ip), not per Render proxy."""
    try:
        return client_ip() or get_remote_address()
    except Exception:
        return get_remote_address()


# REDIS_URL keeps the counters across restarts and workers (Render Key Value or Upstash).
# Without it the counters live in memory. If Redis is down the limiter falls back to memory.
REDIS_URL = _clean_env(os.getenv("REDIS_URL"))
app.config["RATELIMIT_ENABLED"] = os.getenv("RATELIMIT_ENABLED", "true").strip().lower() != "false"
limiter = Limiter(
    key_func=rate_key,
    app=app,
    default_limits=["2000 per day", "300 per hour"],
    storage_uri=REDIS_URL or "memory://",
    storage_options={"socket_connect_timeout": 2, "socket_timeout": 2} if REDIS_URL else {},
    strategy="fixed-window",
    swallow_errors=True,
    in_memory_fallback_enabled=bool(REDIS_URL),
)

login_limit = "5 per minute; 20 per hour"

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
TOTP_REGEX = re.compile(r"^\d{6}$")
# Password-reset codes: 8 letters/digits, no look-alikes (no I, O, 0, 1)
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
RESET_CODE_REGEX = re.compile(r"^[A-HJ-NP-Z2-9]{8}$")
RECOVERY_REGEX = re.compile(r"^[A-HJ-NP-Z2-9]{10}$")

# Used so unknown users / Google-only users cost the same time as a real check
DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt()).decode("utf-8")


def utcnow():
    """Naive UTC 'now' (matches how timestamps are stored)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def mask_email(email):
    if not email or "@" not in email:
        return ""
    name, domain = email.split("@", 1)
    return f"{name[:1]}***@{domain}"


def log_event(event_type, details=None, level="INFO"):
    """Security logging must never break a request. Goes to the logs and to the admin event list."""
    details = details or {}
    try:
        log_security_event(event_type, details, level)
    except Exception:
        app.logger.exception("security log failed")
    try:
        uid = details.get("user_id")
        ip = ""
        if has_request_context():
            uid = uid or session.get("user_id")
            ip = client_ip()
        row = (utcnow(), event_type, level, uid, ip, json.dumps(details, default=str)[:900])
        run_async(lambda: db_run(
            "INSERT INTO security_events (at, event, level, user_id, ip, details) VALUES (%s, %s, %s, %s, %s, %s)",
            row, admin=True))
    except Exception:
        app.logger.exception("security event store failed")


def get_nonce():
    if "csp_nonce" not in g:
        g.csp_nonce = secrets.token_hex(16)
    return g.csp_nonce


@app.before_request
def before_request():
    get_nonce()
    g.request_id = secrets.token_hex(4)
    g.t0 = time.perf_counter()
    g.db_n, g.db_ms = 0, 0.0


def asset_url(filename):
    """/static URL with the file's modification time, so browsers can cache it for a year."""
    try:
        version = int(os.path.getmtime(os.path.join(app.static_folder, filename)))
    except OSError:
        version = 0
    return url_for("static", filename=filename, v=version)


@app.context_processor
def inject_nonce():
    return {"csp_nonce": get_nonce(), "asset": asset_url}


@app.before_request
def enforce_https():
    if os.getenv("FLASK_ENV") == "production":
        is_secure = request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"
        if not is_secure and request.url.startswith("http://"):
            return redirect(request.url.replace("http://", "https://", 1), code=301)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
_GZ_CACHE = {}
COMPRESSIBLE = {"text/html", "text/css", "application/javascript", "text/javascript", "application/json",
                "image/svg+xml", "text/plain"}


def compress_response(response):
    """gzip text responses (HTML, CSS, JS, JSON): pages become about 5x smaller on slow phone networks."""
    try:
        if (response.status_code != 200 or "Content-Encoding" in response.headers
                or "gzip" not in request.headers.get("Accept-Encoding", "").lower()
                or response.mimetype not in COMPRESSIBLE):
            return response
        response.direct_passthrough = False
        data = response.get_data()
        if len(data) < 600:
            return response
        key = (request.path, len(data)) if request.endpoint == "static" else None
        packed = _GZ_CACHE.get(key) if key else None
        if packed is None:
            packed = gzip.compress(data, compresslevel=6, mtime=0)
            if key:
                _GZ_CACHE[key] = packed
        response.set_data(packed)
        response.headers["Content-Encoding"] = "gzip"
        response.headers.add("Vary", "Accept-Encoding")
    except Exception:
        app.logger.exception("compression failed")
    return response


def log_request_timing(response):
    """One searchable line per page: REQ GET /verify-totp 200 ms=412 db_ms=230 db_n=3 (SLOW if > 1.5 s)."""
    try:
        ms = (time.perf_counter() - g.get("t0", time.perf_counter())) * 1000
        level = logging.WARNING if ms > 1500 else logging.INFO
        app.logger.log(level, "%sREQ %s %s %s ms=%d db_ms=%d db_n=%d", "SLOW " if ms > 1500 else "",
                       request.method, request.path, response.status_code, ms, g.get("db_ms", 0), g.get("db_n", 0))
    except Exception:
        pass


@app.after_request
def add_security_headers(response):
    nonce = get_nonce()
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
        f"style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-src 'none'; "
        "object-src 'none'; "
        "base-uri 'self'"
    )
    response.headers["X-Request-ID"] = g.get("request_id", "-")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    if request.endpoint == "static":
        # versioned files (?v=...) never change, so the browser may keep them for a year
        immutable = "v" in request.args
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable" if immutable else "public, max-age=300"
        response.headers.pop("Pragma", None)
        response.headers.pop("Expires", None)
    else:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        log_request_timing(response)
    return compress_response(response)


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf_token():
    if request.method == "POST":
        token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
        if not token or not hmac.compare_digest(str(token), str(session.get("csrf_token", ""))):
            return False
    return True


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
def _connect():
    url = os.getenv("SUPABASE_URL")
    if not url:
        raise RuntimeError("SUPABASE_URL is not set")
    return psycopg2.connect(url, connect_timeout=10)


def get_db_connection(user_id=None):
    if user_id is None and has_request_context() and "user_id" in session:
        user_id = session["user_id"]

    conn = _connect()

    if user_id is not None:
        with conn.cursor() as cur:
            cur.execute("SET app.current_user_id = %s", (str(user_id),))
            conn.commit()
    else:
        with conn.cursor() as cur:
            cur.execute("SET app.is_admin = true")
            conn.commit()
    return conn


def get_admin_connection():
    """Connection that always runs in admin mode (inserts, deletes, lookups)."""
    conn = _connect()
    with conn.cursor() as cur:
        cur.execute("SET app.is_admin = true")
        conn.commit()
    return conn


def reset_connection_context(conn):
    try:
        with conn.cursor() as cur:
            cur.execute("RESET app.current_user_id")
            cur.execute("RESET app.is_admin")
            conn.commit()
    except Exception as e:
        app.logger.error(f"Error resetting connection context: {e}")
    finally:
        conn.close()


# ----- connection pool: connections are opened once and reused ------------------------------
DB_POOL_MAX = max(2, int(os.getenv("DB_POOL_MAX", "5") or 5))
_pool = None
_pool_lock = threading.Lock()


def _get_pool():
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                url = os.getenv("SUPABASE_URL")
                if not url:
                    raise RuntimeError("SUPABASE_URL is not set")
                _pool = pg_pool.ThreadedConnectionPool(
                    1, DB_POOL_MAX, url, connect_timeout=10,
                    keepalives=1, keepalives_idle=30, keepalives_interval=10, keepalives_count=3)
    return _pool


def _borrow():
    """(connection, came_from_pool). Autocommit is on: every call below is a single round trip."""
    try:
        conn, pooled = _get_pool().getconn(), True
    except pg_pool.PoolError:               # every pooled connection is busy: use a temporary one
        conn, pooled = _connect(), False
    conn.autocommit = True
    return conn, pooled


def _release(conn, pooled, broken=False):
    try:
        if pooled:
            _get_pool().putconn(conn, close=bool(broken or conn.closed))
        else:
            conn.close()
    except Exception:
        pass


def _ctx_sql(user_id, admin):
    """Row-level-security context for ONE transaction (set_config(..., true) = local), sent in the
    same round trip as the query itself."""
    if admin or (user_id is None and not (has_request_context() and "user_id" in session)):
        return "SELECT set_config('app.is_admin', 'true', true); "
    uid = user_id if user_id is not None else session["user_id"]
    return f"SELECT set_config('app.current_user_id', '{int(uid)}', true); "


def _db_exec(sql, params, fetch, user_id, admin):
    """Run one statement on a pooled connection (retries once if the connection had gone stale)."""
    full = _ctx_sql(user_id, admin) + sql
    for attempt in (1, 2):
        conn, pooled = _borrow()
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute(full, params)
            result = cur.fetchone() if fetch == "one" else cur.fetchall() if fetch == "all" else None
            _release(conn, pooled)
            return result
        except (psycopg2.OperationalError, psycopg2.InterfaceError):
            _release(conn, pooled, broken=True)
            if attempt == 2:
                raise
        except Exception:
            _release(conn, pooled)
            raise


def _db_exec_batch(statements, admin, user_id):
    """Several statements in ONE round trip and ONE transaction (all or nothing)."""
    for attempt in (1, 2):
        conn, pooled = _borrow()
        try:
            cur = conn.cursor()
            parts = [cur.mogrify(sql, params) for sql, params in statements]
            cur.execute(_ctx_sql(user_id, admin).encode("utf-8") + b"; ".join(parts))
            _release(conn, pooled)
            return
        except (psycopg2.OperationalError, psycopg2.InterfaceError):
            _release(conn, pooled, broken=True)
            if attempt == 2:
                raise
        except Exception:
            _release(conn, pooled)
            raise


def _db_cache():
    """Per-request memory: the same user/passkey rows are read once per page, not once per helper."""
    return g.setdefault("_dbcache", {}) if has_request_context() else None


def _note_db(started, is_write):
    if has_request_context():
        g.db_n = g.get("db_n", 0) + 1
        g.db_ms = g.get("db_ms", 0.0) + (time.perf_counter() - started) * 1000
        if is_write:
            g.pop("_dbcache", None)


def db_run(sql, params=(), fetch=None, user_id=None, admin=False):
    """Run one statement. fetch: None | 'one' | 'all'."""
    started = time.perf_counter()
    try:
        return _db_exec(sql, params, fetch, user_id, admin)
    finally:
        _note_db(started, not sql.lstrip()[:6].upper() == "SELECT")


def db_batch(statements, admin=True, user_id=None):
    """Run several (sql, params) statements in ONE transaction."""
    started = time.perf_counter()
    try:
        _db_exec_batch(statements, admin, user_id)
    finally:
        _note_db(started, True)


def create_users_table():
    """Create tables and add any missing columns. Safe to run every start."""
    conn = get_admin_connection()
    try:
        cur = conn.cursor()
        statements = [
            """CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password TEXT,
                passkey_enabled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                account_locked_until TIMESTAMP
            )""",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS secret TEXT",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS passkey_enabled BOOLEAN DEFAULT FALSE",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS google_sub TEXT",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(10) DEFAULT 'password'",
            "ALTER TABLE users ALTER COLUMN password DROP NOT NULL",
            "CREATE UNIQUE INDEX IF NOT EXISTS users_google_sub_key ON users (google_sub) WHERE google_sub IS NOT NULL",
            "CREATE UNIQUE INDEX IF NOT EXISTS users_email_verified_key ON users (lower(email)) WHERE email_verified",
            """CREATE TABLE IF NOT EXISTS passkeys (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                credential_id TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                sign_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS email_codes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                purpose VARCHAR(20) NOT NULL,
                email TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                attempts INTEGER DEFAULT 0,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS email_codes_user_idx ON email_codes (user_id, purpose)",
            "ALTER TABLE passkeys ADD COLUMN IF NOT EXISTS name TEXT",
            "ALTER TABLE passkeys ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP",
            """CREATE TABLE IF NOT EXISTS recovery_codes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                code_hash TEXT NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                used_at TIMESTAMP,
                created_at TIMESTAMP NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS recovery_codes_user_idx ON recovery_codes (user_id)",
            """CREATE TABLE IF NOT EXISTS user_sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                ip TEXT,
                user_agent TEXT,
                device TEXT,
                location TEXT,
                method VARCHAR(12),
                completed BOOLEAN DEFAULT FALSE,
                revoked BOOLEAN DEFAULT FALSE,
                ended_at TIMESTAMP
            )""",
            "CREATE INDEX IF NOT EXISTS user_sessions_user_idx ON user_sessions (user_id, created_at)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled BOOLEAN DEFAULT FALSE",
            """CREATE TABLE IF NOT EXISTS trusted_devices (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                device TEXT,
                ip TEXT,
                created_at TIMESTAMP NOT NULL,
                last_used TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS trusted_devices_user_idx ON trusted_devices (user_id)",
            """CREATE TABLE IF NOT EXISTS security_events (
                id SERIAL PRIMARY KEY,
                at TIMESTAMP NOT NULL,
                event TEXT NOT NULL,
                level VARCHAR(10),
                user_id INTEGER,
                ip TEXT,
                details TEXT
            )""",
            "CREATE INDEX IF NOT EXISTS security_events_at_idx ON security_events (at)",
        ]
        for sql in statements:
            try:
                cur.execute(sql)
                conn.commit()
            except Exception as e:
                conn.rollback()
                app.logger.error(f"Migration step failed: {e} :: {sql[:60]}")
    finally:
        reset_connection_context(conn)


def init_db():
    try:
        create_users_table()
    except psycopg2.OperationalError as e:
        app.logger.error(
            "Database setup failed: %s | Check SUPABASE_URL in Render (copy a fresh connection "
            "string from Supabase -> Connect, make sure the project isn't paused).", str(e).strip()[:300])
    except Exception:
        app.logger.exception("Database setup failed")


# Runs under gunicorn too (the old code only ran this under `python app.py`)
check_config()
if not os.getenv("SKIP_DB_INIT"):      # tests set this so no database is needed
    init_db()


def get_user(username):
    return db_run("SELECT * FROM users WHERE username = %s", (username,), fetch="one", admin=True)


def get_user_by_id(user_id):
    cache, key = _db_cache(), ("user", user_id)
    if cache is not None and key in cache:
        return dict(cache[key]) if cache[key] else None
    row = db_run("SELECT * FROM users WHERE id = %s", (user_id,), fetch="one", user_id=user_id)
    if cache is not None:
        cache[key] = row
    return dict(row) if row else None


def get_user_by_google_sub(sub):
    return db_run("SELECT * FROM users WHERE google_sub = %s", (sub,), fetch="one", admin=True)


def get_user_by_verified_email(email):
    return db_run(
        "SELECT * FROM users WHERE lower(email) = lower(%s) AND email_verified = TRUE",
        (email,), fetch="one", admin=True,
    )


def get_user_passkeys(user_id):
    cache, key = _db_cache(), ("passkeys", user_id)
    if cache is not None and key in cache:
        return [dict(r) for r in cache[key]]
    rows = db_run("SELECT * FROM passkeys WHERE user_id = %s ORDER BY id", (user_id,), fetch="all", user_id=user_id) or []
    if cache is not None:
        cache[key] = rows
    return [dict(r) for r in rows]


def save_passkey(user_id, credential_id, public_key, name=None):
    db_run(
        "INSERT INTO passkeys (user_id, credential_id, public_key, name) VALUES (%s, %s, %s, %s)",
        (user_id, credential_id, public_key, name), user_id=user_id,
    )


def update_passkey_sign_count(credential_id, sign_count, user_id):
    db_run(
        "UPDATE passkeys SET sign_count = %s, last_used_at = %s WHERE credential_id = %s",
        (sign_count, utcnow(), credential_id), user_id=user_id,
    )


def get_passkey_by_credential_id(credential_id, user_id):
    return db_run(
        "SELECT * FROM passkeys WHERE credential_id = %s AND user_id = %s",
        (credential_id, user_id), fetch="one", user_id=user_id,
    )


def delete_user_everything(user_id):
    """Remove the account and everything attached to it in one transaction."""
    forget_sessions(user_id=user_id)
    db_batch([
        ("DELETE FROM email_codes WHERE user_id = %s", (user_id,)),
        ("DELETE FROM recovery_codes WHERE user_id = %s", (user_id,)),
        ("DELETE FROM user_sessions WHERE user_id = %s", (user_id,)),
        ("DELETE FROM trusted_devices WHERE user_id = %s", (user_id,)),
        ("DELETE FROM passkeys WHERE user_id = %s", (user_id,)),
        ("DELETE FROM users WHERE id = %s", (user_id,)),
    ])


# ---------------------------------------------------------------------------
# Email sending + one-time codes
# ---------------------------------------------------------------------------
def _post_json(url, payload, headers):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={**headers, "Content-Type": "application/json", "User-Agent": HTTP_UA},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return 200 <= resp.status < 300


def _send_via_resend(to_email, subject, text):
    return _post_json(
        "https://api.resend.com/emails",
        {"from": f"{MAIL_FROM_NAME} <{MAIL_FROM}>", "to": [to_email], "subject": subject, "text": text},
        {"Authorization": f"Bearer {RESEND_API_KEY}"},
    )


def _send_via_agentmail(to_email, subject, text):
    inbox = urllib.parse.quote(AGENTMAIL_INBOX, safe="@")
    return _post_json(
        f"https://api.agentmail.to/v0/inboxes/{inbox}/messages/send",
        {"to": [to_email], "subject": subject, "text": text},
        {"Authorization": f"Bearer {AGENTMAIL_API_KEY}"},
    )


def send_email(to_email, subject, text):
    """Send one plain-text email. Returns True on success."""
    if RESEND_API_KEY and MAIL_FROM:
        sender = _send_via_resend
    elif AGENTMAIL_API_KEY and AGENTMAIL_INBOX:
        sender = _send_via_agentmail
    else:
        if os.getenv("FLASK_ENV") == "development":
            app.logger.warning("[DEV EMAIL] to=%s subject=%s\n%s", to_email, subject, text)
            return True
        app.logger.error("Email is not configured (set AGENTMAIL_API_KEY + AGENTMAIL_INBOX, or RESEND_API_KEY + MAIL_FROM).")
        return False
    try:
        return sender(to_email, subject, text)
    except urllib.error.HTTPError as e:
        app.logger.error("Email provider rejected the message: %s %s", e.code, e.read()[:300])
    except Exception as e:
        app.logger.error("Email send failed: %s", e)
    return False


def _code_hash(user_id, purpose, code):
    key = (app.secret_key or "").encode("utf-8")
    msg = f"{user_id}:{purpose}:{code}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def has_active_code(user_id, purpose):
    row = db_run(
        """SELECT 1 AS ok FROM email_codes
           WHERE user_id = %s AND purpose = %s AND used = FALSE
             AND expires_at > %s AND attempts < %s LIMIT 1""",
        (user_id, purpose, utcnow(), EMAIL_CODE_MAX_ATTEMPTS), fetch="one", admin=True,
    )
    return bool(row)


def issue_email_code(user_id, purpose, email):
    """Create a code (6 digits; 8 letters/digits for password reset) and email it. Returns (ok, error_message)."""
    now = utcnow()
    recent = db_run(
        """SELECT created_at FROM email_codes
           WHERE user_id = %s AND purpose = %s AND created_at > %s
           ORDER BY created_at DESC""",
        (user_id, purpose, now - timedelta(hours=1)), fetch="all", admin=True,
    )
    if len(recent) >= 5:
        return False, "Too many codes requested. Please try again in an hour."
    if recent and (now - recent[0]["created_at"]).total_seconds() < 45:
        return False, "Please wait a moment before requesting another code."

    if purpose == "reset":
        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
        shown = f"{code[:4]}-{code[4:]}"
    else:
        code = f"{secrets.randbelow(1000000):06d}"
        shown = code
    db_batch([
        ("UPDATE email_codes SET used = TRUE WHERE user_id = %s AND purpose = %s AND used = FALSE",
         (user_id, purpose)),
        ("INSERT INTO email_codes (user_id, purpose, email, code_hash, expires_at, created_at) "
         "VALUES (%s, %s, %s, %s, %s, %s)",
         (user_id, purpose, email, _code_hash(user_id, purpose, code), now + EMAIL_CODE_TTL, now)),
    ])

    what = {"register": "finish creating your account",
            "delete": "delete your account",
            "reset": "reset your password",
            "chgpw": "change your password",
            "chgemail_old": "change your email address",
            "chgemail_new": "confirm your new email address",
            "chgtotp": "replace your authenticator app"}.get(purpose, "continue")
    ok = send_email(
        email,
        f"Your Secure Login Testing code: {shown}",
        f"Your verification code is {shown}\n\n"
        f"Use it to {what}. It expires in 10 minutes.\n\n"
        "If you didn't ask for this, you can ignore this email.",
    )
    if not ok:
        return False, "We couldn't send the email. Please try again shortly."
    return True, None


def check_email_code(user_id, purpose, code):
    """Returns (ok, error_message, email_the_code_was_sent_to)."""
    row = db_run(
        """SELECT * FROM email_codes
           WHERE user_id = %s AND purpose = %s AND used = FALSE
           ORDER BY created_at DESC LIMIT 1""",
        (user_id, purpose), fetch="one", admin=True,
    )
    if not row or row["expires_at"] <= utcnow() or row["attempts"] >= EMAIL_CODE_MAX_ATTEMPTS:
        return False, "That code has expired. Request a new one.", None

    if hmac.compare_digest(row["code_hash"], _code_hash(user_id, purpose, code)):
        db_run("UPDATE email_codes SET used = TRUE WHERE id = %s", (row["id"],), admin=True)
        return True, None, row["email"]

    db_run("UPDATE email_codes SET attempts = attempts + 1 WHERE id = %s", (row["id"],), admin=True)
    left = EMAIL_CODE_MAX_ATTEMPTS - row["attempts"] - 1
    if left <= 0:
        return False, "Too many wrong codes. Request a new one.", None
    return False, "Incorrect code. Please try again.", None


# ---------------------------------------------------------------------------
# Auth flow helpers
# ---------------------------------------------------------------------------
def client_ip():
    """The visitor's IP behind Render's proxies.

    1) CLIENT_IP_HEADER, if you set one; 2) the PROXY_HOPS-th entry counted from the RIGHT of
    X-Forwarded-For (entries added by your own proxies cannot be faked by the visitor);
    3) the socket address. Check what your deployment shows at /admin/network.
    """
    ip = ""
    if CLIENT_IP_HEADER:
        ip = request.headers.get(CLIENT_IP_HEADER, "").split(",")[0].strip()
    if not ip:
        parts = [p.strip() for p in request.headers.get("X-Forwarded-For", "").split(",") if p.strip()]
        if parts:
            ip = parts[-PROXY_HOPS] if len(parts) >= PROXY_HOPS else parts[0]
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        ip = request.remote_addr or ""
    return ip[:64]


def device_label(ua):
    """Turn a User-Agent string into something like 'Chrome on Android'."""
    ua = ua or ""
    if "Edg/" in ua or "EdgA/" in ua:
        browser = "Edge"
    elif "OPR/" in ua or "Opera" in ua:
        browser = "Opera"
    elif "SamsungBrowser" in ua:
        browser = "Samsung Internet"
    elif "Firefox/" in ua or "FxiOS" in ua:
        browser = "Firefox"
    elif "Chrome/" in ua or "CriOS" in ua:
        browser = "Chrome"
    elif "Safari/" in ua:
        browser = "Safari"
    else:
        browser = "Browser"
    if "Android" in ua:
        system = "Android"
    elif "iPhone" in ua or "iPad" in ua or "iPod" in ua:
        system = "iOS"
    elif "Windows" in ua:
        system = "Windows"
    elif "CrOS" in ua:
        system = "ChromeOS"
    elif "Mac OS X" in ua or "Macintosh" in ua:
        system = "macOS"
    elif "Linux" in ua:
        system = "Linux"
    else:
        system = ""
    return f"{browser} on {system}" if system else browser


_GEO_CACHE = {}


def geo_lookup(ip):
    """Rough 'City, Country' for an IP via ipwho.is (cached for an hour). Set GEOIP=off to disable."""
    if os.getenv("GEOIP", "on").strip().lower() in ("off", "0", "false", "no"):
        return None
    hit = _GEO_CACHE.get(ip)
    if hit and (utcnow() - hit[1]) < timedelta(hours=1):
        return hit[0]
    place = _geo_fetch(ip)
    _GEO_CACHE[ip] = (place, utcnow())
    if len(_GEO_CACHE) > 500:
        _GEO_CACHE.clear()
    return place


def _geo_fetch(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_private or addr.is_loopback or addr.is_reserved:
        return "Local network"
    try:
        url = f"https://ipwho.is/{urllib.parse.quote(ip, safe=':')}?fields=success,city,country"
        req = urllib.request.Request(url, headers={"User-Agent": HTTP_UA})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("success") is False:
            return None
        return ", ".join(p for p in (data.get("city"), data.get("country")) if p) or None
    except Exception:
        return None


def run_async(fn):
    """Run a slow, non-essential job (alert email, geo lookup) without blocking the request."""
    threading.Thread(target=fn, daemon=True).start()


def _fill_location(sid, ip):
    try:
        place = geo_lookup(ip)
        if place:
            db_run("UPDATE user_sessions SET location = %s WHERE id = %s", (place, sid), admin=True)
    except Exception:
        app.logger.exception("location update failed")


def create_session_row(user_id, method):
    sid = secrets.token_urlsafe(32)
    now = utcnow()
    ip = client_ip()
    ua = (request.headers.get("User-Agent") or "")[:300]
    db_run(
        "INSERT INTO user_sessions (id, user_id, created_at, last_seen, ip, user_agent, device, method) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (sid, user_id, now, now, ip, ua, device_label(ua), method), admin=True,
    )
    run_async(lambda: _purge_old_sessions(user_id, now))
    run_async(lambda: _fill_location(sid, ip))
    return sid


def _purge_old_sessions(user_id, now):
    try:
        db_run("DELETE FROM user_sessions WHERE user_id = %s AND created_at < %s",
               (user_id, now - timedelta(days=90)), admin=True)
    except Exception:
        app.logger.exception("session history cleanup failed")


_SESSION_OK = {}                  # session id -> (valid until, user id): saves a query on most requests
SESSION_CACHE_SECONDS = 10


def forget_sessions(user_id=None, sid=None, keep=None):
    """Drop cached 'this session is fine' answers after a sign-out, so it takes effect at once."""
    for key, (_until, uid) in list(_SESSION_OK.items()):
        if (sid and key == sid) or (user_id and uid == user_id and key != keep):
            _SESSION_OK.pop(key, None)


def touch_session(sid, user_id):
    """True if this session is still valid on the server (not signed out remotely).
    A positive answer is remembered for 10 seconds by this process."""
    hit = _SESSION_OK.get(sid)
    if hit and hit[0] > time.monotonic() and hit[1] == user_id:
        return True
    row = db_run("SELECT revoked, last_seen FROM user_sessions WHERE id = %s AND user_id = %s",
                 (sid, user_id), fetch="one", admin=True)
    if not row or row["revoked"]:
        return False
    now = utcnow()
    if (now - row["last_seen"]).total_seconds() > 60:
        db_run("UPDATE user_sessions SET last_seen = %s WHERE id = %s", (now, sid), admin=True)
    if len(_SESSION_OK) > 2000:
        _SESSION_OK.clear()
    _SESSION_OK[sid] = (time.monotonic() + SESSION_CACHE_SECONDS, user_id)
    return True


def end_session(sid):
    if sid:
        forget_sessions(sid=sid)
        try:
            db_run("UPDATE user_sessions SET revoked = TRUE, ended_at = %s WHERE id = %s AND revoked = FALSE",
                   (utcnow(), sid), admin=True)
        except Exception:
            app.logger.exception("could not end session")


def revoke_other_sessions(user_id, keep_sid=None):
    """Sign out every session of this user except keep_sid. Returns how many were active."""
    rows = db_run(
        "UPDATE user_sessions SET revoked = TRUE, ended_at = %s "
        "WHERE user_id = %s AND revoked = FALSE AND id <> %s RETURNING id",
        (utcnow(), user_id, keep_sid or ""), fetch="all", admin=True,
    )
    forget_sessions(user_id=user_id, keep=keep_sid)
    return len(rows or [])


def send_alert(email, subject, what):
    """Fire-and-forget security email. Never blocks and never raises."""
    if not email:
        return
    details = ""
    if has_request_context():
        details = f"Device: {device_label(request.headers.get('User-Agent'))}\nIP address: {client_ip()}\n"
    body = (f"{what}\n\nWhen (UTC): {utcnow().strftime('%Y-%m-%d %H:%M')}\n{details}\n"
            "If this was you, no action is needed.\n"
            "If it wasn't, reset your password and review your passkeys and signed-in devices right away.")

    def _go():
        try:
            send_email(email, f"Security alert: {subject}", body)
        except Exception:
            app.logger.exception("security alert failed")
    run_async(_go)


# ----- recovery codes ------------------------------------------------------
def _norm_code(code):
    return re.sub(r"[^A-Z0-9]", "", (code or "").upper())


def _recovery_hash(user_id, raw):
    key = (app.secret_key or "").encode("utf-8")
    return hmac.new(key, f"{user_id}:recovery:{raw}".encode("utf-8"), hashlib.sha256).hexdigest()


def generate_recovery_codes(user_id, count=8):
    """Replace all recovery codes with new ones. Returns the plain codes (shown once)."""
    now = utcnow()
    codes, stmts = [], [("DELETE FROM recovery_codes WHERE user_id = %s", (user_id,))]
    for _ in range(count):
        raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
        stmts.append(("INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES (%s, %s, %s)",
                      (user_id, _recovery_hash(user_id, raw), now)))
    db_batch(stmts)
    return codes


def count_recovery_codes(user_id):
    row = db_run("SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = %s AND used = FALSE",
                 (user_id,), fetch="one", admin=True)
    return int(row["n"]) if row else 0


def consume_recovery_code(user_id, code):
    raw = _norm_code(code)
    if not RECOVERY_REGEX.match(raw):
        return False
    row = db_run(
        "UPDATE recovery_codes SET used = TRUE, used_at = %s WHERE id = ("
        "SELECT id FROM recovery_codes WHERE user_id = %s AND code_hash = %s AND used = FALSE LIMIT 1) "
        "RETURNING id",
        (utcnow(), user_id, _recovery_hash(user_id, raw)), fetch="one", admin=True,
    )
    return bool(row)


def start_login_session(user, method="password"):
    """Fresh session for a user who just proved their first factor."""
    keep_link = session.get("pending_link")
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["logged_in"] = True
    session["last_activity"] = utcnow().isoformat()
    if keep_link:
        session["pending_link"] = keep_link
    session["sid"] = create_session_row(user["id"], method)
    run_async(lambda: _reset_login_counters(user["id"]))


def _reset_login_counters(user_id):
    try:
        db_run("UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, "
               "last_login = CURRENT_TIMESTAMP WHERE id = %s", (user_id,), admin=True)
    except Exception:
        app.logger.exception("Could not update last_login")


def session_ok():
    """True if the cookie session is still valid on the server (not revoked)."""
    sid, uid = session.get("sid"), session.get("user_id")
    return bool(sid and uid and touch_session(sid, uid))


def link_pending_google(user):
    """Finish a 'link Google to my existing account' request after a full sign-in."""
    pl = session.pop("pending_link", None)
    if not pl:
        return
    try:
        fresh = utcnow() - datetime.fromisoformat(pl["t"]) < PENDING_GOOGLE_TTL
    except Exception:
        fresh = False
    if (not fresh or pl.get("uid") != user["id"] or user.get("google_sub")
            or (user.get("email") or "").lower() != pl.get("email")
            or get_user_by_google_sub(pl["sub"])):
        return
    try:
        db_run("UPDATE users SET google_sub = %s WHERE id = %s", (pl["sub"], user["id"]), admin=True)
    except pg_errors.UniqueViolation:
        return
    flash("Google account linked. You can now sign in with Google too.", "success")
    send_alert(user.get("email"), "Google account linked", "A Google account was linked to your account.")
    log_event("google_linked", {"user_id": user["id"]}, "WARNING")


def finish_signin(user):
    """Called once the last factor (passkey or recovery code) is accepted."""
    session["passkey_verified"] = True
    session["last_activity"] = utcnow().isoformat()
    sid, ip = session.get("sid"), client_ip()
    run_async(lambda: _mark_completed(sid))
    link_pending_google(user)
    device = device_label(request.headers.get("User-Agent"))
    run_async(lambda: check_new_signin(user["id"], user.get("email"), sid, device, ip))


def _mark_completed(sid):
    try:
        db_run("UPDATE user_sessions SET completed = TRUE WHERE id = %s", (sid,), admin=True)
    except Exception:
        app.logger.exception("could not finish sign-in bookkeeping")


def check_new_signin(user_id, email, sid, device, ip):
    """Email the owner when a sign-in comes from a device or place not seen in the last 90 days."""
    try:
        place = geo_lookup(ip)
        if place:
            db_run("UPDATE user_sessions SET location = %s WHERE id = %s AND (location IS NULL OR location = '')",
                   (place, sid), admin=True)
        prev = db_run(
            "SELECT device, location FROM user_sessions WHERE user_id = %s AND completed = TRUE "
            "AND id <> %s AND created_at > %s", (user_id, sid, utcnow() - timedelta(days=90)),
            fetch="all", admin=True) or []
        if not prev or not email:
            return                                  # first ever sign-in, or no email to warn
        new_device = all(p["device"] != device for p in prev)
        known_places = {p["location"] for p in prev if p["location"]}
        new_place = bool(place) and place != "Local network" and bool(known_places) and place not in known_places
        if new_device or new_place:
            where = f" from {place}" if place else ""
            send_alert(email, "New sign-in to your account",
                       f"Your account was just signed in to with {device}{where} (IP {ip}).")
            log_event("new_signin_alert", {"user_id": user_id, "device": device, "place": place or ""}, "WARNING")
    except Exception:
        app.logger.exception("new sign-in check failed")


def next_step(user):
    """Endpoint name of the next page this user must visit."""
    if user.get("email") and not user.get("email_verified"):
        return "verify_email_page"
    if not user.get("secret"):
        return "setup_totp"
    if "2fa_verified" not in session:
        return "verify_totp_page"
    if not get_user_passkeys(user["id"]):
        return "setup_passkey_page"
    if "passkey_verified" not in session:
        return "verify_passkey_page"
    return "dashboard"


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session or "user_id" not in session:
            flash("You must log in first!", "danger")
            return redirect(url_for("login", next=request.path))

        if "last_activity" in session:
            try:
                last_activity = datetime.fromisoformat(session["last_activity"])
                if utcnow() - last_activity > timedelta(minutes=30):
                    session.clear()
                    flash("Session expired. Please log in again.", "warning")
                    return redirect(url_for("login"))
            except ValueError:
                session.clear()
                return redirect(url_for("login"))

        sid = session.get("sid")
        if not sid or not touch_session(sid, session["user_id"]):
            session.clear()
            flash("You were signed out. Please sign in again.", "warning")
            return redirect(url_for("login"))

        session["last_activity"] = utcnow().isoformat()
        return f(*args, **kwargs)
    return decorated_function


def two_factor_required(f):
    @wraps(f)
    def decorated_function_2(*args, **kwargs):
        if "2fa_verified" not in session:
            flash("You must complete 2FA verification first!", "danger")
            return redirect(url_for("verify_totp_page"))
        return f(*args, **kwargs)
    return decorated_function_2


def passkey_verified_required(f):
    @wraps(f)
    def decorated_function_3(*args, **kwargs):
        if "passkey_verified" not in session:
            flash("You must complete Passkey verification first!", "danger")
            return redirect(url_for("verify_passkey_page"))
        return f(*args, **kwargs)
    return decorated_function_3


def verify_totp(secret, code):
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code)


# ---------------------------------------------------------------------------
# Passkeys
# ---------------------------------------------------------------------------
def _json_error(message, code):
    return jsonify({"error": message}), code


def _passkey_register_allowed(user_id):
    """First passkey needs 2FA done; extra passkeys also need a passkey login."""
    if "2fa_verified" not in session:
        return False
    return (not get_user_passkeys(user_id)) or ("passkey_verified" in session)


def _verify_assertion(data, passkey, challenge_b64, require_uv=False):
    resp = data["response"]
    credential = AuthenticationCredential(
        id=data["id"],
        raw_id=base64url_to_bytes(data["rawId"]),
        response=AuthenticatorAssertionResponse(
            authenticator_data=base64url_to_bytes(resp["authenticatorData"]),
            client_data_json=base64url_to_bytes(resp["clientDataJSON"]),
            signature=base64url_to_bytes(resp["signature"]),
            user_handle=base64url_to_bytes(resp["userHandle"]) if resp.get("userHandle") else None,
        ),
        type=data["type"],
    )
    return verify_authentication_response(
        credential=credential,
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
        expected_challenge=base64url_to_bytes(challenge_b64 or ""),
        credential_public_key=base64url_to_bytes(passkey["public_key"]),
        credential_current_sign_count=passkey["sign_count"],
        require_user_verification=require_uv,
    )


# ---------------------------------------------------------------------------
# Account deletion (every factor + typed confirmation)
# ---------------------------------------------------------------------------
# ----- breached passwords (Pwned Passwords k-anonymity API) ------------------
BREACH_MESSAGE = "That password has appeared in a known data breach. Please choose a different one."


def password_breached(raw):
    """True if the password is in the Pwned Passwords list. Only the first 5 characters of its
    SHA-1 are sent, never the password. Fails open (False) if the service can't be reached."""
    if os.getenv("HIBP_CHECK", "on").strip().lower() in ("off", "0", "false", "no"):
        return False
    sha = hashlib.sha1(raw, usedforsecurity=False).hexdigest().upper()
    prefix, suffix = sha[:5], sha[5:]
    try:
        req = urllib.request.Request(f"https://api.pwnedpasswords.com/range/{prefix}",
                                     headers={"User-Agent": HTTP_UA, "Add-Padding": "true"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            body = resp.read().decode("utf-8")
    except Exception as e:
        app.logger.warning("Breach check unavailable: %s", e)
        return False
    for line in body.splitlines():
        h, _, count = line.partition(":")
        if h.strip() == suffix:
            return int(count.strip() or 0) > 0
    return False


# ----- trusted devices (skip the authenticator step for 30 days) ---------------
TRUST_DAYS = 30
TRUST_COOKIE = "td"


def _trust_hash(token):
    return hmac.new((app.secret_key or "").encode("utf-8"), f"trust:{token}".encode("utf-8"),
                    hashlib.sha256).hexdigest()


def create_trusted_device(user_id):
    token = secrets.token_urlsafe(32)
    now = utcnow()
    ua = request.headers.get("User-Agent") or ""
    db_run("INSERT INTO trusted_devices (user_id, token_hash, device, ip, created_at, last_used, expires_at) "
           "VALUES (%s, %s, %s, %s, %s, %s, %s)",
           (user_id, _trust_hash(token), device_label(ua), client_ip(), now, now, now + timedelta(days=TRUST_DAYS)),
           admin=True)
    return token


def trusted_device_valid(user_id):
    token = request.cookies.get(TRUST_COOKIE)
    if not token:
        return False
    row = db_run("SELECT id FROM trusted_devices WHERE user_id = %s AND token_hash = %s AND expires_at > %s",
                 (user_id, _trust_hash(token), utcnow()), fetch="one", admin=True)
    if row:
        db_run("UPDATE trusted_devices SET last_used = %s WHERE id = %s", (utcnow(), row["id"]), admin=True)
    return bool(row)


def set_trust_cookie(response, token):
    response.set_cookie(TRUST_COOKIE, token, max_age=TRUST_DAYS * 86400, httponly=True,
                        secure=app.config["SESSION_COOKIE_SECURE"], samesite="Lax")
    return response


def list_trusted_devices(user_id):
    return db_run("SELECT * FROM trusted_devices WHERE user_id = %s AND expires_at > %s ORDER BY created_at DESC",
                  (user_id, utcnow()), fetch="all", admin=True) or []


def revoke_trusted_devices(user_id, device_id=None):
    if device_id is None:
        db_run("DELETE FROM trusted_devices WHERE user_id = %s", (user_id,), admin=True)
    else:
        db_run("DELETE FROM trusted_devices WHERE user_id = %s AND id = %s", (user_id, device_id), admin=True)


# ----- authenticator QR ------------------------------------------------------
def make_totp_qr(secret, account_name):
    """PNG data-URI of the provisioning QR code for an authenticator app."""
    uri = pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name="Secure Login Testing")
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    buffered = BytesIO()
    qr.make_image(fill_color="black", back_color="white").save(buffered, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode()


# ----- admin ---------------------------------------------------------------------
ADMIN_USERNAMES = {u.strip() for u in os.getenv("ADMIN_USERNAMES", "").split(",") if u.strip()}
ADMIN_STEPUP = timedelta(minutes=15)


def is_admin_user(user):
    return bool(user) and user.get("username") in ADMIN_USERNAMES


def admin_required(f):
    """Signed in with every factor + listed in ADMIN_USERNAMES + authenticator code within 15 minutes."""
    @wraps(f)
    @login_required
    @two_factor_required
    @passkey_verified_required
    def inner(*args, **kwargs):
        user = get_user_by_id(session["user_id"])
        if not is_admin_user(user):
            abort(404)
        until = session.get("admin_until")
        fresh = False
        if until:
            try:
                fresh = utcnow() < datetime.fromisoformat(until)
            except ValueError:
                fresh = False
        if not fresh:
            return redirect(url_for("admin_verify", next=request.path))
        return f(*args, **kwargs)
    return inner


DEL_LABELS = {
    "password": "Password",
    "google": "Google account",
    "email": "Email code",
    "totp": "Authenticator code",
    "passkey": "Passkey",
    "confirm": "Final confirmation",
}


def del_steps(user):
    first = "google" if user.get("auth_provider") == "google" else "password"
    return [first, "email", "totp", "passkey", "confirm"]


def get_del_flow(user_id):
    flow = session.get("del")
    if flow and flow.get("uid") == user_id:
        try:
            if utcnow() - datetime.fromisoformat(flow["t"]) < DEL_TTL:
                return flow
        except Exception:
            pass
    session.pop("del", None)
    return None


def save_del_flow(flow):
    session["del"] = flow
    session.modified = True


def start_del_flow(user_id):
    flow = {"uid": user_id, "t": utcnow().isoformat(), "done": [], "fails": 0, "email_target": None}
    save_del_flow(flow)
    return flow


def _del_current(user, flow):
    return next((s for s in del_steps(user) if s not in flow["done"]), None)


# Everything above is shared with the route modules (underscore names included).
__all__ = [n for n in list(globals()) if not n.startswith("__")]

# END OF core.py
