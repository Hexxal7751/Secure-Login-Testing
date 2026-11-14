import os
import re
import json
import hmac
import base64
import hashlib
import secrets
import logging
import threading
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
logging.basicConfig(level=logging.INFO)
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

def check_config():
    """Log obvious configuration mistakes at startup (values are never printed)."""
    if not os.getenv("FLASK_PASS"):
        app.logger.error("FLASK_PASS is not set: sessions will not work.")
    url = os.getenv("SUPABASE_URL") or ""
    if not url.startswith(("postgresql://", "postgres://")):
        app.logger.error("SUPABASE_URL is missing or doesn't start with postgresql://")
    if GOOGLE_CLIENT_ID and not GOOGLE_CLIENT_ID.endswith(".apps.googleusercontent.com"):
        app.logger.warning("GOOGLE_CLIENT_ID doesn't end with .apps.googleusercontent.com")
    if GOOGLE_CLIENT_ID and not (GOOGLE_CLIENT_SECRET.startswith("GOCSPX-") and len(GOOGLE_CLIENT_SECRET) == 35):
        app.logger.warning(
            "GOOGLE_CLIENT_SECRET looks wrong: expected 35 characters starting with GOCSPX-, got %d characters.",
            len(GOOGLE_CLIENT_SECRET))


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["2000 per day", "300 per hour"],
    storage_uri="memory://",
    strategy="fixed-window",
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
    """Security logging must never break a request."""
    try:
        log_security_event(event_type, details or {}, level)
    except Exception:
        app.logger.exception("security log failed")


def get_nonce():
    if "csp_nonce" not in g:
        g.csp_nonce = secrets.token_hex(16)
    return g.csp_nonce


@app.before_request
def before_request():
    get_nonce()


@app.context_processor
def inject_nonce():
    return {"csp_nonce": get_nonce()}


@app.before_request
def enforce_https():
    if os.getenv("FLASK_ENV") == "production":
        is_secure = request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"
        if not is_secure and request.url.startswith("http://"):
            return redirect(request.url.replace("http://", "https://", 1), code=301)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
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
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


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


def db_run(sql, params=(), fetch=None, user_id=None, admin=False):
    """Run one statement. fetch: None | 'one' | 'all'."""
    conn = get_admin_connection() if admin else get_db_connection(user_id)
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(sql, params)
        result = None
        if fetch == "one":
            result = cur.fetchone()
        elif fetch == "all":
            result = cur.fetchall()
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        reset_connection_context(conn)


def db_batch(statements, admin=True, user_id=None):
    """Run several (sql, params) statements in ONE transaction."""
    conn = get_admin_connection() if admin else get_db_connection(user_id)
    try:
        cur = conn.cursor()
        for sql, params in statements:
            cur.execute(sql, params)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        reset_connection_context(conn)


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
init_db()


def get_user(username):
    return db_run("SELECT * FROM users WHERE username = %s", (username,), fetch="one", admin=True)


def get_user_by_id(user_id):
    return db_run("SELECT * FROM users WHERE id = %s", (user_id,), fetch="one", user_id=user_id)


def get_user_by_google_sub(sub):
    return db_run("SELECT * FROM users WHERE google_sub = %s", (sub,), fetch="one", admin=True)


def get_user_by_verified_email(email):
    return db_run(
        "SELECT * FROM users WHERE lower(email) = lower(%s) AND email_verified = TRUE",
        (email,), fetch="one", admin=True,
    )


def get_user_passkeys(user_id):
    return db_run("SELECT * FROM passkeys WHERE user_id = %s ORDER BY id", (user_id,), fetch="all", user_id=user_id)


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
    db_batch([
        ("DELETE FROM email_codes WHERE user_id = %s", (user_id,)),
        ("DELETE FROM recovery_codes WHERE user_id = %s", (user_id,)),
        ("DELETE FROM user_sessions WHERE user_id = %s", (user_id,)),
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
    with urllib.request.urlopen(req, timeout=15) as resp:
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
            "chgemail_new": "confirm your new email address"}.get(purpose, "continue")
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
    """Best-effort visitor IP behind Render's proxy (for display and alerts only)."""
    ip = (request.headers.get("CF-Connecting-IP")
          or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
          or request.remote_addr or "")
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


def geo_lookup(ip):
    """Rough 'City, Country' for an IP via ipwho.is. Set GEOIP=off to disable."""
    if os.getenv("GEOIP", "on").strip().lower() in ("off", "0", "false", "no"):
        return None
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
    try:
        db_run("DELETE FROM user_sessions WHERE user_id = %s AND created_at < %s",
               (user_id, now - timedelta(days=90)), admin=True)
    except Exception:
        app.logger.exception("session history cleanup failed")
    run_async(lambda: _fill_location(sid, ip))
    return sid


def touch_session(sid, user_id):
    """True if this session is still valid on the server (not signed out remotely)."""
    row = db_run("SELECT revoked, last_seen FROM user_sessions WHERE id = %s AND user_id = %s",
                 (sid, user_id), fetch="one", admin=True)
    if not row or row["revoked"]:
        return False
    now = utcnow()
    if (now - row["last_seen"]).total_seconds() > 60:
        db_run("UPDATE user_sessions SET last_seen = %s WHERE id = %s", (now, sid), admin=True)
    return True


def end_session(sid):
    if sid:
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
    try:
        db_run(
            "UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, "
            "last_login = CURRENT_TIMESTAMP WHERE id = %s",
            (user["id"],), admin=True,
        )
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
    try:
        db_run("UPDATE user_sessions SET completed = TRUE WHERE id = %s", (session.get("sid"),), admin=True)
        db_run("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s", (user["id"],), admin=True)
    except Exception:
        app.logger.exception("could not finish sign-in bookkeeping")
    link_pending_google(user)


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
# Keepalive (Render + Supabase)
# ---------------------------------------------------------------------------
@app.route("/keepalive", methods=["GET"])
@limiter.exempt
def keepalive():
    try:
        db_run("SELECT 1", admin=True)
        return jsonify({"status": "ok", "message": "Services are operational", "timestamp": datetime.now().isoformat()})
    except Exception as e:
        app.logger.error(f"Keepalive check failed: {e}")
        return jsonify({"status": "error", "message": "Database unreachable"}), 500


# ---------------------------------------------------------------------------
# Login / registration (username + password)
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
@limiter.limit(login_limit, methods=["POST"])
def login():
    if session.get("logged_in") and "user_id" in session:
        user = get_user_by_id(session["user_id"])
        if user:
            return redirect(url_for(next_step(user)))
        session.clear()

    error = None
    if request.method == "POST":
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").encode("utf-8")[:72]
            user = get_user(username) if USERNAME_REGEX.match(username) else None

            locked = (
                user and user.get("account_locked_until")
                and user["account_locked_until"] > utcnow()
            )
            if locked:
                error = "Account locked due to too many failed login attempts. Please try again later."
            else:
                stored = user.get("password") if user else None
                matches = bcrypt.checkpw(password, (stored or DUMMY_HASH).encode("utf-8"))
                if user and stored and matches:
                    start_login_session(user, "password")
                    log_event("login_success", {"user_id": user["id"], "method": "password"})
                    return redirect(url_for(next_step(user)))

                error = "Invalid username or password!"
                log_event("login_failure", {"username": username[:20]}, "WARNING")
                if user and stored:
                    row = db_run(
                        "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 "
                        "WHERE id = %s RETURNING failed_login_attempts",
                        (user["id"],), fetch="one", admin=True,
                    )
                    if row and row["failed_login_attempts"] >= 5:
                        db_run(
                            "UPDATE users SET account_locked_until = %s WHERE id = %s",
                            (utcnow() + timedelta(minutes=15), user["id"]), admin=True,
                        )
                        error = "Account locked for 15 minutes due to too many failed login attempts."
                        log_event("account_lockout", {"user_id": user["id"]}, "WARNING")

    return render_template("login.html", error=error, csrf_token=generate_csrf_token(),
                           google_enabled=bool(GOOGLE_CLIENT_ID))


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def register():
    error = None
    if request.method == "POST":
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        else:
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "").encode("utf-8")

            if not USERNAME_REGEX.match(username):
                error = "Invalid username format!"
            elif not validate_email(email) or len(email) > 254:
                error = "Please enter a valid email address."
            elif len(password) < 8:
                error = "Password must be at least 8 characters long!"
            elif len(password) > 72:
                error = "Password must be 72 bytes or fewer."
            else:
                # Free usernames held by registrations that were never finished
                try:
                    db_run(
                        "DELETE FROM users WHERE email IS NOT NULL AND email_verified = FALSE "
                        "AND secret IS NULL AND created_at < %s",
                        (utcnow() - timedelta(hours=24),), admin=True,
                    )
                except Exception:
                    app.logger.exception("stale cleanup failed")

                if get_user(username):
                    error = "Username already taken!"
                elif get_user_by_verified_email(email):
                    error = "That email is already in use."
                else:
                    hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode("utf-8")
                    try:
                        row = db_run(
                            "INSERT INTO users (username, password, email, email_verified, auth_provider) "
                            "VALUES (%s, %s, %s, FALSE, 'password') RETURNING id",
                            (username, hashed, email), fetch="one", admin=True,
                        )
                    except pg_errors.UniqueViolation:
                        row = None
                        error = "Username already taken!"
                    if row:
                        log_event("user_registration", {"user_id": row["id"], "method": "password"})
                        start_login_session({"id": row["id"], "username": username}, "password")
                        ok, msg = issue_email_code(row["id"], "register", email)
                        if not ok:
                            flash(msg, "error")
                        return redirect(url_for("verify_email_page"))

    return render_template("register.html", error=error, csrf_token=generate_csrf_token(),
                           google_enabled=bool(GOOGLE_CLIENT_ID))


@app.route("/check-username/<username>")
@limiter.limit("60 per minute")
def check_username(username):
    if not USERNAME_REGEX.match(username):
        return jsonify({"available": False, "reason": "invalid_format"})
    return jsonify({"available": get_user(username) is None})


# ---------------------------------------------------------------------------
# Email verification (registration only)
# ---------------------------------------------------------------------------
@app.route("/verify-email", methods=["GET", "POST"])
@login_required
@limiter.limit("15 per minute", methods=["POST"])
def verify_email_page():
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))
    if not user.get("email") or user.get("email_verified"):
        return redirect(url_for(next_step(user)))

    error = None
    if request.method == "POST":
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        elif request.form.get("do") == "resend":
            ok, msg = issue_email_code(user["id"], "register", user["email"])
            flash("A new code is on its way." if ok else msg, "success" if ok else "error")
            return redirect(url_for("verify_email_page"))
        else:
            code = request.form.get("totp_code", "")
            if not TOTP_REGEX.match(code):
                error = "Please enter a valid 6-digit code"
            else:
                ok, msg, sent_to = check_email_code(user["id"], "register", code)
                if ok and sent_to == user["email"]:
                    try:
                        db_run("UPDATE users SET email_verified = TRUE WHERE id = %s", (user["id"],), admin=True)
                        flash("Email verified.", "success")
                        return redirect(url_for("setup_totp"))
                    except pg_errors.UniqueViolation:
                        error = "That email is already in use."
                else:
                    error = msg or "Incorrect code. Please try again."
    elif not has_active_code(user["id"], "register"):
        ok, msg = issue_email_code(user["id"], "register", user["email"])
        if not ok:
            flash(msg, "error")

    return render_template("verify_email.html", error=error, masked_email=mask_email(user["email"]),
                           csrf_token=generate_csrf_token())


# ---------------------------------------------------------------------------
# Google sign-in (OpenID Connect, authorization-code flow)
# ---------------------------------------------------------------------------
def _decode_jwt_payload(token):
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part.encode("utf-8")))


def _google_exchange_code(code):
    body = urllib.parse.urlencode({
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }).encode("utf-8")
    req = urllib.request.Request(
        GOOGLE_TOKEN_URL, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


@app.route("/auth/google")
@limiter.limit("15 per minute")
def google_start():
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        flash("Google sign-in isn't set up on this server yet.", "error")
        return redirect(url_for("login"))

    intent = request.args.get("intent", "login")
    if intent not in ("login", "delete", "link"):
        intent = "login"
    if intent in ("delete", "link") and not (session.get("logged_in") and "passkey_verified" in session):
        return redirect(url_for("login"))

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    session["g_state"] = state
    session["g_nonce"] = nonce
    session["g_intent"] = intent

    params = urllib.parse.urlencode({
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "prompt": "select_account",
    })
    return redirect(f"{GOOGLE_AUTH_URL}?{params}")


@app.route("/auth/google/callback")
@limiter.limit("20 per minute")
def google_callback():
    intent = session.pop("g_intent", "login")
    state = session.pop("g_state", None)
    nonce = session.pop("g_nonce", None)
    back = {"delete": url_for("delete_account"), "link": url_for("account")}.get(intent, url_for("login"))

    if request.args.get("error"):
        flash("Google sign-in was cancelled.", "warning")
        return redirect(back)

    returned_state = request.args.get("state", "")
    code = request.args.get("code", "")
    if not state or not code or not hmac.compare_digest(state, returned_state):
        flash("Google sign-in failed. Please try again.", "error")
        return redirect(url_for("login"))

    try:
        tokens = _google_exchange_code(code)
        # The token came straight from Google over HTTPS using our client secret,
        # so Google documents that its signature need not be re-checked here.
        claims = _decode_jwt_payload(tokens["id_token"])
    except urllib.error.HTTPError as e:
        # Google's reply says why (e.g. invalid_client = wrong GOOGLE_CLIENT_SECRET,
        # invalid_grant = code already used, redirect_uri_mismatch = wrong redirect URI)
        detail = e.read()[:300].decode("utf-8", "replace")
        app.logger.error("Google token endpoint returned %s: %s | redirect_uri=%s client_id=%s...",
                         e.code, detail, GOOGLE_REDIRECT_URI, GOOGLE_CLIENT_ID[:12])
        flash("Google sign-in failed. Please try again.", "error")
        return redirect(back)
    except Exception:
        app.logger.exception("Google token exchange failed")
        flash("Google sign-in failed. Please try again.", "error")
        return redirect(back)

    valid = (
        claims.get("iss") in ("https://accounts.google.com", "accounts.google.com")
        and claims.get("aud") == GOOGLE_CLIENT_ID
        and float(claims.get("exp", 0)) > datetime.now().timestamp()
        and nonce and hmac.compare_digest(str(claims.get("nonce", "")), nonce)
        and claims.get("sub") and claims.get("email")
        and str(claims.get("email_verified")).lower() == "true"
    )
    if not valid:
        log_event("google_token_invalid", {}, "WARNING")
        flash("Google sign-in failed. Please try again.", "error")
        return redirect(back)

    sub = str(claims["sub"])
    email = str(claims["email"]).strip().lower()

    # --- Re-verification for account deletion -------------------------------
    if intent == "delete":
        user = get_user_by_id(session["user_id"]) if session.get("user_id") else None
        flow = get_del_flow(user["id"]) if user else None
        if not (user and flow and user.get("google_sub") == sub):
            flash("That Google account doesn't match this account.", "error")
            return redirect(url_for("delete_account"))
        if "google" not in flow["done"]:
            flow["done"].append("google")
            save_del_flow(flow)
        return redirect(url_for("delete_account"))

    # --- Link Google to the account that is signed in right now ----------------
    if intent == "link":
        user = get_user_by_id(session["user_id"]) if (session.get("user_id") and "passkey_verified" in session) else None
        if not user or not session_ok():
            return redirect(url_for("login"))
        if user.get("google_sub"):
            flash("A Google account is already linked.", "warning")
            return redirect(url_for("account"))
        if get_user_by_google_sub(sub):
            flash("That Google account is already linked to another account.", "error")
            return redirect(url_for("account"))
        try:
            db_run("UPDATE users SET google_sub = %s WHERE id = %s", (sub, user["id"]), admin=True)
        except pg_errors.UniqueViolation:
            flash("That Google account is already linked to another account.", "error")
            return redirect(url_for("account"))
        send_alert(user.get("email"), "Google account linked", "A Google account was linked to your account.")
        log_event("google_linked", {"user_id": user["id"]}, "WARNING")
        flash("Google account linked.", "success")
        return redirect(url_for("account"))

    # --- Sign in / sign up ---------------------------------------------------
    user = get_user_by_google_sub(sub)
    if user:
        start_login_session(user, "google")
        log_event("login_success", {"user_id": user["id"], "method": "google"})
        return redirect(url_for(next_step(user)))

    existing = get_user_by_verified_email(email)
    if existing:
        if existing.get("google_sub"):
            flash("That email belongs to an account linked to a different Google account.", "error")
            return redirect(url_for("login"))
        # Same verified email on both sides: offer to link, but only after the
        # real account owner completes a FULL sign-in (password, TOTP, passkey).
        session.clear()
        session["pending_link"] = {"uid": existing["id"], "email": email, "sub": sub,
                                   "t": utcnow().isoformat()}
        flash("An account with this email already exists. Sign in with your username and "
              "password to link your Google account to it.", "warning")
        return redirect(url_for("login"))

    session.clear()
    session["pending_google"] = {"sub": sub, "email": email, "t": utcnow().isoformat()}
    flash("Google confirmed your email. Pick a username to finish creating your account.", "success")
    return redirect(url_for("register_google"))


def get_pending_google():
    pending = session.get("pending_google")
    if not pending:
        return None
    try:
        if utcnow() - datetime.fromisoformat(pending["t"]) < PENDING_GOOGLE_TTL:
            return pending
    except Exception:
        pass
    session.pop("pending_google", None)
    return None


@app.route("/register/google", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def register_google():
    pending = get_pending_google()
    if not pending:
        flash("Your Google sign-in expired. Please try again.", "warning")
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        else:
            username = request.form.get("username", "").strip()
            if not USERNAME_REGEX.match(username):
                error = "Invalid username format!"
            elif get_user(username):
                error = "Username already taken!"
            else:
                try:
                    row = db_run(
                        "INSERT INTO users (username, password, email, email_verified, google_sub, auth_provider) "
                        "VALUES (%s, NULL, %s, TRUE, %s, 'google') RETURNING id",
                        (username, pending["email"], pending["sub"]), fetch="one", admin=True,
                    )
                except pg_errors.UniqueViolation:
                    row = None
                    error = "Username already taken, or this Google account is already registered."
                if row:
                    log_event("user_registration", {"user_id": row["id"], "method": "google"})
                    start_login_session({"id": row["id"], "username": username}, "google")
                    return redirect(url_for("setup_totp"))

    return render_template("choose_username.html", error=error, masked_email=mask_email(pending["email"]),
                           csrf_token=generate_csrf_token())


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


@app.route("/passkey/register/begin", methods=["POST"])
@login_required
def passkey_register_begin():
    if not validate_csrf_token():
        return _json_error("Invalid CSRF token", 403)
    try:
        user = get_user_by_id(session["user_id"])
        if not user:
            return _json_error("User not found", 404)
        if not _passkey_register_allowed(user["id"]):
            return _json_error("Complete the previous steps first.", 403)

        existing = get_user_passkeys(user["id"])
        options = generate_registration_options(
            rp_name=RP_NAME,
            rp_id=RP_ID,
            user_id=str(user["id"]).encode("utf-8"),
            user_name=user["username"],
            user_display_name=user["username"],
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(p["credential_id"])) for p in existing
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
        )
        session["passkey_challenge"] = bytes_to_base64url(options.challenge)
        session["passkey_user_id"] = str(user["id"])
        return jsonify({"publicKey": json.loads(options_to_json(options))})
    except Exception:
        logging.error("Error in passkey_register_begin")
        traceback.print_exc()
        return _json_error("Could not start passkey setup.", 500)


@app.route("/passkey/register/complete", methods=["POST"])
@login_required
def passkey_register_complete():
    if not validate_csrf_token():
        return _json_error("Invalid CSRF token", 403)
    try:
        if not _passkey_register_allowed(session["user_id"]):
            return _json_error("Complete the previous steps first.", 403)
        data = request.get_json()
        if not data:
            return _json_error("No data provided", 400)

        credential = RegistrationCredential(
            id=data["id"],
            raw_id=base64url_to_bytes(data["rawId"]),
            response=AuthenticatorAttestationResponse(
                client_data_json=base64url_to_bytes(data["response"]["clientDataJSON"]),
                attestation_object=base64url_to_bytes(data["response"]["attestationObject"]),
            ),
            type=data["type"],
        )
        verification = verify_registration_response(
            credential=credential,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            expected_challenge=base64url_to_bytes(session.pop("passkey_challenge", "") or ""),
        )
        adding_more = "passkey_verified" in session
        name = device_label(request.headers.get("User-Agent"))
        save_passkey(
            user_id=session["user_id"],
            credential_id=bytes_to_base64url(verification.credential_id),
            public_key=bytes_to_base64url(verification.credential_public_key),
            name=name,
        )
        db_run("UPDATE users SET passkey_enabled = TRUE WHERE id = %s", (session["user_id"],), admin=True)
        session.pop("passkey_user_id", None)
        if adding_more:
            user = get_user_by_id(session["user_id"])
            send_alert(user.get("email") if user else None, "New passkey added",
                       f"A new passkey ({name}) was added to your account.")
            log_event("passkey_added", {"user_id": session["user_id"]}, "WARNING")
            flash("Passkey added.", "success")
        return jsonify({"success": True})
    except Exception:
        logging.error("Error in passkey_register_complete")
        traceback.print_exc()
        return _json_error("Passkey setup failed. Please try again.", 400)


@app.route("/passkey/authenticate/begin", methods=["POST"])
@login_required
def passkey_authenticate_begin():
    if not validate_csrf_token():
        return _json_error("Invalid CSRF token", 403)
    if "2fa_verified" not in session:
        return _json_error("Complete the authenticator step first.", 403)
    try:
        user = get_user_by_id(session["user_id"])
        if not user:
            return _json_error("User not found", 404)
        passkeys = get_user_passkeys(user["id"])
        if not passkeys:
            return _json_error("No passkeys found for this user.", 404)

        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(p["credential_id"])) for p in passkeys
            ],
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        session["passkey_challenge"] = bytes_to_base64url(options.challenge)
        session["passkey_user_id"] = str(user["id"])
        return jsonify({"publicKey": json.loads(options_to_json(options))})
    except Exception:
        logging.error("Error in passkey_authenticate_begin")
        traceback.print_exc()
        return _json_error("Could not start passkey check.", 500)


@app.route("/passkey/authenticate/complete", methods=["POST"])
@login_required
def passkey_authenticate_complete():
    if not validate_csrf_token():
        return _json_error("Invalid CSRF token", 403)
    if "2fa_verified" not in session:
        return _json_error("Complete the authenticator step first.", 403)
    try:
        data = request.get_json()
        if not data:
            return _json_error("No data provided", 400)

        user_id = session["user_id"]
        passkey = get_passkey_by_credential_id(data["id"], user_id)
        if not passkey:
            return _json_error("Invalid credential", 400)

        verification = _verify_assertion(data, passkey, session.pop("passkey_challenge", ""))
        update_passkey_sign_count(data["id"], verification.new_sign_count, user_id)

        finish_signin(get_user_by_id(user_id))
        return jsonify({"redirect": url_for("dashboard")})
    except Exception:
        logging.error("Error in passkey_authenticate_complete")
        traceback.print_exc()
        return _json_error("Passkey verification failed. Please try again.", 400)


@app.route("/passkey/status")
@login_required
def passkey_status():
    try:
        passkeys = get_user_passkeys(session["user_id"])
        return jsonify({"has_passkeys": len(passkeys) > 0, "count": len(passkeys)})
    except Exception:
        logging.error("Error in passkey_status")
        traceback.print_exc()
        return _json_error("Could not check passkeys.", 500)


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------
@app.route("/setup-totp", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
def setup_totp():
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))
    if user.get("email") and not user.get("email_verified"):
        return redirect(url_for("verify_email_page"))
    if user.get("secret"):
        # TOTP can't be re-created from a half-signed-in session
        return redirect(url_for(next_step(user)))

    def page(error=None):
        return render_template("setup_totp.html", qr_code=session.get("temp_qr_code"),
                               secret_key=session.get("temp_secret"), error=error,
                               csrf_token=generate_csrf_token())

    if request.method == "POST":
        if not validate_csrf_token():
            return page("Invalid request. Please try again.")
        totp_code = request.form.get("totp_code")
        if not totp_code or not TOTP_REGEX.match(totp_code):
            return page("Please enter a valid 6-digit code")
        if verify_totp(session.get("temp_secret"), totp_code):
            db_run("UPDATE users SET secret = %s WHERE id = %s",
                   (session.get("temp_secret"), session["user_id"]), admin=True)
            session.pop("temp_qr_code", None)
            session.pop("temp_secret", None)
            session["2fa_verified"] = True
            codes = generate_recovery_codes(session["user_id"])
            return render_template("recovery_codes.html", codes=codes, first_time=True,
                                   continue_url=url_for("setup_passkey_page"),
                                   csrf_token=generate_csrf_token())
        return page("Invalid code. Please try again.")

    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name="Secure Login Testing")
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    buffered = BytesIO()
    qr.make_image(fill_color="black", back_color="white").save(buffered, format="PNG")
    session["temp_qr_code"] = "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode()
    session["temp_secret"] = secret
    return page()


@app.route("/cancel-setup", methods=["POST"])
@login_required
def cancel_setup():
    """Delete an account whose sign-up was never finished (POST + CSRF only)."""
    if not validate_csrf_token():
        flash("Invalid request. Please try again.", "error")
        return redirect(url_for("login"))
    user = get_user_by_id(session["user_id"])
    if user and get_user_passkeys(user["id"]):
        flash("This account is fully set up. Use Delete account on the dashboard instead.", "warning")
        return redirect(url_for("login"))
    if user:
        delete_user_everything(user["id"])
        log_event("setup_cancelled", {"user_id": user["id"]})
    session.clear()
    flash("Setup cancelled and the unfinished account was removed.", "success")
    return redirect(url_for("login"))


@app.route("/verify-totp", methods=["GET", "POST"])
@login_required
def verify_totp_page():
    error = None
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))
    if user.get("email") and not user.get("email_verified"):
        return redirect(url_for("verify_email_page"))
    if not user["secret"]:
        flash("2FA setup is required!", "error")
        return redirect(url_for("setup_totp"))

    if request.method == "POST":
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        else:
            totp_code = request.form.get("totp_code")
            if not totp_code or not TOTP_REGEX.match(totp_code):
                error = "Please enter a valid 6-digit code"
            elif verify_totp(user["secret"], totp_code):
                session["2fa_verified"] = True
                return redirect(url_for("verify_passkey_page"))
            else:
                error = "Invalid 2FA code! Please try again."

    return render_template("verify_totp.html", error=error, csrf_token=generate_csrf_token())


@app.route("/verify-passkey", methods=["GET"])
@login_required
@two_factor_required
def verify_passkey_page():
    if not get_user_passkeys(session["user_id"]):
        return redirect(url_for("setup_passkey_page"))
    return render_template("verify_passkey.html", csrf_token=generate_csrf_token())


@app.route("/setup-passkey")
@login_required
def setup_passkey_page():
    if "2fa_verified" not in session:
        flash("You must complete 2FA verification first!", "error")
        return redirect(url_for("verify_totp_page"))
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))
    if get_user_passkeys(user["id"]):
        return redirect(url_for("dashboard"))
    return render_template("setup_passkey.html", csrf_token=generate_csrf_token())


@app.route("/dashboard")
@login_required
@two_factor_required
@passkey_verified_required
def dashboard():
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))
    if not get_user_passkeys(user["id"]):
        return redirect(url_for("setup_passkey_page"))
    return render_template(
        "dashboard.html",
        last_login=user.get("last_login"),
        provider=user.get("auth_provider") or "password",
        masked_email=mask_email(user.get("email")),
        csrf_token=generate_csrf_token(),
    )


# ---------------------------------------------------------------------------
# Account deletion (every factor + typed confirmation)
# ---------------------------------------------------------------------------
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


@app.route("/account/delete", methods=["GET", "POST"])
@login_required
@two_factor_required
@passkey_verified_required
@limiter.limit("40 per hour", methods=["POST"])
def delete_account():
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    flow = get_del_flow(user["id"])
    if request.method == "GET":
        if flow is None or request.args.get("restart"):
            flow = start_del_flow(user["id"])
    elif flow is None:
        flash("That deletion request expired. Please start again.", "warning")
        return redirect(url_for("delete_account"))

    current = _del_current(user, flow)
    error = None

    if request.method == "POST":
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        elif request.form.get("step") != current:
            error = "That step is already done or out of order."
        else:
            # ---- password ----
            if current == "password":
                pw = request.form.get("password", "").encode("utf-8")[:72]
                if user.get("password") and bcrypt.checkpw(pw, user["password"].encode("utf-8")):
                    flow["done"].append("password")
                    save_del_flow(flow)
                    return redirect(url_for("delete_account"))
                flow["fails"] += 1
                error = "Incorrect password."

            # ---- email code ----
            elif current == "email":
                if request.form.get("do") == "send":
                    target = user.get("email")
                    if not target:
                        target = request.form.get("email", "").strip().lower()
                        existing = get_user_by_verified_email(target) if validate_email(target) else None
                        if not validate_email(target) or len(target) > 254:
                            error, target = "Enter a valid email address.", None
                        elif existing and existing["id"] != user["id"]:
                            error, target = "That email is already in use.", None
                    if target:
                        ok, msg = issue_email_code(user["id"], "delete", target)
                        if ok:
                            flow["email_target"] = target
                            save_del_flow(flow)
                        flash("Code sent. Check your inbox." if ok else msg, "success" if ok else "error")
                        return redirect(url_for("delete_account"))
                else:
                    code = request.form.get("totp_code", "")
                    if not TOTP_REGEX.match(code):
                        error = "Please enter a valid 6-digit code"
                    else:
                        ok, msg, sent_to = check_email_code(user["id"], "delete", code)
                        if ok and user.get("email") and sent_to != user["email"]:
                            ok, msg = False, "That code was sent to a different address."
                        if ok and not user.get("email"):
                            try:
                                db_run("UPDATE users SET email = %s, email_verified = TRUE WHERE id = %s",
                                       (sent_to, user["id"]), admin=True)
                            except pg_errors.UniqueViolation:
                                ok, msg = False, "That email is already in use."
                        if ok:
                            flow["done"].append("email")
                            save_del_flow(flow)
                            return redirect(url_for("delete_account"))
                        flow["fails"] += 1
                        error = msg

            # ---- authenticator code ----
            elif current == "totp":
                code = request.form.get("totp_code", "")
                if not TOTP_REGEX.match(code):
                    error = "Please enter a valid 6-digit code"
                elif verify_totp(user["secret"], code):
                    flow["done"].append("totp")
                    save_del_flow(flow)
                    return redirect(url_for("delete_account"))
                else:
                    flow["fails"] += 1
                    error = "Invalid 2FA code! Please try again."

            # ---- passkey / google are completed by their own endpoints ----
            elif current in ("passkey", "google"):
                error = "Use the button on this page to complete this step."

            # ---- final confirmation ----
            elif current == "confirm":
                phrase = f"DELETE {user['username']}"
                if request.form.get("final") != "yes":
                    error = "Please use the confirmation button."
                elif request.form.get("confirm_text", "").strip() != phrase:
                    error = "That didn't match. Type the phrase exactly as shown."
                else:
                    send_alert(user.get("email"), "Account deleted",
                               f"The account \"{user['username']}\" was permanently deleted.")
                    delete_user_everything(user["id"])
                    log_event("account_deleted", {"user_id": user["id"]}, "WARNING")
                    session.clear()
                    flash("Your account and all its data were permanently deleted.", "success")
                    return redirect(url_for("login"))

        if flow["fails"] >= 5:
            session.pop("del", None)
            log_event("account_delete_aborted", {"user_id": user["id"]}, "WARNING")
            flash("Too many wrong attempts. Account deletion was cancelled.", "error")
            return redirect(url_for("dashboard"))
        save_del_flow(flow)

    steps = [
        {"key": k, "label": DEL_LABELS[k],
         "state": "done" if k in flow["done"] else ("now" if k == current else "")}
        for k in del_steps(user)
    ]
    target = flow.get("email_target") or user.get("email")
    return render_template(
        "delete_account.html",
        steps=steps,
        current=current,
        error=error,
        username=user["username"],
        needs_email=not user.get("email"),
        masked_email=mask_email(target) if target else "",
        code_sent=has_active_code(user["id"], "delete"),
        csrf_token=generate_csrf_token(),
    )


@app.route("/account/delete/cancel")
@login_required
def delete_cancel():
    session.pop("del", None)
    return redirect(url_for("dashboard"))


@app.route("/account/delete/passkey/begin", methods=["POST"])
@login_required
def delete_passkey_begin():
    if not validate_csrf_token():
        return _json_error("Invalid CSRF token", 403)
    try:
        user = get_user_by_id(session["user_id"])
        flow = get_del_flow(user["id"]) if user else None
        if "passkey_verified" not in session or not flow or _del_current(user, flow) != "passkey":
            return _json_error("This step isn't active.", 403)
        passkeys = get_user_passkeys(user["id"])
        if not passkeys:
            return _json_error("No passkeys found for this user.", 404)
        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(p["credential_id"])) for p in passkeys
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        session["del_pk_challenge"] = bytes_to_base64url(options.challenge)
        return jsonify({"publicKey": json.loads(options_to_json(options))})
    except Exception:
        logging.error("Error in delete_passkey_begin")
        traceback.print_exc()
        return _json_error("Could not start passkey check.", 500)


@app.route("/account/delete/passkey/complete", methods=["POST"])
@login_required
def delete_passkey_complete():
    if not validate_csrf_token():
        return _json_error("Invalid CSRF token", 403)
    try:
        user = get_user_by_id(session["user_id"])
        flow = get_del_flow(user["id"]) if user else None
        if "passkey_verified" not in session or not flow or _del_current(user, flow) != "passkey":
            return _json_error("This step isn't active.", 403)
        data = request.get_json()
        if not data:
            return _json_error("No data provided", 400)
        passkey = get_passkey_by_credential_id(data["id"], user["id"])
        if not passkey:
            return _json_error("Invalid credential", 400)

        verification = _verify_assertion(data, passkey, session.pop("del_pk_challenge", ""), require_uv=True)
        update_passkey_sign_count(data["id"], verification.new_sign_count, user["id"])
        flow["done"].append("passkey")
        save_del_flow(flow)
        return jsonify({"redirect": url_for("delete_account")})
    except Exception:
        logging.error("Error in delete_passkey_complete")
        traceback.print_exc()
        return _json_error("Passkey verification failed. Please try again.", 400)


# ---------------------------------------------------------------------------
# Password reset (email code only; sign-in still needs TOTP + passkey afterwards)
# ---------------------------------------------------------------------------
def get_reset_flow():
    flow = session.get("reset")
    if flow:
        try:
            if utcnow() - datetime.fromisoformat(flow["t"]) < RESET_TTL:
                return flow
        except Exception:
            pass
    session.pop("reset", None)
    return None


def _send_reset_code(email):
    """Email a reset code if a password account owns this address. Never reveals whether it does."""
    user = get_user_by_verified_email(email)
    if user and user.get("auth_provider") == "password" and user.get("password"):
        ok, msg = issue_email_code(user["id"], "reset", email)
        if not ok:
            app.logger.warning("Reset code not sent for user %s: %s", user["id"], msg)
        else:
            log_event("password_reset_requested", {"user_id": user["id"]})


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per minute; 15 per hour", methods=["POST"])
def forgot_password():
    if session.get("logged_in"):
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        elif not validate_email(email) or len(email) > 254:
            error = "Please enter a valid email address."
        else:
            _send_reset_code(email)
            session["reset"] = {"email": email, "t": utcnow().isoformat()}
            flash("If that email belongs to an account, a reset code is on its way.", "success")
            return redirect(url_for("reset_password"))

    return render_template("forgot_password.html", error=error, csrf_token=generate_csrf_token())


@app.route("/reset-password", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def reset_password():
    if session.get("logged_in"):
        return redirect(url_for("login"))
    flow = get_reset_flow()
    if not flow:
        flash("Enter your email first to get a reset code.", "warning")
        return redirect(url_for("forgot_password"))

    error = None
    if request.method == "POST":
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        elif request.form.get("do") == "resend":
            _send_reset_code(flow["email"])
            flash("If that email belongs to an account, a new code is on its way.", "success")
            return redirect(url_for("reset_password"))
        else:
            code = re.sub(r"[^A-Z0-9]", "", request.form.get("code", "").upper())
            password = request.form.get("password", "").encode("utf-8")
            confirm = request.form.get("confirm", "").encode("utf-8")
            if not RESET_CODE_REGEX.match(code):
                error = "Enter the 8-character code from the email."
            elif len(password) < 8:
                error = "Password must be at least 8 characters long!"
            elif len(password) > 72:
                error = "Password must be 72 bytes or fewer."
            elif password != confirm:
                error = "The two passwords don't match."
            else:
                user = get_user_by_verified_email(flow["email"])
                ok = False
                if user and user.get("auth_provider") == "password" and user.get("password"):
                    ok, _msg, sent_to = check_email_code(user["id"], "reset", code)
                    ok = ok and sent_to == flow["email"]
                if ok:
                    hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode("utf-8")
                    db_run(
                        "UPDATE users SET password = %s, failed_login_attempts = 0, "
                        "account_locked_until = NULL WHERE id = %s",
                        (hashed, user["id"]), admin=True,
                    )
                    log_event("password_reset_done", {"user_id": user["id"]}, "WARNING")
                    revoke_other_sessions(user["id"])
                    send_alert(user.get("email"), "Password reset",
                               "Your password was reset with an emailed code. All devices were signed out.")
                    session.clear()
                    flash("Password updated. Sign in with your new password.", "success")
                    return redirect(url_for("login"))
                error = "That code is incorrect or has expired."

    return render_template("reset_password.html", error=error, masked_email=mask_email(flow["email"]),
                           csrf_token=generate_csrf_token())


# ---------------------------------------------------------------------------
# Account hub: overview, signed-in devices, recovery codes, Google linking
# ---------------------------------------------------------------------------
def acct_user():
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
    return user


@app.route("/account")
@login_required
@two_factor_required
@passkey_verified_required
def account():
    user = acct_user()
    if not user:
        return redirect(url_for("login"))
    now = utcnow()
    rows = db_run(
        "SELECT * FROM user_sessions WHERE user_id = %s AND completed = TRUE "
        "ORDER BY created_at DESC LIMIT 15", (user["id"],), fetch="all", admin=True) or []
    current = session.get("sid")
    sessions = [{
        "id": r["id"],
        "device": r["device"] or "Unknown device",
        "ip": r["ip"] or "",
        "location": r["location"] or "",
        "method": r["method"] or "",
        "created": r["created_at"],
        "last_seen": r["last_seen"],
        "active": (not r["revoked"]) and (now - r["last_seen"] < SESSION_IDLE),
        "current": r["id"] == current,
    } for r in rows]
    passkeys = get_user_passkeys(user["id"])
    return render_template(
        "account.html",
        username=user["username"],
        masked_email=mask_email(user.get("email")),
        has_password=bool(user.get("password")),
        google_linked=bool(user.get("google_sub")),
        google_only=(user.get("auth_provider") == "google" and not user.get("password")),
        passkey_count=len(passkeys),
        recovery_left=count_recovery_codes(user["id"]),
        sessions=sessions,
        other_active=sum(1 for x in sessions if x["active"] and not x["current"]),
        csrf_token=generate_csrf_token(),
    )


@app.route("/account/sessions/revoke", methods=["POST"])
@login_required
@two_factor_required
@passkey_verified_required
def session_revoke():
    if not validate_csrf_token():
        flash("Invalid request. Please try again.", "error")
        return redirect(url_for("account"))
    sid = request.form.get("sid", "")
    if sid == session.get("sid"):
        flash("Use Sign out to end this device's session.", "warning")
    else:
        db_run("UPDATE user_sessions SET revoked = TRUE, ended_at = %s "
               "WHERE id = %s AND user_id = %s AND revoked = FALSE",
               (utcnow(), sid, session["user_id"]), admin=True)
        flash("That device was signed out.", "success")
    return redirect(url_for("account"))


@app.route("/account/sessions/revoke-others", methods=["POST"])
@login_required
@two_factor_required
@passkey_verified_required
def sessions_signout_others():
    if not validate_csrf_token():
        flash("Invalid request. Please try again.", "error")
        return redirect(url_for("account"))
    user = acct_user()
    if not user:
        return redirect(url_for("login"))
    count = revoke_other_sessions(user["id"], session.get("sid"))
    if count:
        send_alert(user.get("email"), "Signed out of other devices",
                   f"{count} other device(s) were signed out of your account.")
    log_event("sessions_revoked", {"user_id": user["id"], "count": count}, "WARNING")
    flash(f"Signed out {count} other device(s)." if count else "No other devices were signed in.", "success")
    return redirect(url_for("account"))


# ----- recovery codes ------------------------------------------------------
@app.route("/account/recovery-codes", methods=["POST"])
@login_required
@two_factor_required
@passkey_verified_required
@limiter.limit("5 per minute", methods=["POST"])
def regenerate_recovery_codes():
    user = acct_user()
    if not user:
        return redirect(url_for("login"))
    code = request.form.get("totp_code", "")
    if not validate_csrf_token():
        flash("Invalid request. Please try again.", "error")
    elif not TOTP_REGEX.match(code) or not verify_totp(user["secret"], code):
        flash("That authenticator code is incorrect.", "error")
    else:
        codes = generate_recovery_codes(user["id"])
        send_alert(user.get("email"), "New recovery codes",
                   "New recovery codes were generated. Your old codes no longer work.")
        log_event("recovery_codes_regenerated", {"user_id": user["id"]}, "WARNING")
        return render_template("recovery_codes.html", codes=codes, first_time=False,
                               continue_url=url_for("account"), csrf_token=generate_csrf_token())
    return redirect(url_for("account"))


@app.route("/recovery/<kind>", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
def recovery_login(kind):
    """Use a one-time recovery code instead of the authenticator app or the passkey."""
    if kind not in ("totp", "passkey"):
        abort(404)
    user = acct_user()
    if not user:
        return redirect(url_for("login"))
    if user.get("email") and not user.get("email_verified"):
        return redirect(url_for("verify_email_page"))
    if kind == "totp":
        if "2fa_verified" in session or not user.get("secret"):
            return redirect(url_for(next_step(user)))
    elif "2fa_verified" not in session or "passkey_verified" in session or not get_user_passkeys(user["id"]):
        return redirect(url_for(next_step(user)))

    error = None
    if request.method == "POST":
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        elif consume_recovery_code(user["id"], request.form.get("code", "")):
            left = count_recovery_codes(user["id"])
            send_alert(user.get("email"), "Recovery code used",
                       f"A recovery code was used to replace your {'authenticator code' if kind == 'totp' else 'passkey'}"
                       f" at sign-in. {left} code(s) remain.")
            log_event("recovery_code_used", {"user_id": user["id"], "for": kind}, "WARNING")
            session.pop("rec_fails", None)
            if kind == "totp":
                session["2fa_verified"] = True
                flash(f"Recovery code accepted. {left} left. Generate new codes soon.", "warning")
                return redirect(url_for(next_step(user)))
            finish_signin(user)
            flash(f"Recovery code accepted. {left} left. Add a new passkey now.", "warning")
            return redirect(url_for("manage_passkeys"))
        else:
            session["rec_fails"] = session.get("rec_fails", 0) + 1
            error = "That recovery code isn't valid, or it was already used."
            if session["rec_fails"] >= 5:
                end_session(session.get("sid"))
                session.clear()
                flash("Too many wrong recovery codes. Please sign in again.", "error")
                return redirect(url_for("login"))
    return render_template("recovery_login.html", kind=kind, error=error, csrf_token=generate_csrf_token())


# ----- manage passkeys -----------------------------------------------------
@app.route("/account/passkeys")
@login_required
@two_factor_required
@passkey_verified_required
def manage_passkeys():
    user = acct_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("passkeys.html", passkeys=get_user_passkeys(user["id"]),
                           csrf_token=generate_csrf_token())


@app.route("/account/passkeys/rename", methods=["POST"])
@login_required
@two_factor_required
@passkey_verified_required
def passkey_rename():
    name = re.sub(r"[\x00-\x1f\x7f]", "", request.form.get("name", "")).strip()[:40]
    if not validate_csrf_token():
        flash("Invalid request. Please try again.", "error")
    elif not name:
        flash("Enter a name for the passkey.", "error")
    else:
        db_run("UPDATE passkeys SET name = %s WHERE id = %s AND user_id = %s",
               (name, request.form.get("id", type=int), session["user_id"]), user_id=session["user_id"])
        flash("Passkey renamed.", "success")
    return redirect(url_for("manage_passkeys"))


@app.route("/account/passkeys/delete", methods=["POST"])
@login_required
@two_factor_required
@passkey_verified_required
def passkey_delete():
    user = acct_user()
    if not user:
        return redirect(url_for("login"))
    pk_id = request.form.get("id", type=int)
    keys = get_user_passkeys(user["id"])
    target = next((k for k in keys if k["id"] == pk_id), None)
    if not validate_csrf_token():
        flash("Invalid request. Please try again.", "error")
    elif not target:
        flash("That passkey wasn't found.", "error")
    elif len(keys) <= 1:
        flash("You can't remove your only passkey. Add another one first.", "error")
    else:
        db_run("DELETE FROM passkeys WHERE id = %s AND user_id = %s", (pk_id, user["id"]), user_id=user["id"])
        send_alert(user.get("email"), "Passkey removed",
                   f"The passkey \"{target.get('name') or 'Passkey'}\" was removed from your account.")
        log_event("passkey_removed", {"user_id": user["id"]}, "WARNING")
        flash("Passkey removed.", "success")
    return redirect(url_for("manage_passkeys"))


# ----- Google link / unlink ------------------------------------------------
@app.route("/account/google/unlink", methods=["POST"])
@login_required
@two_factor_required
@passkey_verified_required
def google_unlink():
    user = acct_user()
    if not user:
        return redirect(url_for("login"))
    if not validate_csrf_token():
        flash("Invalid request. Please try again.", "error")
    elif not user.get("google_sub"):
        flash("No Google account is linked.", "warning")
    elif not user.get("password"):
        flash("Google is your only way to sign in, so it can't be unlinked.", "error")
    else:
        db_run("UPDATE users SET google_sub = NULL WHERE id = %s", (user["id"],), admin=True)
        send_alert(user.get("email"), "Google account unlinked", "The Google account was unlinked from your account.")
        log_event("google_unlinked", {"user_id": user["id"]}, "WARNING")
        flash("Google account unlinked.", "success")
    return redirect(url_for("account"))


# ----- change password / change email (both need an emailed code) ----------
def get_act(kind, uid):
    a = session.get("act")
    if a and a.get("kind") == kind and a.get("uid") == uid:
        try:
            if utcnow() - datetime.fromisoformat(a["t"]) < ACT_TTL:
                return a
        except Exception:
            pass
    session.pop("act", None)
    return None


def save_act(a):
    session["act"] = a
    session.modified = True


def start_act(kind, uid, stage):
    a = {"kind": kind, "uid": uid, "t": utcnow().isoformat(), "stage": stage, "fails": 0, "new_email": None}
    save_act(a)
    return a


def _act_abort(message):
    session.pop("act", None)
    flash(message, "error")
    return redirect(url_for("account"))


@app.route("/account/change-password", methods=["GET", "POST"])
@login_required
@two_factor_required
@passkey_verified_required
@limiter.limit("30 per hour", methods=["POST"])
def change_password():
    user = acct_user()
    if not user:
        return redirect(url_for("login"))
    if not user.get("password") or not user.get("email") or not user.get("email_verified"):
        flash("Changing the password needs an account with a password and a verified email.", "warning")
        return redirect(url_for("account"))

    a = get_act("pw", user["id"])
    if a is None or (request.method == "GET" and request.args.get("restart")):
        a = start_act("pw", user["id"], "send")
    error = None

    if request.method == "POST":
        do = request.form.get("do")
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        elif do == "send" and a["stage"] in ("send", "code"):
            ok, msg = issue_email_code(user["id"], "chgpw", user["email"])
            if ok:
                a["stage"] = "code"
                save_act(a)
            flash("Code sent. Check your inbox." if ok else msg, "success" if ok else "error")
            return redirect(url_for("change_password"))
        elif do == "verify" and a["stage"] == "code":
            code = request.form.get("totp_code", "")
            if not TOTP_REGEX.match(code):
                error = "Please enter a valid 6-digit code"
            else:
                ok, msg, sent_to = check_email_code(user["id"], "chgpw", code)
                if ok and sent_to == user["email"]:
                    a["stage"] = "form"
                    save_act(a)
                    return redirect(url_for("change_password"))
                a["fails"] += 1
                error = msg or "Incorrect code. Please try again."
        elif do == "save" and a["stage"] == "form":
            current = request.form.get("current", "").encode("utf-8")[:72]
            new = request.form.get("password", "").encode("utf-8")
            confirm = request.form.get("confirm", "").encode("utf-8")
            if not bcrypt.checkpw(current, user["password"].encode("utf-8")):
                a["fails"] += 1
                error = "Your current password is incorrect."
            elif len(new) < 8:
                error = "Password must be at least 8 characters long!"
            elif len(new) > 72:
                error = "Password must be 72 bytes or fewer."
            elif new != confirm:
                error = "The two passwords don't match."
            elif new == current:
                error = "Choose a password you haven't used here before."
            else:
                hashed = bcrypt.hashpw(new, bcrypt.gensalt()).decode("utf-8")
                db_run("UPDATE users SET password = %s WHERE id = %s", (hashed, user["id"]), admin=True)
                revoke_other_sessions(user["id"], session.get("sid"))
                send_alert(user["email"], "Password changed",
                           "Your password was changed. Other devices were signed out.")
                log_event("password_changed", {"user_id": user["id"]}, "WARNING")
                session.pop("act", None)
                flash("Password changed. Other devices were signed out.", "success")
                return redirect(url_for("account"))
        else:
            error = "That step isn't available right now."
        if a["fails"] >= 5:
            return _act_abort("Too many wrong attempts. The password change was cancelled.")
        save_act(a)

    return render_template("change_password.html", stage=a["stage"], error=error,
                           masked_email=mask_email(user["email"]), csrf_token=generate_csrf_token())


@app.route("/account/change-email", methods=["GET", "POST"])
@login_required
@two_factor_required
@passkey_verified_required
@limiter.limit("30 per hour", methods=["POST"])
def change_email():
    user = acct_user()
    if not user:
        return redirect(url_for("login"))
    if user.get("auth_provider") == "google" and not user.get("password"):
        flash("Your email comes from your Google account, so it can't be changed here.", "warning")
        return redirect(url_for("account"))

    has_old = bool(user.get("email") and user.get("email_verified"))
    a = get_act("email", user["id"])
    if a is None or (request.method == "GET" and request.args.get("restart")):
        a = start_act("email", user["id"], "send_old" if has_old else "new")
    error = None

    if request.method == "POST":
        do = request.form.get("do")
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        elif do == "send" and a["stage"] in ("send_old", "code_old") and has_old:
            ok, msg = issue_email_code(user["id"], "chgemail_old", user["email"])
            if ok:
                a["stage"] = "code_old"
                save_act(a)
            flash("Code sent. Check your inbox." if ok else msg, "success" if ok else "error")
            return redirect(url_for("change_email"))
        elif do == "verify" and a["stage"] == "code_old":
            code = request.form.get("totp_code", "")
            if not TOTP_REGEX.match(code):
                error = "Please enter a valid 6-digit code"
            else:
                ok, msg, sent_to = check_email_code(user["id"], "chgemail_old", code)
                if ok and sent_to == user["email"]:
                    a["stage"] = "new"
                    save_act(a)
                    return redirect(url_for("change_email"))
                a["fails"] += 1
                error = msg or "Incorrect code. Please try again."
        elif do == "new" and a["stage"] == "new":
            new_email = request.form.get("email", "").strip().lower()
            other = get_user_by_verified_email(new_email) if validate_email(new_email) else None
            if not validate_email(new_email) or len(new_email) > 254:
                error = "Please enter a valid email address."
            elif new_email == (user.get("email") or "").lower():
                error = "That is already your email address."
            elif other and other["id"] != user["id"]:
                error = "That email is already in use."
           