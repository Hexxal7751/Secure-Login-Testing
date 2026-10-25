import os
import re
import json
import hmac
import base64
import hashlib
import secrets
import logging
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
    Flask, request, render_template, redirect, url_for, session, flash,
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
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", f"{ORIGIN}/auth/google/callback").strip()
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# Email is sent over HTTPS (Render's free tier blocks SMTP). Pick ONE option in .env:
#  A) Gmail relay (no domain needed): MAIL_WEBHOOK_URL + MAIL_WEBHOOK_SECRET  (see mail_relay.gs)
#  B) Resend (needs a domain you own): RESEND_API_KEY + MAIL_FROM
MAIL_WEBHOOK_URL = os.getenv("MAIL_WEBHOOK_URL", "").strip()
MAIL_WEBHOOK_SECRET = os.getenv("MAIL_WEBHOOK_SECRET", "").strip()
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()
MAIL_FROM = os.getenv("MAIL_FROM", "").strip()
MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME", "Secure Login Testing").strip()

EMAIL_CODE_TTL = timedelta(minutes=10)
EMAIL_CODE_MAX_ATTEMPTS = 5
DEL_TTL = timedelta(minutes=10)
PENDING_GOOGLE_TTL = timedelta(minutes=15)

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

# Track failed login attempts per IP (helpers kept for optional use)
failed_attempts = {}
LOCKOUT_THRESHOLD = 5
LOCKOUT_TIME = 15 * 60


def is_ip_blocked(ip):
    if ip in failed_attempts:
        attempts, timestamp = failed_attempts[ip]
        if attempts >= LOCKOUT_THRESHOLD:
            if datetime.now().timestamp() - timestamp < LOCKOUT_TIME:
                return True
            failed_attempts[ip] = (0, datetime.now().timestamp())
    return False


def record_failed_attempt(ip):
    now = datetime.now().timestamp()
    attempts = failed_attempts.get(ip, (0, now))[0]
    failed_attempts[ip] = (attempts + 1, now)


def reset_failed_attempts(ip):
    if ip in failed_attempts:
        failed_attempts[ip] = (0, datetime.now().timestamp())


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
TOTP_REGEX = re.compile(r"^\d{6}$")

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
def get_db_connection(user_id=None):
    if user_id is None and has_request_context() and "user_id" in session:
        user_id = session["user_id"]

    conn = psycopg2.connect(os.getenv("SUPABASE_URL"))

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
    conn = psycopg2.connect(os.getenv("SUPABASE_URL"))
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
    except Exception:
        app.logger.exception("Database setup failed")


# Runs under gunicorn too (the old code only ran this under `python app.py`)
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
    return db_run("SELECT * FROM passkeys WHERE user_id = %s", (user_id,), fetch="all", user_id=user_id)


def save_passkey(user_id, credential_id, public_key):
    db_run(
        "INSERT INTO passkeys (user_id, credential_id, public_key) VALUES (%s, %s, %s)",
        (user_id, credential_id, public_key), user_id=user_id,
    )


def update_passkey_sign_count(credential_id, sign_count, user_id):
    db_run(
        "UPDATE passkeys SET sign_count = %s WHERE credential_id = %s",
        (sign_count, credential_id), user_id=user_id,
    )


def get_passkey_by_credential_id(credential_id, user_id):
    return db_run(
        "SELECT * FROM passkeys WHERE credential_id = %s AND user_id = %s",
        (credential_id, user_id), fetch="one", user_id=user_id,
    )


def delete_user_everything(user_id):
    """Remove the account and everything attached to it in one transaction."""
    conn = get_admin_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM email_codes WHERE user_id = %s", (user_id,))
        cur.execute("DELETE FROM passkeys WHERE user_id = %s", (user_id,))
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        reset_connection_context(conn)


# ---------------------------------------------------------------------------
# Email sending + one-time codes
# ---------------------------------------------------------------------------
def _send_via_resend(to_email, subject, text):
    payload = {
        "from": f"{MAIL_FROM_NAME} <{MAIL_FROM}>",
        "to": [to_email],
        "subject": subject,
        "text": text,
    }
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        # Resend blocks the default Python User-Agent, so we set our own
        headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json",
                 "User-Agent": "secure-login-testing/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return 200 <= resp.status < 300


def _send_via_relay(to_email, subject, text):
    payload = {
        "secret": MAIL_WEBHOOK_SECRET,
        "to": to_email,
        "subject": subject,
        "message": text,
        "name": MAIL_FROM_NAME,
    }
    req = urllib.request.Request(
        MAIL_WEBHOOK_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    # Apps Script answers a POST with a redirect; urllib follows it automatically.
    with urllib.request.urlopen(req, timeout=25) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    if body.get("ok") is True:
        return True
    app.logger.error("Mail relay refused the email: %s", str(body.get("error"))[:200])
    return False


def send_email(to_email, subject, text):
    """Send one plain-text email. Returns True on success."""
    if RESEND_API_KEY and MAIL_FROM:
        sender = _send_via_resend
    elif MAIL_WEBHOOK_URL and MAIL_WEBHOOK_SECRET:
        sender = _send_via_relay
    else:
        if os.getenv("FLASK_ENV") == "development":
            app.logger.warning("[DEV EMAIL] to=%s subject=%s\n%s", to_email, subject, text)
            return True
        app.logger.error("Email is not configured (set MAIL_WEBHOOK_URL + MAIL_WEBHOOK_SECRET, or RESEND_API_KEY + MAIL_FROM).")
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
    """Create a 6-digit code and email it. Returns (ok, error_message)."""
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

    code = f"{secrets.randbelow(1000000):06d}"
    conn = get_admin_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE email_codes SET used = TRUE WHERE user_id = %s AND purpose = %s AND used = FALSE",
            (user_id, purpose),
        )
        cur.execute(
            """INSERT INTO email_codes (user_id, purpose, email, code_hash, expires_at, created_at)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (user_id, purpose, email, _code_hash(user_id, purpose, code), now + EMAIL_CODE_TTL, now),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        reset_connection_context(conn)

    what = "finish creating your account" if purpose == "register" else "delete your account"
    ok = send_email(
        email,
        f"Your Secure Login Testing code: {code}",
        f"Your verification code is {code}\n\n"
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
def start_login_session(user):
    """Fresh session for a user who just proved their first factor."""
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["logged_in"] = True
    session["last_activity"] = utcnow().isoformat()
    try:
        db_run(
            "UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, "
            "last_login = CURRENT_TIMESTAMP WHERE id = %s",
            (user["id"],), admin=True,
        )
    except Exception:
        app.logger.exception("Could not update last_login")


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
                    start_login_session(user)
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
                        start_login_session({"id": row["id"], "username": username})
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
    if intent not in ("login", "delete"):
        intent = "login"
    if intent == "delete" and not (session.get("logged_in") and "passkey_verified" in session):
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
    back = url_for("delete_account") if intent == "delete" else url_for("login")

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

    # --- Sign in / sign up ---------------------------------------------------
    user = get_user_by_google_sub(sub)
    if user:
        start_login_session(user)
        log_event("login_success", {"user_id": user["id"], "method": "google"})
        return redirect(url_for(next_step(user)))

    if get_user_by_verified_email(email):
        flash("An account with this email already exists. Sign in with your username and password.", "error")
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
                    start_login_session({"id": row["id"], "username": username})
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
        save_passkey(
            user_id=session["user_id"],
            credential_id=bytes_to_base64url(verification.credential_id),
            public_key=bytes_to_base64url(verification.credential_public_key),
        )
        db_run("UPDATE users SET passkey_enabled = TRUE WHERE id = %s", (session["user_id"],), admin=True)
        session.pop("passkey_user_id", None)
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

        session["passkey_verified"] = True
        session["last_activity"] = utcnow().isoformat()
        db_run("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s", (user_id,), admin=True)
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
            return redirect(url_for("setup_passkey_page"))
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
# Logout
# ---------------------------------------------------------------------------
def _logout_response():
    session.clear()
    response = make_response(redirect(url_for("login")))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/logout")
def logout():
    return _logout_response()


@app.route("/emergency-logout")
def emergency_logout():
    """Hidden emergency logout route for use during authentication process"""
    return _logout_response()


# ---------------------------------------------------------------------------
# Error pages
# One handler renders every error (400, 403, 404, 405, 429, 500, ...) with
# templates/error.html. Fetch/JSON callers get JSON instead of HTML.
# Messages are fixed strings so internal details never leak to the browser.
# ---------------------------------------------------------------------------
ERROR_PAGES = {
    400: ("Bad request", "That request didn't look right. Go back and try again.", "alert", "warn"),
    401: ("Sign in required", "Please sign in to continue.", "lock", "warn"),
    403: ("Access denied", "You don't have permission to view this page.", "lock", "warn"),
    404: ("Page not found", "The page you're looking for doesn't exist or has moved.", "compass", "info"),
    405: ("Action not allowed", "That action isn't supported on this page.", "alert", "warn"),
    408: ("Request timed out", "The request took too long. Please try again.", "clock", "warn"),
    413: ("Request too large", "What you sent was too large to process.", "alert", "warn"),
    429: ("Slow down a little", "Too many requests. Wait a minute, then try again.", "clock", "warn"),
    500: ("Server error", "Something went wrong on our end. Please try again shortly.", "server", "danger"),
    502: ("Bad gateway", "The server is waking up or unreachable. Try again in a moment.", "server", "danger"),
    503: ("Service unavailable", "We're temporarily unavailable. Please try again shortly.", "server", "danger"),
    504: ("Gateway timeout", "The server took too long to respond. Try again in a moment.", "server", "danger"),
}

JSON_PREFIXES = ("/passkey/", "/account/delete/passkey/", "/check-username")


def _wants_json():
    return request.is_json or request.path.startswith(JSON_PREFIXES)


def render_error(code, extra_headers=None):
    title, message, icon, tone = ERROR_PAGES.get(
        code,
        ("Something went wrong", "An unexpected error occurred. Please try again.", "alert",
         "danger" if code >= 500 else "warn"),
    )
    try:
        if _wants_json():
            response = make_response(jsonify({"error": message}), code)
        else:
            response = make_response(
                render_template("error.html", code=code, title=title, message=message, glyph=icon, tone=tone),
                code,
            )
    except Exception:
        # Never let the error page itself raise (that would loop)
        app.logger.exception("Failed to render error page")
        response = make_response(message, code)
        response.headers["Content-Type"] = "text/plain; charset=utf-8"
    for key, value in (extra_headers or []):
        if key.lower() not in ("content-type", "content-length"):
            response.headers[key] = value
    return response


@app.errorhandler(Exception)
def handle_any_exception(e):
    if isinstance(e, HTTPException):
        # 404 / 405 / 429 (rate limiter) and friends
        return render_error(e.code or 500, e.get_headers())
    app.logger.exception("Unhandled exception")
    return render_error(500)


if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=10000, debug=debug_mode)
