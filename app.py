import os
import io
import re
import ssl
import json
import hmac
import time
import hashlib
import secrets
import logging
import smtplib
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

import bcrypt
import psycopg2
import pyotp
import qrcode
from authlib.integrations.base_client import OAuthError
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from email_validator import EmailNotValidError, validate_email
from flask import (
    Flask, abort, flash, g, has_request_context, jsonify, redirect,
    render_template, request, send_file, session, url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape
from psycopg2.extras import RealDictCursor
from werkzeug.exceptions import HTTPException

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

load_dotenv()

# --------------------------------------------------------------------------
# App configuration
# --------------------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

IS_PROD = os.getenv("FLASK_ENV") == "production"

app.secret_key = os.getenv("FLASK_PASS")
if not app.secret_key:
    raise RuntimeError("FLASK_PASS environment variable must be set")

app.config["PREFERRED_URL_SCHEME"] = "https"
if IS_PROD:
    from werkzeug.middleware.proxy_fix import ProxyFix
    # x_for=1 so rate limiting sees the real client IP behind Render's proxy
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = IS_PROD
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_REFRESH_EACH_REQUEST"] = True
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

# WebAuthn
RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = "Secure Login Testing"
ORIGIN = os.getenv("ORIGIN", "http://localhost:10000").strip().rstrip("/")

# Google OAuth (OpenID Connect)
GOOGLE_ENABLED = bool(os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"))
oauth = OAuth(app)
if GOOGLE_ENABLED:
    oauth.register(
        name="google",
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window",
)
login_limit = "5 per minute; 20 per hour"
register_limit = "5 per minute; 20 per hour"


@limiter.request_filter
def skip_static_and_keepalive():
    return request.endpoint in ("static", "keepalive")


USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
CODE_REGEX = re.compile(r"^\d{6}$")
DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt())

LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 15

OTP_TTL_SECONDS = 600
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN = 60
DELETE_WINDOW_SECONDS = 600


# --------------------------------------------------------------------------
# Request plumbing: nonce, CSRF, HTTPS, security headers
# --------------------------------------------------------------------------
def get_nonce():
    # Lazy so it also exists when a before_request hook (e.g. the rate limiter)
    # aborts before our own hooks run.
    if not hasattr(g, "csp_nonce"):
        g.csp_nonce = secrets.token_hex(16)
    return g.csp_nonce


def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.context_processor
def inject_template_globals():
    return {
        "csp_nonce": get_nonce(),
        "csrf_token": generate_csrf_token,
        "google_enabled": GOOGLE_ENABLED,
        "logged_in": bool(session.get("logged_in")),
    }


@app.before_request
def enforce_https():
    if IS_PROD:
        is_secure = request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"
        if not is_secure and request.url.startswith("http://"):
            return redirect(request.url.replace("http://", "https://", 1), code=301)


@app.before_request
def csrf_guard():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRFToken") or ""
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, description="Your session expired or the form was invalid. Go back, refresh the page, and try again.")


@app.after_request
def add_security_headers(response):
    nonce = get_nonce()
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
        # No form-action directive on purpose: the Google re-authentication
        # form POSTs and then redirects to accounts.google.com.
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    if IS_PROD:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# --------------------------------------------------------------------------
# Error pages
# --------------------------------------------------------------------------
ERROR_TEXT = {
    400: ("Request couldn't be processed", "The request was invalid or your session expired. Go back and try again."),
    401: ("Sign in required", "Log in to view this page."),
    403: ("Access denied", "You don't have permission to do that."),
    404: ("Page not found", "That page doesn't exist or has moved."),
    405: ("Method not allowed", "This page doesn't accept that kind of request."),
    408: ("Request timed out", "The request took too long. Try again."),
    413: ("Request too large", "The data you sent was too large."),
    429: ("Too many requests", "You're going too fast. Wait a minute, then try again."),
    500: ("Something went wrong", "An unexpected error happened on our side. Try again in a moment."),
}


def wants_json():
    return (
        request.is_json
        or request.path.startswith(("/passkey/", "/account/delete/passkey/"))
        or request.accept_mimetypes.best == "application/json"
    )


def render_error(code, title, message):
    if wants_json():
        return jsonify({"error": message}), code
    try:
        return render_template("error.html", code=code, title=title, message=message), code
    except Exception:
        app.logger.exception("error.html failed to render")
        return (
            f"<!doctype html><title>{code}</title><h1>{code} - {escape(title)}</h1><p>{escape(message)}</p>",
            code,
        )


@app.errorhandler(Exception)
def handle_any_exception(e):
    if isinstance(e, HTTPException):
        # Redirects and responses built with abort(redirect(...)) pass through
        if e.response is not None or (e.code is not None and e.code < 400):
            return e
        code = e.code or 500
        title, message = ERROR_TEXT.get(code, (e.name, "Something went wrong with that request."))
        if code in (400, 403) and e.description and e.description != type(e).description:
            message = e.description
        return render_error(code, title, message)
    app.logger.exception("Unhandled exception: %s", e)
    title, message = ERROR_TEXT[500]
    return render_error(500, title, message)


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
def get_db_connection(user_id=None):
    if user_id is None and has_request_context() and "user_id" in session:
        user_id = session["user_id"]

    conn = psycopg2.connect(os.getenv("SUPABASE_URL"))
    with conn.cursor() as cur:
        if user_id is not None:
            cur.execute("SET app.current_user_id = %s", (str(user_id),))
        else:
            cur.execute("SET app.is_admin = true")
    conn.commit()
    return conn


def reset_connection_context(conn):
    try:
        with conn.cursor() as cur:
            cur.execute("RESET app.current_user_id")
            cur.execute("RESET app.is_admin")
        conn.commit()
    except Exception as exc:
        app.logger.error("Error resetting connection context: %s", exc)
    finally:
        conn.close()


@contextmanager
def db(user_id=None):
    """Yield a RealDictCursor; commit on success, roll back on error, always clean up."""
    conn = get_db_connection(user_id)
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        reset_connection_context(conn)


def fetch_one(sql, params=(), user_id=None):
    with db(user_id) as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def init_db():
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
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(320)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS google_sub VARCHAR(255)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(20) NOT NULL DEFAULT 'password'",
        # Existing users count as fully registered; new sign-ups set this to FALSE explicitly
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS registration_complete BOOLEAN NOT NULL DEFAULT TRUE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT",
        "CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_uq ON users (lower(email)) WHERE email IS NOT NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS users_google_sub_uq ON users (google_sub) WHERE google_sub IS NOT NULL",
        """CREATE TABLE IF NOT EXISTS passkeys (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            credential_id TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            sign_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        """CREATE TABLE IF NOT EXISTS email_otps (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            purpose VARCHAR(20) NOT NULL,
            target_email VARCHAR(320) NOT NULL,
            code_hash TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at TIMESTAMPTZ NOT NULL
        )""",
        # RLS on with no policies: blocks Supabase's public API, the owner role used by this app still works
        "ALTER TABLE email_otps ENABLE ROW LEVEL SECURITY",
    ]
    try:
        with db() as cur:
            for stmt in statements:
                cur.execute(stmt)
    except Exception as exc:
        app.logger.error("Error creating/updating tables: %s", exc)


def purge_stale_registrations():
    """Delete sign-ups that never finished within 24 hours so usernames/emails free up."""
    try:
        with db() as cur:
            cur.execute(
                "DELETE FROM users WHERE registration_complete = FALSE "
                "AND created_at < now() - interval '24 hours'"
            )
    except Exception as exc:
        app.logger.error("purge_stale_registrations failed: %s", exc)


def get_user(username):
    return fetch_one("SELECT * FROM users WHERE username = %s", (username,))


def get_user_by_id(user_id):
    return fetch_one("SELECT * FROM users WHERE id = %s", (user_id,), user_id)


def get_user_by_google_sub(sub):
    return fetch_one("SELECT * FROM users WHERE google_sub = %s", (sub,))


def get_user_passkeys(user_id):
    with db(user_id) as cur:
        cur.execute("SELECT * FROM passkeys WHERE user_id = %s", (user_id,))
        return cur.fetchall()


def get_passkey_by_credential_id(credential_id, user_id):
    return fetch_one("SELECT * FROM passkeys WHERE credential_id = %s", (credential_id,), user_id)


# --------------------------------------------------------------------------
# Email (HTTPS API via Resend if configured, otherwise SMTP)
# --------------------------------------------------------------------------
def send_email(to_addr, subject, body):
    sender = os.getenv("EMAIL_FROM") or os.getenv("SMTP_FROM") or os.getenv("SMTP_USER")
    api_key = os.getenv("RESEND_API_KEY")
    smtp_host = os.getenv("SMTP_HOST")

    if api_key and sender:
        payload = json.dumps({"from": sender, "to": [to_addr], "subject": subject, "text": body}).encode()
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15):
                return True
        except (urllib.error.URLError, TimeoutError) as exc:
            app.logger.error("Resend email failed: %s", exc)
            return False

    if smtp_host and sender:
        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(body)
        port = int(os.getenv("SMTP_PORT", "587"))
        user = os.getenv("SMTP_USER")
        password = os.getenv("SMTP_PASSWORD")
        try:
            ctx = ssl.create_default_context()
            if port == 465:
                with smtplib.SMTP_SSL(smtp_host, port, timeout=15, context=ctx) as smtp:
                    if user and password:
                        smtp.login(user, password)
                    smtp.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, port, timeout=15) as smtp:
                    smtp.starttls(context=ctx)
                    if user and password:
                        smtp.login(user, password)
                    smtp.send_message(msg)
            return True
        except (smtplib.SMTPException, OSError) as exc:
            app.logger.error("SMTP email failed: %s", exc)
            return False

    if not IS_PROD:
        app.logger.warning("Email not configured. DEV ONLY - to=%s subject=%s\n%s", to_addr, subject, body)
        return True
    app.logger.error("No email provider configured (set RESEND_API_KEY or SMTP_HOST)")
    return False


def _otp_hash(user_id, purpose, code):
    return hmac.new(
        app.secret_key.encode(), f"{user_id}:{purpose}:{code}".encode(), hashlib.sha256
    ).hexdigest()


def issue_email_otp(user, purpose, target_email):
    """Create + email a 6-digit code. Returns (ok, message)."""
    with db() as cur:
        cur.execute(
            "SELECT EXTRACT(EPOCH FROM (now() - created_at)) AS age FROM email_otps "
            "WHERE user_id = %s AND purpose = %s ORDER BY created_at DESC LIMIT 1",
            (user["id"], purpose),
        )
        last = cur.fetchone()
        if last and last["age"] < OTP_RESEND_COOLDOWN:
            wait = int(OTP_RESEND_COOLDOWN - last["age"]) + 1
            return False, f"Please wait {wait} seconds before requesting another code."

        code = f"{secrets.randbelow(1_000_000):06d}"
        cur.execute("DELETE FROM email_otps WHERE user_id = %s AND purpose = %s", (user["id"], purpose))
        cur.execute(
            "INSERT INTO email_otps (user_id, purpose, target_email, code_hash, expires_at) "
            "VALUES (%s, %s, %s, %s, now() + make_interval(secs => %s))",
            (user["id"], purpose, target_email, _otp_hash(user["id"], purpose, code), OTP_TTL_SECONDS),
        )

    if purpose == "delete":
        subject = "Confirm account deletion - Secure Login Testing"
        body = (
            f"Your account deletion code is {code}.\n\n"
            f"It expires in {OTP_TTL_SECONDS // 60} minutes. If you didn't start deleting your account, "
            "do not share this code and change your password or revoke Google access."
        )
    else:
        subject = "Verify your email - Secure Login Testing"
        body = (
            f"Your verification code is {code}.\n\n"
            f"It expires in {OTP_TTL_SECONDS // 60} minutes. If you didn't create an account, ignore this email."
        )
    if not send_email(target_email, subject, body):
        return False, "We couldn't send the email. Try again shortly."
    return True, "Code sent. Check your inbox."


def verify_email_otp(user_id, purpose, code):
    """Return the email the code was sent to if valid, else None. Single use."""
    with db() as cur:
        cur.execute(
            "SELECT id, code_hash, target_email, attempts, expires_at > now() AS valid "
            "FROM email_otps WHERE user_id = %s AND purpose = %s "
            "ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
            (user_id, purpose),
        )
        row = cur.fetchone()
        if not row or not row["valid"] or row["attempts"] >= OTP_MAX_ATTEMPTS:
            return None
        if hmac.compare_digest(row["code_hash"], _otp_hash(user_id, purpose, code)):
            cur.execute("DELETE FROM email_otps WHERE id = %s", (row["id"],))
            return row["target_email"]
        cur.execute("UPDATE email_otps SET attempts = attempts + 1 WHERE id = %s", (row["id"],))
        return None


def normalize_email(raw):
    raw = (raw or "").strip()
    if not raw or len(raw) > 254:
        return None
    try:
        v = validate_email(raw, check_deliverability=False)
        return (getattr(v, "normalized", None) or v.email).lower()
    except EmailNotValidError:
        return None


def mask_email(email):
    if not email or "@" not in email:
        return ""
    local, domain = email.split("@", 1)
    return f"{local[:1]}{'*' * max(len(local) - 1, 2)}@{domain}"


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------
def start_session(user):
    """Fresh session for a user who has passed the first factor (password or Google)."""
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["logged_in"] = True
    session["last_activity"] = datetime.now().isoformat()


def current_user():
    user = get_user_by_id(session["user_id"]) if "user_id" in session else None
    if not user:
        session.clear()
        abort(redirect(url_for("login")))
    return user


def next_step_endpoint(user):
    """Single source of truth for where a half-authenticated user goes next."""
    if (not user["registration_complete"] and user["auth_provider"] == "password"
            and not user["email_verified"]):
        return "verify_email_page"
    if not user["secret"]:
        return "setup_totp"
    if not get_user_passkeys(user["id"]):
        return "setup_passkey_page"
    if not session.get("2fa_verified"):
        return "verify_totp_page"
    if not session.get("passkey_verified"):
        return "verify_passkey_page"
    return "dashboard"


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "logged_in" not in session or "user_id" not in session:
            flash("You must log in first.", "danger")
            return redirect(url_for("login"))
        last = session.get("last_activity")
        if last and datetime.now() - datetime.fromisoformat(last) > timedelta(minutes=30):
            session.clear()
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for("login"))
        session["last_activity"] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return wrapper


def fully_authenticated(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()
        endpoint = next_step_endpoint(user)
        if endpoint != "dashboard":
            return redirect(url_for(endpoint))
        if not user["registration_complete"]:
            with db(user["id"]) as cur:
                cur.execute("UPDATE users SET registration_complete = TRUE WHERE id = %s", (user["id"],))
        g.user = user
        return f(*args, **kwargs)
    return login_required(wrapper)


def record_password_failure(user_id):
    """Atomically bump the failure counter and lock the account at the threshold. Returns True if locked."""
    locked_until = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
    with db() as cur:
        cur.execute(
            "UPDATE users SET failed_login_attempts = failed_login_attempts + 1, "
            "account_locked_until = CASE WHEN failed_login_attempts + 1 >= %s THEN %s ELSE account_locked_until END "
            "WHERE id = %s RETURNING failed_login_attempts",
            (LOCKOUT_THRESHOLD, locked_until, user_id),
        )
        return cur.fetchone()["failed_login_attempts"] >= LOCKOUT_THRESHOLD


def check_password(user, raw_password):
    hashed = user["password"].encode() if user and user.get("password") else DUMMY_HASH
    ok = bcrypt.checkpw(raw_password.encode()[:72], hashed)
    return bool(user and user.get("password") and ok)


def check_totp(user, code):
    """Verify a TOTP code, allowing +/-1 step and refusing replays of an already used step."""
    if not user.get("secret") or not CODE_REGEX.match(code or ""):
        return False
    totp = pyotp.TOTP(user["secret"])
    cur_step = int(time.time()) // 30
    last = user.get("totp_last_step") or 0
    for offset in (-1, 0, 1):
        step = cur_step + offset
        if hmac.compare_digest(totp.at(step * 30), code) and step > last:
            with db(user["id"]) as cur:
                cur.execute(
                    "UPDATE users SET totp_last_step = %s "
                    "WHERE id = %s AND (totp_last_step IS NULL OR totp_last_step < %s)",
                    (step, user["id"], step),
                )
                return cur.rowcount == 1
    return False


# --------------------------------------------------------------------------
# Passkey helpers
# --------------------------------------------------------------------------
def passkey_authentication_options(user):
    passkeys = get_user_passkeys(user["id"])
    if not passkeys:
        return None
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(p["credential_id"])) for p in passkeys
        ],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return options


def verify_passkey_assertion(data, challenge_b64, user_id):
    """Verify an assertion and make sure the credential belongs to user_id."""
    passkey = get_passkey_by_credential_id(data["id"], user_id)
    if not passkey or passkey["user_id"] != user_id or not challenge_b64:
        return False
    credential = AuthenticationCredential(
        id=data["id"],
        raw_id=base64url_to_bytes(data["rawId"]),
        response=AuthenticatorAssertionResponse(
            authenticator_data=base64url_to_bytes(data["response"]["authenticatorData"]),
            client_data_json=base64url_to_bytes(data["response"]["clientDataJSON"]),
            signature=base64url_to_bytes(data["response"]["signature"]),
            user_handle=(
                base64url_to_bytes(data["response"]["userHandle"])
                if data["response"].get("userHandle") else None
            ),
        ),
        type=data["type"],
    )
    verification = verify_authentication_response(
        credential=credential,
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
        expected_challenge=base64url_to_bytes(challenge_b64),
        credential_public_key=base64url_to_bytes(passkey["public_key"]),
        credential_current_sign_count=passkey["sign_count"],
    )
    with db(user_id) as cur:
        cur.execute(
            "UPDATE passkeys SET sign_count = %s WHERE credential_id = %s",
            (verification.new_sign_count, data["id"]),
        )
    return True


# --------------------------------------------------------------------------
# Login / logout
# --------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
@limiter.limit(login_limit)
def login():
    if session.get("logged_in") and session.get("user_id"):
        user = get_user_by_id(session["user_id"])
        if user:
            return redirect(url_for(next_step_endpoint(user)))
        session.clear()

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_user(username) if USERNAME_REGEX.match(username) else None

        if user and user.get("account_locked_until") and user["account_locked_until"] > datetime.now():
            error = "Account locked due to too many failed login attempts. Try again later."
        elif check_password(user, password):
            with db() as cur:
                cur.execute(
                    "UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, "
                    "last_login = CURRENT_TIMESTAMP WHERE id = %s",
                    (user["id"],),
                )
            start_session(user)
            return redirect(url_for(next_step_endpoint(user)))
        else:
            error = "Invalid username or password."
            if user and user.get("password") and record_password_failure(user["id"]):
                error = f"Account locked for {LOCKOUT_MINUTES} minutes due to too many failed attempts."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Registration - path A: username + email + password
# --------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
@limiter.limit(register_limit)
def register():
    error = None
    form = {"username": "", "email": ""}
    if request.method == "POST":
        purge_stale_registrations()
        username = request.form.get("username", "").strip()
        email = normalize_email(request.form.get("email"))
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        form = {"username": username, "email": request.form.get("email", "").strip()}

        if not USERNAME_REGEX.match(username):
            error = "Username must be 3-20 characters: letters, numbers, underscore."
        elif not email:
            error = "Enter a valid email address."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif len(password.encode()) > 72:
            error = "Password must be 72 bytes or fewer."
        elif password != confirm:
            error = "Passwords don't match."
        else:
            existing = fetch_one(
                "SELECT username, lower(email) AS email FROM users WHERE username = %s OR lower(email) = %s",
                (username, email),
            )
            if existing and existing["username"] == username:
                error = "Username already taken."
            elif existing:
                error = "That email is already registered."

        if not error:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            try:
                with db() as cur:
                    cur.execute(
                        "INSERT INTO users (username, email, password, auth_provider, email_verified, "
                        "registration_complete) VALUES (%s, %s, %s, 'password', FALSE, FALSE) RETURNING id",
                        (username, email, hashed),
                    )
                    user_id = cur.fetchone()["id"]
            except psycopg2.IntegrityError:
                error = "That username or email is already registered."
            else:
                user = get_user_by_id(user_id)
                start_session(user)
                ok, message = issue_email_otp(user, "register", email)
                flash(message, "success" if ok else "danger")
                return redirect(url_for("verify_email_page"))
    return render_template("register.html", error=error, form=form)


@app.route("/register/verify-email", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute")
def verify_email_page():
    user = current_user()
    if next_step_endpoint(user) != "verify_email_page":
        return redirect(url_for(next_step_endpoint(user)))

    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        target = verify_email_otp(user["id"], "register", code) if CODE_REGEX.match(code) else None
        if target and target == user["email"]:
            with db(user["id"]) as cur:
                cur.execute("UPDATE users SET email_verified = TRUE WHERE id = %s", (user["id"],))
            flash("Email verified.", "success")
            return redirect(url_for(next_step_endpoint(get_user_by_id(user["id"]))))
        error = "That code is invalid or has expired."
    return render_template("verify_email.html", error=error, masked_email=mask_email(user["email"]))


@app.route("/register/resend-email", methods=["POST"])
@login_required
@limiter.limit("3 per minute")
def resend_register_email():
    user = current_user()
    if next_step_endpoint(user) != "verify_email_page":
        return redirect(url_for(next_step_endpoint(user)))
    ok, message = issue_email_otp(user, "register", user["email"])
    flash(message, "success" if ok else "danger")
    return redirect(url_for("verify_email_page"))


@app.route("/cancel-setup", methods=["POST"])
@login_required
def cancel_setup():
    """Abandon an unfinished sign-up (never deletes a completed account)."""
    with db(session["user_id"]) as cur:
        cur.execute(
            "DELETE FROM users WHERE id = %s AND registration_complete = FALSE", (session["user_id"],)
        )
    session.clear()
    flash("Sign-up cancelled.", "info")
    return redirect(url_for("register"))


# --------------------------------------------------------------------------
# Google sign-in (login + registration path B) and re-auth for deletion
# --------------------------------------------------------------------------
def google_redirect_uri():
    return os.getenv("GOOGLE_REDIRECT_URI") or url_for("google_callback", _external=True)


@app.route("/auth/google")
@limiter.limit("10 per minute")
def google_auth():
    if not GOOGLE_ENABLED:
        abort(404)
    session["oauth_purpose"] = "auth"
    return oauth.google.authorize_redirect(
        google_redirect_uri(), nonce=secrets.token_urlsafe(16), prompt="select_account"
    )


@app.route("/auth/google/callback")
@limiter.limit("20 per minute")
def google_callback():
    if not GOOGLE_ENABLED:
        abort(404)
    purpose = session.pop("oauth_purpose", "auth")
    fallback = url_for("delete_account") if purpose == "delete" and session.get("user_id") else url_for("login")

    try:
        token = oauth.google.authorize_access_token()
        info = token.get("userinfo") or oauth.google.userinfo(token=token)
    except OAuthError as exc:
        app.logger.warning("Google OAuth error: %s", exc)
        flash("Google sign-in was cancelled or failed. Please try again.", "danger")
        return redirect(fallback)

    sub = info.get("sub")
    email = (info.get("email") or "").strip().lower()
    if not sub or not email or not info.get("email_verified"):
        flash("Your Google account must have a verified email address.", "danger")
        return redirect(fallback)

    # Re-authentication for account deletion
    if purpose == "delete":
        if not session.get("logged_in") or "user_id" not in session:
            return redirect(url_for("login"))
        user = get_user_by_id(session["user_id"])
        if user and user["google_sub"] == sub and next_step_endpoint(user) == "dashboard":
            delete_state_init()
            delete_mark("google")
            flash("Google account verified.", "success")
        else:
            flash("That Google account doesn't match this account.", "danger")
        return redirect(url_for("delete_account"))

    # Normal login / registration
    user = get_user_by_google_sub(sub)
    if user:
        with db() as cur:
            cur.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s", (user["id"],))
        start_session(user)
        return redirect(url_for(next_step_endpoint(user)))

    if fetch_one("SELECT 1 AS x FROM users WHERE lower(email) = %s", (email,)):
        flash("An account with this email already exists. Log in with your username and password.", "danger")
        return redirect(url_for("login"))

    session.clear()
    session["pending_google"] = {"sub": sub, "email": email, "ts": time.time()}
    return redirect(url_for("register_google"))


@app.route("/register/google", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register_google():
    pending = session.get("pending_google")
    if not pending or time.time() - pending["ts"] > 900:
        session.pop("pending_google", None)
        flash("Your Google sign-in expired. Please start again.", "warning")
        return redirect(url_for("register"))

    error = None
    if request.method == "POST":
        purge_stale_registrations()
        username = request.form.get("username", "").strip()
        if not USERNAME_REGEX.match(username):
            error = "Username must be 3-20 characters: letters, numbers, underscore."
        elif get_user(username):
            error = "Username already taken."
        else:
            try:
                with db() as cur:
                    cur.execute(
                        "INSERT INTO users (username, email, email_verified, google_sub, auth_provider, "
                        "registration_complete) VALUES (%s, %s, TRUE, %s, 'google', FALSE) RETURNING id",
                        (username, pending["email"], pending["sub"]),
                    )
                    user_id = cur.fetchone()["id"]
            except psycopg2.IntegrityError:
                error = "That username or Google account is already registered."
            else:
                user = get_user_by_id(user_id)
                start_session(user)
                return redirect(url_for(next_step_endpoint(user)))
    return render_template("register_google.html", error=error, email=pending["email"])


@app.route("/check-username/<username>")
@limiter.limit("30 per minute")
def check_username(username):
    if not USERNAME_REGEX.match(username):
        return jsonify({"available": False, "reason": "invalid_format"})
    return jsonify({"available": get_user(username) is None})


# --------------------------------------------------------------------------
# TOTP
# --------------------------------------------------------------------------
@app.route("/setup-totp", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute")
def setup_totp():
    user = current_user()
    if next_step_endpoint(user) != "setup_totp":
        return redirect(url_for(next_step_endpoint(user)))

    error = None
    if request.method == "POST":
        secret = session.get("temp_secret")
        code = request.form.get("totp_code", "").strip()
        if not secret or not CODE_REGEX.match(code):
            error = "Enter the 6-digit code from your authenticator app."
        elif pyotp.TOTP(secret).verify(code, valid_window=1):
            with db(user["id"]) as cur:
                cur.execute(
                    "UPDATE users SET secret = %s, totp_last_step = %s WHERE id = %s",
                    (secret, int(time.time()) // 30, user["id"]),
                )
            session.pop("temp_secret", None)
            session["2fa_verified"] = True
            return redirect(url_for(next_step_endpoint(get_user_by_id(user["id"]))))
        else:
            error = "Invalid code. Try again."

    if "temp_secret" not in session:
        session["temp_secret"] = pyotp.random_base32()
    return render_template("setup_totp.html", secret_key=session["temp_secret"], error=error)


@app.route("/setup-totp/qr.png")
@login_required
def totp_qr():
    secret = session.get("temp_secret")
    if not secret:
        abort(404)
    uri = pyotp.TOTP(secret).provisioning_uri(name=session["username"], issuer_name="Secure Login Testing")
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, "PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


@app.route("/verify-totp", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute")
def verify_totp_page():
    user = current_user()
    if next_step_endpoint(user) != "verify_totp_page":
        return redirect(url_for(next_step_endpoint(user)))

    error = None
    if request.method == "POST":
        if check_totp(user, request.form.get("totp_code", "").strip()):
            session["2fa_verified"] = True
            return redirect(url_for(next_step_endpoint(user)))
        error = "Invalid or already used code. Wait for the next code and try again."
    return render_template("verify_totp.html", error=error)


# --------------------------------------------------------------------------
# Passkeys (setup + login verification)
# --------------------------------------------------------------------------
@app.route("/setup-passkey")
@login_required
def setup_passkey_page():
    user = current_user()
    if next_step_endpoint(user) != "setup_passkey_page":
        return redirect(url_for(next_step_endpoint(user)))
    return render_template("setup_passkey.html")


@app.route("/verify-passkey")
@login_required
def verify_passkey_page():
    user = current_user()
    if next_step_endpoint(user) != "verify_passkey_page":
        return redirect(url_for(next_step_endpoint(user)))
    return render_template("verify_passkey.html")


@app.route("/passkey/register/begin", methods=["POST"])
@login_required
def passkey_register_begin():
    user = current_user()
    if next_step_endpoint(user) != "setup_passkey_page":
        return jsonify({"error": "Passkey setup isn't available right now."}), 403
    options = generate_registration_options(
        rp_name=RP_NAME,
        rp_id=RP_ID,
        user_id=str(user["id"]).encode("utf-8"),
        user_name=user["username"],
        user_display_name=user["username"],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    session["passkey_challenge"] = bytes_to_base64url(options.challenge)
    return jsonify({"publicKey": json.loads(options_to_json(options))})


@app.route("/passkey/register/complete", methods=["POST"])
@login_required
def passkey_register_complete():
    user = current_user()
    if next_step_endpoint(user) != "setup_passkey_page":
        return jsonify({"error": "Passkey setup isn't available right now."}), 403
    data = request.get_json(silent=True)
    challenge = session.pop("passkey_challenge", None)
    if not data or not challenge:
        return jsonify({"error": "Missing data. Start again."}), 400
    try:
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
            expected_challenge=base64url_to_bytes(challenge),
        )
    except Exception as exc:
        app.logger.warning("Passkey registration failed: %s", exc)
        return jsonify({"error": "Passkey registration failed. Try again."}), 400

    with db(user["id"]) as cur:
        cur.execute(
            "INSERT INTO passkeys (user_id, credential_id, public_key) VALUES (%s, %s, %s)",
            (
                user["id"],
                bytes_to_base64url(verification.credential_id),
                bytes_to_base64url(verification.credential_public_key),
            ),
        )
        # Registration is finished once TOTP + passkey are both in place
        cur.execute(
            "UPDATE users SET passkey_enabled = TRUE, registration_complete = TRUE WHERE id = %s",
            (user["id"],),
        )
    session["2fa_verified"] = True
    session["passkey_verified"] = True
    return jsonify({"success": True, "redirect": url_for("dashboard")})


@app.route("/passkey/authenticate/begin", methods=["POST"])
@login_required
def passkey_authenticate_begin():
    user = current_user()
    if next_step_endpoint(user) != "verify_passkey_page":
        return jsonify({"error": "Passkey verification isn't available right now."}), 403
    options = passkey_authentication_options(user)
    if not options:
        return jsonify({"error": "No passkeys found for this account."}), 404
    session["passkey_challenge"] = bytes_to_base64url(options.challenge)
    return jsonify({"publicKey": json.loads(options_to_json(options))})


@app.route("/passkey/authenticate/complete", methods=["POST"])
@login_required
def passkey_authenticate_complete():
    user = current_user()
    if next_step_endpoint(user) != "verify_passkey_page":
        return jsonify({"error": "Passkey verification isn't available right now."}), 403
    data = request.get_json(silent=True)
    challenge = session.pop("passkey_challenge", None)
    if not data:
        return jsonify({"error": "No data provided."}), 400
    try:
        ok = verify_passkey_assertion(data, challenge, user["id"])
    except Exception as exc:
        app.logger.warning("Passkey verification failed: %s", exc)
        ok = False
    if not ok:
        return jsonify({"error": "Passkey verification failed."}), 400
    session["passkey_verified"] = True
    return jsonify({"success": True, "redirect": url_for("dashboard")})


@app.route("/passkey/status")
@login_required
def passkey_status():
    passkeys = get_user_passkeys(session["user_id"])
    return jsonify({"has_passkeys": len(passkeys) > 0, "count": len(passkeys)})


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------
@app.route("/dashboard")
@fully_authenticated
def dashboard():
    user = g.user
    return render_template(
        "dashboard.html",
        username=user["username"],
        masked_email=mask_email(user["email"]),
        provider=user["auth_provider"],
        last_login=user["last_login"],
    )


# --------------------------------------------------------------------------
# Account deletion: every verification method on the account + final challenge
# --------------------------------------------------------------------------
DELETE_LABELS = {
    "password": "Confirm your password",
    "google": "Re-authenticate with Google",
    "totp": "Enter your authenticator code",
    "passkey": "Verify with your passkey",
    "email": "Verify with an email code",
}


def delete_required_steps(user):
    first = "google" if user["auth_provider"] == "google" else "password"
    return [first, "totp", "passkey", "email"]


def delete_state_init():
    st = session.get("del")
    if not st or time.time() - st["started"] > DELETE_WINDOW_SECONDS:
        st = {
            "started": time.time(),
            "done": [],
            "email_sent": False,
            "challenge": secrets.token_hex(3).upper(),
        }
    session["del"] = st
    return st


def delete_mark(step):
    st = session["del"]
    if step not in st["done"]:
        st["done"].append(step)
    session["del"] = st


def delete_active_state():
    """Current state or None (also tells the user if it timed out)."""
    st = session.get("del")
    if st and time.time() - st["started"] > DELETE_WINDOW_SECONDS:
        session.pop("del", None)
        flash("Deletion verification timed out. Start again.", "warning")
        return None
    return st


def delete_back(message=None, category="danger"):
    if message:
        flash(message, category)
    return redirect(url_for("delete_account"))


@app.route("/account/delete")
@fully_authenticated
def delete_account():
    user = g.user
    st = delete_state_init()
    steps = [
        {"key": k, "label": DELETE_LABELS[k], "done": k in st["done"]}
        for k in delete_required_steps(user)
    ]
    return render_template(
        "delete_account.html",
        steps=steps,
        all_done=all(s["done"] for s in steps),
        email_sent=st["email_sent"],
        user_email=user["email"],
        masked_email=mask_email(user["email"]),
        challenge=st["challenge"],
        username=user["username"],
        minutes=DELETE_WINDOW_SECONDS // 60,
    )


@app.route("/account/delete/password", methods=["POST"])
@fully_authenticated
@limiter.limit("5 per minute")
def delete_verify_password():
    user = g.user
    if user["auth_provider"] != "password":
        abort(403)
    if delete_active_state() is None:
        return delete_back()
    if check_password(user, request.form.get("password", "")):
        delete_mark("password")
        return delete_back("Password confirmed.", "success")
    if record_password_failure(user["id"]):
        session.clear()
        flash("Too many failed attempts. Account locked for a while.", "danger")
        return redirect(url_for("login"))
    return delete_back("Incorrect password.")


@app.route("/account/delete/google", methods=["POST"])
@fully_authenticated
@limiter.limit("5 per minute")
def delete_verify_google():
    if not GOOGLE_ENABLED or g.user["auth_provider"] != "google":
        abort(403)
    delete_state_init()
    session["oauth_purpose"] = "delete"
    return oauth.google.authorize_redirect(
        google_redirect_uri(), nonce=secrets.token_urlsafe(16), prompt="login"
    )


@app.route("/account/delete/totp", methods=["POST"])
@fully_authenticated
@limiter.limit("5 per minute")
def delete_verify_totp():
    if delete_active_state() is None:
        return delete_back()
    if check_totp(g.user, request.form.get("totp_code", "").strip()):
        delete_mark("totp")
        return delete_back("Authenticator code accepted.", "success")
    return delete_back("Invalid or already used code.")


@app.route("/account/delete/passkey/begin", methods=["POST"])
@fully_authenticated
@limiter.limit("10 per minute")
def delete_passkey_begin():
    if delete_active_state() is None:
        return jsonify({"error": "Verification timed out. Reload the page."}), 400
    options = passkey_authentication_options(g.user)
    if not options:
        return jsonify({"error": "No passkeys found."}), 404
    session["del_passkey_challenge"] = bytes_to_base64url(options.challenge)
    return jsonify({"publicKey": json.loads(options_to_json(options))})


@app.route("/account/delete/passkey/complete", methods=["POST"])
@fully_authenticated
@limiter.limit("10 per minute")
def delete_passkey_complete():
    if delete_active_state() is None:
        return jsonify({"error": "Verification timed out. Reload the page."}), 400
    data = request.get_json(silent=True)
    challenge = session.pop("del_passkey_challenge", None)
    if not data:
        return jsonify({"error": "No data provided."}), 400
    try:
        ok = verify_passkey_assertion(data, challenge, g.user["id"])
    except Exception as exc:
        app.logger.warning("Delete passkey verification failed: %s", exc)
        ok = False
    if not ok:
        return jsonify({"error": "Passkey verification failed."}), 400
    delete_mark("passkey")
    return jsonify({"success": True})


@app.route("/account/delete/email/send", methods=["POST"])
@fully_authenticated
@limiter.limit("3 per minute")
def delete_email_send():
    user = g.user
    st = delete_active_state()
    if st is None:
        return delete_back()
    target = user["email"]
    if not target:
        # Accounts created before email support must add + verify one here
        target = normalize_email(request.form.get("email"))
        if not target:
            return delete_back("Enter a valid email address.")
        if fetch_one("SELECT 1 AS x FROM users WHERE lower(email) = %s AND id <> %s", (target, user["id"])):
            return delete_back("That email is already used by another account.")
    ok, message = issue_email_otp(user, "delete", target)
    if ok:
        st["email_sent"] = True
        session["del"] = st
    return delete_back(message, "success" if ok else "danger")


@app.route("/account/delete/email/verify", methods=["POST"])
@fully_authenticated
@limiter.limit("5 per minute")
def delete_email_verify():
    user = g.user
    if delete_active_state() is None:
        return delete_back()
    code = request.form.get("code", "").strip()
    target = verify_email_otp(user["id"], "delete", code) if CODE_REGEX.match(code) else None
    if not target:
        return delete_back("That code is invalid or has expired.")
    if not user["email"]:
        try:
            with db(user["id"]) as cur:
                cur.execute(
                    "UPDATE users SET email = %s, email_verified = TRUE WHERE id = %s", (target, user["id"])
                )
        except psycopg2.IntegrityError:
            return delete_back("That email is already used by another account.")
    elif target != user["email"]:
        return delete_back("That code is invalid or has expired.")
    delete_mark("email")
    return delete_back("Email verified.", "success")


@app.route("/account/delete/confirm", methods=["POST"])
@fully_authenticated
@limiter.limit("5 per minute")
def delete_confirm():
    user = g.user
    st = delete_active_state()
    if st is None:
        return delete_back()
    if not all(step in st["done"] for step in delete_required_steps(user)):
        return delete_back("Complete every verification step first.")

    phrase = request.form.get("confirm_phrase", "").strip()
    challenge = request.form.get("challenge_code", "").strip().upper()
    understood = request.form.get("understand") == "yes"
    if (
        not understood
        or phrase != f"DELETE {user['username']}"
        or not hmac.compare_digest(challenge, st["challenge"])
    ):
        return delete_back("Confirmation didn't match. Type the phrase and code exactly.")

    with db(user["id"]) as cur:
        cur.execute("DELETE FROM users WHERE id = %s", (user["id"],))  # passkeys + OTPs cascade
    app.logger.info("Account deleted: user_id=%s", user["id"])
    session.clear()
    flash("Your account and all its data were permanently deleted.", "success")
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Health check
# --------------------------------------------------------------------------
@app.route("/keepalive")
def keepalive():
    try:
        with db() as cur:
            cur.execute("SELECT 1")
        return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})
    except Exception as exc:
        app.logger.error("Keepalive check failed: %s", exc)
        return jsonify({"status": "error"}), 500


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")), debug=not IS_PROD)
