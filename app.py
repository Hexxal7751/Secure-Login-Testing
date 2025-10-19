import os
import pyotp
import qrcode
import io
import bcrypt
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, request, render_template, redirect, url_for, session, send_file, flash, make_response, jsonify, g, has_request_context
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import re
from functools import wraps
from datetime import datetime, timedelta
from io import BytesIO
import base64
import secrets
import json
import logging
import traceback
from security_logging import log_security_event, LOGIN_SUCCESS, LOGIN_FAILURE, REGISTRATION, ACCOUNT_LOCKOUT
from security_middleware import validate_request_json, validate_email, validate_username, validate_password_strength
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

# Load environment variables
load_dotenv()

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
app.secret_key = os.getenv("FLASK_PASS")

# Configure Flask to trust proxy headers (needed for Render)
app.config['PREFERRED_URL_SCHEME'] = 'https'
if os.getenv("FLASK_ENV") == "production":
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Security configurations
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_REFRESH_EACH_REQUEST"] = True

# WebAuthn configuration
RP_ID = os.getenv("RP_ID", "localhost")  # Your domain
RP_NAME = "Secure Login Testing"
ORIGIN = os.getenv("ORIGIN", "http://localhost:5000")

# Flask-Limiter for Rate Limiting and Anti-Brute Force Protection
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

# Define stricter limits for authentication endpoints
login_limit = "5 per minute; 20 per hour"
register_limit = "3 per minute; 10 per hour"
sensitive_limit = "3 per minute; 15 per hour"

# Track failed login attempts
failed_attempts = {}
LOCKOUT_THRESHOLD = 5  # Number of failed attempts before lockout
LOCKOUT_TIME = 15 * 60  # Lockout time in seconds (15 minutes)

def is_ip_blocked(ip):
    """Check if an IP is currently blocked due to too many failed attempts"""
    if ip in failed_attempts:
        attempts, timestamp = failed_attempts[ip]
        if attempts >= LOCKOUT_THRESHOLD:
            # Check if lockout period has expired
            if datetime.now().timestamp() - timestamp < LOCKOUT_TIME:
                return True
            else:
                # Reset after lockout period
                failed_attempts[ip] = (0, datetime.now().timestamp())
    return False

def record_failed_attempt(ip):
    """Record a failed login attempt"""
    now = datetime.now().timestamp()
    if ip in failed_attempts:
        attempts, _ = failed_attempts[ip]
        failed_attempts[ip] = (attempts + 1, now)
    else:
        failed_attempts[ip] = (1, now)
    
def reset_failed_attempts(ip):
    """Reset failed attempts counter after successful login"""
    if ip in failed_attempts:
        failed_attempts[ip] = (0, datetime.now().timestamp())

@app.before_request
def before_request():
    g.csp_nonce = secrets.token_hex(16)

@app.context_processor
def inject_nonce():
    if 'csp_nonce' in g:
        return {'csp_nonce': g.csp_nonce}
    return {}

# Keepalive endpoint for Render and Supabase services
@app.route("/keepalive", methods=["GET"])
def keepalive():
    """
    Endpoint to maintain persistent connections for both Render and Supabase services.
    This helps prevent cold starts and connection timeouts.
    """
    try:
        # Test database connection
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.close()
        return jsonify({"status": "ok", "message": "Services are operational", "timestamp": datetime.now().isoformat()})
    except Exception as e:
        app.logger.error(f"Keepalive check failed: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

# Security Headers
@app.after_request
def add_security_headers(response):
    """Add comprehensive security headers to every response"""
    # Content Security Policy
    csp = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{g.csp_nonce}'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-src 'none'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    
    # Set security headers
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Permissions-Policy'] = 'microphone=(), camera=(), geolocation=()'
    
    nonce = getattr(g, 'csp_nonce', '')
    if nonce:
        csp = (
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
            f"style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            f"font-src 'self' https://fonts.gstatic.com; "
            f"img-src 'self' data:; "
            f"connect-src 'self'"
        )
        response.headers['Content-Security-Policy'] = csp
    else:
        # Fallback for requests without a nonce
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'"

    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# CSRF Protection
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token():
    if request.method == 'POST':
        # Check form data first
        token = request.form.get('csrf_token')
        
        # If not in form data, check headers (for JSON requests)
        if not token:
            token = request.headers.get('X-CSRFToken')
        
        if not token or token != session.get('csrf_token'):
            return False
    return True

# Regular Expressions for Validation
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
TOTP_REGEX = re.compile(r"^\d{6}$")

# Handle 429 Too Many Requests
@app.errorhandler(429)
def ratelimit_error(e):
    return make_response("Too many requests! Slow down.", 429)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or 'user_id' not in session:
            flash("You must log in first!", "danger")
            return redirect(url_for('login', next=request.path))
        
        # Check session timeout
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(minutes=30):
                session.clear()
                flash("Session expired. Please log in again.", "warning")
                return redirect(url_for('login'))
        
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def two_factor_required(f):
    @wraps(f)
    def decorated_function_2(*args, **kwargs):
        if '2fa_verified' not in session:
            flash("You must complete 2FA verification first!", "danger")
            return redirect(url_for('verify_totp_page'))
        return f(*args, **kwargs)
    return decorated_function_2

def passkey_verified_required(f):
    @wraps(f)
    def decorated_function_3(*args, **kwargs):
        if 'passkey_verified' not in session:
            flash("You must complete Passkey verification first!", "danger")
            return redirect(url_for('verify_passkey_page'))
        return f(*args, **kwargs)
    return decorated_function_3

def get_db_connection(user_id=None):
    # Get user_id from session if not provided and within request context
    if user_id is None and has_request_context() and 'user_id' in session:
        user_id = session['user_id']
    
    conn = psycopg2.connect(os.getenv("SUPABASE_URL"))
    
    # Set the user ID for Row-Level Security if provided
    if user_id is not None:
        with conn.cursor() as cur:
            # Set the user ID for RLS policies
            cur.execute("SET app.current_user_id = %s", (str(user_id),))
            conn.commit()
    
    # For admin operations (like initial user lookup), set admin flag
    if user_id is None:  # If no user_id, we're likely doing an admin operation
        with conn.cursor() as cur:
            cur.execute('SET app.is_admin = true')
            conn.commit()
    
    return conn

def reset_connection_context(conn):
    """Reset RLS context before closing a connection"""
    try:
        with conn.cursor() as cur:
            cur.execute("RESET app.current_user_id")
            cur.execute("RESET app.is_admin")
            conn.commit()
    except Exception as e:
        app.logger.error(f"Error resetting connection context: {e}")
    finally:
        conn.close()

def create_users_table():
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Create table if it doesn't exist
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password TEXT,
                passkey_enabled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                account_locked_until TIMESTAMP
            );
        """)
        conn.commit()
        
        # Add secret column if it doesn't exist
        cur.execute("""
            DO $$ 
            BEGIN 
                IF NOT EXISTS (
                    SELECT 1 
                    FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'secret'
                ) THEN
                    ALTER TABLE users ADD COLUMN secret TEXT;
                END IF;
            END $$;
        """)
        
        # Add last_login column if it doesn't exist
        cur.execute("""
            DO $$ 
            BEGIN 
                IF NOT EXISTS (
                    SELECT 1 
                    FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'last_login'
                ) THEN
                    ALTER TABLE users ADD COLUMN last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
                END IF;
            END $$;
        """)
        
        # Add passkey_enabled column if it doesn't exist
        cur.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_name = 'users' AND column_name = 'passkey_enabled'
                ) THEN
                    ALTER TABLE users ADD COLUMN passkey_enabled BOOLEAN DEFAULT FALSE;
                END IF;
            END $$;
        """)
        
        # Create passkeys table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS passkeys (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                credential_id TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                sign_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        conn.commit()
    except Exception as e:
        print(f"Error creating/updating tables: {e}")
    finally:
        reset_connection_context(conn)

def get_user(username):
    # For initial login, we don't have a user_id yet, so we use admin access
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        return user
    finally:
        reset_connection_context(conn)

def get_user_by_id(user_id):
    # Pass the user_id to the connection for RLS
    conn = get_db_connection(user_id)
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        return user
    finally:
        reset_connection_context(conn)

def get_user_passkeys(user_id):
    # Pass the user_id to the connection for RLS
    conn = get_db_connection(user_id)
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM passkeys WHERE user_id = %s", (user_id,))
        passkeys = cur.fetchall()
        return passkeys
    finally:
        reset_connection_context(conn)

def save_passkey(user_id, credential_id, public_key):
    # Pass the user_id to the connection for RLS
    conn = get_db_connection(user_id)
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO passkeys (user_id, credential_id, public_key)
            VALUES (%s, %s, %s)
        """, (user_id, credential_id, public_key))
        conn.commit()
    finally:
        reset_connection_context(conn)

def update_passkey_sign_count(credential_id, sign_count, user_id=None):
    # Get user_id from session if not provided
    if user_id is None and 'user_id' in session:
        user_id = session['user_id']
        
    conn = get_db_connection(user_id)
    cur = conn.cursor()
    cur.execute("""
        UPDATE passkeys SET sign_count = %s 
        WHERE credential_id = %s
    """, (sign_count, credential_id))
    conn.commit()
    conn.close()

def get_passkey_by_credential_id(credential_id, user_id=None):
    # Get user_id from session if not provided
    if user_id is None and 'user_id' in session:
        user_id = session['user_id']
        
    conn = get_db_connection(user_id)
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM passkeys WHERE credential_id = %s", (credential_id,))
    passkey = cur.fetchone()
    conn.close()
    return passkey

@app.before_request
def enforce_https():
    if os.getenv("FLASK_ENV") == "production":
        # Check if we're already on HTTPS or if the proxy indicates HTTPS
        is_secure = request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https'
        
        # Only redirect if we're definitely not on HTTPS
        if not is_secure and request.url.startswith('http://'):
            return redirect(request.url.replace("http://", "https://"), code=301)

@app.route("/", methods=["GET", "POST"])
@limiter.limit(login_limit)
def login():
    # Check if user is already logged in
    if 'logged_in' in session and 'user_id' in session:
        user = get_user_by_id(session['user_id'])
        if user:
            if user['secret'] and '2fa_verified' not in session:
                return redirect(url_for("verify_totp_page"))
            elif user['secret'] and '2fa_verified' in session:
                # Check if user has passkeys
                passkeys = get_user_passkeys(user['id'])
                if not passkeys:
                    return redirect(url_for("setup_passkey_page"))
                else:
                    return redirect(url_for("dashboard"))
            else:
                return redirect(url_for("setup_totp"))
    
    error = None
    if request.method == "POST":
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        else:
            username = request.form["username"]
            password = request.form["password"].encode("utf-8")

            if not USERNAME_REGEX.match(username):
                error = "Invalid username or password!"
            else:
                user = get_user(username)

                if user:
                    # Check for account lockout
                    if user['account_locked_until'] and user['account_locked_until'] > datetime.now():
                        error = "Account locked due to too many failed login attempts. Please try again later."
                    elif bcrypt.checkpw(password, user["password"].encode("utf-8")):
                        # Reset failed attempts on successful login
                        conn = get_db_connection()
                        cur = conn.cursor()
                        cur.execute("UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = %s", (user['id'],))
                        conn.commit()
                        conn.close()

                        # Regenerate session to prevent session fixation
                        session.clear()
                        session.permanent = True
                        session['user_id'] = user['id']
                        session['username'] = user['username']
                        session['logged_in'] = True
                        session['last_activity'] = datetime.now().isoformat()

                        if user["secret"]:
                            return redirect(url_for("verify_totp_page"))
                        else:
                            return redirect(url_for("setup_totp"))
                    else:
                        # Increment failed login attempts
                        conn = get_db_connection()
                        cur = conn.cursor()
                        cur.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = %s RETURNING failed_login_attempts", (user['id'],))
                        failed_attempts = cur.fetchone()[0]
                        
                        # Lock account if attempts exceed threshold
                        if failed_attempts >= 5:
                            lock_duration = timedelta(minutes=15)
                            locked_until = datetime.now() + lock_duration
                            cur.execute("UPDATE users SET account_locked_until = %s WHERE id = %s", (locked_until, user['id']))
                            error = "Account locked for 15 minutes due to too many failed login attempts."
                        else:
                            error = "Invalid username or password!"
                        
                        conn.commit()
                        conn.close()
                else:
                    error = "Invalid username or password!"
    
    return render_template("login.html", error=error, csrf_token=generate_csrf_token())

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    error = None
    if request.method == "POST":
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        else:
            username = request.form["username"]
            password = request.form["password"].encode("utf-8")

            if not USERNAME_REGEX.match(username):
                error = "Invalid username format!"
            elif len(password) < 8:
                error = "Password must be at least 8 characters long!"

            if get_user(username):
                error = "Username already taken!"
            else:
                hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
                conn = get_db_connection()
                try:
                    cur = conn.cursor()
                    cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", 
                                (username, hashed_password.decode("utf-8")))
                    conn.commit()
                finally:
                    reset_connection_context(conn)

                return redirect(url_for("login"))

    return render_template("register.html", error=error, csrf_token=generate_csrf_token())

@app.route("/check-username/<username>")
def check_username(username):
    if not USERNAME_REGEX.match(username):
        return jsonify({"available": False, "reason": "invalid_format"})
    
    user = get_user(username)
    return jsonify({"available": user is None})

def verify_totp(secret, code):
    """Verify a TOTP code against a secret."""
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

# Passkey Registration
@app.route("/passkey/register/begin", methods=["POST"])
@login_required
def passkey_register_begin():
    if not validate_csrf_token():
        return jsonify({"error": "Invalid CSRF token"}), 403
    
    try:
        user = get_user_by_id(session['user_id'])
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Generate registration options
        options = generate_registration_options(
            rp_name=RP_NAME,
            rp_id=RP_ID,
            user_id=str(user['id']).encode('utf-8'),
            user_name=user['username'],
            user_display_name=user['username'],
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED
            )
        )

        # Store challenge in session
        session['passkey_challenge'] = bytes_to_base64url(options.challenge)
        session['passkey_user_id'] = str(user['id'])

        return jsonify({
            "publicKey": {
                "challenge": base64.b64encode(options.challenge).decode('utf-8'),
                "rp": {
                    "name": options.rp.name,
                    "id": options.rp.id
                },
                "user": {
                    "id": base64.b64encode(options.user.id).decode('utf-8'),
                    "name": options.user.name,
                    "displayName": options.user.display_name
                },
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": -7},  # ES256
                    {"type": "public-key", "alg": -257}  # RS256
                ],
                "timeout": 60000,
                "attestation": "direct",
                "authenticatorSelection": {
                    "authenticatorAttachment": "platform",
                    "userVerification": "preferred"
                }
            }
        })

    except Exception as e:
        logging.error(f"Error in passkey_register_begin: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/passkey/register/complete", methods=["POST"])
@login_required
def passkey_register_complete():
    if not validate_csrf_token():
        return jsonify({"error": "Invalid CSRF token"}), 403
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Manually construct the RegistrationCredential object from the JSON data
        credential_to_verify = RegistrationCredential(
            id=data["id"],
            raw_id=base64url_to_bytes(data["rawId"]),
            response=AuthenticatorAttestationResponse(
                client_data_json=base64url_to_bytes(data["response"]["clientDataJSON"]),
                attestation_object=base64url_to_bytes(data["response"]["attestationObject"])
            ),
            type=data["type"],
        )

        # Verify the registration response
        verification = verify_registration_response(
            credential=credential_to_verify,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            expected_challenge=base64url_to_bytes(session.get('passkey_challenge', ''))
        )

        # Save the passkey
        save_passkey(
            user_id=session['user_id'],
            credential_id=bytes_to_base64url(verification.credential_id),
            public_key=bytes_to_base64url(verification.credential_public_key)
        )

        # Update user to enable passkeys
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET passkey_enabled = TRUE WHERE id = %s", (session['user_id'],))
        conn.commit()
        conn.close()

        # Clear session data
        session.pop('passkey_challenge', None)
        session.pop('passkey_user_id', None)

        return jsonify({"success": True})

    except Exception as e:
        logging.error(f"Error in passkey_register_complete: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# Passkey Authentication
@app.route("/passkey/authenticate/begin", methods=["POST"])
@login_required
def passkey_authenticate_begin():
    if not validate_csrf_token():
        return jsonify({"error": "Invalid CSRF token"}), 403
    
    try:
        user = get_user_by_id(session['user_id'])
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Get user's passkeys
        passkeys = get_user_passkeys(user['id'])
        if not passkeys:
            return jsonify({"error": "No passkeys found for this user."}), 404

        # Generate authentication options
        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(passkey['credential_id']),
                    type="public-key"
                ) for passkey in passkeys
            ],
            user_verification=UserVerificationRequirement.PREFERRED
        )

        # Store challenge and user info in session
        session['passkey_challenge'] = bytes_to_base64url(options.challenge)
        session['passkey_user_id'] = str(user['id'])

        return jsonify({
            "publicKey": {
                "challenge": base64.b64encode(options.challenge).decode('utf-8'),
                "timeout": 60000,
                "rpId": options.rp_id,
                "allowCredentials": [
                    {
                        "id": base64.b64encode(base64url_to_bytes(passkey['credential_id'])).decode('utf-8'),
                        "type": "public-key"
                    } for passkey in passkeys
                ],
                "userVerification": "preferred"
            }
        })

    except Exception as e:
        logging.error(f"Error in passkey_authenticate_begin: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/passkey/authenticate/complete", methods=["POST"])
def passkey_authenticate_complete():
    if not validate_csrf_token():
        return jsonify({"error": "Invalid CSRF token"}), 403
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Get the passkey
        credential_id = data['id']
        passkey = get_passkey_by_credential_id(credential_id)
        
        if not passkey:
            return jsonify({"error": "Invalid credential"}), 400

        credential_to_verify = AuthenticationCredential(
            id=data["id"],
            raw_id=base64url_to_bytes(data["rawId"]),
            response=AuthenticatorAssertionResponse(
                authenticator_data=base64url_to_bytes(data["response"]["authenticatorData"]),
                client_data_json=base64url_to_bytes(data["response"]["clientDataJSON"]),
                signature=base64url_to_bytes(data["response"]["signature"]),
                user_handle=base64url_to_bytes(data["response"]["userHandle"]) if data["response"].get("userHandle") else None,
            ),
            type=data["type"],
        )

        # Verify the authentication response
        verification = verify_authentication_response(
            credential=credential_to_verify,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            expected_challenge=base64url_to_bytes(session.get('passkey_challenge', '')),
            credential_public_key=base64url_to_bytes(passkey['public_key']),
            credential_current_sign_count=passkey['sign_count']
        )

        # Update sign count
        update_passkey_sign_count(credential_id, verification.new_sign_count)

        # Get user and create session
        user = get_user_by_id(passkey['user_id'])
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Regenerate session
        session.clear()
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['logged_in'] = True
        session['last_activity'] = datetime.now().isoformat()
        session['2fa_verified'] = True # For TOTP
        session['passkey_verified'] = True # For Passkey

        # Update last login time
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s", (user['id'],))
        conn.commit()
        conn.close()

        return jsonify({"redirect": url_for('dashboard')})

    except Exception as e:
        logging.error(f"Error in passkey_authenticate_complete: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/setup-totp", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute")
def setup_totp():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = get_user_by_id(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if not validate_csrf_token():
            return render_template('setup_totp.html', 
                                 qr_code=session.get('temp_qr_code'),
                                 secret_key=session.get('temp_secret'),
                                 error='Invalid request. Please try again.',
                                 csrf_token=generate_csrf_token())
        
        totp_code = request.form.get('totp_code')
        if not totp_code or not TOTP_REGEX.match(totp_code):
            return render_template('setup_totp.html', 
                                 qr_code=session.get('temp_qr_code'),
                                 secret_key=session.get('temp_secret'),
                                 error='Please enter a valid 6-digit code',
                                 csrf_token=generate_csrf_token())
        
        # Verify the code
        if verify_totp(session.get('temp_secret'), totp_code):
            # Update user's secret
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("UPDATE users SET secret = %s WHERE id = %s", 
                       (session.get('temp_secret'), session['user_id']))
            conn.commit()
            conn.close()
            
            # Clear temporary data
            session.pop('temp_qr_code', None)
            session.pop('temp_secret', None)
            
            # Set 2FA verified flag
            session['2fa_verified'] = True
            
            return redirect(url_for('dashboard'))
        else:
            return render_template('setup_totp.html',
                                 qr_code=session.get('temp_qr_code'),
                                 secret_key=session.get('temp_secret'),
                                 error='Invalid code. Please try again.',
                                 csrf_token=generate_csrf_token())
    
    # Generate new TOTP secret
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user['username'],
        issuer_name="Secure Login Testing"
    )
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert QR code to base64
    buffered = BytesIO()
    qr_img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()
    
    # Store temporary data in session
    session['temp_qr_code'] = f"data:image/png;base64,{qr_base64}"
    session['temp_secret'] = secret
    
    return render_template('setup_totp.html',
                         qr_code=session['temp_qr_code'],
                         secret_key=secret,
                         csrf_token=generate_csrf_token())

@app.route("/cancel-setup")
@login_required
def cancel_setup():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = get_user_by_id(session['user_id'])
    if user:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id = %s", (session['user_id'],))
        conn.commit()
        conn.close()
    
    session.clear()
    response = make_response(redirect(url_for('login')))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route("/qrcode")
@login_required
def generate_qr():
    if "temp_totp_secret" not in session:
        flash("TOTP setup not initialized!", "error")
        return redirect(url_for("setup_totp"))

    username = session["username"]
    totp = pyotp.TOTP(session["temp_totp_secret"])
    otp_url = totp.provisioning_uri(username, issuer_name="Secure Login Testing")

    qr = qrcode.make(otp_url)
    img_io = io.BytesIO()
    qr.save(img_io, "PNG")
    img_io.seek(0)
    response = send_file(img_io, mimetype="image/png")
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@app.route("/verify-totp", methods=["GET", "POST"])
@login_required
def verify_totp_page():
    error = None

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = get_user_by_id(session["user_id"])
    if not user or not user["secret"]:
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
                session['2fa_verified'] = True
                
                # After TOTP, redirect to passkey verification
                return redirect(url_for("verify_passkey_page"))
            else:
                error = "Invalid 2FA code! Please try again."

    return render_template("verify_totp.html", error=error, csrf_token=generate_csrf_token())

@app.route("/verify-passkey", methods=["GET"])
@login_required
@two_factor_required
def verify_passkey_page():
    # Check if user has passkeys. If not, they must set one up.
    passkeys = get_user_passkeys(session['user_id'])
    if not passkeys:
        return redirect(url_for('setup_passkey_page'))
    
    # Render the page that will trigger the passkey verification
    return render_template('verify_passkey.html', csrf_token=generate_csrf_token())

@app.route("/setup-passkey")
@login_required
def setup_passkey_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Ensure user has completed 2FA
    if '2fa_verified' not in session:
        flash("You must complete 2FA verification first!", "error")
        return redirect(url_for("verify_totp_page"))
    
    user = get_user_by_id(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Check if user already has passkeys
    passkeys = get_user_passkeys(user['id'])
    if passkeys:
        return redirect(url_for('dashboard'))
    
    return render_template('setup_passkey.html', csrf_token=generate_csrf_token())

@app.route("/dashboard")
@login_required
@two_factor_required
@passkey_verified_required
def dashboard():
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Check if user has passkeys - if not, redirect to passkey setup
    passkeys = get_user_passkeys(user['id'])
    if not passkeys:
        return redirect(url_for("setup_passkey_page"))
    
    last_login = user["last_login"] if user and user["last_login"] else None
    return render_template("dashboard.html", last_login=last_login, csrf_token=generate_csrf_token())

@app.route("/passkey/status")
@login_required
def passkey_status():
    try:
        passkeys = get_user_passkeys(session['user_id'])
        return jsonify({
            "has_passkeys": len(passkeys) > 0,
            "count": len(passkeys)
        })
    except Exception as e:
        logging.error(f"Error in passkey_status: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/logout")
def logout():
    session.clear()
    response = make_response(redirect(url_for('login')))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route("/emergency-logout")
def emergency_logout():
    """Hidden emergency logout route for use during authentication process"""
    session.clear()
    response = make_response(redirect(url_for('login')))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response



@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == "__main__":
    create_users_table()
    # Disable debug mode in production
    debug_mode = os.getenv("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
