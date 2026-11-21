"""Sign-in routes: login, register, email check, Google, passkeys, TOTP, dashboard."""
from core import *  # noqa: F401,F403  (shared app, helpers and imports)


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
                if user and stored and matches and user.get("disabled"):
                    log_event("login_blocked_disabled", {"user_id": user["id"]}, "WARNING")
                    return render_template("login.html", csrf_token=generate_csrf_token(),
                                           error="This account has been disabled. Contact the administrator.",
                                           google_enabled=bool(GOOGLE_CLIENT_ID))
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
            elif password_breached(password):
                error = BREACH_MESSAGE
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
    if user and user.get("disabled"):
        log_event("login_blocked_disabled", {"user_id": user["id"]}, "WARNING")
        flash("This account has been disabled. Contact the administrator.", "error")
        return redirect(url_for("login"))
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
    session["temp_qr_code"] = make_totp_qr(secret, user["username"])
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

    if request.method == "GET" and trusted_device_valid(user["id"]):
        session["2fa_verified"] = True          # trusted device: the passkey is still required
        return redirect(url_for("verify_passkey_page"))

    if request.method == "POST":
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        else:
            totp_code = request.form.get("totp_code")
            if not totp_code or not TOTP_REGEX.match(totp_code):
                error = "Please enter a valid 6-digit code"
            elif verify_totp(user["secret"], totp_code):
                session["2fa_verified"] = True
                response = make_response(redirect(url_for("verify_passkey_page")))
                if request.form.get("trust") == "1":
                    set_trust_cookie(response, create_trusted_device(user["id"]))
                    log_event("trusted_device_added", {"user_id": user["id"]})
                return response
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

# END OF routes_auth.py
