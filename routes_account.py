"""Account routes: deletion, password reset, account hub, recovery codes, passkeys, changes."""
from core import *  # noqa: F401,F403  (shared app, helpers and imports)


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
            elif password_breached(password):
                error = BREACH_MESSAGE
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
                    revoke_trusted_devices(user["id"])
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
        trusted=list_trusted_devices(user["id"]),
        is_admin=is_admin_user(user),
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
        forget_sessions(sid=sid)
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
    revoke_trusted_devices(user["id"])
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


# ----- trusted devices -------------------------------------------------------
@app.route("/account/trusted/revoke", methods=["POST"])
@login_required
@two_factor_required
@passkey_verified_required
def trusted_revoke():
    if not validate_csrf_token():
        flash("Invalid request. Please try again.", "error")
    elif request.form.get("all") == "1":
        revoke_trusted_devices(session["user_id"])
        flash("All trusted devices were removed.", "success")
    else:
        revoke_trusted_devices(session["user_id"], request.form.get("id", type=int))
        flash("Trusted device removed.", "success")
    return redirect(url_for("account"))


# ----- replace the authenticator app (new phone, lost phone) ---------------------
@app.route("/account/replace-authenticator", methods=["GET", "POST"])
@login_required
@two_factor_required
@passkey_verified_required
@limiter.limit("30 per hour", methods=["POST"])
def replace_authenticator():
    user = acct_user()
    if not user:
        return redirect(url_for("login"))
    if not user.get("email") or not user.get("email_verified"):
        flash("Replacing the authenticator needs a verified email. Add one in Change email first.", "warning")
        return redirect(url_for("account"))

    a = get_act("totp", user["id"])
    if a is None or (request.method == "GET" and request.args.get("restart")):
        a = start_act("totp", user["id"], "send")
    error = None

    if request.method == "POST":
        do = request.form.get("do")
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        elif do == "send" and a["stage"] in ("send", "code"):
            ok, msg = issue_email_code(user["id"], "chgtotp", user["email"])
            if ok:
                a["stage"] = "code"
                save_act(a)
            flash("Code sent. Check your inbox." if ok else msg, "success" if ok else "error")
            return redirect(url_for("replace_authenticator"))
        elif do == "verify" and a["stage"] == "code":
            code = request.form.get("totp_code", "")
            if not TOTP_REGEX.match(code):
                error = "Please enter a valid 6-digit code"
            else:
                ok, msg, sent_to = check_email_code(user["id"], "chgtotp", code)
                if ok and sent_to == user["email"]:
                    a["stage"], a["secret"] = "scan", pyotp.random_base32()
                    save_act(a)
                    return redirect(url_for("replace_authenticator"))
                a["fails"] += 1
                error = msg or "Incorrect code. Please try again."
        elif do == "confirm" and a["stage"] == "scan":
            code = request.form.get("totp_code", "")
            if not TOTP_REGEX.match(code):
                error = "Please enter a valid 6-digit code"
            elif verify_totp(a.get("secret"), code):
                db_run("UPDATE users SET secret = %s WHERE id = %s", (a["secret"], user["id"]), admin=True)
                revoke_other_sessions(user["id"], session.get("sid"))
                revoke_trusted_devices(user["id"])
                send_alert(user["email"], "Authenticator app replaced",
                           "The authenticator app on your account was replaced. Other devices were signed out.")
                log_event("totp_replaced", {"user_id": user["id"]}, "WARNING")
                session.pop("act", None)
                flash("Authenticator replaced. Other devices were signed out.", "success")
                return redirect(url_for("account"))
            else:
                a["fails"] += 1
                error = "Invalid 2FA code! Please try again."
        else:
            error = "That step isn't available right now."
        if a["fails"] >= 5:
            return _act_abort("Too many wrong attempts. The change was cancelled.")
        save_act(a)

    qr = secret = None
    if a["stage"] == "scan" and a.get("secret"):
        secret, qr = a["secret"], make_totp_qr(a["secret"], user["username"])
    return render_template("replace_authenticator.html", stage=a["stage"], error=error,
                           masked_email=mask_email(user["email"]), qr_code=qr, secret_key=secret,
                           csrf_token=generate_csrf_token())


# ----- download my data ----------------------------------------------------------------
@app.route("/account/export", methods=["POST"])
@login_required
@two_factor_required
@passkey_verified_required
@limiter.limit("5 per hour", methods=["POST"])
def export_data():
    user = acct_user()
    if not user:
        return redirect(url_for("login"))
    if not validate_csrf_token():
        flash("Invalid request. Please try again.", "error")
        return redirect(url_for("account"))
    uid = user["id"]

    def iso(value):
        return value.isoformat() if hasattr(value, "isoformat") else value

    data = {
        "exported_at_utc": iso(utcnow()),
        "profile": {
            "username": user["username"], "email": user.get("email"),
            "email_verified": bool(user.get("email_verified")),
            "sign_in_method": user.get("auth_provider"), "has_password": bool(user.get("password")),
            "google_linked": bool(user.get("google_sub")), "created_at": iso(user.get("created_at")),
            "last_login": iso(user.get("last_login")),
        },
        "passkeys": [{"name": p.get("name"), "added": iso(p.get("created_at")), "last_used": iso(p.get("last_used_at"))}
                     for p in get_user_passkeys(uid)],
        "recovery_codes_unused": count_recovery_codes(uid),
        "trusted_devices": [{"device": t["device"], "ip": t["ip"], "added": iso(t["created_at"]),
                             "expires": iso(t["expires_at"])} for t in list_trusted_devices(uid)],
        "sign_ins": [{"device": r["device"], "ip": r["ip"], "location": r["location"], "method": r["method"],
                      "signed_in": iso(r["created_at"]), "last_seen": iso(r["last_seen"]), "ended": iso(r["ended_at"])}
                     for r in (db_run("SELECT * FROM user_sessions WHERE user_id = %s AND completed = TRUE "
                                      "ORDER BY created_at DESC LIMIT 100", (uid,), fetch="all", admin=True) or [])],
        "security_events": [{"at": iso(r["at"]), "event": r["event"], "ip": r["ip"]}
                            for r in (db_run("SELECT at, event, ip FROM security_events WHERE user_id = %s "
                                             "ORDER BY id DESC LIMIT 100", (uid,), fetch="all", admin=True) or [])],
        "note": "Password hashes, authenticator secrets and recovery code hashes are never included.",
    }
    send_alert(user.get("email"), "Your data was downloaded", "A copy of your account data was downloaded.")
    log_event("data_exported", {"user_id": uid})
    response = make_response(json.dumps(data, indent=2, default=str))
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="{user["username"]}-account-data.json"'
    return response


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
            elif password_breached(new):
                error = BREACH_MESSAGE
            else:
                hashed = bcrypt.hashpw(new, bcrypt.gensalt()).decode("utf-8")
                db_run("UPDATE users SET password = %s WHERE id = %s", (hashed, user["id"]), admin=True)
                revoke_other_sessions(user["id"], session.get("sid"))
                revoke_trusted_devices(user["id"])
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
            else:
                ok, msg = issue_email_code(user["id"], "chgemail_new", new_email)
                if ok:
                    a["stage"], a["new_email"] = "code_new", new_email
                    save_act(a)
                    flash("Code sent to your new address.", "success")
                    return redirect(url_for("change_email"))
                error = msg
        elif do == "resend" and a["stage"] == "code_new" and a.get("new_email"):
            ok, msg = issue_email_code(user["id"], "chgemail_new", a["new_email"])
            flash("A new code is on its way." if ok else msg, "success" if ok else "error")
            return redirect(url_for("change_email"))
        elif do == "verify" and a["stage"] == "code_new":
            code = request.form.get("totp_code", "")
            if not TOTP_REGEX.match(code):
                error = "Please enter a valid 6-digit code"
            else:
                ok, msg, sent_to = check_email_code(user["id"], "chgemail_new", code)
                if ok and sent_to == a.get("new_email"):
                    try:
                        db_run("UPDATE users SET email = %s, email_verified = TRUE WHERE id = %s",
                               (sent_to, user["id"]), admin=True)
                    except pg_errors.UniqueViolation:
                        return _act_abort("That email is already in use.")
                    revoke_other_sessions(user["id"], session.get("sid"))
                    send_alert(user.get("email"), "Email address changed",
                               f"The email on your account was changed to {mask_email(sent_to)}.")
                    send_alert(sent_to, "Email address changed",
                               "This address is now the email on your account.")
                    log_event("email_changed", {"user_id": user["id"]}, "WARNING")
                    session.pop("act", None)
                    flash("Email changed. Other devices were signed out.", "success")
                    return redirect(url_for("account"))
                a["fails"] += 1
                error = msg or "Incorrect code. Please try again."
        else:
            error = "That step isn't available right now."
        if a["fails"] >= 5:
            return _act_abort("Too many wrong attempts. The email change was cancelled.")
        save_act(a)

    return render_template("change_email.html", stage=a["stage"], error=error,
                           masked_old=mask_email(user.get("email")), masked_new=mask_email(a.get("new_email")),
                           csrf_token=generate_csrf_token())

# END OF routes_account.py
