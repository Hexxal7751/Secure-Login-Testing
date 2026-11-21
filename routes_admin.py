"""Admin pages (users, security events, network check) and the public status page.

Admins are the usernames listed in the ADMIN_USERNAMES environment variable. On top of a full
sign-in (password/Google, authenticator, passkey) an admin must enter an authenticator code again
every 15 minutes before any admin page opens.
"""
from core import *  # noqa: F401,F403  (shared app, helpers and imports)

STARTED_AT = utcnow()
_status_cache = {"at": None, "data": None}


# ---------------------------------------------------------------------------
# Admin step-up
# ---------------------------------------------------------------------------
@app.route("/admin/verify", methods=["GET", "POST"])
@login_required
@two_factor_required
@passkey_verified_required
@limiter.limit("10 per minute", methods=["POST"])
def admin_verify():
    user = get_user_by_id(session["user_id"])
    if not is_admin_user(user):
        abort(404)
    nxt = request.args.get("next", "/admin")
    if not nxt.startswith("/admin") or nxt.startswith("//"):
        nxt = "/admin"
    error = None
    if request.method == "POST":
        code = request.form.get("totp_code", "")
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        elif TOTP_REGEX.match(code) and verify_totp(user["secret"], code):
            session["admin_until"] = (utcnow() + ADMIN_STEPUP).isoformat()
            log_event("admin_stepup", {"user_id": user["id"]}, "WARNING")
            return redirect(nxt)
        else:
            error = "Invalid 2FA code! Please try again."
            log_event("admin_stepup_failed", {"user_id": user["id"]}, "WARNING")
    return render_template("admin_verify.html", error=error, csrf_token=generate_csrf_token())


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
def _count(sql, params=()):
    row = db_run(sql, params, fetch="one", admin=True)
    return int(row["n"]) if row else 0


@app.route("/admin")
@admin_required
def admin():
    now = utcnow()
    q = re.sub(r"[%_\\\\]", "", request.args.get("q", "")).strip()[:30]
    event = re.sub(r"[^a-z_]", "", request.args.get("event", "").lower())[:40]
    stats = {
        "users": _count("SELECT COUNT(*) AS n FROM users"),
        "disabled": _count("SELECT COUNT(*) AS n FROM users WHERE disabled = TRUE"),
        "locked": _count("SELECT COUNT(*) AS n FROM users WHERE account_locked_until > %s", (now,)),
        "online": _count("SELECT COUNT(*) AS n FROM user_sessions WHERE completed = TRUE AND revoked = FALSE "
                         "AND last_seen > %s", (now - SESSION_IDLE,)),
    }
    users = db_run(
        "SELECT id, username, email, auth_provider, google_sub, created_at, last_login, disabled, "
        "account_locked_until FROM users WHERE username LIKE %s ORDER BY id DESC LIMIT 50",
        (f"%{q}%",), fetch="all", admin=True) or []
    if event:
        events = db_run("SELECT * FROM security_events WHERE event = %s ORDER BY id DESC LIMIT 50",
                        (event,), fetch="all", admin=True) or []
    else:
        events = db_run("SELECT * FROM security_events ORDER BY id DESC LIMIT 50", fetch="all", admin=True) or []
    rows = [{
        "id": u["id"], "username": u["username"], "email": mask_email(u.get("email")),
        "provider": "google" if u.get("auth_provider") == "google" else ("password + google" if u.get("google_sub") else "password"),
        "created": u.get("created_at"), "last_login": u.get("last_login"),
        "disabled": bool(u.get("disabled")),
        "locked": bool(u.get("account_locked_until") and u["account_locked_until"] > now),
        "is_admin": u["username"] in ADMIN_USERNAMES, "is_me": u["id"] == session["user_id"],
    } for u in users]
    return render_template("admin.html", stats=stats, users=rows, events=events, q=q, event=event,
                           csrf_token=generate_csrf_token())


def _admin_action(uid, what):
    """Run one admin action on a user, with a log entry and an email to the user."""
    if not validate_csrf_token():
        flash("Invalid request. Please try again.", "error")
        return redirect(url_for("admin"))
    target = get_user_by_id(uid)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("admin"))
    if what in ("disable", "signout") and (target["id"] == session["user_id"] or target["username"] in ADMIN_USERNAMES):
        flash("Admins can't be disabled or signed out from here.", "error")
        return redirect(url_for("admin"))

    if what == "disable":
        db_run("UPDATE users SET disabled = TRUE WHERE id = %s", (uid,), admin=True)
        revoke_other_sessions(uid)
        revoke_trusted_devices(uid)
        send_alert(target.get("email"), "Account disabled", "An administrator disabled your account.")
        flash(f"{target['username']} was disabled and signed out everywhere.", "success")
    elif what == "enable":
        db_run("UPDATE users SET disabled = FALSE WHERE id = %s", (uid,), admin=True)
        send_alert(target.get("email"), "Account enabled", "An administrator enabled your account again.")
        flash(f"{target['username']} was enabled.", "success")
    elif what == "unlock":
        db_run("UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE id = %s", (uid,), admin=True)
        flash(f"{target['username']} was unlocked.", "success")
    elif what == "signout":
        count = revoke_other_sessions(uid)
        revoke_trusted_devices(uid)
        flash(f"Signed {target['username']} out of {count} device(s).", "success")
    log_event("admin_action", {"user_id": session["user_id"], "action": what, "target": uid}, "WARNING")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:uid>/<what>", methods=["POST"])
@admin_required
def admin_user_action(uid, what):
    if what not in ("disable", "enable", "unlock", "signout"):
        abort(404)
    return _admin_action(uid, what)


@app.route("/admin/network")
@admin_required
def admin_network():
    """Shows how the app sees your connection, to configure client-IP detection."""
    names = ("X-Forwarded-For", "CF-Connecting-IP", "True-Client-IP", "X-Real-IP", "Forwarded")
    return render_template("admin_network.html", ip=client_ip(), remote=request.remote_addr,
                           headers=[(n, request.headers.get(n, "")) for n in names],
                           configured_header=CLIENT_IP_HEADER, hops=PROXY_HOPS)


# ---------------------------------------------------------------------------
# Public status page
# ---------------------------------------------------------------------------
def _status():
    """Cached for 15 seconds so monitors can't hammer the database."""
    now = utcnow()
    if _status_cache["at"] and (now - _status_cache["at"]).total_seconds() < 15:
        return _status_cache["data"]
    try:
        db_run("SELECT 1 AS ok", fetch="one", admin=True)
        db_ok = True
    except Exception:
        db_ok = False
    email_ok = bool((AGENTMAIL_API_KEY and AGENTMAIL_INBOX) or (RESEND_API_KEY and MAIL_FROM))
    data = {
        "status": "operational" if db_ok else "degraded",
        "checks": {"web": True, "database": db_ok, "email": email_ok, "google_sign_in": bool(GOOGLE_CLIENT_ID)},
        "uptime_seconds": int((now - STARTED_AT).total_seconds()),
        "checked_at_utc": now.strftime("%Y-%m-%d %H:%M:%S"),
    }
    _status_cache.update(at=now, data=data)
    return data


@app.route("/status")
@limiter.limit("60 per minute")
def status_page():
    data = _status()
    return render_template("status.html", **data), (200 if data["checks"]["database"] else 503)


@app.route("/status.json")
@limiter.limit("60 per minute")
def status_json():
    data = _status()
    return jsonify(data), (200 if data["checks"]["database"] else 503)


# END OF routes_admin.py
