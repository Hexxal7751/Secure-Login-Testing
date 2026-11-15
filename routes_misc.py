"""Logout and error pages."""
from core import *  # noqa: F401,F403  (shared app, helpers and imports)


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------
def _logout_response():
    end_session(session.get("sid"))
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


@app.errorhandler(psycopg2.OperationalError)
def handle_db_down(e):
    app.logger.error("Database unavailable: %s", str(e).strip()[:300])
    return render_error(503)


@app.errorhandler(Exception)
def handle_any_exception(e):
    if isinstance(e, HTTPException):
        # 404 / 405 / 429 (rate limiter) and friends
        return render_error(e.code or 500, e.get_headers())
    app.logger.exception("Unhandled exception")
    return render_error(500)

# END OF routes_misc.py
