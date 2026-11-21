"""Entry point. Gunicorn runs `app:app`; `python app.py` starts the dev server.

The code is split into small files so each one is easy to copy and paste without
being cut off. The check below stops the app with a clear message if any file is
incomplete (for example a copy/paste that was truncated).
"""
import os

PARTS = ("app", "core", "routes_auth", "routes_account", "routes_admin", "routes_misc",
         "i18n", "translations_es", "translations_fr")


def _check_files_complete():
    here = os.path.dirname(os.path.abspath(__file__))
    for name in PARTS:
        path = os.path.join(here, name + ".py")
        with open(path, encoding="utf-8") as f:
            last = [ln for ln in f.read().splitlines() if ln.strip()][-1].strip()
        if last != f"# END OF {name}.py":
            raise RuntimeError(f"{name}.py looks cut off (the last line should be '# END OF {name}.py'). "
                               "Paste the whole file again.")


_check_files_complete()

from core import app  # noqa: E402  (creates the Flask app, config, database and email helpers)
import routes_auth  # noqa: E402,F401
import routes_account  # noqa: E402,F401
import routes_admin  # noqa: E402,F401
import routes_misc  # noqa: E402,F401

if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=10000, debug=debug_mode)

# END OF app.py
