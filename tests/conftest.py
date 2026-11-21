"""Test setup: runs before the app is imported, so the app starts without any real services."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.update({
    "FLASK_PASS": "test-secret-not-for-production",
    "SUPABASE_URL": "postgresql://user:pass@127.0.0.1:1/none",   # never contacted: SKIP_DB_INIT + fake db
    "SKIP_DB_INIT": "1",
    "GEOIP": "off",                 # no location lookups
    "HIBP_CHECK": "off",            # no breached-password lookups (tests that need it mock it)
    "RATELIMIT_ENABLED": "false",
    "ADMIN_USERNAMES": "root",
})
