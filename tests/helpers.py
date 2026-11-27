"""Shared test tools: an in-memory SQLite database that stands in for Postgres, a tiny browser
(`Client`) and helpers to create fully signed-up users. No network or real services are used."""
import importlib
import re
import sqlite3
import time
import types
from datetime import datetime

import pyotp
from psycopg2 import errors as pg_errors

import app as entry  # noqa: F401  (also runs the "is every file complete" check)

MODULES = [importlib.import_module(n) for n in
           ("core", "routes_auth", "routes_account", "routes_admin", "routes_misc")]
UA_PHONE = ("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/157.0.0.0 Mobile Safari/537.36")
UA_PC = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
         "Chrome/120.0 Safari/537.36")


class _Proxy:
    """Read and patch names across every module of the split app at once."""
    def __getattr__(self, name):
        for m in MODULES:
            if hasattr(m, name):
                return getattr(m, name)
        raise AttributeError(name)

    def __setattr__(self, name, value):
        hit = False
        for m in MODULES:
            if hasattr(m, name):
                setattr(m, name, value)
                hit = True
        if not hit:
            setattr(MODULES[0], name, value)


A = _Proxy()
A.app.config["SESSION_COOKIE_SECURE"] = False   # the test client talks plain http
ROOT = __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__)))
# the real functions, kept so tests can still reach them after setup() replaces some with fakes
REAL = types.SimpleNamespace(password_breached=A.password_breached, geo_lookup=A.geo_lookup,
                            db_exec=A._db_exec, db_exec_batch=A._db_exec_batch)

SCHEMA = """
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT, secret TEXT,
  passkey_enabled BOOLEAN DEFAULT 0, email TEXT, email_verified BOOLEAN DEFAULT 0, google_sub TEXT UNIQUE,
  auth_provider TEXT DEFAULT 'password', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP, failed_login_attempts INTEGER DEFAULT 0,
  account_locked_until TIMESTAMP, disabled BOOLEAN DEFAULT 0);
CREATE TABLE passkeys (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, credential_id TEXT UNIQUE NOT NULL,
  public_key TEXT NOT NULL, sign_count INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  name TEXT, last_used_at TIMESTAMP);
CREATE TABLE email_codes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, purpose TEXT, email TEXT,
  code_hash TEXT, expires_at TIMESTAMP, attempts INTEGER DEFAULT 0, used BOOLEAN DEFAULT 0, created_at TIMESTAMP);
CREATE TABLE recovery_codes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, code_hash TEXT,
  used BOOLEAN DEFAULT 0, used_at TIMESTAMP, created_at TIMESTAMP);
CREATE TABLE user_sessions (id TEXT PRIMARY KEY, user_id INTEGER, created_at TIMESTAMP, last_seen TIMESTAMP,
  ip TEXT, user_agent TEXT, device TEXT, location TEXT, method TEXT, completed BOOLEAN DEFAULT 0,
  revoked BOOLEAN DEFAULT 0, ended_at TIMESTAMP);
CREATE TABLE trusted_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, token_hash TEXT UNIQUE,
  device TEXT, ip TEXT, created_at TIMESTAMP, last_used TIMESTAMP, expires_at TIMESTAMP);
CREATE TABLE security_events (id INTEGER PRIMARY KEY AUTOINCREMENT, at TIMESTAMP, event TEXT, level TEXT,
  user_id INTEGER, ip TEXT, details TEXT);
"""
sqlite3.register_adapter(datetime, lambda d: d.isoformat(" "))
sqlite3.register_converter("TIMESTAMP", lambda b: datetime.fromisoformat(b.decode()))


def _sql(sql):
    return sql.replace("%s", "?").replace("TRUE", "1").replace("FALSE", "0")


class Env:
    """One fresh database, mailbox and set of patches per test."""
    def __init__(self):
        self.db = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
        self.db.row_factory = lambda cur, row: {d[0]: row[i] for i, d in enumerate(cur.description)}
        self.db.executescript(SCHEMA)
        self.mails = []
        self.counter = 0
        A._db_exec, A._db_exec_batch = self._run, self._batch   # the lowest layer: caches/logging stay real
        A._SESSION_OK.clear()
        A.run_async = lambda fn: fn()                      # background jobs run inline
        A.send_email = lambda to, subject, text: (self.mails.append((to, subject, text)) or True)
        A.password_breached = lambda raw: False
        A.geo_lookup = REAL.geo_lookup
        A.bytes_to_base64url = lambda b: b.decode() if isinstance(b, bytes) else b
        A.base64url_to_bytes = lambda s: s.encode() if isinstance(s, str) else b""
        A._verify_assertion = lambda *a, **k: types.SimpleNamespace(new_sign_count=5)
        A.verify_registration_response = self._fake_registration
        A.PROXY_HOPS, A.CLIENT_IP_HEADER = 1, ""
        A._status_cache.update(at=None, data=None)
        A._GEO_CACHE.clear()

    def _run(self, sql, params=(), fetch=None, user_id=None, admin=False):
        try:
            cur = self.db.execute(_sql(sql), tuple(params))
            result = cur.fetchone() if fetch == "one" else cur.fetchall() if fetch == "all" else None
            self.db.commit()
            return result
        except sqlite3.IntegrityError as e:
            self.db.rollback()
            raise pg_errors.UniqueViolation(str(e))

    def _batch(self, statements, admin=True, user_id=None):
        try:
            for sql, params in statements:
                self.db.execute(_sql(sql), tuple(params))
            self.db.commit()
        except sqlite3.IntegrityError as e:
            self.db.rollback()
            raise pg_errors.UniqueViolation(str(e))

    def _fake_registration(self, **kwargs):
        self.counter += 1
        return types.SimpleNamespace(credential_id=f"cred-{self.counter}".encode(), credential_public_key=b"pub")

    def one(self, sql, *params):
        return self.db.execute(sql, params).fetchone()

    def all(self, sql, *params):
        return self.db.execute(sql, params).fetchall()

    def last_code(self, to):
        """Most recent verification code emailed to this address."""
        for mail in reversed(self.mails):
            if mail[0] == to:
                found = re.search(r"code is ([A-Z0-9-]+)", mail[2])
                if found:
                    return found.group(1).replace("-", "")
        return None

    def alerts(self, to):
        return [m[1] for m in self.mails if m[0] == to and m[1].startswith("Security alert")]


def setup():
    return Env()


class Client:
    """A minimal browser: keeps cookies, sends a User-Agent and a client IP."""
    def __init__(self, ua=UA_PHONE, ip="8.8.8.8"):
        self.c = A.app.test_client()
        self.ua, self.ip = ua, ip

    def _headers(self):
        return {"User-Agent": self.ua, "X-Forwarded-For": self.ip}

    def get(self, path, extra=None, **kw):
        return self.c.get(path, headers={**self._headers(), **(extra or {})}, **kw)

    def token(self, path="/"):
        html = self.get(path).get_data(as_text=True)
        return re.search(r'(?:name="csrf_token" value|data-csrf)="([0-9a-f]+)"', html).group(1)

    def post(self, path, token_from=None, **data):
        return self.c.post(path, data={"csrf_token": self.token(token_from or path), **data},
                           headers=self._headers())

    def post_json(self, path, payload):
        with self.c.session_transaction() as s:
            token = s.get("csrf_token", "")
        return self.c.post(path, json=payload, headers={**self._headers(), "X-CSRFToken": token})

    def session(self):
        with self.c.session_transaction() as s:
            return dict(s)


def loc(response):
    return response.headers.get("Location", "")


def totp_now(secret):
    """Current authenticator code. Waits out the last second of a 30-second window so the code
    can't expire between creating it and the app checking it."""
    left = 30 - (time.time() % 30)
    if left < 1.0:
        time.sleep(left + 0.05)
    return pyotp.TOTP(secret).now()


class Person:
    def __init__(self, username, email, password, client):
        self.username, self.email, self.password, self.client = username, email, password, client
        self.codes, self.secret, self.cred = [], None, None

    def code(self):
        return totp_now(self.secret)


RECOVERY_RE = re.compile(r"\b[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}\b")


def signup(env, username="alice", email=None, password="pw123456", ua=UA_PHONE, ip="8.8.8.8"):
    """Register, verify email, set up TOTP, add a passkey and sign in: a fully signed-in user."""
    email = email or f"{username}@x.com"
    p = Person(username, email, password, Client(ua, ip))
    c = p.client
    assert loc(c.post("/register", token_from="/register", username=username, email=email,
                      password=password)).endswith("/verify-email")
    assert loc(c.post("/verify-email", do="verify", totp_code=env.last_code(email))).endswith("/setup-totp")
    c.get("/setup-totp")
    p.secret = c.session()["temp_secret"]
    # the token must come from another page: loading /setup-totp again would create a NEW secret
    page = c.post("/setup-totp", token_from="/register", totp_code=totp_now(p.secret)).get_data(as_text=True)
    p.codes = RECOVERY_RE.findall(page)
    assert c.post_json("/passkey/register/complete", {
        "id": "x", "rawId": "x", "type": "public-key",
        "response": {"clientDataJSON": "a", "attestationObject": "b"}}).status_code == 200
    p.cred = env.one("SELECT credential_id FROM passkeys WHERE user_id = "
                     "(SELECT id FROM users WHERE username = ?)", username)["credential_id"]
    assert passkey_step(c, p).status_code == 200
    return p


def passkey_step(client, person):
    client.get("/verify-passkey")          # the page that carries the CSRF token, like a real browser
    return client.post_json("/passkey/authenticate/complete",
                            {"id": person.cred, "rawId": "x", "type": "public-key", "response": {}})


def full_login(person, client=None, trust=False):
    """Password, authenticator code and passkey on a (new) client."""
    c = client or Client(person.client.ua, person.client.ip)
    c.post("/", token_from="/", username=person.username, password=person.password)
    extra = {"trust": "1"} if trust else {}
    first = c.get("/verify-totp")
    if "/verify-passkey" not in loc(first):             # not a trusted device: enter the code
        c.post("/verify-totp", token_from="/verify-totp", totp_code=person.code(), **extra)
    resp = passkey_step(c, person)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return c
