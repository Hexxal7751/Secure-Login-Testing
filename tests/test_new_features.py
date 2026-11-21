import io
import json
import logging
import types
import urllib.request

import os

from helpers import A, Client, ROOT, UA_PC, UA_PHONE, full_login, loc, setup, signup, totp_now


# ---------------------------------------------------------------- authenticator replace
def test_replace_authenticator_needs_email_code_and_forgets_trusted_devices():
    env = setup()
    alice = signup(env)
    c = alice.client
    full_login(alice, Client(), trust=True)                   # creates a trusted device
    assert env.one("SELECT COUNT(*) AS n FROM trusted_devices")["n"] == 1
    other = full_login(alice, Client(UA_PC, "9.9.9.9"))
    old_secret = env.one("SELECT secret FROM users")["secret"]
    c.get("/account/replace-authenticator?restart=1")
    assert b"isn&#39;t available" in c.post("/account/replace-authenticator", token_from="/account/replace-authenticator",
                                            do="confirm", totp_code="123456").data
    c.post("/account/replace-authenticator", token_from="/account/replace-authenticator", do="send")
    c.post("/account/replace-authenticator", token_from="/account/replace-authenticator", do="verify",
           totp_code=env.last_code("alice@x.com"))
    page = c.get("/account/replace-authenticator").get_data(as_text=True)
    assert "data:image/png;base64" in page
    new_secret = c.session()["act"]["secret"]
    assert new_secret != old_secret
    r = c.post("/account/replace-authenticator", token_from="/account/replace-authenticator", do="confirm",
               totp_code=totp_now(new_secret))
    assert loc(r).endswith("/account")
    assert env.one("SELECT secret FROM users")["secret"] == new_secret
    assert env.one("SELECT COUNT(*) AS n FROM trusted_devices")["n"] == 0
    assert "/" == loc(other.get("/dashboard")).split("?")[0]
    assert any("Authenticator app replaced" in a for a in env.alerts("alice@x.com"))


# ---------------------------------------------------------------- trusted devices
def test_trusted_device_skips_totp_but_not_the_passkey_and_can_be_revoked():
    env = setup()
    alice = signup(env)
    phone = Client()
    full_login(alice, phone, trust=True)
    assert env.one("SELECT COUNT(*) AS n FROM trusted_devices")["n"] == 1
    phone.get("/logout")
    phone.post("/", token_from="/", username="alice", password="pw123456")
    assert loc(phone.get("/verify-totp")).endswith("/verify-passkey")        # TOTP skipped
    assert phone.get("/dashboard").status_code == 302                         # passkey still required
    # a different browser without the cookie still gets the TOTP page
    stranger = Client()
    stranger.post("/", token_from="/", username="alice", password="pw123456")
    assert stranger.get("/verify-totp").status_code == 200
    # revoke it from the account page: TOTP is asked again
    from helpers import passkey_step
    passkey_step(phone, alice)
    tid = env.one("SELECT id FROM trusted_devices")["id"]
    phone.post("/account/trusted/revoke", token_from="/account", id=tid)
    phone.get("/logout")
    phone.post("/", token_from="/", username="alice", password="pw123456")
    assert phone.get("/verify-totp").status_code == 200


def test_changing_the_password_forgets_trusted_devices():
    env = setup()
    alice = signup(env)
    full_login(alice, Client(), trust=True)
    c = alice.client
    c.get("/account/change-password?restart=1")
    c.post("/account/change-password", token_from="/account/change-password", do="send")
    c.post("/account/change-password", token_from="/account/change-password", do="verify",
           totp_code=env.last_code("alice@x.com"))
    c.post("/account/change-password", token_from="/account/change-password", do="save",
           current="pw123456", password="another-pass9", confirm="another-pass9")
    assert env.one("SELECT COUNT(*) AS n FROM trusted_devices")["n"] == 0


# ---------------------------------------------------------------- new sign-in alerts
def test_new_device_triggers_an_email_but_a_known_one_does_not():
    env = setup()
    alice = signup(env)                                    # first sign-in: no alert
    assert not [a for a in env.alerts("alice@x.com") if "New sign-in" in a]
    full_login(alice, Client(UA_PC, "7.7.7.7"))            # a different device
    assert len([a for a in env.alerts("alice@x.com") if "New sign-in" in a]) == 1
    full_login(alice, Client(UA_PC, "7.7.7.7"))            # same device again
    assert len([a for a in env.alerts("alice@x.com") if "New sign-in" in a]) == 1


def test_new_place_triggers_an_email():
    env = setup()
    alice = signup(env)
    env.db.execute("UPDATE user_sessions SET location = 'Paris, France'"); env.db.commit()
    A.geo_lookup = lambda ip: "Berlin, Germany"
    full_login(alice, Client(UA_PHONE, "5.5.5.5"))         # same device label, new place
    mail = [m for m in env.mails if m[1].startswith("Security alert: New sign-in")]
    assert mail and "Berlin, Germany" in mail[0][2]


# ---------------------------------------------------------------- breached passwords
class _Resp:
    def __init__(self, body):
        self.body = body
    def __enter__(self):
        return self
    def __exit__(self, *a):
        pass
    def read(self):
        return self.body.encode()


def test_breached_password_check_sends_only_a_hash_prefix():
    import os
    from helpers import REAL
    original, seen = urllib.request.urlopen, []
    try:
        os.environ["HIBP_CHECK"] = "on"
        # SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8

        def fake(req, timeout=0):
            seen.append(req.full_url)
            return _Resp("0000000000000000000000000000000000A:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n")
        urllib.request.urlopen = fake
        assert REAL.password_breached(b"password") is True
        assert seen == ["https://api.pwnedpasswords.com/range/5BAA6"]       # only the 5-character prefix
        urllib.request.urlopen = lambda req, timeout=0: _Resp("0000000000000000000000000000000000B:3\r\n")
        assert REAL.password_breached(b"password") is False

        def boom(req, timeout=0):
            raise OSError("offline")
        urllib.request.urlopen = boom
        assert REAL.password_breached(b"password") is False                  # fails open when offline
    finally:
        urllib.request.urlopen = original
        os.environ["HIBP_CHECK"] = "off"


def test_breached_passwords_are_refused_at_signup_and_change():
    env = setup()
    A.password_breached = lambda raw: raw == b"password123"
    c = Client()
    r = c.post("/register", username="bob", email="bob@x.com", password="password123")
    assert b"known data breach" in r.data and env.one("SELECT COUNT(*) AS n FROM users")["n"] == 0
    alice = signup(env)
    cc = alice.client
    cc.get("/account/change-password?restart=1")
    cc.post("/account/change-password", token_from="/account/change-password", do="send")
    cc.post("/account/change-password", token_from="/account/change-password", do="verify",
            totp_code=env.last_code("alice@x.com"))
    r = cc.post("/account/change-password", token_from="/account/change-password", do="save",
                current="pw123456", password="password123", confirm="password123")
    assert b"known data breach" in r.data


# ---------------------------------------------------------------- admin
def test_admin_pages_have_extra_checks_and_actions_work():
    env = setup()
    root = signup(env, "root")
    bob = signup(env, "bob")
    assert bob.client.get("/admin").status_code == 404                        # not an admin
    c = root.client
    assert "/admin/verify" in loc(c.get("/admin"))                           # step-up first
    r = c.post("/admin/verify", token_from="/admin/verify", totp_code="000000")
    assert b"Invalid 2FA" in r.data
    assert loc(c.post("/admin/verify", token_from="/admin/verify", totp_code=root.code())).endswith("/admin")
    html = c.get("/admin").get_data(as_text=True)
    assert "bob" in html and "Users" in html and "security events" in html.lower()
    bob_id = env.one("SELECT id FROM users WHERE username = 'bob'")["id"]
    root_id = env.one("SELECT id FROM users WHERE username = 'root'")["id"]
    c.post(f"/admin/users/{bob_id}/disable", token_from="/admin")
    assert env.one("SELECT disabled FROM users WHERE id = ?", bob_id)["disabled"]
    assert "/" == loc(bob.client.get("/dashboard")).split("?")[0]             # signed out everywhere
    assert b"disabled" in Client().post("/", username="bob", password="pw123456").data
    c.post(f"/admin/users/{root_id}/disable", token_from="/admin")           # admins are protected
    assert not env.one("SELECT disabled FROM users WHERE id = ?", root_id)["disabled"]
    c.post(f"/admin/users/{bob_id}/enable", token_from="/admin")
    assert Client().post("/", username="bob", password="pw123456").status_code == 302
    assert env.one("SELECT COUNT(*) AS n FROM security_events WHERE event = 'admin_action'")["n"] >= 2
    assert b"X-Forwarded-For" in c.get("/admin/network").data


def test_status_page_reports_database_problems_with_503():
    env = setup()
    c = Client()
    r = c.get("/status.json")
    body = json.loads(r.data)
    assert r.status_code == 200 and body["status"] == "operational" and body["checks"]["database"] is True
    assert b"Service status" in c.get("/status").data
    A._status_cache.update(at=None, data=None)
    def down(*a, **k):
        raise RuntimeError("db down")
    A.db_run = down
    r = c.get("/status.json")
    assert r.status_code == 503 and json.loads(r.data)["status"] == "degraded"


# ---------------------------------------------------------------- data export
def test_export_contains_no_secrets():
    env = setup()
    alice = signup(env)
    r = alice.client.post("/account/export", token_from="/account")
    assert r.status_code == 200 and "attachment" in r.headers["Content-Disposition"]
    data = json.loads(r.data)
    assert data["profile"]["username"] == "alice" and len(data["passkeys"]) == 1
    text = r.get_data(as_text=True)
    stored = env.one("SELECT password, secret FROM users")
    assert stored["password"] not in text and stored["secret"] not in text
    assert any("data was downloaded" in a for a in env.alerts("alice@x.com"))


# ---------------------------------------------------------------- language and theme
def test_language_switch_translates_and_is_safe():
    setup()
    c = Client()
    assert b"Welcome back! Sign in" in c.get("/").data
    r = c.get("/lang/es?next=/")
    assert loc(r).endswith("/")
    page = c.get("/").get_data(as_text=True)
    assert 'lang="es"' in page and "Iniciar sesión" in page and "¡Bienvenido de nuevo!" in page
    c.get("/lang/fr?next=/")
    assert "Bon retour" in c.get("/").get_data(as_text=True)
    assert c.get("/lang/zz").status_code == 404
    assert loc(c.get("/lang/en?next=//evil.example")) == "/"                    # no open redirect
    assert "Welcome back" in c.get("/").get_data(as_text=True)


def test_translation_skips_scripts_and_untranslated_text():
    from i18n import translate_html
    out = translate_html("<p>Sign in</p><script>var s='Sign in'</script><p>Bob</p>", {"Sign in": "Entrar"})
    assert out == "<p>Entrar</p><script>var s='Sign in'</script><p>Bob</p>"


def test_theme_toggle_is_wired_up():
    setup()
    page = Client().get("/").get_data(as_text=True)
    assert "data-theme-toggle" in page and "localStorage.getItem('theme')" in page
    css = open(os.path.join(ROOT, "static", "css", "style.css"), encoding="utf-8").read()
    js = open(os.path.join(ROOT, "static", "js", "app.js"), encoding="utf-8").read()
    assert 'html[data-theme="light"]' in css and "data-theme-toggle" in js


# ---------------------------------------------------------------- client IP, limiter key, logs
def test_client_ip_detection():
    setup()
    app = A.app
    with app.test_request_context("/", headers={"X-Forwarded-For": "1.1.1.1, 2.2.2.2"}, environ_base={"REMOTE_ADDR": "10.0.0.9"}):
        A.PROXY_HOPS = 1
        assert A.client_ip() == "2.2.2.2" and A.rate_key() == "2.2.2.2"
        A.PROXY_HOPS = 2
        assert A.client_ip() == "1.1.1.1"
        A.PROXY_HOPS = 5                                    # more hops than entries: first entry
        assert A.client_ip() == "1.1.1.1"
        A.CLIENT_IP_HEADER = "CF-Connecting-IP"
    with app.test_request_context("/", headers={"CF-Connecting-IP": "3.3.3.3", "X-Forwarded-For": "1.1.1.1"}):
        assert A.client_ip() == "3.3.3.3"
    with app.test_request_context("/", headers={"X-Forwarded-For": "not-an-ip"}, environ_base={"REMOTE_ADDR": "10.0.0.9"}):
        A.CLIENT_IP_HEADER = ""
        assert A.client_ip() == "10.0.0.9"                  # junk is ignored


def test_security_events_are_searchable_log_lines_and_stored_for_admins():
    env = setup()
    import security_logging
    lines = []
    handler = logging.Handler()
    handler.emit = lambda record: lines.append(record.getMessage())
    security_logging.security_logger.addHandler(handler)
    try:
        c = Client()
        r = c.post("/", username="nobody", password="whatever1")
        assert r.headers["X-Request-ID"]
        wanted = [ln for ln in lines if ln.startswith("SEC event=login_failure")]
        assert wanted and "level=WARNING" in wanted[0] and "request_id=" in wanted[0] and "ip=8.8.8.8" in wanted[0]
        assert env.one("SELECT COUNT(*) AS n FROM security_events WHERE event = 'login_failure'")["n"] == 1
        with A.app.test_request_context("/"):
            security_logging.log_security_event("x", {"user_id": 5, "device": "Chrome on Android"}, "INFO")
        assert any('user_id=5' in ln and 'device="Chrome on Android"' in ln for ln in lines)
    finally:
        security_logging.security_logger.removeHandler(handler)
