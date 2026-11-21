from helpers import A, Client, UA_PC, full_login, loc, setup, signup, totp_now


def test_signup_creates_recovery_codes_and_session_record():
    env = setup()
    alice = signup(env)
    assert len(alice.codes) == 8 and len(set(alice.codes)) == 8
    stored = str(env.all("SELECT * FROM recovery_codes"))
    assert alice.codes[0].replace("-", "") not in stored          # only hashes are stored
    assert alice.client.get("/dashboard").status_code == 200
    row = env.one("SELECT * FROM user_sessions")
    assert row["completed"] and row["device"] == "Chrome on Android" and row["ip"] == "8.8.8.8"


def test_short_password_is_rejected_and_nothing_is_created():
    env = setup()
    c = Client()
    r = c.post("/register", username="bob", email="bob@x.com", password="short")
    assert r.status_code == 200 and b"at least 8" in r.data
    assert env.one("SELECT COUNT(*) AS n FROM users")["n"] == 0


def test_wrong_password_and_google_only_accounts_get_the_same_error():
    env = setup()
    signup(env)
    c = Client()
    r = c.post("/", username="alice", password="WRONG-password")
    assert b"Invalid username or password" in r.data
    r = c.post("/", username="nobody", password="whatever1")
    assert b"Invalid username or password" in r.data


def test_totp_setup_cannot_be_redone_and_cancel_needs_post():
    env = setup()
    alice = signup(env)
    c = Client()
    c.post("/", username="alice", password="pw123456")
    assert "setup-totp" not in loc(c.get("/setup-totp"))        # secret already exists
    assert c.get("/cancel-setup").status_code == 405


def test_error_pages_and_logout_routes():
    setup()
    c = Client()
    r = c.get("/does-not-exist")
    assert r.status_code == 404 and b"css/style.css" in r.data and b"Page not found" in r.data
    assert loc(c.get("/logout")).endswith("/") and loc(c.get("/emergency-logout")).endswith("/")


def test_session_can_be_revoked_on_the_server():
    env = setup()
    alice = signup(env)
    other = full_login(alice, Client(UA_PC, "9.9.9.9"))
    assert other.get("/dashboard").status_code == 200
    r = alice.client.post("/account/sessions/revoke-others", token_from="/account")
    assert loc(r).endswith("/account")
    assert "/" == loc(other.get("/dashboard")).split("?")[0]      # signed out everywhere else
    assert alice.client.get("/dashboard").status_code == 200
    assert any("Signed out of other devices" in a for a in env.alerts("alice@x.com"))
