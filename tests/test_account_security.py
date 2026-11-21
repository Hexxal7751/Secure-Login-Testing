import re

from helpers import A, Client, RECOVERY_RE, UA_PC, full_login, loc, setup, signup, totp_now


def test_recovery_code_replaces_totp_then_passkey_and_is_single_use():
    env = setup()
    alice = signup(env)
    c = Client()
    c.post("/", username="alice", password="pw123456")
    r = c.post("/recovery/totp", code=alice.codes[0].lower())
    assert loc(r).endswith("/verify-passkey")
    d = Client()
    d.post("/", username="alice", password="pw123456")
    r = d.post("/recovery/totp", code=alice.codes[0])
    assert b"valid" in r.data and "verify-passkey" not in loc(r)  # already used
    assert d.get("/recovery/passkey").status_code == 302          # passkey step not reached yet
    r = c.post("/recovery/passkey", code=alice.codes[1])
    assert loc(r).endswith("/account/passkeys")
    assert c.get("/dashboard").status_code == 200
    assert any("Recovery code used" in a for a in env.alerts("alice@x.com"))


def test_five_wrong_recovery_codes_end_the_session():
    env = setup()
    signup(env)
    c = Client()
    c.post("/", username="alice", password="pw123456")
    for _ in range(5):
        r = c.post("/recovery/totp", code="AAAAA-BBBBB")
    assert loc(r).endswith("/")
    assert "/?next=" in loc(c.get("/verify-totp")) or loc(c.get("/verify-totp")).endswith("/")


def test_regenerate_recovery_codes_needs_a_valid_authenticator_code():
    env = setup()
    alice = signup(env)
    c = alice.client
    c.post("/account/recovery-codes", token_from="/account", totp_code="000000")
    assert env.one("SELECT COUNT(*) AS n FROM recovery_codes WHERE used = 0")["n"] == 8
    page = c.post("/account/recovery-codes", token_from="/account", totp_code=alice.code()).get_data(as_text=True)
    new = RECOVERY_RE.findall(page)
    assert len(new) == 8 and not set(new) & set(alice.codes)
    d = Client()
    d.post("/", username="alice", password="pw123456")
    assert "verify-passkey" not in loc(d.post("/recovery/totp", code=alice.codes[0]))   # old set is dead


def test_passkey_management():
    env = setup()
    alice = signup(env)
    c = alice.client
    first = env.one("SELECT * FROM passkeys")
    assert first["name"] == "Chrome on Android"
    # last passkey cannot be removed
    c.post("/account/passkeys/delete", token_from="/account/passkeys", id=first["id"])
    assert env.one("SELECT COUNT(*) AS n FROM passkeys")["n"] == 1
    # add a second one from the account
    assert c.post_json("/passkey/register/complete", {
        "id": "y", "rawId": "y", "type": "public-key",
        "response": {"clientDataJSON": "a", "attestationObject": "b"}}).status_code == 200
    assert any("New passkey added" in a for a in env.alerts("alice@x.com"))
    second = env.all("SELECT * FROM passkeys ORDER BY id")[1]
    c.post("/account/passkeys/rename", token_from="/account/passkeys", id=second["id"], name="  My <b>Laptop</b> ")
    html = c.get("/account/passkeys").get_data(as_text=True)
    assert "My &lt;b&gt;Laptop&lt;/b&gt;" in html and "<b>Laptop</b>" not in html
    c.post("/account/passkeys/delete", token_from="/account/passkeys", id=second["id"])
    assert env.one("SELECT COUNT(*) AS n FROM passkeys")["n"] == 1
    assert any("Passkey removed" in a for a in env.alerts("alice@x.com"))


def test_change_password_needs_an_emailed_code_and_signs_out_others():
    env = setup()
    alice = signup(env)
    c = alice.client
    other = full_login(alice, Client(UA_PC, "9.9.9.9"))
    c.get("/account/change-password?restart=1")
    r = c.post("/account/change-password", token_from="/account/change-password", do="save",
               current="pw123456", password="newpass99", confirm="newpass99")
    assert b"isn&#39;t available" in r.data                       # cannot skip the email step
    c.post("/account/change-password", token_from="/account/change-password", do="send")
    assert b"Incorrect" in c.post("/account/change-password", token_from="/account/change-password",
                                  do="verify", totp_code="000000").get_data()
    c.post("/account/change-password", token_from="/account/change-password", do="verify",
           totp_code=env.last_code("alice@x.com"))
    r = c.post("/account/change-password", token_from="/account/change-password", do="save",
               current="WRONG", password="newpass99", confirm="newpass99")
    assert b"current password is incorrect" in r.data
    r = c.post("/account/change-password", token_from="/account/change-password", do="save",
               current="pw123456", password="newpass99", confirm="newpass99")
    assert loc(r).endswith("/account")
    assert any("Password changed" in a for a in env.alerts("alice@x.com"))
    assert "/" == loc(other.get("/dashboard")).split("?")[0]
    assert b"Invalid username or password" in Client().post("/", username="alice", password="pw123456").data
    assert Client().post("/", username="alice", password="newpass99").status_code == 302


def test_change_email_uses_old_and_new_address():
    env = setup()
    alice = signup(env)
    c = alice.client
    c.get("/account/change-email?restart=1")
    c.post("/account/change-email", token_from="/account/change-email", do="send")
    c.post("/account/change-email", token_from="/account/change-email", do="verify",
           totp_code=env.last_code("alice@x.com"))
    assert b"already your email" in c.post("/account/change-email", token_from="/account/change-email",
                                           do="new", email="alice@x.com").get_data()
    c.post("/account/change-email", token_from="/account/change-email", do="new", email="new@x.com")
    assert env.last_code("new@x.com")
    r = c.post("/account/change-email", token_from="/account/change-email", do="verify",
               totp_code=env.last_code("new@x.com"))
    assert loc(r).endswith("/account")
    assert env.one("SELECT email FROM users")["email"] == "new@x.com"
    assert env.alerts("alice@x.com") and env.alerts("new@x.com")


def test_password_reset_signs_everyone_out_and_alerts():
    env = setup()
    alice = signup(env)
    c = Client()
    c.post("/forgot-password", email="alice@x.com")
    code = env.last_code("alice@x.com")
    assert code and len(code) == 8
    r = c.post("/reset-password", code=code.lower(), password="resetpw123", confirm="resetpw123")
    assert loc(r).endswith("/")
    assert "/" == loc(alice.client.get("/dashboard")).split("?")[0]
    assert any("Password reset" in a for a in env.alerts("alice@x.com"))
    # unknown email gets the same answer and no mail
    n = len(env.mails)
    assert loc(Client().post("/forgot-password", email="nobody@x.com")).endswith("/reset-password")
    assert len(env.mails) == n


def test_account_deletion_removes_everything_and_alerts():
    env = setup()
    alice = signup(env)
    c = alice.client
    uid = env.one("SELECT id FROM users")["id"]
    c.get("/account/delete")
    with c.c.session_transaction() as s:
        s["del"] = {"uid": uid, "done": ["password", "email", "totp", "passkey"],
                    "t": A.utcnow().isoformat(), "fails": 0, "email_target": None}
    r = c.post("/account/delete", token_from="/account/delete", step="confirm", final="yes",
               confirm_text="DELETE alice")
    assert loc(r).endswith("/")
    for table in ("passkeys", "recovery_codes", "user_sessions", "email_codes", "trusted_devices"):
        assert env.one(f"SELECT COUNT(*) AS n FROM {table} WHERE user_id = ?", uid)["n"] == 0
    assert any("Account deleted" in m[1] for m in env.mails)
