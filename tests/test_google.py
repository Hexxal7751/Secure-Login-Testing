import base64
import json
from datetime import datetime

from helpers import A, Client, RECOVERY_RE, full_login, loc, setup, signup


def _tokens(nonce, sub, email):
    claims = {"iss": "https://accounts.google.com", "aud": "cid", "exp": datetime.now().timestamp() + 600,
              "nonce": nonce, "sub": sub, "email": email, "email_verified": True}
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return {"id_token": f"h.{body}.s"}


def _google(client, intent, sub, email):
    A.GOOGLE_CLIENT_ID, A.GOOGLE_CLIENT_SECRET = "cid", "sec"
    r = client.get("/auth/google" + (f"?intent={intent}" if intent else ""))
    q = dict(x.split("=", 1) for x in loc(r).split("?", 1)[1].split("&"))
    A._google_exchange_code = lambda code: _tokens(q["nonce"], sub, email)
    return client.get(f"/auth/google/callback?code=c&state={q['state']}")


def test_google_signup_then_link_unlink_and_same_email_linking():
    env = setup()
    alice = signup(env)                                   # password account alice@x.com
    c = alice.client
    # link from the account page, then unlink (allowed: the account has a password)
    assert loc(_google(c, "link", "g-111", "whoever@gmail.com")).endswith("/account")
    assert env.one("SELECT google_sub FROM users")["google_sub"] == "g-111"
    c.post("/account/google/unlink", token_from="/account")
    assert env.one("SELECT google_sub FROM users")["google_sub"] is None
    # Google sign-in with the SAME verified email: nothing happens until a full sign-in
    other = Client()
    assert loc(_google(other, None, "g-222", "alice@x.com")).endswith("/")
    assert env.one("SELECT google_sub FROM users")["google_sub"] is None
    full_login(alice, other)
    assert env.one("SELECT google_sub FROM users")["google_sub"] == "g-222"
    assert any("Google account linked" in a for a in env.alerts("alice@x.com"))
    # an existing link is never overwritten
    _google(Client(), None, "g-333", "alice@x.com")
    assert env.one("SELECT google_sub FROM users")["google_sub"] == "g-222"


def test_google_only_account_flow():
    env = setup()
    g = Client()
    assert loc(_google(g, None, "gsub-1", "gina@gmail.com")).endswith("/register/google")
    assert loc(g.post("/register/google", username="gina")).endswith("/setup-totp")
    g.get("/setup-totp")
    from helpers import totp_now
    secret = g.session()["temp_secret"]
    page = g.post("/setup-totp", token_from="/register", totp_code=totp_now(secret)).get_data(as_text=True)
    assert len(RECOVERY_RE.findall(page)) == 8              # recovery codes shown
    assert loc(_google(Client(), None, "gsub-1", "gina@gmail.com")).endswith("/verify-totp")
