"""Speed guards: one round trip per query, pooled connections, caches, compression, query budgets."""
import gzip
import logging
import os
import runpy

from psycopg2 import OperationalError
from psycopg2 import pool as pg_pool

from helpers import A, Client, REAL, ROOT, loc, setup, signup


# --------------------------------------------------------------------- fake database pieces
class FakeCursor:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql, params=None):
        if self.conn.fail:
            self.conn.fail = False
            raise OperationalError("server closed the connection")
        self.conn.log.append((sql, params))

    def mogrify(self, sql, params):
        return (sql % tuple(repr(p) for p in params)).encode()

    def fetchone(self):
        return {"ok": 1}

    def fetchall(self):
        return [{"ok": 1}]


class FakeConn:
    def __init__(self, fail=False):
        self.fail, self.log, self.autocommit, self.closed, self.was_closed = fail, [], False, 0, False

    def cursor(self, cursor_factory=None):
        return FakeCursor(self)

    def close(self):
        self.was_closed = True


class FakePool:
    def __init__(self, *conns, exhausted=False):
        self.conns, self.exhausted, self.returned = list(conns), exhausted, []

    def getconn(self):
        if self.exhausted:
            raise pg_pool.PoolError("exhausted")
        return self.conns.pop(0)

    def putconn(self, conn, close=False):
        self.returned.append((conn, close))


def _with_pool(pool, fn):
    A._pool = pool
    try:
        return fn()
    finally:
        A._pool = None


# --------------------------------------------------------------------- the database layer
def test_one_round_trip_per_query_with_security_context():
    setup()
    conn = FakeConn()
    pool = FakePool(conn)
    row = _with_pool(pool, lambda: REAL.db_exec("SELECT 1 AS ok", (), "one", None, True))
    assert row == {"ok": 1}
    assert conn.autocommit is True and len(conn.log) == 1                  # a single execute()
    assert conn.log[0][0] == "SELECT set_config('app.is_admin', 'true', true); SELECT 1 AS ok"
    assert pool.returned == [(conn, False)]                                # went back to the pool, still open
    conn2, pool2 = FakeConn(), None
    pool2 = FakePool(conn2)
    _with_pool(pool2, lambda: REAL.db_exec("SELECT 1", (), "one", 5, False))
    assert "app.current_user_id', '5'" in conn2.log[0][0]


def test_a_stale_connection_is_replaced_and_the_query_retried():
    setup()
    stale, fresh = FakeConn(fail=True), FakeConn()
    pool = FakePool(stale, fresh)
    assert _with_pool(pool, lambda: REAL.db_exec("SELECT 1", (), "one", None, True)) == {"ok": 1}
    assert pool.returned[0] == (stale, True)                               # discarded, not reused
    assert pool.returned[1] == (fresh, False)


def test_busy_pool_falls_back_to_a_temporary_connection():
    setup()
    temp = FakeConn()
    original = A._connect
    A._connect = lambda: temp
    try:
        assert _with_pool(FakePool(exhausted=True), lambda: REAL.db_exec("SELECT 1", (), "one", None, True)) == {"ok": 1}
    finally:
        A._connect = original
    assert temp.was_closed


def test_batches_run_as_one_statement_string():
    setup()
    conn = FakeConn()
    _with_pool(FakePool(conn), lambda: REAL.db_exec_batch(
        [("INSERT INTO a VALUES (%s)", (1,)), ("UPDATE b SET x = %s", ("ok",))], True, None))
    assert len(conn.log) == 1
    sent = conn.log[0][0].decode()
    assert sent.startswith("SELECT set_config('app.is_admin'") and "INSERT INTO a VALUES (1); UPDATE b SET x = 'ok'" in sent


# --------------------------------------------------------------------- caches
def _count_calls(env):
    calls = []
    inner = A._db_exec

    def counting(sql, params, fetch, user_id, admin):
        calls.append(sql)
        return inner(sql, params, fetch, user_id, admin)
    A._db_exec = counting
    return calls


def test_user_and_passkey_rows_are_read_once_per_request_and_refreshed_after_writes():
    env = setup()
    signup(env)
    calls = _count_calls(env)
    with A.app.test_request_context("/"):
        A.get_user_by_id(1); A.get_user_by_id(1); A.get_user_passkeys(1); A.get_user_passkeys(1)
        assert len(calls) == 2
        A.db_run("UPDATE users SET disabled = FALSE WHERE id = %s", (1,), admin=True)
        A.get_user_by_id(1)
        assert len(calls) == 4                                              # the write cleared the memory
    with A.app.test_request_context("/"):
        A.get_user_by_id(1)
        assert len(calls) == 5                                              # a new request starts fresh


def test_session_check_is_cached_briefly_but_sign_out_is_immediate():
    env = setup()
    alice = signup(env)
    sid = env.one("SELECT id FROM user_sessions")["id"]
    uid = env.one("SELECT id FROM users")["id"]
    calls = _count_calls(env)
    A._SESSION_OK.clear()
    assert A.touch_session(sid, uid) and len(calls) == 1
    assert A.touch_session(sid, uid) and len(calls) == 1                    # answered from memory
    A.end_session(sid)
    assert A.touch_session(sid, uid) is False                               # revoked at once


# --------------------------------------------------------------------- how many queries a page may need
def test_pages_stay_within_their_query_budget():
    env = setup()
    alice = signup(env)
    A.run_async = lambda fn: None                      # background work doesn't make visitors wait
    calls = _count_calls(env)
    c = Client()

    def used(fn):
        calls.clear()
        fn()
        return len(calls)
    t = c.token("/")
    assert used(lambda: c.c.post("/", data={"csrf_token": t, "username": "alice", "password": "pw123456"},
                                 headers=c._headers())) <= 3
    assert used(lambda: c.get("/verify-totp")) <= 3
    t = c.token("/verify-totp")
    assert used(lambda: c.c.post("/verify-totp", data={"csrf_token": t, "totp_code": alice.code()},
                                 headers=c._headers())) <= 2
    assert used(lambda: c.get("/verify-passkey")) <= 2
    from helpers import passkey_step
    assert used(lambda: passkey_step(c, alice)) <= 5
    assert used(lambda: c.get("/dashboard")) <= 3
    assert used(lambda: c.get("/account")) <= 6
    assert used(lambda: c.get("/account/passkeys")) <= 3
    d = Client()
    assert used(lambda: d.post("/register", token_from="/register", username="bob", email="bob@x.com",
                               password="pw123456")) <= 7


# --------------------------------------------------------------------- static files, compression, timing log
def test_static_files_are_cached_for_a_year_and_compressed():
    setup()
    c = Client()
    page = c.get("/").get_data(as_text=True)
    assert "style.css?v=" in page and "app.js?v=" in page                   # versioned URLs
    r = c.get("/static/css/style.css?v=1", extra={"Accept-Encoding": "gzip"})
    assert "immutable" in r.headers["Cache-Control"] and r.headers["Content-Encoding"] == "gzip"
    plain = open(os.path.join(ROOT, "static", "css", "style.css"), "rb").read()
    assert gzip.decompress(r.data) == plain and len(r.data) < len(plain) / 3
    r = c.get("/", extra={"Accept-Encoding": "gzip"})
    assert r.headers["Content-Encoding"] == "gzip" and "no-store" in r.headers["Cache-Control"]
    assert "Accept-Encoding" in r.headers["Vary"]
    assert "Content-Encoding" not in c.get("/").headers                     # only when the browser asks


def test_every_page_logs_how_long_it_took_and_how_many_queries_it_used():
    setup()
    lines = []
    handler = logging.Handler()
    handler.emit = lambda record: lines.append(record.getMessage())
    logger = logging.getLogger(A.app.logger.name)
    logger.addHandler(handler)
    root = logging.getLogger()
    before = root.level
    root.setLevel(logging.WARNING)            # what pytest does: the app must not depend on the root level
    try:
        Client().get("/")
        assert any(ln.startswith("REQ GET / 200 ms=") and "db_ms=" in ln and "db_n=" in ln for ln in lines), lines
    finally:
        root.setLevel(before)
        logger.removeHandler(handler)


def test_gunicorn_uses_threads_so_one_slow_request_does_not_block_everyone():
    conf = runpy.run_path(os.path.join(ROOT, "gunicorn.conf.py"))
    assert conf["worker_class"] == "gthread" and conf["threads"] >= 2 and conf["workers"] >= 1


# --------------------------------------------------------------------- theme and admin access
def test_light_theme_covers_every_section_of_the_stylesheet():
    css = open(os.path.join(ROOT, "static", "css", "style.css"), encoding="utf-8").read()
    for selector in (".topbar", ".brand-name", ".field input", ".btn-ghost", ".alert", ".stepper", ".otp input",
                     ".tile", ".row", ".pill", ".codes", ".sheet", ".toast", ".lang summary", ".lang .menu",
                     ".del-steps li", ".facts li", ".secret", ".credit-list li", ".fab", ".mini"):
        assert f'html[data-theme="light"] {selector}' in css, selector
    assert 'html[data-theme="light"] .btn-primary' in css and "--panel:rgba(255,255,255" in css


def test_admins_see_an_admin_button_and_others_do_not():
    env = setup()
    root = signup(env, "root")
    bob = signup(env, "bob")
    assert "/admin" in root.client.get("/dashboard").get_data(as_text=True)
    assert 'href="/admin"' not in bob.client.get("/dashboard").get_data(as_text=True)
    assert "/admin/verify" in loc(root.client.get("/admin"))               # signing in is the normal sign-in + a code
