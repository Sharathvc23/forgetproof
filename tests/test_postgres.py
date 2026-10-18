"""Postgres + pgvector, against a real server: FORGETPROOF_TEST_PG_URL (a superuser URL, as in CI)
or a throwaway one started with pgserver."""

import json
import os
import random
import tempfile
import threading
import time
import uuid

import pytest
from conftest import email

psycopg = pytest.importorskip("psycopg")

from forgetproof import postgres  # noqa: E402
from forgetproof.cli import main  # noqa: E402
from forgetproof.fixer import FixError, fix  # noqa: E402
from forgetproof.scanner import scan  # noqa: E402


@pytest.fixture(scope="session")
def server_url():
    if url := os.environ.get("FORGETPROOF_TEST_PG_URL"):
        yield url
        return
    pgserver = pytest.importorskip("pgserver")
    try:
        srv = pgserver.get_server(tempfile.mkdtemp(prefix="fp-pg-"), cleanup_mode="delete")
    except Exception as e:  # e.g. initdb refuses to run as Administrator on Windows CI runners
        pytest.skip(f"couldn't start a throwaway Postgres ({type(e).__name__}); set FORGETPROOF_TEST_PG_URL")
    yield srv.get_uri()
    srv.cleanup()


def url_for(info: dict) -> str:
    """A postgresql:// URL (what the CLI takes) for a libpq connection dict, socket or TCP."""
    user = info.get("user", "postgres") + (f":{info['password']}" if info.get("password") else "")
    host, port, db = info.get("host", ""), info.get("port", "5432"), info["dbname"]
    if host.startswith("/"):
        return f"postgresql://{user}@/{db}?host={host}&port={port}"
    return f"postgresql://{user}@{host}:{port}/{db}"


def info_of(url: str) -> dict:
    return psycopg.conninfo.conninfo_to_dict(url)


@pytest.fixture
def db(server_url):
    """A fresh database with pgvector; yields its URL."""
    name = f"fp_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(server_url, autocommit=True) as c:
        c.execute(f"create database {name}")
    url = url_for({**info_of(server_url), "dbname": name})
    with psycopg.connect(url, autocommit=True) as c:
        c.execute("create extension if not exists vector")
    yield url
    with psycopg.connect(server_url, autocommit=True) as c:
        c.execute(f"drop database if exists {name} with (force)")


def make_memories(url, n=3000, dim=8, seed=1):
    """n memories with personal data; every 3rd deleted, every 7th updated. Returns deleted and replaced texts."""
    rng = random.Random(seed)
    with psycopg.connect(url, autocommit=True) as c:
        c.execute(f"create table memories (id int primary key, doc text, meta jsonb, emb vector({dim}))")
        with c.cursor() as cur:
            cur.executemany(
                "insert into memories values (%s, %s, %s, %s)",
                [(i, f"note {i}: email {email(i)}", json.dumps({"phone": f"415-555-{i:04d}"}),
                  str([round(rng.random(), 4) for _ in range(dim)])) for i in range(n)],
            )
        c.execute("create index on memories using hnsw (emb vector_l2_ops)")
        c.execute("delete from memories where id % 3 = 0")
        c.execute("update memories set doc = 'moved, email ' || replace(doc, 'person', 'moved') where id % 7 = 0 and id % 3 <> 0")
    deleted = [i for i in range(n) if i % 3 == 0]
    replaced = [i for i in range(n) if i % 7 == 0 and i % 3]
    return deleted, replaced


def live_rows(url):
    with psycopg.connect(url) as c:
        return c.execute("select id, doc, meta::text, emb::text from memories order by id").fetchall()


def raw_contains(url, needle: str, wal: bool = False) -> list[str]:
    """Where a value appears in this database's table files (or WAL), read independently of the scanner."""
    hits = []
    with psycopg.connect(url, autocommit=True) as c:
        paths = [r[0] for r in c.execute(
            "select pg_relation_filepath(oid) from pg_class where relnamespace = 'public'::regnamespace "
            "or oid in (select reltoastrelid from pg_class where relnamespace = 'public'::regnamespace)")]
        c.execute("checkpoint")
        if wal:
            paths += ["pg_wal/" + r[0] for r in c.execute("select name from pg_ls_waldir()")]
        for p in filter(None, paths):
            data = c.execute("select pg_read_binary_file(%s, true)", (p,)).fetchone()[0]
            if data is not None and needle.encode() in bytes(data):
                hits.append(p)
    return hits


def checks(r):
    return {f.check: f.records for f in r.findings}


def test_finds_deleted_and_overwritten_rows_in_table_files(db):
    deleted, replaced = make_memories(db)
    r = scan(db, [email(deleted[5]), "never-stored@example.com"])
    c = checks(r)
    assert c["pg.table_residue"] > 0
    f = next(f for f in r.findings if f.check == "pg.table_residue")
    assert f.pii["email"] > 0 and all("*" in s for s in f.samples)
    assert r.canaries[1].found_in == []
    assert r.stats == {"tables": 1, "live_records": 2000}
    assert not r.clean


def test_plain_vacuum_leaves_the_bytes(db):
    deleted, _ = make_memories(db)
    with psycopg.connect(db, autocommit=True) as c:
        c.execute("vacuum memories")
    assert "pg.table_residue" in checks(scan(db))


@pytest.mark.parametrize("vacuum_first", [False, True])
def test_fix_erases_residue_and_keeps_live_rows(db, vacuum_first):
    deleted, replaced = make_memories(db)
    if vacuum_first:
        with psycopg.connect(db, autocommit=True) as c:
            c.execute("vacuum memories")
    before = live_rows(db)
    probe = before[10][3]
    with psycopg.connect(db) as c:
        nearest = c.execute("select id from memories order by emb <-> %s::vector limit 10", (probe,)).fetchall()

    result = fix(db, [email(deleted[5])])
    assert not result.before.clean
    assert result.after.clean, result.after.findings
    assert live_rows(db) == before
    canary_note = [w for w in result.after.warnings if "canary #1" in w]
    assert bool(canary_note) == bool(raw_contains(db, email(deleted[5]), wal=True))  # WAL is reported, not hidden
    with psycopg.connect(db) as c:
        c.execute("set enable_seqscan = off")  # make sure the rebuilt HNSW index answers
        assert c.execute("select id from memories order by emb <-> %s::vector limit 10", (probe,)).fetchall() == nearest
    for i in deleted[::50]:
        assert raw_contains(db, email(i)) == [], email(i)
    for i in replaced[::20]:
        assert raw_contains(db, f"note {i}: email {email(i)}") == []


def test_long_values_in_toast_storage(db):
    """Values over ~2 KB live in a separate TOAST table; incompressible ones are stored as is."""
    rng = random.Random(3)
    with psycopg.connect(db, autocommit=True) as c:
        c.execute("create table notes (id int primary key, body text, emb vector(3))")
        bodies = {i: "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(6000))
                  + f" contact toast{i}@example.com" for i in range(40)}
        with c.cursor() as cur:
            cur.executemany("insert into notes values (%s, %s, '[1,2,3]')", list(bodies.items()))
        c.execute("delete from notes where id < 20")
    r = scan(db, ["toast3@example.com"])
    assert any("(toast)" in where for where in r.canaries[0].found_in)
    assert fix(db, ["toast3@example.com"]).after.clean
    assert raw_contains(db, "toast3@example.com") == []


def test_tables_without_vectors_are_left_alone(db):
    with psycopg.connect(db, autocommit=True) as c:
        c.execute("create table audit (id int, who text)")
        c.execute("insert into audit select g, 'auditor' || g || '@example.com' from generate_series(1, 500) g")
        c.execute("delete from audit where id < 100")
    r = scan(db)
    assert r.stats["tables"] == 0 and r.clean
    assert any("no tables with a pgvector column" in w for w in r.warnings)


def test_role_without_file_access_gets_an_incomplete_scan_and_a_clear_fix_error(db):
    make_memories(db, n=600)
    role = f"agent_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(db, autocommit=True) as c:
        c.execute(f"create role {role} login password 'pw-not-printed'")
        c.execute(f"grant select on memories to {role}")
    url = url_for({**info_of(db), "user": role, "password": "pw-not-printed"})
    try:
        r = scan(url, [email(3)])
        assert r.incomplete and not r.clean
        assert "pw-not-printed" not in json.dumps(r.to_dict())
        with pytest.raises(FixError, match="owner"):
            fix(url, [])
    finally:
        with psycopg.connect(db, autocommit=True) as c:
            c.execute(f"drop owned by {role}")
            c.execute(f"drop role {role}")


def test_fix_gives_up_cleanly_when_the_app_holds_the_table(db, monkeypatch):
    make_memories(db, n=300)
    monkeypatch.setattr(postgres, "LOCK_TIMEOUT", "500ms")
    holding, release = threading.Event(), threading.Event()

    def app():
        with psycopg.connect(db) as c:  # an open transaction that has read the table
            c.execute("select count(*) from memories").fetchone()
            holding.set()
            release.wait(30)

    t = threading.Thread(target=app)
    t.start()
    try:
        holding.wait(10)
        with pytest.raises(FixError, match="in use"):
            fix(db, [])
    finally:
        release.set()
        t.join()
    assert fix(db, []).after.clean


def test_cli_scan_fix_verify_and_no_password_anywhere(db, tmp_path, capsys):
    make_memories(db, n=600)
    info = info_of(db)
    secret = info.get("password") or "hunter2-not-printed"  # trust auth ignores it; it must still never print
    secret_url = url_for({**info, "password": secret})
    rec = tmp_path / "r.json"
    assert main(["scan", secret_url]) == 1
    assert main(["fix", secret_url, "--dry-run"]) == 1
    assert main(["fix", secret_url, "--yes", "--receipt", str(rec), "--canary", email(3)]) == 0
    assert main(["verify", str(rec), "--against", secret_url]) == 0
    out = capsys.readouterr()
    assert secret not in out.out + out.err
    assert secret not in rec.read_text()
    receipt = json.loads(rec.read_text())
    assert receipt["verdict"] == "CLEAN" and receipt["target"].startswith("postgresql://")
    assert receipt["files"], "receipt should fingerprint the table files"


def test_mcp_forget_me_scan_verify_and_no_password_anywhere(db, tmp_path):
    pytest.importorskip("mcp")
    from test_mcp import call, ok

    from forgetproof.mcp_server import build, parse_store

    deleted, _ = make_memories(db, n=600)
    info = info_of(db)
    secret = info.get("password") or "hunter2-not-printed"
    subj = tmp_path / "subject"
    subj.write_text(email(deleted[2]))
    server = build([parse_store(f"pg={url_for({**info, 'password': secret})}")], allow_fix=True,
                   receipts_dir=tmp_path / "receipts", subject_file=subj)
    replies = [call(server, "list_stores")]
    replies.append(call(server, "scan_store", store_name="pg"))
    assert not ok(replies[-1])["clean"]
    # Whether this one row still shows up depends on opportunistic page pruning, so
    # check_if_forgotten isn't asserted here; forget_me's result below is deterministic.
    replies.append(call(server, "check_if_forgotten", store_name="pg"))
    time.sleep(1.1)  # past the per-store cooldown shared by check_if_forgotten and forget_me
    replies.append(call(server, "forget_me", store_name="pg"))
    fixed = ok(replies[-1])
    assert fixed["done"] and fixed["clean"]
    time.sleep(1.1)
    replies.append(call(server, "check_if_forgotten", store_name="pg"))
    assert ok(replies[-1])["forgotten"] is True
    replies.append(call(server, "verify_receipt", receipt_id=fixed["receipt_id"]))
    assert ok(replies[-1])["signature_valid"] and ok(replies[-1])["clean_now"]
    replies.append(call(server, "get_receipt", receipt_id=fixed["receipt_id"]))
    assert all(secret not in r.model_dump_json() for r in replies)
    assert all(email(deleted[2]) not in r.model_dump_json() for r in replies)
    assert all(secret not in p.read_text() for p in (tmp_path / "receipts").iterdir())
