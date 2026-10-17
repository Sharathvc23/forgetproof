"""fix must never lose live data or damage a store, whatever state it finds it in."""

import hashlib
import json
import os
import random
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import chroma, email, live, make_chroma, make_sqlite

from forgetproof import fixer, hnsw
from forgetproof._chroma_rebuild import JOURNAL
from forgetproof.cli import main
from forgetproof.fixer import FixError, Options, fix
from forgetproof.scanner import scan


def snapshot(path):
    files = [p for p in path.rglob("*") if p.is_file()] if path.is_dir() else [path]
    return {str(p): (p.stat().st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest()) for p in files}


def same_records(a, b, cosine=False):
    """Ids, documents and metadata exactly; embeddings exactly, or for cosine to float32 rounding:
    Chroma keeps cosine vectors normalised plus a norm, and get() rebuilds them from the two."""
    assert [r[:3] for r in a] == [r[:3] for r in b]
    for x, y in zip(a, b):
        assert x[3] == (pytest.approx(y[3], rel=1e-6, abs=1e-7) if cosine else y[3]), x[0]
    return True


def raw_contains(path, needle: str) -> bool:
    return any(needle.encode() in p.read_bytes() for p in path.rglob("*") if p.is_file())


# --- scanning and dry runs change nothing ------------------------------------

def test_scan_never_modifies_a_chroma_store(tmp_path):
    path = tmp_path / "s"
    make_chroma(path, 3000, after=500)
    before = snapshot(path)
    scan(path, [email(3)])
    assert snapshot(path) == before


def test_scan_never_modifies_a_wal_sqlite_file(tmp_path):
    db = tmp_path / "agent.db"
    conn = sqlite3.connect(db)
    conn.execute("pragma journal_mode=wal")
    conn.execute("create table t (v text)")
    conn.executemany("insert into t values (?)", [(email(i),) for i in range(100)])
    conn.commit()
    conn.execute("delete from t where rowid % 2 = 0")
    conn.commit()
    conn.close()
    before = snapshot(tmp_path)
    scan(db)
    assert snapshot(tmp_path) == before


def test_dry_run_changes_nothing_and_shows_the_plan(tmp_path, capsys):
    path = tmp_path / "s"
    make_chroma(path, 300)
    before = snapshot(path)
    assert main(["fix", str(path), "--dry-run"]) == 1
    out = capsys.readouterr().out
    assert "fix would:" in out and "rebuild 1 collection" in out and "nothing was changed" in out
    assert snapshot(path) == before


# --- pre-flight checks -------------------------------------------------------

@pytest.mark.fix
def test_fix_refuses_while_another_process_has_the_store_open(tmp_path):
    path = tmp_path / "s"
    make_chroma(path, 300)
    holder = subprocess.Popen([sys.executable, "-c", (
        "import chromadb, sys, time\n"
        f"c = chromadb.PersistentClient(path={str(path)!r}).get_collection('mem')\n"
        "c.count(); print('ready', flush=True); time.sleep(60)\n"
    )], stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "ready"
        with pytest.raises(FixError, match="open in another process"):
            fix(path, [])
    finally:
        holder.kill()
        holder.wait()
    assert fix(path, []).after.clean  # and works once it has stopped


def test_fix_refuses_without_enough_disk_space(tmp_path, monkeypatch):
    db = tmp_path / "agent.db"
    make_sqlite(db)
    monkeypatch.setattr(fixer.safety, "free_space", lambda target: 1024)
    with pytest.raises(FixError, match="MB free"):
        fix(db, [])
    assert fix(db, [], Options(force=True)).after.clean


def _fake_child(rows):
    def run(*args):
        return subprocess.CompletedProcess(args, 0, json.dumps({"chromadb": "9.9.9", "migrations": rows}), "")
    return run


def test_fix_refuses_to_upgrade_an_older_store(tmp_path, monkeypatch):
    path = tmp_path / "s"
    make_chroma(path, 30)
    rows = sqlite3.connect(path / "chroma.sqlite3").execute("select dir, version from migrations").fetchall()
    monkeypatch.setattr(fixer, "_run_child", _fake_child(rows + [("sysdb", 99)]))
    with pytest.raises(FixError, match="older Chroma"):
        fixer._check_chroma_version(path, allow_upgrade=False)
    fixer._check_chroma_version(path, allow_upgrade=True)
    monkeypatch.setattr(fixer, "_run_child", _fake_child(rows[:-1]))
    with pytest.raises(FixError, match="newer Chroma"):
        fixer._check_chroma_version(path, allow_upgrade=True)


@pytest.mark.fix
def test_rebuild_child_ignores_modules_in_the_current_directory(tmp_path, monkeypatch):
    """A chromadb.py planted where the user runs the tool must not be executed."""
    path = tmp_path / "s"
    make_chroma(path, 30)
    trap = tmp_path / "cwd"
    trap.mkdir()
    marker = tmp_path / "pwned"
    (trap / "chromadb.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    monkeypatch.chdir(trap)
    assert fix(path, []).after.clean
    assert not marker.exists()


# --- crash safety ------------------------------------------------------------

@pytest.mark.fix
@pytest.mark.parametrize("crash_at", ["copy", "swap"])
def test_interrupted_fix_loses_nothing_and_finishes_on_rerun(tmp_path, monkeypatch, crash_at):
    path = tmp_path / "s"
    make_chroma(path, 3000, after=200)
    expected = live(path)
    monkeypatch.setenv("FORGETPROOF_TEST_CRASH", crash_at)
    with pytest.raises(FixError, match="no live data was lost"):
        fix(path, [])
    assert (path / JOURNAL).exists()
    assert any("interrupted" in w for w in scan(path).warnings)

    monkeypatch.delenv("FORGETPROOF_TEST_CRASH")
    result = fix(path, [])
    assert any(a.startswith("recovered mem") for a in result.actions)
    assert result.after.clean and not result.after.warnings
    assert not (path / JOURNAL).exists()
    assert chroma(path, "result = [c.name for c in client.list_collections()]") == ["mem"]
    assert live(path) == expected


# --- what the rebuild must preserve -----------------------------------------

def collection_row(path, name):
    conn = sqlite3.connect(path / "chroma.sqlite3")
    conn.row_factory = sqlite3.Row
    row = dict(conn.execute("select * from collections where name = ?", (name,)).fetchone())
    meta = sorted(map(tuple, conn.execute(
        "select key, str_value, int_value, float_value, bool_value from collection_metadata where collection_id = ?",
        (row.pop("id"),))))
    conn.close()
    flat = {}

    def walk(prefix, value):
        if isinstance(value, dict):
            for k, v in value.items():
                walk(f"{prefix}.{k}", v)
        else:
            flat[prefix] = value

    for col in ("config_json_str", "schema_str"):
        walk(col, json.loads(row.pop(col, None) or "{}"))  # schema_str is new in Chroma 1.3
    return row, flat, meta


@pytest.mark.fix
def test_fix_preserves_collection_settings(tmp_path):
    path = tmp_path / "s"
    rng = random.Random(4)
    probe = [rng.uniform(-1, 1) for _ in range(8)]
    chroma(path, """
        import random
        rng = random.Random(5)
        col = client.create_collection(  # default embedding function, cosine space, custom HNSW settings
            "settings", metadata={"owner": "agent-7", "version": 3, "tuned": True},
            configuration={"hnsw": {"space": "cosine", "ef_construction": 150, "ef_search": 40, "max_neighbors": 24}})
        col.add(ids=[f"r{i}" for i in range(1200)], embeddings=[[rng.uniform(-1, 1) for _ in range(8)] for _ in range(1200)],
                documents=[f"doc person{i}@example.com" for i in range(1200)])
        col.delete(ids=[f"r{i}" for i in range(0, 1200, 4)])
    """)
    query = """
        col = client.get_collection("settings")
        result = [col.configuration["hnsw"]["space"],
                  col.query(query_embeddings=[params["probe"]], n_results=10, include=["distances"])]
    """
    space, nearest = chroma(path, query, probe=probe)
    before = collection_row(path, "settings")
    records = live(path, "settings")  # get() rebuilds cosine embeddings from the norms in length.bin

    assert fix(path, []).after.clean
    assert collection_row(path, "settings") == before
    space_after, after = chroma(path, query, probe=probe)
    assert space == space_after == "cosine"
    assert after["ids"] == nearest["ids"]
    assert after["distances"][0] == pytest.approx(nearest["distances"][0], abs=1e-6)
    assert same_records(live(path, "settings"), records, cosine=True)


@pytest.mark.fix
def test_empty_store_and_store_without_collections(tmp_path):
    path = tmp_path / "s"
    chroma(path, "client.heartbeat()")
    assert scan(path).clean
    assert fix(path, []).after.clean
    chroma(path, "client.create_collection('empty_one', embedding_function=None)")
    assert fix(path, []).after.clean


# --- overwritten memories ----------------------------------------------------

@pytest.mark.fix
def test_updated_records_leave_old_versions_until_fix(tmp_path):
    path = tmp_path / "s"
    chroma(path, """
        col = client.create_collection("mem", embedding_function=None)
        col.add(ids=[f"m{i}" for i in range(50)], embeddings=[[i / 50] * 4 for i in range(50)],
                documents=[f"lives at old-address-{i}." for i in range(50)])
        col.update(ids=[f"m{i}" for i in range(10)], embeddings=[[0.5] * 4] * 10,
                   documents=[f"moved to new-address-{i}" for i in range(10)])
        col.upsert(ids=["m10"], embeddings=[[0.9] * 4], documents=["moved to new-address-10"])
    """)
    r = scan(path)
    assert {f.check: f.records for f in r.findings}.get("chroma.write_log_overwritten") == 11
    assert fix(path, []).after.clean
    assert not any(raw_contains(path, f"old-address-{i}.") for i in range(11))
    assert raw_contains(path, "old-address-11.") and raw_contains(path, "new-address-3")


# --- randomised end-to-end ---------------------------------------------------

@pytest.mark.fix
@pytest.mark.parametrize("seed", range(int(os.environ.get("FORGETPROOF_TEST_SEEDS", 6))))
def test_random_histories_end_clean_with_live_data_intact(tmp_path, seed):
    """Random add/update/upsert/delete/drop histories over several collections. After fix,
    every live record is identical and no token of a deleted or replaced version is on disk."""
    path = tmp_path / "s"
    script = Path(__file__).with_name("random_history.py")
    out = subprocess.run([sys.executable, str(script), str(path), str(seed)], capture_output=True, text=True, check=True)
    history = json.loads(out.stdout)
    model: dict[str, dict[str, str]] = history["model"]
    gone = set(history["gone"])

    result = fix(path, [])
    assert result.after.clean, result.after.findings

    live_tokens = {d.split()[2] for recs in model.values() for d in recs.values()}
    files = {p: p.read_bytes() for p in path.rglob("*") if p.is_file()}
    for d in gone:
        token = d.split()[2].encode()
        if token.decode() not in live_tokens:
            holders = [str(p.relative_to(path)) for p, b in files.items() if token in b]
            assert not holders, f"{token} survived fix in {holders}"

    got = chroma(path, """
        result = {c.name: dict(zip(*(lambda g: (g["ids"], g["documents"]))(
            client.get_collection(c.name, embedding_function=None).get(include=["documents"]))))
            for c in client.list_collections()}
    """)
    assert got == model


# --- large-index scanning -----------------------------------------------------

def test_tail_scan_finds_values_straddling_chunk_boundaries(tmp_path, monkeypatch):
    monkeypatch.setattr(hnsw, "_CHUNK", 1000)
    f = tmp_path / "data"
    blob = bytearray(5000)
    secret = b"straddle.person@example.com"
    blob[990:990 + len(secret)] = secret
    f.write_bytes(bytes(blob))
    index = hnsw.HnswIndex(tmp_path, 0, 0, 1)
    hnsw._scan_tail(f, 0, index)
    assert ("email", secret) in index.leaked_pii
    assert index.leaked_text == 1


@pytest.mark.fix
def test_receipt_contains_no_canary_value_or_hash(tmp_path):
    path = tmp_path / "s"
    make_chroma(path, 30)
    rec = tmp_path / "r.json"
    assert main(["fix", str(path), "--yes", "--receipt", str(rec), "--canary", email(3)]) == 0
    text = rec.read_text()
    assert email(3) not in text and hashlib.sha256(email(3).encode()).hexdigest() not in text
    assert json.loads(text)["canaries"] == [{"canary": 1, "found_in": []}]


def test_cli_reports_corrupt_stores_without_a_traceback(tmp_path, capsys):
    bad = tmp_path / "s"
    bad.mkdir()
    (bad / "chroma.sqlite3").write_bytes(b"not a database at all" * 100)
    assert main(["scan", str(bad)]) == 2
    assert "error:" in capsys.readouterr().err
    assert main(["scan", str(tmp_path / "missing")]) == 2


def test_rebuild_child_runs_offline_without_telemetry():
    env = fixer._child_env()
    assert env["HF_HUB_OFFLINE"] == "1" and env["TRANSFORMERS_OFFLINE"] == "1"
    assert env["ANONYMIZED_TELEMETRY"] == "False"


@pytest.mark.fix
@pytest.mark.parametrize("space", ["l2", "ip", "cosine"])
def test_length_file_is_leftover_memory_except_for_cosine(tmp_path, space):
    """Chroma only writes (and reads) length.bin for cosine indexes; for l2 and ip all of it is
    leftover process memory, including the slots of live vectors."""
    path = tmp_path / "s"
    chroma(path, """
        col = client.create_collection("mem", metadata={"hnsw:space": params["space"]}, embedding_function=None)
        col.add(ids=[f"m{i}" for i in range(1500)], embeddings=[[(i % 97) / 97 + 0.01, 1.0, (i % 13) / 13] for i in range(1500)],
                documents=[f"doc {i}" for i in range(1500)])
    """, space=space)
    (seg,) = [p for p in path.iterdir() if (p / "length.bin").exists()]
    length = seg / "length.bin"
    before = live(path)
    planted = b"leftover: call carol9@example.com"
    if space != "cosine":
        with length.open("r+b") as f:  # inside the live slots
            f.seek(16)
            f.write(planted)
        r = scan(path)
        assert "chroma.uninitialized_index_memory" in {f.check for f in r.findings}
    assert fix(path, []).after.clean
    (seg,) = [p for p in path.iterdir() if (p / "length.bin").exists()]  # the rebuilt index
    data = (seg / "length.bin").read_bytes()
    if space == "cosine":
        assert data.strip(b"\x00"), "cosine norms must survive"
    else:
        assert data.count(0) == len(data)
    assert same_records(live(path), before, cosine=space == "cosine")
