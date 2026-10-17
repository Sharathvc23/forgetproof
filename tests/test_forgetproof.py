import json

import pytest
from conftest import CHROMA_SECURE_DELETE, chroma, email, live, make_chroma, make_sqlite

from forgetproof import receipt
from forgetproof.cli import main
from forgetproof.fixer import fix
from forgetproof.pii import find_pii, redact
from forgetproof.scanner import UnsupportedStore, scan


def raw_contains(path, needle: str) -> bool:
    files = [p for p in path.rglob("*") if p.is_file()] if path.is_dir() else [path]
    return any(needle.encode() in p.read_bytes() for p in files)


def checks(report):
    return {f.check: f.records for f in report.findings}


# --- scanning ---------------------------------------------------------------

def test_small_store_keeps_deleted_records_in_write_log(tmp_path):
    deleted = make_chroma(tmp_path / "s", 300)
    r = scan(tmp_path / "s")
    assert checks(r)["chroma.write_log"] == len(deleted)
    f = next(f for f in r.findings if f.check == "chroma.write_log")
    assert f.pii["email"] == len(deleted)
    assert all("person" not in s or "*" in s for s in f.samples)  # samples are redacted


def test_large_store_keeps_tombstoned_vectors_and_slack(tmp_path):
    deleted = make_chroma(tmp_path / "s", 3000, after=1500)
    r = scan(tmp_path / "s")
    c = checks(r)
    assert c["chroma.hnsw_tombstones"] == len(deleted)
    if not CHROMA_SECURE_DELETE:
        assert c["sqlite.slack"] >= len(deleted)
    assert r.stats["live_records"] == 3000 - len(deleted) + 1500


def test_canary_reports_where_a_deleted_value_survives(tmp_path):
    make_chroma(tmp_path / "s", 300)
    r = scan(tmp_path / "s", [email(3), "never-stored@example.com"])
    # Usually only chroma.sqlite3; Chroma's unzeroed index capacity can add an index file too.
    assert "chroma.sqlite3" in r.canaries[0].found_in
    assert r.canaries[1].found_in == []
    assert email(3) not in json.dumps(r.to_dict())  # canary value itself is never echoed


def test_generic_sqlite_slack(tmp_path):
    db = tmp_path / "agent.db"
    deleted = make_sqlite(db)
    r = scan(db)
    assert checks(r)["sqlite.slack"] >= len(deleted)
    assert r.store == "sqlite"


def test_sqlite_with_secure_delete_is_clean(tmp_path):
    db = tmp_path / "agent.db"
    make_sqlite(db, secure_delete=True)
    assert scan(db).clean


def test_clean_store_is_clean(tmp_path):
    make_chroma(tmp_path / "s", 50, delete_every=10**9)  # deletes only id 0
    chroma(tmp_path / "t", """
        col = client.create_collection("clean_store", embedding_function=None)
        col.add(ids=["a"], embeddings=[[0.1] * 16], documents=["hi"])
    """)
    assert scan(tmp_path / "t").clean


def test_unsupported_target(tmp_path):
    (tmp_path / "notes.txt").write_text("hello")
    with pytest.raises(UnsupportedStore):
        scan(tmp_path / "notes.txt")


# --- fixing -----------------------------------------------------------------

@pytest.mark.fix
@pytest.mark.parametrize("n,after", [(300, 0), (3000, 1500)])
def test_fix_erases_residue_and_keeps_live_data(tmp_path, n, after):
    path = tmp_path / "s"
    deleted = make_chroma(path, n, after=after)
    nearest = """
        col = client.get_collection("mem", embedding_function=None)
        probe = col.get(ids=["m1"], include=["embeddings"])["embeddings"][0]
        result = col.query(query_embeddings=[probe], n_results=5)["ids"][0]
    """
    before, nearest_before = live(path), chroma(path, nearest)

    result = fix(path, [email(deleted[1])])
    assert not result.before.clean and result.after.clean
    assert not any(raw_contains(path, email(i)) for i in deleted)
    assert live(path) == before
    assert chroma(path, nearest) == nearest_before


@pytest.mark.fix
def test_fix_removes_orphaned_index_of_deleted_collection(tmp_path):
    path = tmp_path / "s"
    make_chroma(path, 1500, delete_every=10**9)
    chroma(path, """
        client.delete_collection("mem")
        client.create_collection("other", embedding_function=None).add(ids=["a"], embeddings=[[0.2] * 16])
    """)
    assert "chroma.orphaned_index" in checks(scan(path))
    fix(path, [])
    assert scan(path).clean


@pytest.mark.fix
def test_rebuild_handles_mixed_missing_documents_and_metadata(tmp_path):
    path = tmp_path / "s"
    chroma(path, """
        col = client.create_collection("mixed", embedding_function=None)
        col.add(ids=["a", "b", "c"], embeddings=[[0.1] * 4, [0.2] * 4, [0.3] * 4],
                documents=["doc a", None, "secret c person9@example.com"], metadatas=[{"k": 1}, None, {"k": 3}])
        col.delete(ids=["c"])
    """)
    assert fix(path, []).after.clean
    got = chroma(path, """
        result = client.get_collection("mixed", embedding_function=None).get(ids=["a", "b"], include=["documents", "metadatas"])
    """)
    assert dict(zip(got["ids"], got["documents"])) == {"a": "doc a", "b": None}
    assert dict(zip(got["ids"], got["metadatas"])) == {"a": {"k": 1}, "b": None}


def test_fix_generic_sqlite(tmp_path):
    db = tmp_path / "agent.db"
    deleted = make_sqlite(db)
    assert fix(db, []).after.clean
    assert not any(raw_contains(db, email(i)) for i in deleted)
    assert raw_contains(db, email(1))  # live row survives


# --- receipts and CLI -------------------------------------------------------

@pytest.mark.fix
def test_cli_end_to_end_and_receipt_tamper_detection(tmp_path, capsys):
    path = tmp_path / "s"
    make_chroma(path, 300)
    rec_path = tmp_path / "r.json"
    assert main(["scan", str(path)]) == 1
    assert main(["fix", str(path), "--yes", "--receipt", str(rec_path), "--canary", email(0)]) == 0
    assert main(["scan", str(path)]) == 0
    assert main(["verify", str(rec_path), "--against", str(path)]) == 0

    rec = json.loads(rec_path.read_text())
    assert rec["verdict"] == "CLEAN" and "@example.com" not in rec_path.read_text()
    rec["after"]["clean"] = False
    tampered = tmp_path / "t.json"
    tampered.write_text(json.dumps(rec))
    assert main(["verify", str(tampered)]) == 2

    pub = receipt.public_key_b64(receipt.load_or_create_key())
    fp = receipt.fingerprint(pub)
    assert main(["verify", str(rec_path), "--key", fp]) == 0
    assert main(["verify", str(rec_path), f"--key={pub}"]) == 0
    assert main(["verify", str(rec_path), "--key", "0" * 32]) == 2


def test_pii_detection_and_redaction():
    data = b"x a.b@example.org y (415) 555-0100 z 123-45-6789 card 4111 1111 1111 1111 key sk-" + b"a" * 24
    kinds = {k for k, _ in find_pii(data)}
    assert kinds == {"email", "phone", "ssn", "card", "api_key"}
    assert not list(find_pii(b"4111 1111 1111 1112"))  # fails Luhn
    assert redact("email", b"alice@example.org") == "a***e@example.org"
    # a stray byte after the address in a raw page doesn't make a new address
    assert list(find_pii(b"\x00person7@example.comC\x01")) == [("email", b"person7@example.com")]
    assert list(find_pii(b"x a@b.photography y")) == [("email", b"a@b.photography")]  # unknown TLDs untouched
    assert redact("card", b"4111 1111 1111 1111") == "************1111"


# --- uninitialized index memory (Chroma persists unzeroed capacity) ----------

def _bob_store(path):
    chroma(path, """
        bob = client.create_collection("user-bob", embedding_function=None)
        bob.add(ids=[f"b{i}" for i in range(20)], embeddings=[[0.02 * i] * 16 for i in range(20)],
                documents=[f"bob note {i}" for i in range(20)])
    """)
    (seg,) = [p for p in path.iterdir() if (p / "data_level0.bin").exists()]
    return seg


def test_detects_and_zeroes_leftover_memory_in_unused_index_capacity(tmp_path):
    from forgetproof import hnsw
    path = tmp_path / "s"
    seg = _bob_store(path)
    index = hnsw.read_index(seg)
    data = seg / "data_level0.bin"
    size = data.stat().st_size
    with data.open("r+b") as f:  # simulate what malloc reuse leaves behind
        f.seek(index.vectors * index.element_size + 64)
        f.write(b"alice note: SSN 078-05-1120, email alice7@example.com")
    r = scan(path)
    f = next(f for f in r.findings if f.check == "chroma.uninitialized_index_memory")
    assert {("email", b"alice7@example.com"), ("ssn", b"078-05-1120")} <= hnsw.read_index(seg).leaked_pii
    assert f.pii["email"] >= 1 and f.pii["ssn"] >= 1

    zeroed = hnsw.zero_unused(hnsw.read_index(seg))
    assert zeroed > 0 and data.stat().st_size == size
    assert not raw_contains(path, "alice7@example.com")
    count, nearest = chroma(path, """
        bob = client.get_collection("user-bob", embedding_function=None)
        result = [bob.count(), bob.query(query_embeddings=[[0.5] * 16], n_results=3)["ids"][0]]
    """)
    assert count == 20 and nearest == ["b19", "b18", "b17"]


@pytest.mark.fix
def test_per_user_collections_leave_no_trace_of_forgotten_user_after_fix(tmp_path):
    path = tmp_path / "s"
    chroma(path, """
        alice = client.create_collection("user-alice", embedding_function=None)
        alice.add(ids=[f"a{i}" for i in range(300)], embeddings=[[0.01 * i] * 16 for i in range(300)],
                  documents=[f"alice note {i}: SSN 078-05-{i:04d}, email alice{i}@example.com" for i in range(300)])
        client.delete_collection("user-alice")
        bob = client.create_collection("user-bob", embedding_function=None)
        bob.add(ids=[f"b{i}" for i in range(20)], embeddings=[[0.02 * i] * 16 for i in range(20)])
    """)
    assert not scan(path).clean
    assert fix(path, ["alice5@example.com"]).after.clean
    assert not any(raw_contains(path, f"alice{i}@example.com") for i in range(300))
    assert chroma(path, "result = client.get_collection('user-bob', embedding_function=None).count()") == 20


@pytest.mark.fix
def test_leftover_memory_without_deleted_personal_data_is_only_a_warning(tmp_path):
    from forgetproof import hnsw
    path = tmp_path / "s"
    chroma(path, """
        col = client.create_collection("user-bob", embedding_function=None)
        col.add(ids=[f"b{i}" for i in range(20)], embeddings=[[0.02 * i] * 16 for i in range(20)],
                documents=[f"bob note {i}, reach me at bob{i}@example.com" for i in range(20)])
    """)
    (seg,) = [p for p in path.iterdir() if (p / "data_level0.bin").exists()]
    index = hnsw.read_index(seg)
    with (seg / "data_level0.bin").open("r+b") as f:  # library strings, plus a *live* address
        f.seek(index.vectors * index.element_size + 64)
        f.write(b"libonnxruntime.so.1 /usr/lib/python3/site-packages bob3@example.com")
    r = scan(path)
    assert "chroma.uninitialized_index_memory" not in checks(r) and r.clean
    assert any("leftover process memory" in w for w in r.warnings)
    fix(path, [])
    assert not scan(path).warnings


def test_output_survives_a_legacy_windows_code_page(tmp_path):
    """Redirected output on Windows defaults to cp1252, which can't encode ✓ ✗ ❌."""
    import os
    import subprocess
    import sys
    db = tmp_path / "agent.db"
    make_sqlite(db)
    env = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    for fmt in ("text", "markdown"):
        p = subprocess.run([sys.executable, "-m", "forgetproof", "scan", str(db), "--format", fmt],
                           capture_output=True, env=env)
        assert p.returncode == 1, p.stderr
        assert "✗".encode() in p.stdout or "❌".encode() in p.stdout
