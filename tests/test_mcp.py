import asyncio
import json
import os
import subprocess
import sys
import time

import pytest
from conftest import email, make_chroma, make_sqlite

pytest.importorskip("mcp")

from mcp import Client, StdioServerParameters  # noqa: E402

from forgetproof import forget as forget_mod  # noqa: E402
from forgetproof.mcp_server import Store, build, parse_store  # noqa: E402


def call(server, tool, **args):
    async def go():
        async with Client(server) as c:
            return await c.call_tool(tool, args)
    return asyncio.run(go())


def tools(server):
    async def go():
        async with Client(server) as c:
            return sorted(t.name for t in (await c.list_tools()).tools)
    return asyncio.run(go())


def ok(result) -> dict:
    assert not result.is_error, result.content
    return result.structured_content


def error(result) -> str:
    assert result.is_error
    return result.content[0].text


def test_fix_is_only_offered_when_the_operator_allows_it(tmp_path):
    make_sqlite(tmp_path / "a.db")
    stores = [Store("chat", tmp_path / "a.db")]
    assert tools(build(stores)) == ["get_receipt", "list_stores", "plan_fix", "scan_store", "verify_receipt"]
    assert "fix_store" in tools(build(stores, allow_fix=True))
    assert ok(call(build(stores), "list_stores")) == {
        "stores": [{"name": "chat", "location": str(tmp_path / "a.db")}],
        "fix_enabled": False, "subject_configured": False}


def test_subject_scoped_tools_appear_only_with_a_subject_file(tmp_path):
    make_sqlite(tmp_path / "a.db")
    subj = tmp_path / "subject"
    subj.write_text(email(0))
    stores = [Store("chat", tmp_path / "a.db")]
    assert "check_if_forgotten" not in tools(build(stores))
    assert "check_if_forgotten" in tools(build(stores, subject_file=subj))
    assert "forget_me" not in tools(build(stores, subject_file=subj))  # needs allow_fix too
    assert "forget_me" in tools(build(stores, allow_fix=True, subject_file=subj))


def test_scan_store_cannot_look_up_an_arbitrary_value(tmp_path):
    """The old scan_store(store_name, canaries) let an agent ask "is X still here?" for any X.
    The tool has no such parameter now; the MCP SDK drops an unknown argument rather than letting
    it reach the call, so it can have no effect on the result."""
    deleted = make_chroma(tmp_path / "s", 300)
    server = build([Store("memory", tmp_path / "s")])
    with_bogus_arg = ok(call(server, "scan_store", store_name="memory", canaries=[email(deleted[1])]))
    plain = ok(call(server, "scan_store", store_name="memory"))
    assert with_bogus_arg == plain
    assert "canaries" not in with_bogus_arg


def test_scan_reports_counts_but_never_values_or_samples(tmp_path):
    make_chroma(tmp_path / "s", 300)
    server = build([Store("memory", tmp_path / "s")])
    result = call(server, "scan_store", store_name="memory")
    r = ok(result)
    assert not r["clean"]
    assert {f["check"] for f in r["findings"]} >= {"chroma.write_log"}
    wire = result.model_dump_json()
    assert "@" not in wire and "555" not in wire  # no values, no samples (not even redacted ones)


def test_check_if_forgotten_is_scoped_to_the_subject_file_not_the_agent(tmp_path):
    path = tmp_path / "s"
    deleted = make_chroma(path, 300)
    subj = tmp_path / "subject"
    subj.write_text(email(deleted[1]))  # a value that is NOT forgotten (still on disk)
    server = build([Store("memory", path)], subject_file=subj)

    # The tool takes no value argument: naming a different (forgotten) value has no effect.
    r = ok(call(server, "check_if_forgotten", store_name="memory", subject="never-stored@example.com"))
    assert r == {"forgotten": False, "store_type": "chroma", "incomplete": None}

    # The operator's app changes who the next check is about; the agent still can't.
    time.sleep(1.1)  # past the per-store cooldown
    subj.write_text("never-stored@example.com")
    r2 = ok(call(server, "check_if_forgotten", store_name="memory"))
    assert r2["forgotten"] is True


def test_check_if_forgotten_requires_a_configured_subject(tmp_path):
    make_sqlite(tmp_path / "a.db")
    subj = tmp_path / "subject"
    server = build([Store("chat", tmp_path / "a.db")], subject_file=subj)
    assert "no user is currently identified" in error(call(server, "check_if_forgotten", store_name="chat"))
    time.sleep(1.1)  # past the per-store cooldown
    subj.write_text("")
    assert "no user is currently identified" in error(call(server, "check_if_forgotten", store_name="chat"))


def test_agent_can_only_reach_configured_stores(tmp_path):
    make_sqlite(tmp_path / "a.db")
    make_sqlite(tmp_path / "other.db")
    server = build([Store("chat", tmp_path / "a.db")])
    assert "unknown store" in error(call(server, "scan_store", store_name=str(tmp_path / "other.db")))
    for bad in ["../../etc/passwd", "chat.20261018T000000000000Z/../x", "chat"]:
        assert "receipt" in error(call(server, "get_receipt", receipt_id=bad))
    assert "no receipt" in error(call(server, "verify_receipt", receipt_id="chat.20261018T000000000000Z"))


def test_parse_store_rejects_bad_specs(tmp_path):
    for spec in ["noequals", "bad name=x", f"a.b={tmp_path}", "x="]:
        with pytest.raises(ValueError):
            parse_store(spec)
    with pytest.raises(ValueError, match="does not exist"):
        parse_store(f"x={tmp_path / 'missing'}")
    assert parse_store("pg=postgresql://app:secret@db/agent").location == "postgresql://app@db/agent"


@pytest.mark.fix
def test_fix_store_erases_everything_with_no_value_argument(tmp_path):
    path = tmp_path / "s"
    deleted = make_chroma(path, 300)
    server = build([Store("memory", path)], allow_fix=True, receipts_dir=tmp_path / "receipts")

    r = ok(call(server, "fix_store", store_name="memory"))
    assert r["clean"] and r["actions"]
    assert not any(email(deleted[1]).encode() in p.read_bytes() for p in path.rglob("*") if p.is_file())

    rec = ok(call(server, "get_receipt", receipt_id=r["receipt_id"]))
    assert rec["verdict"] == "CLEAN"
    v = ok(call(server, "verify_receipt", receipt_id=r["receipt_id"]))
    assert v["signature_valid"] and v["store_unchanged"] and v["clean_now"]

    # A receipt edited and re-signed with another key is rejected.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from forgetproof import receipt
    other = Ed25519PrivateKey.generate()
    forged = {k: v for k, v in rec.items() if k != "signature"} | {"public_key": receipt.public_key_b64(other)}
    forged["signature"] = receipt._b64(other.sign(receipt.canonical(forged)))
    (tmp_path / "receipts" / f"{r['receipt_id']}.json").write_text(json.dumps(forged))
    assert "different key" in error(call(server, "verify_receipt", receipt_id=r["receipt_id"]))


@pytest.mark.fix
def test_forget_me_erases_the_subject_and_issues_a_verifiable_receipt(tmp_path):
    path = tmp_path / "s"
    deleted = make_chroma(path, 300)
    gone = email(deleted[1])
    subj = tmp_path / "subject"
    subj.write_text(gone)
    server = build([Store("memory", path)], allow_fix=True, receipts_dir=tmp_path / "receipts", subject_file=subj,
                   queue_dir=tmp_path / "queue")

    r = ok(call(server, "forget_me", store_name="memory"))
    assert r == {"queued": False, "done": True, "clean": True, "receipt_id": r["receipt_id"],
                 "signing_key": r["signing_key"]}
    assert not any(gone.encode() in p.read_bytes() for p in path.rglob("*") if p.is_file())
    rec = ok(call(server, "get_receipt", receipt_id=r["receipt_id"]))
    assert gone not in json.dumps(rec)


@pytest.mark.fix
def test_forget_me_queues_instead_of_failing_while_chroma_is_open(tmp_path):
    path = tmp_path / "s"
    deleted = make_chroma(path, 300)
    gone = email(deleted[1])
    subj = tmp_path / "subject"
    subj.write_text(gone)
    qdir = tmp_path / "queue"
    server = build([Store("memory", path)], allow_fix=True, receipts_dir=tmp_path / "receipts", subject_file=subj,
                   queue_dir=qdir)
    holder = subprocess.Popen([sys.executable, "-c", (
        "import chromadb, sys, time\n"
        f"c = chromadb.PersistentClient(path={str(path)!r}).get_collection('mem')\n"
        "c.count(); print('ready', flush=True); time.sleep(60)\n"
    )], stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "ready"
        r = ok(call(server, "forget_me", store_name="memory"))
        assert r["queued"] and not r["done"]
        assert all(gone not in p.read_text() for p in qdir.glob("*.json"))  # encrypted at rest
    finally:
        holder.kill()
        holder.wait()
    assert not (tmp_path / "receipts").exists()

    # Starting a server for this store now drains the queue before offering anything else.
    receipts = tmp_path / "receipts"
    build([Store("memory", path)], allow_fix=True, receipts_dir=receipts, queue_dir=qdir)
    assert forget_mod.pending(path, queue_dir=qdir) == 0
    rec_files = list(receipts.glob("*.json"))
    assert len(rec_files) == 1
    assert json.loads(rec_files[0].read_text())["verdict"] == "CLEAN"
    assert not any(gone.encode() in p.read_bytes() for p in path.rglob("*") if p.is_file())


def test_forget_me_has_a_per_store_cooldown(tmp_path):
    make_sqlite(tmp_path / "a.db")
    subj = tmp_path / "subject"
    subj.write_text("never-stored@example.com")
    server = build([Store("chat", tmp_path / "a.db")], allow_fix=True, receipts_dir=tmp_path / "receipts",
                   subject_file=subj)
    assert ok(call(server, "forget_me", store_name="chat"))["done"]
    assert "too many requests" in error(call(server, "forget_me", store_name="chat"))


def test_fix_sqlite_and_postgres_style_errors_stay_tool_errors(tmp_path):
    make_sqlite(tmp_path / "a.db")
    server = build([Store("chat", tmp_path / "a.db"), Store("pg", "postgresql://u:pw@127.0.0.1:1/none")],
                   allow_fix=True, receipts_dir=tmp_path / "receipts")
    assert ok(call(server, "fix_store", store_name="chat"))["clean"]
    msg = error(call(server, "scan_store", store_name="pg"))
    assert "pw" not in msg


def test_stdio_server_over_the_cli(tmp_path):
    """The real entry point: stdout must carry only the protocol."""
    db = tmp_path / "a.db"
    deleted = make_sqlite(db)
    subj = tmp_path / "subject"
    subj.write_text(email(deleted[0]))
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "forgetproof", "mcp", "--store", f"chat={db}", "--subject-file", str(subj)],
        env={**os.environ})

    async def go():
        async with Client(params) as c:
            names = sorted(t.name for t in (await c.list_tools()).tools)
            scanned = await c.call_tool("scan_store", {"store_name": "chat"})
            checked = await c.call_tool("check_if_forgotten", {"store_name": "chat"})
            return names, scanned, checked

    names, scanned, checked = asyncio.run(go())
    assert "fix_store" not in names and "forget_me" not in names  # --allow-fix wasn't passed
    assert "check_if_forgotten" in names
    r = ok(scanned)
    assert not r["clean"]
    assert ok(checked) == {"forgotten": False, "store_type": "sqlite", "incomplete": None}
