import asyncio
import json
import os
import subprocess
import sys

import pytest
from conftest import email, make_chroma, make_sqlite

pytest.importorskip("mcp")

from mcp import Client, StdioServerParameters  # noqa: E402

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
        "stores": [{"name": "chat", "location": str(tmp_path / "a.db")}], "fix_enabled": False}


def test_scan_reports_counts_but_never_values_or_samples(tmp_path):
    deleted = make_chroma(tmp_path / "s", 300)
    server = build([Store("memory", tmp_path / "s")])
    result = call(server, "scan_store", store_name="memory", canaries=[email(deleted[1]), "never-stored@example.com"])
    r = ok(result)
    assert not r["clean"]
    assert {f["check"] for f in r["findings"]} >= {"chroma.write_log"}
    assert [(c["canary"], c["still_on_disk"]) for c in r["canaries"]] == [(1, True), (2, False)]
    wire = result.model_dump_json()
    assert "@" not in wire and "555" not in wire  # no canary values, no samples (not even redacted ones)


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
def test_fix_erases_and_issues_a_receipt_the_agent_can_verify(tmp_path):
    path = tmp_path / "s"
    deleted = make_chroma(path, 300)
    server = build([Store("memory", path)], allow_fix=True, receipts_dir=tmp_path / "receipts")
    gone = email(deleted[1])

    r = ok(call(server, "fix_store", store_name="memory", canaries=[gone]))
    assert r["clean"] and r["actions"]
    assert r["after"]["canaries"] == [{"canary": 1, "still_on_disk": False, "found_in": []}]
    assert not any(gone.encode() in p.read_bytes() for p in path.rglob("*") if p.is_file())

    rec = ok(call(server, "get_receipt", receipt_id=r["receipt_id"]))
    assert rec["verdict"] == "CLEAN" and gone not in json.dumps(rec)
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
def test_fix_refuses_while_the_app_has_the_store_open(tmp_path):
    path = tmp_path / "s"
    make_chroma(path, 300)
    server = build([Store("memory", path)], allow_fix=True, receipts_dir=tmp_path / "receipts")
    holder = subprocess.Popen([sys.executable, "-c", (
        "import chromadb, sys, time\n"
        f"c = chromadb.PersistentClient(path={str(path)!r}).get_collection('mem')\n"
        "c.count(); print('ready', flush=True); time.sleep(60)\n"
    )], stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "ready"
        assert "open in another process" in error(call(server, "fix_store", store_name="memory"))
    finally:
        holder.kill()
        holder.wait()
    assert not (tmp_path / "receipts").exists()


def test_fix_sqlite_and_postgres_style_errors_stay_tool_errors(tmp_path):
    make_sqlite(tmp_path / "a.db")
    server = build([Store("chat", tmp_path / "a.db"), Store("pg", "postgresql://u:pw@127.0.0.1:1/none")],
                   allow_fix=True, receipts_dir=tmp_path / "receipts")
    assert ok(call(server, "fix_store", store_name="chat"))["clean"]
    msg = error(call(server, "scan_store", store_name="pg"))
    assert "pw" not in msg


def test_stdio_server_over_the_cli(tmp_path):
    """The real entry point: stdout must carry only the protocol."""
    make_sqlite(tmp_path / "a.db")
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "forgetproof", "mcp", "--store", f"chat={tmp_path / 'a.db'}"],
        env={**os.environ})

    async def go():
        async with Client(params) as c:
            names = sorted(t.name for t in (await c.list_tools()).tools)
            scanned = await c.call_tool("scan_store", {"store_name": "chat", "canaries": [email(0)]})
            return names, scanned

    names, scanned = asyncio.run(go())
    assert "fix_store" not in names
    r = ok(scanned)
    assert not r["clean"] and r["canaries"][0]["still_on_disk"]
