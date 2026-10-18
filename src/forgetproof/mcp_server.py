"""MCP server: lets an agent scan, fix and verify the stores its operator allows.

    forgetproof mcp --store memory=./chroma_dir --store pg=postgresql://app@db/agent [--allow-fix]

The agent names stores, never paths, so it can only reach what the operator listed. `fix` is
not offered unless --allow-fix is given. Responses carry counts only: no samples (even redacted)
and never a canary value, so nothing personal ends up in the agent's context or chat logs.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import __version__, postgres, receipt
from .fixer import FixError, Options, fix, plan
from .report import Report
from .scanner import UnsupportedStore, scan

STORE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
RECEIPT_ID = re.compile(r"^([A-Za-z0-9_-]{1,64})\.(\d{8}T\d{12}Z)$")
_EXPECTED = (UnsupportedStore, FixError, postgres.PostgresError, ValueError, OSError, sqlite3.DatabaseError)

INSTRUCTIONS = """\
forgetproof checks whether deleted data is really gone from a memory store's files on disk.

When a user asks to be forgotten: delete their records with your normal memory tools first, then
call `scan` with identifying values (their email, phone, user id) as canaries. If the scan is not
clean and `fix` is available, call `fix` with the same canaries and give the user the receipt id.
Canary values are never returned; results refer to them by number in the order you passed them.

`fix` rewrites the store. For Chroma it refuses while the app holds the store open; tell the user
the erasure is scheduled for a maintenance window instead of retrying.
"""


@dataclass(frozen=True)
class Store:
    name: str
    target: Path | str

    @property
    def location(self) -> str:
        return postgres.display(self.target) if isinstance(self.target, str) else str(self.target)


def parse_store(spec: str) -> Store:
    name, sep, where = spec.partition("=")
    if not sep or not STORE_NAME.match(name) or not where:
        raise ValueError(f"--store expects NAME=PATH_OR_URL with NAME made of letters, digits, - and _: {spec!r}")
    if postgres.is_postgres(where):
        return Store(name, where)
    path = Path(where).expanduser().resolve()
    if not path.exists():
        raise ValueError(f"store {name!r}: {path} does not exist")
    return Store(name, path)


def _findings(r: Report) -> dict[str, Any]:
    return {
        "clean": r.clean,
        "store_type": r.store,
        "incomplete": r.incomplete,
        "findings": [
            {"check": f.check, "what": f.title, "amount": f.records, "unit": f.unit,
             "personal_data": f.pii, "location": f.location}
            for f in r.findings
        ],
        "canaries": [{"canary": c.number, "still_on_disk": bool(c.found_in), "found_in": c.found_in}
                     for c in r.canaries],
        "warnings": r.warnings,
        "stats": r.stats,
    }


def build(stores: list[Store], allow_fix: bool = False, receipts_dir: Path | None = None) -> MCPServer:
    by_name = {s.name: s for s in stores}
    if len(by_name) != len(stores):
        raise ValueError("store names must be unique")
    receipts = receipts_dir or receipt.key_path().parent / "receipts"
    locks = {s.name: threading.Lock() for s in stores}

    def store(name: str) -> Store:
        if name not in by_name:
            raise ToolError(f"unknown store {name!r}; configured: {', '.join(by_name) or 'none'}")
        return by_name[name]

    def exclusive(name: str):
        lock = locks[name]
        if not lock.acquire(blocking=False):
            raise ToolError(f"store {name!r} is busy with another forgetproof call; try again when it finishes")
        return lock

    def receipt_path(receipt_id: str) -> tuple[Store, Path]:
        m = RECEIPT_ID.match(receipt_id)
        if not m:
            raise ToolError(f"not a receipt id: {receipt_id!r}")
        path = receipts / f"{receipt_id}.json"
        if not path.is_file():
            raise ToolError(f"no receipt {receipt_id!r}")
        return store(m.group(1)), path

    server = MCPServer("forgetproof", version=__version__, instructions=INSTRUCTIONS)

    @server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def list_stores() -> dict[str, Any]:
        """List the stores this server may check, and whether fix is enabled."""
        return {
            "stores": [{"name": s.name, "location": s.location} for s in stores],
            "fix_enabled": allow_fix,
        }

    @server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def scan_store(store_name: str, canaries: list[str] | None = None) -> dict[str, Any]:
        """Scan a store's files for deleted data that is still recoverable.

        canaries: exact values that must be gone, such as a forgotten user's email. They are never
        returned; results name them by 1-based position.
        """
        s = store(store_name)
        lock = exclusive(s.name)
        try:
            return _findings(scan(s.target, canaries or []))
        except _EXPECTED as e:
            raise ToolError(str(e)) from None
        finally:
            lock.release()

    @server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def plan_fix(store_name: str) -> dict[str, Any]:
        """Show what fix would change in a store, without changing anything."""
        s = store(store_name)
        lock = exclusive(s.name)
        try:
            r = scan(s.target)
            return {"clean": r.clean, "steps": plan(r), "fix_enabled": allow_fix}
        except _EXPECTED as e:
            raise ToolError(str(e)) from None
        finally:
            lock.release()

    @server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def verify_receipt(receipt_id: str) -> dict[str, Any]:
        """Check a receipt was signed by this server and unaltered, and whether its store still matches it
        and still scans clean."""
        s, path = receipt_path(receipt_id)
        lock = exclusive(s.name)
        try:
            rec = json.loads(path.read_text())
            # Receipts in this directory were issued by this server, so pin its key: a receipt re-signed
            # with some other key is rejected, not just checked for internal consistency.
            receipt.verify_signature(rec, receipt.public_key_b64(receipt.load_or_create_key()))
            now = scan(s.target)
            return {
                "signature_valid": True,
                "issued_at": rec["issued_at"],
                "signing_key": receipt.fingerprint(rec["public_key"]),
                "verdict_at_issue": rec["verdict"],
                "store_unchanged": receipt.file_hashes(s.target) == rec["files"],
                "clean_now": now.clean,
            }
        except _EXPECTED as e:
            raise ToolError(str(e)) from None
        finally:
            lock.release()

    @server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def get_receipt(receipt_id: str) -> dict[str, Any]:
        """Return a signed receipt to hand to the user. It holds counts and file hashes, never erased values."""
        _, path = receipt_path(receipt_id)
        return json.loads(path.read_text())

    if allow_fix:
        @server.tool(annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=True, open_world_hint=False))
        def fix_store(store_name: str, canaries: list[str] | None = None) -> dict[str, Any]:
            """Erase deleted data from a store's files, rescan, and issue a signed receipt.

            Rewrites the store in place with no backup; live records are kept. Chroma: refuses while
            another process has the store open. Postgres: locks each vector table while it is rewritten.
            canaries: as for scan_store; the receipt records whether each was still found afterwards.
            """
            s = store(store_name)
            lock = exclusive(s.name)
            try:
                result = fix(s.target, canaries or [], Options())
                before, after = result.before.summary(), result.after.summary()
                canary_results = [{"canary": c.number, "found_in": c.found_in} for c in result.after.canaries]
                rec = receipt.issue(s.target, before, after, result.actions, canary_results, label=s.location)
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                receipt_id = f"{s.name}.{stamp}"
                receipts.mkdir(parents=True, exist_ok=True)
                (receipts / f"{receipt_id}.json").write_text(json.dumps(rec, indent=2) + "\n")
                return {
                    "clean": after["clean"],
                    "actions": result.actions,
                    "receipt_id": receipt_id,
                    "signing_key": receipt.fingerprint(rec["public_key"]),
                    "after": _findings(result.after),
                }
            except _EXPECTED as e:
                raise ToolError(str(e)) from None
            finally:
                lock.release()

    return server
