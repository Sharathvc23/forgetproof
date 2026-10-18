"""MCP server: lets an agent scan the stores its operator allows, and ask to be forgotten.

    forgetproof mcp --store memory=./chroma_dir --store pg=postgresql://app@db/agent \\
        [--allow-fix] [--subject-file /run/forgetproof/current-user]

The agent names stores, never paths, so it can only reach what the operator listed.

The agent can never name an arbitrary value to check or erase — that would turn this into a
tool for looking people up ("is bob@example.com still in here?"). The one value a `forget_me`
or `check_if_forgotten` call acts on is read from --subject-file, which only the operator's
application controls and refreshes (typically with the identity of whoever is signed in).
Generic `scan_store` reports counts only, never whether a specific value is present.

`fix` is not offered unless --allow-fix is given. Responses carry counts only: no samples
(even redacted) and no values, so nothing personal ends up in the agent's context or chat logs.
"""

from __future__ import annotations

import json
import re
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import __version__, forget as forget_mod, postgres, receipt
from .fixer import FixError, Options, fix, plan
from .report import Report
from .scanner import UnsupportedStore, scan

STORE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
RECEIPT_ID = re.compile(r"^([A-Za-z0-9_-]{1,64})\.(\d{8}T\d{12}Z)$")
_EXPECTED = (UnsupportedStore, FixError, postgres.PostgresError, ValueError, OSError, sqlite3.DatabaseError)
_COOLDOWN = 1.0  # seconds between subject-scoped calls on the same store, to blunt rapid probing

INSTRUCTIONS = """\
forgetproof checks whether deleted data is really gone from a memory store's files on disk.

Call `scan_store` to see whether a store has deleted-but-recoverable data in general. It never
checks for one specific value: you cannot use it, or any other tool here, to ask whether a
particular person's data is present. Call `check_if_forgotten` / `forget_me` for the one person
this session is about — the operator's application identifies who that is, not you.

When a user asks to be forgotten: delete their records with your normal memory tools first, then
call `forget_me` (if available) and give the user the resulting receipt id.

`forget_me` can come back queued rather than done: for Chroma it can't rewrite the store while
the application still has it open, so it queues the erasure for the application's next start.
Tell the user it's scheduled, not failed.
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
        "warnings": r.warnings,
        "stats": r.stats,
    }


def build(stores: list[Store], allow_fix: bool = False, receipts_dir: Path | None = None,
          subject_file: Path | str | None = None, queue_dir: Path | str | None = None) -> MCPServer:
    by_name = {s.name: s for s in stores}
    if len(by_name) != len(stores):
        raise ValueError("store names must be unique")
    receipts = receipts_dir or receipt.key_path().parent / "receipts"
    subject_path = Path(subject_file).expanduser().resolve() if subject_file else None
    locks = {s.name: threading.Lock() for s in stores}
    last_subject_call: dict[str, float] = {}

    def store(name: str) -> Store:
        if name not in by_name:
            raise ToolError(f"unknown store {name!r}; configured: {', '.join(by_name) or 'none'}")
        return by_name[name]

    def exclusive(name: str):
        lock = locks[name]
        if not lock.acquire(blocking=False):
            raise ToolError(f"store {name!r} is busy with another forgetproof call; try again when it finishes")
        return lock

    def cooldown(name: str) -> None:
        now = time.monotonic()
        if now - last_subject_call.get(name, 0.0) < _COOLDOWN:
            raise ToolError("too many requests for this store in a row; wait a moment and try again")
        last_subject_call[name] = now

    def current_subject() -> str:
        if subject_path is None:
            raise ToolError(
                "this server wasn't started with --subject-file, so it has no signed-in user to act for. "
                "The operator's application sets that file to the current user's identity; the agent cannot."
            )
        try:
            value = subject_path.read_text().strip()
        except OSError:
            value = ""
        if not value:
            raise ToolError("no user is currently identified right now (the subject file is missing or empty)")
        return value

    def receipt_path(receipt_id: str) -> tuple[Store, Path]:
        m = RECEIPT_ID.match(receipt_id)
        if not m:
            raise ToolError(f"not a receipt id: {receipt_id!r}")
        path = receipts / f"{receipt_id}.json"
        if not path.is_file():
            raise ToolError(f"no receipt {receipt_id!r}")
        return store(m.group(1)), path

    def write_receipt(name: str, rec: dict) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        receipt_id = f"{name}.{stamp}"
        receipts.mkdir(parents=True, exist_ok=True)
        (receipts / f"{receipt_id}.json").write_text(json.dumps(rec, indent=2) + "\n")
        return receipt_id

    if allow_fix:
        # Finish anything a previous forget_me queued (Chroma, store open elsewhere at the time)
        # before this server starts offering fix on it. A failure here doesn't stop the server —
        # it just means that queue is tried again on the next startup — and never reaches stdout.
        for s in stores:
            try:
                for rec in forget_mod.run_queued(s.target, queue_dir=queue_dir):
                    receipt_id = write_receipt(s.name, rec)
                    if rec["verdict"] != "CLEAN":
                        print(f"forgetproof: a queued erasure for store {s.name!r} still shows residue "
                              f"(receipt {receipt_id}); it stays queued and is retried, up to "
                              f"{forget_mod.MAX_ATTEMPTS} attempts, rather than being dropped", file=sys.stderr)
            except _EXPECTED as e:
                print(f"forgetproof: couldn't finish a queued erasure for store {s.name!r}: {e}", file=sys.stderr)

    server = MCPServer("forgetproof", version=__version__, instructions=INSTRUCTIONS)

    @server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def list_stores() -> dict[str, Any]:
        """List the stores this server may check, and which capabilities are enabled."""
        return {
            "stores": [{"name": s.name, "location": s.location} for s in stores],
            "fix_enabled": allow_fix,
            "subject_configured": subject_path is not None,
        }

    @server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def scan_store(store_name: str) -> dict[str, Any]:
        """Scan a store's files for deleted data that is still recoverable, as counts only.

        This never checks for a specific value — use check_if_forgotten for the current user.
        """
        s = store(store_name)
        lock = exclusive(s.name)
        try:
            return _findings(scan(s.target))
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

    if subject_path is not None:
        @server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
        def check_if_forgotten(store_name: str) -> dict[str, Any]:
            """Check whether the current user (identified by the operator, not by you) still has
            recoverable data in a store."""
            s = store(store_name)
            lock = exclusive(s.name)
            try:
                cooldown(s.name)
                r = scan(s.target, [current_subject()])
                return {"forgotten": not r.canaries[0].found_in, "store_type": r.store, "incomplete": r.incomplete}
            except _EXPECTED as e:
                raise ToolError(str(e)) from None
            finally:
                lock.release()

    if allow_fix:
        @server.tool(annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=True, open_world_hint=False))
        def fix_store(store_name: str) -> dict[str, Any]:
            """Erase every deleted-but-recoverable record from a store's files, rescan, and issue
            a signed receipt. For a single user's request, prefer forget_me.

            Rewrites the store in place with no backup; live records are kept. Chroma: refuses while
            another process has the store open. Postgres: locks each vector table while it is rewritten.
            """
            s = store(store_name)
            lock = exclusive(s.name)
            try:
                result = fix(s.target, [], Options())
                rec = receipt.issue(s.target, result.before.summary(), result.after.summary(), result.actions, [],
                                     label=s.location)
                return {
                    "clean": result.after.clean,
                    "actions": result.actions,
                    "receipt_id": write_receipt(s.name, rec),
                    "signing_key": receipt.fingerprint(rec["public_key"]),
                    "after": _findings(result.after),
                }
            except _EXPECTED as e:
                raise ToolError(str(e)) from None
            finally:
                lock.release()

        if subject_path is not None:
            @server.tool(annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=True, open_world_hint=False))
            def forget_me(store_name: str) -> dict[str, Any]:
                """Erase the current user's data from a store and issue a signed receipt.

                The user is the one the operator's application identified, not one you name. On
                Chroma this can come back queued instead of done, if the application still has the
                store open; it completes at the application's next start, before it reopens the store.
                """
                s = store(store_name)
                lock = exclusive(s.name)
                try:
                    cooldown(s.name)
                    result = forget_mod.forget(s.target, current_subject(), queue_dir=queue_dir)
                    if isinstance(result, forget_mod.Queued):
                        return {"queued": True, "done": False, "queued_at": result.queued_at}
                    return {
                        "queued": False,
                        "done": True,
                        "clean": result["verdict"] == "CLEAN",
                        "receipt_id": write_receipt(s.name, result),
                        "signing_key": receipt.fingerprint(result["public_key"]),
                    }
                except _EXPECTED as e:
                    raise ToolError(str(e)) from None
                finally:
                    lock.release()

    return server
