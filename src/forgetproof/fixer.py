"""Erase residue found by the scanner, rescan, and report what changed."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

from . import hnsw, postgres, safety
from ._chroma_rebuild import JOURNAL
from .report import Report
from .scanner import normalized_segments, scan
from .sqlite_residue import connect_ro, vacuum


class FixError(Exception):
    pass


@dataclass
class Options:
    force: bool = False  # skip the open-process and free-space checks
    allow_upgrade: bool = False  # let chromadb migrate an older store to its own format


@dataclass
class Result:
    before: Report
    after: Report
    actions: list[str] = field(default_factory=list)


def _run_child(*args: str) -> subprocess.CompletedProcess:
    # -c rather than -m, with the current directory dropped from sys.path before anything is
    # imported: a chromadb.py in whatever directory the user runs us from must not be executed.
    bootstrap = (
        "import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]; "
        "from forgetproof import _chroma_rebuild as m; "
        "m.rebuild(__import__('pathlib').Path(sys.argv[2])) if sys.argv[1] == 'rebuild' else m.migrations()"
    )
    return subprocess.run([sys.executable, "-c", bootstrap, *args], capture_output=True, text=True, env=_child_env())


def _child_env() -> dict[str, str]:
    """The rebuild only copies stored embeddings; it never needs to fetch or run a model. A collection's
    saved settings can name an embedding model to load, so keep model hubs offline (remote model code is
    how the 2026 chromadb code-injection advisories work) and keep Chroma's usage telemetry off."""
    return {
        **os.environ,
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "ANONYMIZED_TELEMETRY": "False",
    }


def _require_chromadb() -> None:
    # Check from package metadata: chromadb itself only ever loads in the rebuild child process.
    try:
        installed = metadata.version("chromadb")
    except metadata.PackageNotFoundError:
        raise FixError("fixing a Chroma store needs chromadb: pip install 'forgetproof[chroma]'") from None
    if int(installed.split(".")[0]) < 1:
        raise FixError(
            f"fixing needs chromadb 1.0 or later (installed: {installed}). Scanning works with any "
            "version. To fix a store from Chroma 0.x, install chromadb>=1.0 and pass --allow-upgrade: the store "
            "will then need Chroma 1.x to open."
        )


def _check_chroma_version(target: Path, allow_upgrade: bool) -> None:
    """Refuse to let the installed chromadb silently migrate the user's store."""
    conn = connect_ro(target / "chroma.sqlite3")
    try:
        store = {tuple(r) for r in conn.execute("select dir, version from migrations")}
    except sqlite3.Error:
        store = set()
    finally:
        conn.close()
    proc = _run_child("migrations")
    if proc.returncode != 0:
        raise FixError(f"could not start chromadb:\n{proc.stderr.strip()[-2000:]}")
    info = json.loads(proc.stdout)
    installed = {tuple(r) for r in info["migrations"]}
    if store - installed:
        raise FixError(
            f"this store was written by a newer Chroma than the installed chromadb {info['chromadb']}. "
            "Upgrade chromadb to the version your app uses, then run fix again."
        )
    if installed - store and not allow_upgrade:
        raise FixError(
            f"this store was written by an older Chroma. Fixing it with chromadb {info['chromadb']} would upgrade "
            "it to that version's format, and your app's older Chroma may not open it afterwards. Install the "
            "chromadb version your app uses (pip install chromadb==<version>) and run fix again, or pass "
            "--allow-upgrade if your app is moving to this version anyway."
        )


def preflight(target: Path, report: Report, options: Options) -> None:
    if report.store == "postgres":
        return  # VACUUM FULL takes its own locks; fix() checks ownership and uses a lock timeout
    if not options.force:
        holders = safety.open_by_other_processes(target)
        if holders:
            raise FixError(
                "the store is open in another process: " + ", ".join(holders[:5])
                + ". Stop it first; rewriting files under a running app corrupts them. (--force skips this check.)"
            )
        need, free = safety.space_needed(target), safety.free_space(target)
        if free < need:
            raise FixError(f"fix needs about {need >> 20} MB free next to the store; {free >> 20} MB available. (--force skips this check.)")
    if report.store == "chroma":
        _require_chromadb()
        _check_chroma_version(target, options.allow_upgrade)


def plan(report: Report) -> list[str]:
    """What fix would do to this store, without doing it."""
    if report.store == "postgres":
        return postgres.plan(report)
    if report.store != "chroma":
        return [f"VACUUM {Path(report.target).name} with secure_delete on (rewrites the file without free pages)"]
    target = Path(report.target)
    steps = []
    if (target / JOURNAL).exists():
        steps.append("finish the interrupted fix recorded in " + JOURNAL)
    n = report.stats.get("collections", 0)
    steps.append(f"rebuild {n} collection(s) from their live records "
                 "(ids, documents, metadata and embeddings kept; collections get new internal IDs)")
    steps.append("delete the index files the rebuild replaces, with their deleted vectors")
    checks = {f.check for f in report.findings}
    if checks & {"chroma.write_log", "chroma.write_log_overwritten"}:
        steps.append("drop write-log entries of the replaced collections")
    if "chroma.orphaned_index" in checks:
        steps.append("delete index directories no collection uses: "
                     + next(f.location for f in report.findings if f.check == "chroma.orphaned_index"))
    steps.append("zero never-used capacity in the remaining index files (sizes unchanged)")
    steps.append("VACUUM chroma.sqlite3 with secure_delete on")
    return steps


def _fix_chroma(target: Path) -> list[str]:
    actions = []
    proc = _run_child("rebuild", str(target))
    if proc.returncode != 0:
        raise FixError(
            "rebuilding collections failed; no live data was lost, and running fix again finishes or undoes "
            f"the interrupted step.\n{proc.stderr.strip()[-2000:]}"
        )
    actions += [line for line in proc.stderr.splitlines() if line.startswith(("rebuilt ", "recovered "))]

    db = target / "chroma.sqlite3"
    conn = sqlite3.connect(db)
    try:
        segments = {r[0] for r in conn.execute("select id from segments")}
        normalized = normalized_segments(conn)
        collections = {r[0] for r in conn.execute("select id from collections")}
        stale = [
            topic for (topic,) in conn.execute("select distinct topic from embeddings_queue")
            if topic.rsplit("/", 1)[-1] not in collections
        ]
        for topic in stale:
            conn.execute("delete from embeddings_queue where topic = ?", (topic,))
        conn.commit()
    finally:
        conn.close()
    if stale:
        actions.append(f"dropped write-log entries of {len(stale)} deleted collection(s)")

    for sub in sorted(p for p in target.iterdir() if p.is_dir()):
        index = hnsw.read_index(sub, normalized.get(sub.name, True))
        if index is None:
            continue
        if sub.name not in segments:
            shutil.rmtree(sub)
            actions.append(f"removed orphaned index {sub.name}")
        elif index.leaked_bytes:
            zeroed = hnsw.zero_unused(index)
            actions.append(f"zeroed {zeroed} bytes of unused index capacity in {sub.name}")

    vacuum(db)
    actions.append("vacuumed chroma.sqlite3 (secure_delete on)")
    return actions


def fix(target: Path | str, canaries: list[str], options: Options | None = None) -> Result:
    if postgres.is_postgres(target):
        before = scan(target, canaries)
        try:
            actions = postgres.fix(str(target))
        except postgres.PostgresError as e:
            raise FixError(str(e)) from None
        return Result(before, scan(target, canaries), actions)
    target = Path(target).resolve()
    before = scan(target, canaries)
    preflight(target, before, options or Options())
    if before.store == "chroma":
        actions = _fix_chroma(target)
    else:
        vacuum(target)
        actions = [f"vacuumed {target.name} (secure_delete on)"]
    return Result(before, scan(target, canaries), actions)
