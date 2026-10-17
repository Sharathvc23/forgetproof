"""Chroma operations that need the chromadb client. Run in a child process by the fixer:

    rebuild PATH   rebuild every collection from its live records
    migrations     print the schema migrations this chromadb applies to a new store, as JSON

A separate process means Chroma's file handles and caches are fully released before
the fixer touches the files directly.

Each swap is journaled in PATH/.forgetproof-rebuild.json before it starts, so a crash
at any point is repaired by `recover` on the next run, and no live record is ever lost:
until the original is deleted it is untouched, and after that the full copy exists
under its temporary name.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import uuid
from pathlib import Path

BATCH = 1000
JOURNAL = ".forgetproof-rebuild.json"
TMP_PREFIX = "fp-rebuild-"


def _crash_point(name: str) -> None:
    """Test hook: simulate the process dying at a named step."""
    if os.environ.get("FORGETPROOF_TEST_CRASH") == name:
        os._exit(70)


def _names(client) -> set[str]:
    return {c if isinstance(c, str) else c.name for c in client.list_collections()}


def _write_journal(path: Path, entries: dict[str, str]) -> None:
    journal = path / JOURNAL
    if not entries:
        journal.unlink(missing_ok=True)
        return
    tmp = journal.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries))
    os.replace(tmp, journal)


def recover(client, path: Path) -> list[str]:
    """Finish or undo swaps left by an interrupted rebuild."""
    journal = path / JOURNAL
    if not journal.exists():
        return []
    entries: dict[str, str] = json.loads(journal.read_text())
    notes = []
    for tmp_name, orig in entries.items():
        names = _names(client)
        if tmp_name not in names:
            continue
        if orig in names:
            client.delete_collection(tmp_name)  # crashed before the swap: original is intact
            notes.append(f"recovered {orig}: discarded an unfinished copy")
        else:
            client.get_collection(tmp_name, embedding_function=None).modify(name=orig)
            notes.append(f"recovered {orig}: completed an interrupted swap")
    journal.unlink()
    return notes


def _create_like(client, name, src):
    try:
        return client.create_collection(name, metadata=src.metadata, configuration=src.configuration, embedding_function=None)
    except Exception:
        # Older/newer configuration shapes: keep only the index settings.
        conf = {k: v for k, v in (src.configuration or {}).items() if k in ("hnsw", "spann") and v}
        return client.create_collection(name, metadata=src.metadata, configuration=conf or None, embedding_function=None)


def _column(batch, key):
    values = batch.get(key)
    if values is None or all(v is None for v in values):
        return None
    return values


def rebuild_collection(client, path: Path, name: str) -> int:
    src = client.get_collection(name, embedding_function=None)
    ids = src.get(include=[])["ids"]
    tmp_name = f"{TMP_PREFIX}{uuid.uuid4().hex[:12]}"
    _write_journal(path, {tmp_name: name})
    tmp = _create_like(client, tmp_name, src)
    for start in range(0, len(ids), BATCH):
        batch = src.get(ids=ids[start:start + BATCH], include=["embeddings", "documents", "metadatas", "uris"])
        tmp.add(
            ids=batch["ids"],
            embeddings=batch["embeddings"],
            documents=_column(batch, "documents"),
            metadatas=_column(batch, "metadatas"),
            uris=_column(batch, "uris"),
        )
        _crash_point("copy")
    if tmp.count() != len(ids):
        client.delete_collection(tmp_name)
        _write_journal(path, {})
        raise RuntimeError(f"rebuild of {name!r} copied {tmp.count()} of {len(ids)} records; original left untouched")
    client.delete_collection(name)
    _crash_point("swap")
    tmp.modify(name=name)
    _write_journal(path, {})
    return len(ids)


def rebuild(path: Path) -> None:
    import chromadb

    client = chromadb.PersistentClient(path=str(path))
    for note in recover(client, path):
        print(note, file=sys.stderr)
    for name in sorted(_names(client)):
        n = rebuild_collection(client, path, name)
        print(f"rebuilt {name}: {n} records", file=sys.stderr)


def migrations() -> None:
    import chromadb

    scratch = tempfile.mkdtemp(prefix="forgetproof-")
    try:
        client = chromadb.PersistentClient(path=scratch)
        client.heartbeat()
        conn = sqlite3.connect(Path(scratch) / "chroma.sqlite3")
        rows = conn.execute("select dir, version from migrations").fetchall()
        conn.close()
        del client
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    print(json.dumps({"chromadb": chromadb.__version__, "migrations": sorted(rows)}))


if __name__ == "__main__":
    if sys.argv[1] == "rebuild":
        rebuild(Path(sys.argv[2]))
    else:
        migrations()
