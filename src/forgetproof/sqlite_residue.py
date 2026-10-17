"""Find personal data that survives in a SQLite file after its rows were deleted.

SQLite does not overwrite deleted rows by default (secure_delete is off): the
bytes stay in page slack and on free pages until a VACUUM rewrites the file.
We compare personal data found in the raw bytes against personal data reachable
through SQL. Anything only the raw bytes contain is residue.
"""

from __future__ import annotations

import mmap
import sqlite3
from collections.abc import Iterator
from pathlib import Path

from .pii import LivePii, find_pii, pii_set

SQLITE_MAGIC = b"SQLite format 3\x00"


def is_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(16) == SQLITE_MAGIC
    except OSError:
        return False


def _is_wal(path: Path) -> bool:
    with path.open("rb") as f:
        header = f.read(20)
    return len(header) == 20 and header[18] == 2  # file format write version 2 = WAL


def connect_ro(path: Path) -> sqlite3.Connection:
    """Open read-only so scanning never changes the evidence.

    Opening a WAL database even read-only creates -wal and -shm files. When no -wal file
    exists there is nothing to replay, so open it as immutable and touch nothing.
    """
    if _is_wal(path) and not path.with_name(path.name + "-wal").exists():
        return sqlite3.connect(f"{path.as_uri()}?immutable=1", uri=True)
    try:
        conn = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
        conn.execute("select count(*) from sqlite_master").fetchone()
        return conn
    except sqlite3.OperationalError:
        # Read-only directory with a WAL database: fall back to an immutable view.
        return sqlite3.connect(f"{path.as_uri()}?immutable=1", uri=True)


def _live_values(conn: sqlite3.Connection) -> Iterator[bytes]:
    tables = [r[0] for r in conn.execute("select name from sqlite_master where type='table'")]
    for (sql,) in conn.execute("select sql from sqlite_master where sql is not null"):
        yield sql.encode()
    for table in tables:
        quoted = '"' + table.replace('"', '""') + '"'
        try:
            rows = conn.execute(f"select * from {quoted}")
        except sqlite3.Error:
            continue  # e.g. a virtual table whose module isn't loaded
        for row in rows:
            for value in row:
                if isinstance(value, str):
                    yield value.encode()
                elif isinstance(value, bytes):
                    yield value


def _raw_pii(path: Path) -> set[tuple[str, bytes]]:
    found: set[tuple[str, bytes]] = set()
    for p in (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-journal")):
        if not p.exists() or p.stat().st_size == 0:
            continue
        with p.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            found.update(find_pii(mm))
    return found


def live_pii(path: Path) -> LivePii:
    """Personal data reachable through SQL in this SQLite file."""
    conn = connect_ro(path)
    try:
        return LivePii(pii_set(_live_values(conn)))
    finally:
        conn.close()


def residue_pii(path: Path, live: LivePii | None = None) -> set[tuple[str, bytes]]:
    """Personal data present in the file's bytes but not reachable via SQL."""
    return (live or live_pii(path)).not_live(_raw_pii(path))


def vacuum(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute("pragma secure_delete=on")
        if conn.execute("pragma journal_mode").fetchone()[0].lower() == "wal":
            conn.execute("pragma wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
        if conn.execute("pragma journal_mode").fetchone()[0].lower() == "wal":
            conn.execute("pragma wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
