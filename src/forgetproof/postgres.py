"""Postgres + pgvector: find deleted rows that are still in the table files, and erase them.

What a DELETE or UPDATE leaves behind in Postgres:

- The old row version stays in the table's pages as a dead tuple until VACUUM.
- Plain VACUUM (and autovacuum) frees that space but does not overwrite it, so the bytes
  stay readable in the table files until new rows happen to land on them.
- The same goes for TOAST storage (long values) and for index entries.
- The write-ahead log (WAL) records the row as it was written. It is shared by every database on
  the server and recycled rather than wiped, so it is checked for canaries and reported as a warning.
- Recent changes may exist only in shared memory and the WAL until a checkpoint, so the scan
  runs CHECKPOINT first (it flushes pages; it changes no data).

VACUUM FULL rewrites the table, its TOAST data and its indexes into new files holding only
live rows. Switching WAL segments and checkpointing lets Postgres recycle old WAL.

Reading the files needs superuser or the pg_read_server_files role, because we read them
through SQL (pg_read_binary_file) and never need filesystem access to the server.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass

from .pii import ByteScanner, LivePii, find_pii
from .report import CanaryResult, Finding, Report

CHUNK = 8 << 20
LOCK_TIMEOUT = "15s"  # how long VACUUM FULL waits for the app to release a table
VECTOR_TYPES = ("vector", "halfvec", "sparsevec")


class PostgresError(Exception):
    pass


def is_postgres(target) -> bool:
    return str(target).startswith(("postgres://", "postgresql://"))


def _psycopg():
    try:
        import psycopg
    except ImportError:
        raise PostgresError("Postgres support needs psycopg: pip install 'forgetproof[postgres]'") from None
    return psycopg


def display(dsn: str) -> str:
    """The connection string without its password, safe to print and to put in receipts."""
    psycopg = _psycopg()
    info = psycopg.conninfo.conninfo_to_dict(dsn)
    info.pop("password", None)
    host = info.get("host", "")
    where = f"{info.get('user', '')}@{host}" if "/" not in host else f"{info.get('user', '')}@(socket)"
    return f"postgresql://{where}{':' + str(info['port']) if info.get('port') else ''}/{info.get('dbname', '')}"


def connect(dsn: str):
    psycopg = _psycopg()
    try:
        return psycopg.connect(dsn, autocommit=True)
    except psycopg.Error as e:
        raise PostgresError(f"could not connect to {display(dsn)}: {str(e).strip()}") from None


def _quote(schema: str, table: str) -> str:
    return '"' + schema.replace('"', '""') + '"."' + table.replace('"', '""') + '"'


@dataclass
class Table:
    oid: int
    schema: str
    name: str

    @property
    def sql(self) -> str:
        return _quote(self.schema, self.name)

    @property
    def label(self) -> str:
        return f"{self.schema}.{self.name}"


def vector_tables(conn) -> list[Table]:
    """User tables with at least one pgvector column: where agent memories live."""
    rows = conn.execute(
        """
        select distinct c.oid, n.nspname, c.relname
        from pg_attribute a
        join pg_class c on c.oid = a.attrelid
        join pg_namespace n on n.oid = c.relnamespace
        join pg_type t on t.oid = a.atttypid
        where t.typname = any(%s) and c.relkind in ('r', 'p', 'm') and a.attnum > 0 and not a.attisdropped
          and n.nspname not in ('pg_catalog', 'information_schema')
        order by n.nspname, c.relname
        """,
        (list(VECTOR_TYPES),),
    ).fetchall()
    return [Table(*r) for r in rows]


def can_read_files(conn) -> bool:
    try:
        conn.execute("select pg_read_binary_file('PG_VERSION', 0, 1)").fetchone()
        return True
    except Exception:
        return False


def _relations(conn, table: Table) -> list[tuple[str, int]]:
    """(label, oid) of the table, its TOAST table and every index on either."""
    rows = conn.execute(
        """
        select 'heap', c.oid from pg_class c where c.oid = %(t)s
        union all
        select 'toast', c.reltoastrelid from pg_class c where c.oid = %(t)s and c.reltoastrelid <> 0
        union all
        select 'index ' || i.indexrelid::regclass::text, i.indexrelid from pg_index i
        where i.indrelid = %(t)s
           or i.indrelid = (select reltoastrelid from pg_class where oid = %(t)s)
        """,
        {"t": table.oid},
    ).fetchall()
    return [(label, oid) for label, oid in rows]


def _files(conn, oid: int) -> list[tuple[str, int]]:
    """A relation's data files: the main fork split into 1 GB segments (path, path.1, ...)."""
    base = conn.execute("select pg_relation_filepath(%s)", (oid,)).fetchone()[0]
    if base is None:
        return []
    out = []
    for n in range(10_000):
        path = base if n == 0 else f"{base}.{n}"
        row = conn.execute("select size from pg_stat_file(%s, true)", (path,)).fetchone()
        if row is None or row[0] is None:
            break
        out.append((path, row[0]))
    return out


def _wal_files(conn) -> list[tuple[str, int]]:
    return [(f"pg_wal/{name}", size) for name, size in conn.execute("select name, size from pg_ls_waldir() order by name")]


def _read(conn, path: str, size: int) -> Iterator[bytes]:
    for offset in range(0, size, CHUNK):
        row = conn.execute("select pg_read_binary_file(%s, %s, %s, true)", (path, offset, min(CHUNK, size - offset))).fetchone()
        if row is None or row[0] is None:
            return  # file went away (e.g. WAL recycled) while we read it
        yield bytes(row[0])


def _live(conn, tables: list[Table]) -> tuple[LivePii, int]:
    """Personal data in every live row, read as text; and the live row count."""
    values: set[tuple[str, bytes]] = set()
    rows = 0
    for t in tables:
        with conn.cursor(name="forgetproof_live") as cur:  # server-side: big tables stream
            # Explicit transaction: a named cursor needs one, and autocommit is on.
            with conn.transaction():
                cur.execute(f"select t::text from {t.sql} t")
                for (text,) in cur:
                    rows += 1
                    values.update(find_pii(text.encode()))
    return LivePii(values), rows


def scan(dsn: str, canaries: list[str]) -> Report:
    conn = connect(dsn)
    try:
        return _scan(conn, display(dsn), canaries)
    finally:
        conn.close()


def _scan(conn, target: str, canaries: list[str]) -> Report:
    report = Report(target=target, store="postgres")
    tables = vector_tables(conn)
    live, rows = _live(conn, tables)
    report.stats = {"tables": len(tables), "live_records": rows}
    if not tables:
        report.warnings.append("no tables with a pgvector column (vector, halfvec, sparsevec) in this database")

    if not can_read_files(conn):
        report.incomplete = (
            "this role can't read table files, so bytes left after VACUUM can't be checked. Connect as a "
            "superuser or a role with pg_read_server_files for a full scan."
        )
        dead = conn.execute(
            "select relid, n_dead_tup from pg_stat_user_tables where relid = any(%s)", ([t.oid for t in tables],)
        ).fetchall()
        n_dead = sum(n for _, n in dead)
        if n_dead:
            report.findings.append(Finding(
                check="pg.dead_tuples",
                title="Deleted or overwritten rows not yet vacuumed (Postgres statistics estimate)",
                location=", ".join(t.label for t in tables),
                records=n_dead,
                unit="row versions",
                why="a DELETE or UPDATE only marks the old row version dead; it stays in the table files",
            ))
        report.canaries = [CanaryResult(i, ["(not checked: no file access)"]) for i in range(1, len(canaries) + 1)]
        return report

    # Changed pages sit in shared memory until a checkpoint writes them out; flush them so the
    # files show what Postgres holds. A checkpoint writes no new data and changes no rows.
    try:
        conn.execute("checkpoint")
    except Exception:
        report.warnings.append(
            "couldn't CHECKPOINT (needs superuser or pg_checkpoint), so very recent changes may not be in "
            "the table files yet; they are in the WAL, which is also scanned"
        )
    canaries = [c for c in canaries if c]
    found_in: list[list[str]] = [[] for _ in canaries]
    table_scan = ByteScanner(canaries)
    locations = []
    for t in tables:
        for label, oid in _relations(conn, t):
            for path, size in _files(conn, oid):
                table_scan.feed(_read(conn, path, size))
                for i, seen in enumerate(table_scan.last_seen):
                    if seen:
                        found_in[i].append(f"{t.label} ({label}) {path}")
        locations.append(t.label)
    # The WAL is shared by every database on the server, so its personal data can't be compared
    # with this database's live rows. Only canaries, which name one specific value, are checked there.
    wal_hits: list[list[str]] = [[] for _ in canaries]
    if canaries:
        wal_scan = ByteScanner(canaries)
        for path, size in _wal_files(conn):
            wal_scan.feed(_read(conn, path, size))
            for i, seen in enumerate(wal_scan.last_seen):
                if seen:
                    wal_hits[i].append(path)
    for i, paths in enumerate(wal_hits, 1):
        if paths:
            report.warnings.append(
                f"canary #{i} is still in the write-ahead log ({', '.join(paths)}). Postgres recycles WAL rather "
                "than wiping it, so it can stay until the segment is reused; backups and replicas may also hold it"
            )

    from .scanner import _pii_summary  # shared formatting

    residue = live.not_live(table_scan.pii)
    if residue:
        pii, samples = _pii_summary(residue)
        report.findings.append(Finding(
            check="pg.table_residue",
            title="Deleted or overwritten personal data still in table files",
            location=", ".join(locations),
            records=len(residue),
            unit="personal-data values",
            why="DELETE and UPDATE leave the old row in the page; VACUUM frees the space but doesn't "
                "overwrite it. Anyone who can read the files or a disk image can recover it",
            pii=pii,
            samples=samples,
        ))
    report.canaries = [CanaryResult(i, found) for i, found in enumerate(found_in, 1)]
    return report


def plan(report: Report) -> list[str]:
    tables = report.stats.get("tables", 0)
    return [
        f"VACUUM FULL the {tables} table(s) with a pgvector column: rewrites each table, its TOAST data and "
        "its indexes with live rows only. Each table is locked (reads and writes wait) while it is rewritten.",
        "switch WAL segments and CHECKPOINT twice, so Postgres can recycle WAL that recorded the deleted rows",
    ]


def fix(dsn: str) -> list[str]:
    conn = connect(dsn)
    psycopg = _psycopg()
    try:
        tables = vector_tables(conn)
        not_owned = [r[0] for r in conn.execute(
            """
            select c.oid::regclass::text from pg_class c
            where c.oid = any(%s)
              and not pg_has_role(current_user, c.relowner, 'USAGE')
              and not (select rolsuper from pg_roles where rolname = current_user)
            """,
            ([t.oid for t in tables],),
        )]
        if not_owned:
            raise PostgresError(
                f"VACUUM FULL needs the table owner or a superuser; this role doesn't own: {', '.join(not_owned)}"
            )
        conn.execute(f"set lock_timeout = '{LOCK_TIMEOUT}'")
        actions = []
        for t in tables:
            try:
                conn.execute(f"vacuum (full, analyze) {t.sql}")
            except psycopg.errors.LockNotAvailable:
                raise PostgresError(
                    f"{t.label} is in use (couldn't lock it within {LOCK_TIMEOUT}). Stop the app's writes and run fix again; "
                    f"tables already rewritten: {', '.join(a.split()[1] for a in actions) or 'none'}"
                ) from None
            actions.append(f"rewrote {t.label} (VACUUM FULL)")
        try:
            for _ in range(2):
                conn.execute("select pg_switch_wal()")
                conn.execute("checkpoint")
            actions.append("switched WAL segments and checkpointed")
        except psycopg.Error as e:
            actions.append(f"could not rotate WAL ({str(e).strip().splitlines()[0]}); deleted rows may stay in it until Postgres recycles it")
        return actions
    finally:
        conn.close()


def fingerprints(dsn: str) -> dict[str, str]:
    """SHA-256 of each scanned relation file, for receipts. Empty without file access."""
    conn = connect(dsn)
    try:
        if not can_read_files(conn):
            return {}
        out = {}
        for t in vector_tables(conn):
            for label, oid in _relations(conn, t):
                for path, size in _files(conn, oid):
                    h = hashlib.sha256()
                    for chunk in _read(conn, path, size):
                        h.update(chunk)
                    out[f"{t.label} ({label}) {path}"] = h.hexdigest()
        return out
    finally:
        conn.close()
