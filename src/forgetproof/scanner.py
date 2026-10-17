"""Scan an agent memory store for data that was deleted but is still on disk."""

from __future__ import annotations

import json
import mmap
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path

from . import hnsw, postgres
from ._chroma_rebuild import JOURNAL, TMP_PREFIX
from .pii import find_pii, redact
from .report import CanaryResult, Finding, Report
from .safety import store_files
from .pii import LivePii
from .sqlite_residue import connect_ro, is_sqlite, live_pii, residue_pii

GHOST_VECTORS = "embeddings can be inverted back to text (Ghost Vectors, arXiv:2606.18497)"
MAX_SAMPLES = 5

# Chroma's embeddings_queue operation codes
_ADD, _UPDATE, _UPSERT = 0, 1, 2


class UnsupportedStore(Exception):
    pass


def detect(target: Path | str) -> str:
    if postgres.is_postgres(target):
        return "postgres"
    target = Path(target)
    if target.is_dir() and (target / "chroma.sqlite3").exists():
        return "chroma"
    if target.is_file() and is_sqlite(target):
        return "sqlite"
    raise UnsupportedStore(
        f"{target}: not a supported store. Give a Chroma persist directory (contains chroma.sqlite3), "
        "a SQLite file, or a postgresql:// URL."
    )


def _pii_summary(values: Iterable[tuple[str, bytes]]) -> tuple[dict[str, int], list[str]]:
    values = sorted(set(values))
    counts = Counter(kind for kind, _ in values)
    samples = [f"{kind}: {redact(kind, v)}" for kind, v in values[:MAX_SAMPLES]]
    return dict(counts), samples


def _spaces_in(value) -> Iterator[str]:
    """Every hnsw "space" setting anywhere in a stored collection configuration."""
    if isinstance(value, dict):
        if value.get("space") in ("l2", "ip", "cosine"):
            yield value["space"]
        for v in value.values():
            yield from _spaces_in(v)
    elif isinstance(value, list):
        for v in value:
            yield from _spaces_in(v)


def normalized_segments(conn) -> dict[str, bool]:
    """segment id -> whether its HNSW index may be cosine (normalised), which decides whether
    length.bin holds real data. Chroma has stored the space as collection metadata (hnsw:space),
    in config_json_str and in schema_str, and they can disagree: 0.x keeps a default "l2" in its
    config and applies the metadata on top. So an index counts as l2/ip only when every setting
    found says l2 or ip; otherwise it's treated as cosine, which only makes fix zero less."""
    columns = {r[1] for r in conn.execute("pragma table_info(collections)")}
    configs = [c for c in ("config_json_str", "schema_str") if c in columns]
    found: dict[str, set[str]] = {}
    for row in conn.execute(f"select id{''.join(', ' + c for c in configs)} from collections"):
        spaces = found.setdefault(row[0], set())
        for raw in row[1:]:
            try:
                spaces.update(_spaces_in(json.loads(raw or "{}")))
            except ValueError:
                spaces.add("unknown")
    for coll, value in conn.execute("select collection_id, str_value from collection_metadata where key = 'hnsw:space'"):
        found.setdefault(coll, set()).add(value)

    def normalized(coll: str) -> bool:
        spaces = found.get(coll, set())
        return not spaces or not spaces <= {"l2", "ip"}

    return {sid: normalized(coll) for sid, coll in conn.execute("select id, collection from segments")}


def _sqlite_slack_finding(db: Path, target: Path, live: LivePii | None = None) -> Finding | None:
    residue = residue_pii(db, live)
    if not residue:
        return None
    pii, samples = _pii_summary(residue)
    return Finding(
        check="sqlite.slack",
        title="Deleted personal data recoverable from free space in the SQLite file",
        location=str(db.relative_to(target)) if db != target else db.name,
        records=len(residue),
        unit="personal-data values",
        why="SQLite leaves deleted rows' bytes in place until VACUUM; any file reader can carve them out",
        pii=pii,
        samples=samples,
    )


def _scan_chroma(target: Path, report: Report) -> None:
    db = target / "chroma.sqlite3"
    conn = connect_ro(db)
    try:
        segments = {sid: (scope, coll) for sid, scope, coll in conn.execute("select id, scope, collection from segments")}
        collections = dict(conn.execute("select id, name from collections"))
        meta_seg = {coll: sid for sid, (scope, coll) in segments.items() if scope == "METADATA"}
        normalized = normalized_segments(conn)
        # Chroma < 1.0 stored seq_id as 8 big-endian bytes.
        max_seq = {seg: int.from_bytes(seq, "big") if isinstance(seq, bytes) else seq
                   for seg, seq in conn.execute("select segment_id, seq_id from max_seq_id")}

        live: dict[str, set[str]] = {c: set() for c in collections}
        for seg_id, emb_id in conn.execute("select segment_id, embedding_id from embeddings"):
            coll = segments.get(seg_id, (None, None))[1]
            if coll in live:
                live[coll].add(emb_id)

        def applied_seq(coll: str) -> int:
            return max_seq.get(meta_seg.get(coll), -1)

        # The newest applied write for each record: any earlier write is an old version.
        newest: dict[tuple[str, str], int] = {}
        for seq_id, topic, emb_id in conn.execute("select seq_id, topic, id from embeddings_queue"):
            coll = topic.rsplit("/", 1)[-1]
            if coll in collections and seq_id <= applied_seq(coll):
                key = (coll, emb_id)
                newest[key] = max(newest.get(key, seq_id), seq_id)

        retained_ids: set[tuple[str, str]] = set()
        retained_vectors = overwritten = 0
        retained_pii: set[tuple[str, bytes]] = set()
        rows = conn.execute("select seq_id, operation, topic, id, vector, metadata from embeddings_queue")
        for seq_id, op, topic, emb_id, vector, metadata in rows:
            if op not in (_ADD, _UPDATE, _UPSERT):
                continue
            coll = topic.rsplit("/", 1)[-1]
            if coll in collections:
                if seq_id > applied_seq(coll):
                    continue  # not yet applied to the index: still the record's current content
                if emb_id in live[coll]:
                    overwritten += seq_id < newest[(coll, emb_id)]
                    continue
            retained_ids.add((coll, emb_id))
            retained_vectors += vector is not None
            if metadata:
                retained_pii.update(find_pii(metadata.encode() if isinstance(metadata, str) else metadata))

        unfinished = sorted(n for n in collections.values() if n.startswith(TMP_PREFIX))
        if (target / JOURNAL).exists() or unfinished:
            report.warnings.append("a previous `forgetproof fix` was interrupted; run fix again to finish it"
                                   + (f" (temporary collections: {', '.join(unfinished)})" if unfinished else ""))
        report.stats["collections"] = len(collections)
        report.stats["live_records"] = sum(len(v) for v in live.values())
    finally:
        conn.close()

    if retained_ids:
        pii, samples = _pii_summary(retained_pii)
        report.findings.append(Finding(
            check="chroma.write_log",
            title="Deleted records still readable in Chroma's write log (embeddings_queue table)",
            location="chroma.sqlite3",
            records=len(retained_ids),
            why=f"a plain SQL query returns their full text and {retained_vectors} embeddings",
            pii=pii,
            samples=samples,
        ))
    if overwritten:
        report.findings.append(Finding(
            check="chroma.write_log_overwritten",
            title="Old versions of updated records still readable in Chroma's write log",
            location="chroma.sqlite3",
            records=overwritten,
            unit="old versions",
            why="update() and upsert() keep the previous text and embedding; a memory your agent corrected "
                "is still on disk as it was",
        ))

    tombstoned = orphaned_vectors = leaked_text = 0
    orphan_dirs: list[str] = []
    leaked_dirs: list[str] = []
    leaked_pii: set[tuple[str, bytes]] = set()
    for sub in sorted(p for p in target.iterdir() if p.is_dir()):
        index = hnsw.read_index(sub, normalized.get(sub.name, True))
        if index is None:
            continue
        if sub.name not in segments:
            orphan_dirs.append(sub.name)
            orphaned_vectors += index.vectors
            continue
        tombstoned += index.deleted
        if index.leaked_text or index.leaked_pii:
            leaked_dirs.append(sub.name)
            leaked_text += index.leaked_text
            leaked_pii |= index.leaked_pii
    live = live_pii(db)
    leaked_pii = live.not_live(leaked_pii)
    if leaked_pii:
        pii, samples = _pii_summary(leaked_pii)
        report.findings.append(Finding(
            check="chroma.uninitialized_index_memory",
            title="Personal data in leftover process memory written into vector index files",
            location=", ".join(d[:8] + "…/data_level0.bin, length.bin" for d in leaked_dirs),
            records=len(leaked_pii),
            unit="personal-data values",
            why="Chroma persists never-used index capacity without zeroing it; it can contain other "
                "collections' documents, including deleted ones",
            pii=pii,
            samples=samples,
        ))
    elif leaked_text:
        report.warnings.append(
            f"{leaked_text} text fragments of leftover process memory in unused index capacity "
            f"({len(leaked_dirs)} index(es)); no personal data detected in them. Chroma writes this "
            "without zeroing it; `fix` zeroes it, and canaries check it for specific values."
        )
    if tombstoned:
        report.findings.append(Finding(
            check="chroma.hnsw_tombstones",
            title="Deleted vectors still stored in the HNSW index — only flagged as deleted",
            location="<segment>/data_level0.bin",
            records=tombstoned,
            unit="vectors",
            why=GHOST_VECTORS,
        ))
    if orphan_dirs:
        report.findings.append(Finding(
            check="chroma.orphaned_index",
            title=f"Index files left behind by {len(orphan_dirs)} deleted collection(s)",
            location=", ".join(d[:8] + "…" for d in orphan_dirs),
            records=orphaned_vectors,
            unit="vectors",
            why=f"delete_collection removed the rows but not these vectors; {GHOST_VECTORS}",
        ))

    slack = _sqlite_slack_finding(db, target, live)
    if slack:
        report.findings.append(slack)


def check_canaries(target: Path, canaries: Iterable[str]) -> list[CanaryResult]:
    """Look for specific values you deleted (e.g. a user's email) anywhere in the store's files."""
    canaries = [c for c in canaries if c]
    hits: list[list[str]] = [[] for _ in canaries]
    needles = [{c.encode(), c.lower().encode()} for c in canaries]
    for f in store_files(target):
        if f.stat().st_size == 0:
            continue
        with f.open("rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for i, wanted in enumerate(needles):
                if any(mm.find(n) != -1 for n in wanted):
                    hits[i].append(str(f.relative_to(target)) if target.is_dir() else f.name)
    return [CanaryResult(i, found) for i, found in enumerate(hits, 1)]


def scan(target: Path | str, canaries: Iterable[str] = ()) -> Report:
    if postgres.is_postgres(target):
        return postgres.scan(str(target), list(canaries))
    target = Path(target).resolve()
    store = detect(target)
    report = Report(target=str(target), store=store)
    if store == "chroma":
        _scan_chroma(target, report)
    else:
        slack = _sqlite_slack_finding(target, target)
        if slack:
            report.findings.append(slack)
    report.canaries = check_canaries(target, canaries)
    return report
