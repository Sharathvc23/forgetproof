import json
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from conftest import email, make_chroma, make_sqlite

from forgetproof import forget
from forgetproof.cli import main
from forgetproof.fixer import FixError


def _run_queued_retrying(target, *, queue_dir=None, attempts=10, delay=1):
    """run_queued(), tolerating a transient 'still open' error for a few seconds.

    A just-killed holder process's file handles (or, on Windows CI, antivirus scanning the
    files it just wrote) aren't always released the instant wait() returns. A real caller would
    simply retry at its own next start, which never consumes one of run_queued()'s own retries —
    fix() raising means nothing was written to the entry — so this does the same.
    """
    for attempt in range(attempts):
        try:
            return forget.run_queued(target, queue_dir=queue_dir)
        except FixError as e:
            if "open in another process" not in str(e) or attempt == attempts - 1:
                raise
            time.sleep(delay)


def _park(qdir, target, subject, days_ago: float, attempts=forget.MAX_ATTEMPTS):
    """Write a parked (.failed) entry directly, as run_queued() would have left it. Returns its path."""
    key = forget._queue_key(forget._queue_dir(qdir))
    when = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat(timespec="seconds")
    entry = forget._queue_dir(qdir) / f"{uuid.uuid4().hex}.failed"
    entry.write_text(json.dumps({
        "target": forget._label(target), "subject": key.encrypt(subject.encode()).decode(),
        "queued_at": when, "parked_at": when, "attempts": attempts,
    }))
    return entry


def test_forget_erases_the_subject_immediately_on_sqlite(tmp_path):
    db = tmp_path / "a.db"
    deleted = make_sqlite(db)
    gone = email(deleted[0])
    rec = forget.forget(db, gone, queue_dir=tmp_path / "queue")
    assert rec["verdict"] == "CLEAN"
    assert gone not in db.read_bytes().decode(errors="ignore")
    assert forget.pending(db, queue_dir=tmp_path / "queue") == 0


@pytest.mark.fix
def test_forget_queues_when_chroma_is_open_elsewhere(tmp_path):
    path = tmp_path / "s"
    deleted = make_chroma(path, 300)
    gone = email(deleted[1])
    qdir = tmp_path / "queue"
    holder = subprocess.Popen([sys.executable, "-c", (
        "import chromadb, sys, time\n"
        f"c = chromadb.PersistentClient(path={str(path)!r}).get_collection('mem')\n"
        "c.count(); print('ready', flush=True); time.sleep(60)\n"
    )], stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "ready"
        result = forget.forget(path, gone, queue_dir=qdir)
        assert isinstance(result, forget.Queued)
        assert result.target == str(path.resolve())
        assert forget.pending(path, queue_dir=qdir) == 1

        # The queue entry on disk never holds the plaintext subject.
        entries = list(qdir.glob("*.json"))
        assert len(entries) == 1
        assert gone not in entries[0].read_text()
        assert json.loads(entries[0].read_text())["subject"] != gone
    finally:
        holder.kill()
        holder.wait()

    # Once nothing has the store open, run_queued finishes it and leaves no entry behind.
    receipts = _run_queued_retrying(path, queue_dir=qdir)
    assert len(receipts) == 1 and receipts[0]["verdict"] == "CLEAN"
    assert forget.pending(path, queue_dir=qdir) == 0
    assert not any(gone.encode() in p.read_bytes() for p in path.rglob("*") if p.is_file())


@pytest.mark.fix
def test_run_queued_keeps_retrying_a_subject_that_is_still_genuinely_live(tmp_path):
    """The subject can legitimately still be found after fix(): the same value can be part of
    another, unrelated live record that must not be erased. run_queued() must not delete the
    entry or report CLEAN in that case — and must not retry it forever either."""
    path = tmp_path / "s"
    make_chroma(path, 300)
    live_value = email(1)  # id 1 is never deleted by make_chroma (only every 3rd id is)
    qdir = tmp_path / "queue"
    holder = subprocess.Popen([sys.executable, "-c", (
        "import chromadb, sys, time\n"
        f"c = chromadb.PersistentClient(path={str(path)!r}).get_collection('mem')\n"
        "c.count(); print('ready', flush=True); time.sleep(60)\n"
    )], stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "ready"
        assert isinstance(forget.forget(path, live_value, queue_dir=qdir), forget.Queued)
    finally:
        holder.kill()
        holder.wait()

    for attempt in range(1, forget.MAX_ATTEMPTS + 1):
        receipts = _run_queued_retrying(path, queue_dir=qdir)
        assert len(receipts) == 1 and receipts[0]["verdict"] == "RESIDUE_REMAINS"
        if attempt < forget.MAX_ATTEMPTS:
            assert forget.pending(path, queue_dir=qdir) == 1  # still retried automatically
            assert forget.stale_entries(path, queue_dir=qdir) == 0
        else:
            assert forget.pending(path, queue_dir=qdir) == 0  # parked: no longer auto-retried
            assert forget.stale_entries(path, queue_dir=qdir) == 1

    # Parked, not lost or silently reprocessed: one more drain changes nothing.
    assert forget.run_queued(path, queue_dir=qdir) == []
    assert forget.stale_entries(path, queue_dir=qdir) == 1
    # And the record forget() was asked to protect is, correctly, still there.
    assert any(live_value.encode() in p.read_bytes() for p in path.rglob("*") if p.is_file())


def test_purge_stale_respects_age_and_target(tmp_path):
    db_a, db_b = tmp_path / "a.db", tmp_path / "b.db"
    qdir = tmp_path / "queue"
    old_a = _park(qdir, db_a, email(1), days_ago=forget.PARK_RETENTION_DAYS + 1)
    recent_a = _park(qdir, db_a, email(2), days_ago=1)
    old_b = _park(qdir, db_b, email(3), days_ago=forget.PARK_RETENTION_DAYS + 1)

    # Filtered by target: only db_a's old entry goes; db_a's recent one and db_b's are untouched.
    assert forget.purge_stale(db_a, queue_dir=qdir) == 1
    assert not old_a.exists() and recent_a.exists() and old_b.exists()

    # Unfiltered (no target): every old entry across every store goes.
    assert forget.purge_stale(queue_dir=qdir) == 1
    assert not old_b.exists() and recent_a.exists()
    assert forget.stale_entries(db_a, queue_dir=qdir) == 1  # the recent one is still parked, just not purged


@pytest.mark.fix
def test_run_queued_auto_purges_old_parked_entries(tmp_path):
    path = tmp_path / "s"
    qdir = tmp_path / "queue"
    _park(qdir, path, email(1), days_ago=forget.PARK_RETENTION_DAYS + 1)
    assert forget.stale_entries(path, queue_dir=qdir) == 1

    # Nothing active to drain, but the old parked entry is purged as part of the same call —
    # a parked entry is never kept forever just because nobody called purge_stale() explicitly.
    assert forget.run_queued(path, queue_dir=qdir) == []
    assert forget.stale_entries(path, queue_dir=qdir) == 0


def test_cli_purge_stale(tmp_path):
    path = tmp_path / "s"
    qdir = tmp_path / "queue"
    _park(qdir, path, email(1), days_ago=forget.PARK_RETENTION_DAYS + 1)
    _park(qdir, path, email(2), days_ago=1)
    assert main(["purge-stale", str(path), "--queue-dir", str(qdir)]) == 0
    assert forget.stale_entries(path, queue_dir=qdir) == 1  # the recent one survives the default retention


def test_run_queued_only_drains_entries_for_its_own_target(tmp_path):
    db_a, db_b = tmp_path / "a.db", tmp_path / "b.db"
    deleted_a = make_sqlite(db_a)
    make_sqlite(db_b)
    qdir = tmp_path / "queue"
    qdir.mkdir()
    key = forget._queue_key(qdir)
    entry = qdir / "fake.json"
    entry.write_text(json.dumps({
        "target": str(db_b.resolve()),
        "subject": key.encrypt(email(0).encode()).decode(),
        "queued_at": "2026-01-01T00:00:00+00:00",
    }))
    # Nothing was actually queued for db_a (a real forget() never queues on SQLite), so this is a no-op.
    assert forget.run_queued(db_a, queue_dir=qdir) == []
    assert entry.exists()
    assert forget.pending(db_b, queue_dir=qdir) == 1
    deleted_a  # unused; keeps make_sqlite's return visible for readability


@pytest.mark.fix
def test_cli_run_queued_reports_residue_rather_than_claiming_success(tmp_path, capsys):
    path = tmp_path / "s"
    make_chroma(path, 300)
    live_value = email(1)
    holder = subprocess.Popen([sys.executable, "-c", (
        "import chromadb, sys, time\n"
        f"c = chromadb.PersistentClient(path={str(path)!r}).get_collection('mem')\n"
        "c.count(); print('ready', flush=True); time.sleep(60)\n"
    )], stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "ready"
        forget.forget(path, live_value)  # queues to the default dir (isolated via FORGETPROOF_HOME)
    finally:
        holder.kill()
        holder.wait()

    out_dir = tmp_path / "receipts"
    for attempt in range(10):
        exit_code = main(["run-queued", str(path), "--receipts-dir", str(out_dir)])
        out, err = capsys.readouterr()
        if exit_code == 2 and "open in another process" in err and attempt < 9:
            time.sleep(1)  # same transient lock _run_queued_retrying works around
            continue
        break
    assert exit_code == 1  # EXIT_RESIDUE, not 0 — nothing here claims the erasure finished
    assert "RESIDUE_REMAINS" in out
    assert any(json.loads(p.read_text())["verdict"] == "RESIDUE_REMAINS" for p in out_dir.glob("*.json"))


def test_cli_forget_and_run_queued(tmp_path):
    db = tmp_path / "a.db"
    deleted = make_sqlite(db)
    gone = email(deleted[0])
    rec = tmp_path / "r.json"
    assert main(["forget", str(db), "--subject", gone, "--receipt", str(rec)]) == 0
    assert json.loads(rec.read_text())["verdict"] == "CLEAN"

    out_dir = tmp_path / "out"
    assert main(["run-queued", str(db), "--receipts-dir", str(out_dir)]) == 0  # nothing queued
    assert not list(out_dir.glob("*.json"))
