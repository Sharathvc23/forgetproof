"""forget(): erase one subject's data now, or queue it when the store can't be rewritten yet.

Postgres and SQLite can be fixed while the application is running: `fix` takes its own locks.
Chroma cannot — it must not be rewritten while the application still has it open. `forget()`
queues the request instead of failing, encrypted at rest under a local key. Call `run_queued()`
before the application reopens the store (its own next start is the natural point) to finish it.

A queued entry holds nothing but an encrypted subject value and the store it is for. It is
deleted the moment it is drained, so the queue is never a durable list of who asked to be forgotten.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet

from . import postgres, receipt
from .fixer import FixError, Options, fix


@dataclass(frozen=True)
class Queued:
    target: str
    queued_at: str


def _label(target: Path | str) -> str:
    return postgres.display(target) if postgres.is_postgres(target) else str(Path(target).resolve())


def _queue_dir(queue_dir: Path | str | None = None) -> Path:
    d = Path(queue_dir) if queue_dir else receipt.key_path().parent / "queue"
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass  # best-effort on platforms without POSIX permissions (e.g. some Windows filesystems)
    return d


def _queue_key(queue_dir: Path) -> Fernet:
    path = queue_dir / "queue.key"
    if not path.exists():
        path.write_bytes(Fernet.generate_key())
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return Fernet(path.read_bytes())


def _issue(target: Path | str, result) -> dict:
    before, after = result.before.summary(), result.after.summary()
    canaries = [{"canary": c.number, "found_in": c.found_in} for c in result.after.canaries]
    return receipt.issue(target, before, after, result.actions, canaries, label=_label(target))


def forget(target: Path | str, subject: str, *, options: Options | None = None,
           queue_dir: Path | str | None = None) -> dict | Queued:
    """Erase `subject`'s data from `target` and return a signed receipt.

    If the store can't be rewritten right now (Chroma, with the application still holding it
    open), the request is queued instead and a `Queued` marker is returned. Call `run_queued`
    for this target before the application next opens the store to finish it.
    """
    try:
        result = fix(target, [subject], options or Options())
    except FixError as e:
        if "open in another process" not in str(e):
            raise
        qd = _queue_dir(queue_dir)
        token = _queue_key(qd).encrypt(subject.encode())
        queued_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        entry = qd / f"{uuid.uuid4().hex}.json"
        entry.write_text(json.dumps({"target": _label(target), "subject": token.decode(), "queued_at": queued_at}))
        try:
            entry.chmod(0o600)
        except OSError:
            pass
        return Queued(_label(target), queued_at)
    return _issue(target, result)


def pending(target: Path | str, *, queue_dir: Path | str | None = None) -> int:
    """How many forget() calls are queued for this target."""
    qd = _queue_dir(queue_dir)
    label = _label(target)
    return sum(1 for e in qd.glob("*.json") if json.loads(e.read_text()).get("target") == label)


def run_queued(target: Path | str, *, options: Options | None = None,
               queue_dir: Path | str | None = None) -> list[dict]:
    """Finish every forget() queued for `target`. Call this before the application reopens
    a Chroma store, so nothing else has it open while the queued erasures run.

    Each receipt is issued as its entry is drained; an entry is removed only after its
    receipt is written, so a crash midway leaves it to retry on the next call.
    """
    qd = _queue_dir(queue_dir)
    key = _queue_key(qd)
    label = _label(target)
    receipts = []
    for entry in sorted(qd.glob("*.json")):
        data = json.loads(entry.read_text())
        if data.get("target") != label:
            continue
        subject = key.decrypt(data["subject"].encode()).decode()
        result = fix(target, [subject], options or Options())
        receipts.append(_issue(target, result))
        entry.unlink()
    return receipts
