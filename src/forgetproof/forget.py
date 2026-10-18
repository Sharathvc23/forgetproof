"""forget(): erase one subject's data now, or queue it when the store can't be rewritten yet.

Postgres and SQLite can be fixed while the application is running: `fix` takes its own locks.
Chroma cannot — it must not be rewritten while the application still has it open. `forget()`
queues the request instead of failing, encrypted at rest under a local key. Call `run_queued()`
before the application reopens the store (its own next start is the natural point) to finish it.

A queued entry holds nothing but an encrypted subject value and the store it is for. It is
deleted once it drains *clean* — not merely once it's been tried. A subject can legitimately
still be found after `fix()`: the same value can appear in another, unrelated live record that
must not be erased. Retrying that forever won't help, so after a few attempts the entry is parked
(kept, but no longer retried automatically) instead of either looping forever or being silently
dropped as if it had succeeded.
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

MAX_ATTEMPTS = 3  # how many run_queued() calls retry an entry that isn't clean yet before parking it


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
    """How many forget() calls for this target will still be retried automatically.

    Doesn't count entries parked by run_queued() after MAX_ATTEMPTS — those need the operator's
    attention; stale_entries() reports them.
    """
    qd = _queue_dir(queue_dir)
    label = _label(target)
    return sum(1 for e in qd.glob("*.json") if json.loads(e.read_text()).get("target") == label)


def stale_entries(target: Path | str, *, queue_dir: Path | str | None = None) -> int:
    """How many forget() calls for this target were parked: tried MAX_ATTEMPTS times by
    run_queued() without becoming clean, so they're no longer retried automatically. Each
    attempt's receipt recorded why — a value that's still genuinely live elsewhere, most often."""
    qd = _queue_dir(queue_dir)
    label = _label(target)
    return sum(1 for e in qd.glob("*.failed") if json.loads(e.read_text()).get("target") == label)


def run_queued(target: Path | str, *, options: Options | None = None,
               queue_dir: Path | str | None = None) -> list[dict]:
    """Finish every forget() queued for `target`. Call this before the application reopens
    a Chroma store, so nothing else has it open while the queued erasures run.

    Each receipt is issued as its entry is drained. An entry is removed only once its receipt's
    verdict is CLEAN — never merely because it was attempted — so a crash midway, or a fix that
    didn't fully succeed, leaves it to retry rather than being silently treated as done. After
    MAX_ATTEMPTS without a clean result, an entry is parked (kept, but excluded from future
    automatic retries) instead of being retried forever; stale_entries() reports those.
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
        rec = _issue(target, result)
        receipts.append(rec)
        if rec["verdict"] == "CLEAN":
            entry.unlink()
            continue
        attempts = data.get("attempts", 0) + 1
        data["attempts"] = attempts
        if attempts >= MAX_ATTEMPTS:
            entry.rename(entry.with_suffix(".failed")).write_text(json.dumps(data))
        else:
            entry.write_text(json.dumps(data))
    return receipts
