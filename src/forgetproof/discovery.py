"""forgetproof init: find likely memory stores under a directory, confirm once, and pin them.

The point of pinning is that the *operator* decides what forgetproof may ever touch, not
whatever an automated scan happens to find lying around a directory tree later on — init only
proposes; it writes nothing without one confirmation. Once pinned, every command that resolves a
store by its name refuses it outright if what's actually there no longer matches what was pinned
(a file where a directory used to be, and the reverse), rather than silently acting on it.

A pinned Postgres store records the *name* of an environment variable, never the URL itself, so
a config file on disk never holds a password and a rotated credential needs no re-pinning.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

CONFIG_NAME = ".forgetproof.json"
ENV_URL_VARS = ("DATABASE_URL", "POSTGRES_URL", "PG_URL", "FORGETPROOF_PG_URL")
_SKIP_NAMES = {".git", ".hg", ".venv", "venv", "node_modules", "__pycache__", "site-packages", ".tox", ".mypy_cache"}
_SQLITE_SUFFIXES = (".db", ".sqlite", ".sqlite3")
_SQLITE_MAGIC = b"SQLite format 3\x00"


@dataclass(frozen=True)
class Found:
    name: str
    kind: str  # "chroma" | "sqlite" | "postgres"
    where: str  # a resolved path, or (for postgres) the name of an environment variable


def _looks_like_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(len(_SQLITE_MAGIC)) == _SQLITE_MAGIC
    except OSError:
        return False


def _unique(name: str, taken: set[str]) -> str:
    candidate, n = name, 2
    while candidate in taken:
        candidate, n = f"{name}-{n}", n + 1
    taken.add(candidate)
    return candidate


def discover(root: Path, *, max_depth: int = 4) -> list[Found]:
    """Chroma directories and SQLite files under `root`, plus any of ENV_URL_VARS that currently
    holds a postgresql:// URL. Doesn't follow symlinks, so a planted one can't widen the search."""
    root = root.resolve()
    found: list[Found] = []
    taken: set[str] = set()

    def walk(d: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            entries = sorted(d.iterdir())
        except OSError:
            return
        if (d / "chroma.sqlite3").is_file():
            found.append(Found(_unique(d.name, taken), "chroma", str(d)))
            return  # a store's own internals aren't a separate thing to find
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name in _SKIP_NAMES or entry.name.startswith("."):
                    continue
                walk(entry, depth + 1)
            elif entry.suffix in _SQLITE_SUFFIXES and _looks_like_sqlite(entry):
                found.append(Found(_unique(entry.stem, taken), "sqlite", str(entry)))

    walk(root, 0)
    for var in ENV_URL_VARS:
        url = os.environ.get(var, "")
        if url.startswith(("postgresql://", "postgres://")):
            found.append(Found(_unique(var.lower(), taken), "postgres", var))
    return found


def config_path(root: Path) -> Path:
    return root.resolve() / CONFIG_NAME


def find_config(start: Path, *, max_up: int = 10) -> Path | None:
    """Walk upward from `start` (like git finds .git) for a directory holding CONFIG_NAME."""
    d = start.resolve()
    for _ in range(max_up):
        candidate = d / CONFIG_NAME
        if candidate.is_file():
            return candidate
        if d.parent == d:
            break
        d = d.parent
    return None


def write_config(root: Path, chosen: list[Found]) -> Path:
    path = config_path(root)
    data = {"stores": {f.name: {"kind": f.kind, "where": f.where} for f in chosen}}
    path.write_text(json.dumps(data, indent=2) + "\n")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def load_config(path: Path) -> dict[str, Found]:
    data = json.loads(path.read_text())
    return {name: Found(name, v["kind"], v["where"]) for name, v in data.get("stores", {}).items()}


def resolve(found: Found) -> Path | str:
    """What this pinned entry currently points to — refusing if its kind no longer matches."""
    if found.kind == "postgres":
        url = os.environ.get(found.where, "")
        if not url.startswith(("postgresql://", "postgres://")):
            raise ValueError(
                f"store {found.name!r} was pinned to the {found.where} environment variable, which "
                "doesn't currently hold a postgresql:// URL"
            )
        return url
    path = Path(found.where)
    if found.kind == "chroma" and not (path / "chroma.sqlite3").is_file():
        raise ValueError(f"store {found.name!r} was pinned to a Chroma directory at {path}, "
                          "which no longer looks like one")
    if found.kind == "sqlite" and not _looks_like_sqlite(path):
        raise ValueError(f"store {found.name!r} was pinned to a SQLite file at {path}, "
                          "which no longer looks like one")
    return path
