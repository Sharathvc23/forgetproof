"""forgetproof init: find likely memory stores under a directory, confirm once, and pin them.

The point of pinning is that the *operator* decides what forgetproof may ever touch, not
whatever an automated scan happens to find lying around a directory tree later on — init only
proposes; it writes nothing without one confirmation. Once pinned, every command that resolves a
store by its name refuses it outright if what's actually there no longer matches what was pinned
(a file where a directory used to be, and the reverse), rather than silently acting on it.

A pinned Postgres store records the *name* of an environment variable, never the URL itself, so
a config file on disk never holds a password and a rotated credential needs no re-pinning.

Finding a config by walking up from the current directory, the way `init` makes that convenient,
means the directory it's found in isn't necessarily one `init` was ever run in on purpose — a
shared, world-writable directory (a bare `/tmp`, say) could hold one planted by someone else
entirely. find_config() only ever considers a candidate this user owns, isn't a symlink, and isn't
writable by anyone else, and stops climbing the moment an ancestor directory itself isn't owned by
this user — a directory nobody here owns is exactly where another user could have planted one.
resolve() narrows what a trusted config can still do: a path-kind entry must resolve inside the
directory the config file came from, and a postgres entry must name one of ENV_URL_VARS.

The ownership and writability checks are POSIX-only (Python's stat() can't see a real owner or
ACL on Windows); on Windows, every directory is treated as this user's own, same as before this
module existed. The containment and allowlist checks in resolve() hold on every platform.
"""

from __future__ import annotations

import json
import os
import stat
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


def _owned_by_me(path: Path) -> bool:
    if not hasattr(os, "getuid"):
        return True  # no POSIX ownership model to check (Windows)
    try:
        return path.stat().st_uid == os.getuid()
    except OSError:
        return False


def _trustworthy_config(path: Path) -> bool:
    """Would `init` itself plausibly have written this: this user's own, a real file (not a
    symlink someone else could have swapped in), and not writable by anyone else."""
    if path.is_symlink() or not _owned_by_me(path):
        return False
    if not hasattr(os, "getuid"):
        return path.is_file()
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and not (mode & (stat.S_IWGRP | stat.S_IWOTH))


def find_config(start: Path, *, max_up: int = 10) -> Path | None:
    """Walk upward from `start` (like git finds .git) for a trustworthy CONFIG_NAME.

    Stops — rather than skipping past — the first ancestor this user doesn't own: nothing
    above a directory nobody here owns should be treated as this user's own project.
    """
    d = start.resolve()
    for _ in range(max_up):
        if not _owned_by_me(d):
            return None
        candidate = d / CONFIG_NAME
        if candidate.exists() and _trustworthy_config(candidate):
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


def resolve(found: Found, root: Path | None = None) -> Path | str:
    """What this pinned entry currently points to — refusing if its kind no longer matches, if a
    postgres entry names anything other than one of ENV_URL_VARS, or (when `root` is given — pass
    the directory the config file came from) if it points outside that directory tree. That last
    check matters even for a config this user does trust: nothing a pinned entry says should be
    able to send forgetproof to touch a path outside the project `init` was run in.
    """
    if found.kind == "postgres":
        if found.where not in ENV_URL_VARS:
            raise ValueError(f"store {found.name!r} names {found.where!r}, which isn't one of the "
                              f"recognised environment variables ({', '.join(ENV_URL_VARS)})")
        url = os.environ.get(found.where, "")
        if not url.startswith(("postgresql://", "postgres://")):
            raise ValueError(
                f"store {found.name!r} was pinned to the {found.where} environment variable, which "
                "doesn't currently hold a postgresql:// URL"
            )
        return url
    path = Path(found.where)
    if root is not None:
        try:
            path.resolve().relative_to(root.resolve())
        except ValueError:
            raise ValueError(f"store {found.name!r} points to {path}, which is outside {root}") from None
    if found.kind == "chroma" and not (path / "chroma.sqlite3").is_file():
        raise ValueError(f"store {found.name!r} was pinned to a Chroma directory at {path}, "
                          "which no longer looks like one")
    if found.kind == "sqlite" and not _looks_like_sqlite(path):
        raise ValueError(f"store {found.name!r} was pinned to a SQLite file at {path}, "
                          "which no longer looks like one")
    return path
