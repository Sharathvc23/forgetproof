"""Pre-flight checks that keep `fix` from damaging a store it can't safely rewrite."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


_SQLITE_NAMES = (".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".sqlite3-journal")


def store_files(target: Path) -> list[Path]:
    """Every file belonging to the store: the directory's files, or a SQLite file and its sidecars."""
    if target.is_dir():
        return sorted(p for p in target.rglob("*") if p.is_file())
    sidecars = (target.with_name(target.name + s) for s in ("-wal", "-shm", "-journal"))
    return [target, *(p for p in sidecars if p.exists())]


def _proc_holders(target: Path) -> list[str]:
    """Linux: processes with a store file open or mapped (only those this user can inspect)."""
    wanted = {str(p) for p in store_files(target)}
    prefix = str(target) + os.sep if target.is_dir() else None
    me = str(os.getpid())

    def ours(path: str, pid: str) -> bool:
        path = path.removesuffix(" (deleted)")
        if pid == me and path.endswith(_SQLITE_NAMES):
            # A chromadb client in this process keeps its SQLite pool open for the life of the process,
            # which is harmless while idle. Its index files are what it can flush over our changes.
            return False
        return path in wanted or (prefix is not None and path.startswith(prefix))

    holders = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            hit = any(ours(os.readlink(fd), proc.name) for fd in (proc / "fd").iterdir())
            if not hit:
                hit = any(ours(parts[5].strip(), proc.name) for line in (proc / "maps").read_text().splitlines()
                          if len(parts := line.split(maxsplit=5)) == 6)
        except OSError:
            continue  # exited, or another user's process
        if hit:
            if proc.name == me:
                holders.append("this process (close your Chroma client first, or run the forgetproof CLI)")
                continue
            try:
                name = (proc / "comm").read_text().strip()
            except OSError:
                name = "?"
            holders.append(f"pid {proc.name} ({name})")
    return holders


def _lsof_holders(target: Path) -> list[str]:
    """macOS and other Unixes: ask lsof."""
    if not shutil.which("lsof"):
        return []
    args = ["lsof", "-F", "pc", "+D", str(target)] if target.is_dir() else ["lsof", "-F", "pc", "--", *map(str, store_files(target))]
    out = subprocess.run(args, capture_output=True, text=True).stdout
    holders, pid = [], None
    for line in out.splitlines():
        if line.startswith("p"):
            pid = line[1:]
        elif line.startswith("c") and pid and int(pid) != os.getpid():
            holders.append(f"pid {pid} ({line[1:]})")
    return sorted(set(holders))


def _windows_holders(target: Path) -> list[str]:
    """Windows refuses to rename a file another process has open."""
    busy = []
    for p in store_files(target):
        probe = p.with_name(p.name + ".forgetproof-probe")
        try:
            p.rename(probe)
        except PermissionError:
            busy.append(f"a process holding {p.name}")
            continue
        probe.rename(p)
    return busy


def open_by_other_processes(target: Path) -> list[str]:
    """Best effort: describe processes that have the store open. Empty when none are found."""
    if sys.platform.startswith("linux") and Path("/proc/self/fd").exists():
        return _proc_holders(target)
    if sys.platform == "win32":
        return _windows_holders(target)
    return _lsof_holders(target)


def space_needed(target: Path) -> int:
    """Rebuilding copies the data once and VACUUM writes a second copy of the SQLite file."""
    total = sum(p.stat().st_size for p in store_files(target))
    return 2 * total + (64 << 20)


def free_space(target: Path) -> int:
    return shutil.disk_usage(target if target.is_dir() else target.parent).free
