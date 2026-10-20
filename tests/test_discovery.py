import json
import os

import pytest
from conftest import make_sqlite

from forgetproof import discovery
from forgetproof.cli import main


def test_discover_finds_chroma_sqlite_and_env_postgres(tmp_path, monkeypatch):
    chroma_dir = tmp_path / "agent_memory"
    chroma_dir.mkdir()
    (chroma_dir / "chroma.sqlite3").write_bytes(b"not a real chroma store, just the marker file")
    (chroma_dir / "some_segment_dir").mkdir()
    (chroma_dir / "some_segment_dir" / "data_level0.bin").write_bytes(b"x")

    make_sqlite(tmp_path / "chatlog.db")
    (tmp_path / "notes.txt").write_text("not a store")  # wrong suffix: ignored
    (tmp_path / "fake.db").write_bytes(b"not actually sqlite")  # right suffix, wrong contents: ignored

    monkeypatch.setenv("DATABASE_URL", "postgresql://app:secret@db.internal:5432/agent")
    found = {f.name: f for f in discovery.discover(tmp_path)}

    assert found["agent_memory"].kind == "chroma" and found["agent_memory"].where == str(chroma_dir)
    assert found["chatlog"].kind == "sqlite"
    assert found["database_url"] == discovery.Found("database_url", "postgres", "DATABASE_URL")
    assert "notes" not in found and "fake" not in found
    # The password is never written to disk via discover()/Found — only the env var's name is kept.
    assert "secret" not in json.dumps([f.__dict__ for f in found.values()])


def test_discover_does_not_descend_into_a_chroma_store_or_follow_symlinks(tmp_path):
    chroma_dir = tmp_path / "mem"
    chroma_dir.mkdir()
    (chroma_dir / "chroma.sqlite3").write_bytes(b"marker")
    seg = chroma_dir / "seg"
    seg.mkdir()
    make_sqlite(seg / "decoy.db")  # a real sqlite file inside the store's own internals

    outside = make_sqlite(tmp_path / "outside.db")
    try:
        (tmp_path / "link_to_outside").symlink_to(tmp_path / "outside.db")
        has_symlinks = True
    except OSError:
        has_symlinks = False  # e.g. no symlink privilege on this Windows runner

    names = {f.name for f in discovery.discover(tmp_path)}
    assert names == {"mem", "outside"}  # the chroma dir's internals and any symlink are excluded
    outside  # unused; keeps make_sqlite's return visible for readability
    assert not has_symlinks or "link_to_outside" not in names


def test_discover_skips_vendored_and_vcs_directories(tmp_path):
    for skip in (".git", ".venv", "node_modules"):
        d = tmp_path / skip
        d.mkdir()
        make_sqlite(d / "irrelevant.db")
    make_sqlite(tmp_path / "real.db")
    assert {f.name for f in discovery.discover(tmp_path)} == {"real"}


def test_write_find_and_load_config_round_trip(tmp_path):
    db = tmp_path / "a.db"
    make_sqlite(db)
    found = [discovery.Found("chat", "sqlite", str(db))]
    path = discovery.write_config(tmp_path, found)
    assert path == tmp_path / discovery.CONFIG_NAME
    assert oct(path.stat().st_mode)[-3:] in ("600", "644", "666")  # best-effort; never asserted stricter on CI

    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    assert discovery.find_config(sub) == path
    assert discovery.find_config(tmp_path.parent, max_up=0) is None  # too far to climb

    loaded = discovery.load_config(path)
    assert loaded == {"chat": discovery.Found("chat", "sqlite", str(db))}
    assert discovery.resolve(loaded["chat"]) == db


def test_resolve_refuses_a_store_whose_kind_changed(tmp_path):
    chroma_dir = tmp_path / "mem"
    chroma_dir.mkdir()
    (chroma_dir / "chroma.sqlite3").write_bytes(b"marker")
    pinned = discovery.Found("mem", "chroma", str(chroma_dir))
    assert discovery.resolve(pinned) == chroma_dir

    (chroma_dir / "chroma.sqlite3").unlink()  # no longer looks like a Chroma store
    with pytest.raises(ValueError, match="no longer looks like one"):
        discovery.resolve(pinned)


def test_resolve_refuses_a_postgres_store_whose_env_var_is_gone(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="DATABASE_URL"):
        discovery.resolve(discovery.Found("db", "postgres", "DATABASE_URL"))


def test_cli_init_asks_before_writing_anything(tmp_path, monkeypatch, capsys):
    make_sqlite(tmp_path / "a.db")
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    assert main(["init", str(tmp_path)]) == 2  # EXIT_ERROR: declined
    assert not discovery.config_path(tmp_path).exists()
    assert "a" in capsys.readouterr().out  # it was shown before being asked about


def test_cli_init_yes_writes_and_resolves_by_bare_name(tmp_path, monkeypatch):
    db = tmp_path / "a.db"
    make_sqlite(db)
    assert main(["init", str(tmp_path), "--yes"]) == 0
    assert discovery.config_path(tmp_path).is_file()

    monkeypatch.chdir(tmp_path)
    assert main(["scan", "a"]) == 1  # resolved "a" to the pinned sqlite file; it has residue
    assert main(["scan", "no-such-store"]) == 2  # not pinned, not an existing path either


def test_cli_init_resolves_from_a_subdirectory_like_git_finds_dot_git(tmp_path, monkeypatch):
    make_sqlite(tmp_path / "a.db")
    assert main(["init", str(tmp_path), "--yes"]) == 0
    sub = tmp_path / "nested" / "deeper"
    sub.mkdir(parents=True)
    monkeypatch.chdir(sub)
    assert main(["scan", "a"]) == 1


def test_cli_init_reports_nothing_found_without_asking(tmp_path, monkeypatch):
    asked = []
    monkeypatch.setattr("builtins.input", lambda *_: asked.append(1) or "y")
    assert main(["init", str(tmp_path)]) == 0
    assert not asked
    assert not discovery.config_path(tmp_path).exists()


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="the writability check is POSIX-only, documented in discovery.py")
def test_find_config_rejects_a_world_writable_config_file(tmp_path):
    path = discovery.write_config(tmp_path, [])
    path.chmod(0o666)
    assert discovery.find_config(tmp_path) is None


def test_find_config_rejects_a_symlinked_config_file(tmp_path):
    real = tmp_path / "elsewhere.json"
    real.write_text('{"stores": {}}')
    link = tmp_path / discovery.CONFIG_NAME
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("no symlink privilege on this runner")
    assert discovery.find_config(tmp_path) is None


def test_find_config_stops_at_the_first_ancestor_it_does_not_own(tmp_path, monkeypatch):
    """Simulates a shared, world-writable ancestor (a bare /tmp, say): nothing above a
    directory nobody here owns should be treated as this user's own project."""
    outer = tmp_path  # stands in for a directory this user does NOT own
    inner = tmp_path / "mine"
    inner.mkdir()
    discovery.write_config(outer, [])  # planted by "someone else" one level up

    real_owned = discovery._owned_by_me
    monkeypatch.setattr(discovery, "_owned_by_me", lambda p: real_owned(p) and p != outer)
    assert discovery.find_config(inner) is None  # climbing stopped before reaching outer's config

    # A trustworthy config one level further down, inside the user's own territory, still works.
    discovery.write_config(inner, [])
    assert discovery.find_config(inner) == discovery.config_path(inner)


def test_resolve_rejects_a_path_outside_the_configs_own_directory(tmp_path):
    inside = tmp_path / "project"
    inside.mkdir()
    outside = tmp_path / "elsewhere.db"
    make_sqlite(outside)
    pinned = discovery.Found("escape", "sqlite", str(outside))
    with pytest.raises(ValueError, match="outside"):
        discovery.resolve(pinned, root=inside)
    assert discovery.resolve(pinned, root=tmp_path) == outside  # inside this wider root: fine


def test_resolve_rejects_a_postgres_entry_naming_an_unrecognized_env_var(monkeypatch):
    monkeypatch.setenv("SOME_OTHER_SECRET", "postgresql://app@db/agent")
    with pytest.raises(ValueError, match="recognized environment variable"):
        discovery.resolve(discovery.Found("db", "postgres", "SOME_OTHER_SECRET"))


def test_cli_scan_by_bare_name_ignores_an_unowned_ancestors_config(tmp_path, monkeypatch):
    sub = tmp_path / "sub"
    sub.mkdir()
    victim_db = sub / "a.db"
    make_sqlite(victim_db)
    attacker_db = tmp_path / "attacker.db"
    make_sqlite(attacker_db)
    discovery.write_config(tmp_path, [discovery.Found("a", "sqlite", str(attacker_db))])

    real_owned = discovery._owned_by_me
    monkeypatch.setattr(discovery, "_owned_by_me", lambda p: real_owned(p) and p != tmp_path)
    monkeypatch.chdir(sub)
    assert main(["scan", "a"]) == 2  # not resolved against the untrusted ancestor's config at all


def test_cli_mcp_config_rejects_an_entry_pointing_outside_its_own_directory(tmp_path, capsys):
    pytest.importorskip("mcp")
    inside = tmp_path / "project"
    inside.mkdir()
    outside_db = tmp_path / "outside.db"
    make_sqlite(outside_db)
    config = discovery.write_config(inside, [discovery.Found("escape", "sqlite", str(outside_db))])
    assert main(["mcp", "--config", str(config)]) == 2
    assert "outside" in capsys.readouterr().err
