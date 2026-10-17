import json
import sqlite3
import subprocess
import sys
import textwrap
from importlib.metadata import PackageNotFoundError, version

import pytest

try:
    CHROMA_VERSION = version("chromadb")
except PackageNotFoundError:
    pytest.skip("chromadb is not installed", allow_module_level=True)

CHROMA_0 = int(CHROMA_VERSION.split(".")[0]) < 1
# Chroma 0.x writes through Python's sqlite3, and some SQLite builds (e.g. Debian's) overwrite deleted rows.
CHROMA_SECURE_DELETE = CHROMA_0 and sqlite3.connect(":memory:").execute("pragma secure_delete").fetchone()[0] == 1


def pytest_configure(config):
    config.addinivalue_line("markers", "fix: runs `fix`, which needs chromadb 1.0 or later")


def pytest_collection_modifyitems(config, items):
    if CHROMA_0:
        skip = pytest.mark.skip(reason="fix needs chromadb >= 1.0; scanning is still tested")
        for item in items:
            if "fix" in item.keywords:
                item.add_marker(skip)


@pytest.fixture(autouse=True, scope="session")
def no_chroma_in_test_process():
    """Chroma keeps a store's state in memory for the life of the process that opened it and can
    write it back later, racing with fix. Every Chroma call in tests goes through chroma()."""
    yield
    assert "chromadb" not in sys.modules, "a test or forgetproof itself imported chromadb in the test process"


@pytest.fixture(autouse=True)
def isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGETPROOF_HOME", str(tmp_path / "fphome"))


def email(i):
    return f"person{i}@example.com"


_PREAMBLE = """
import json, sys
import chromadb

def plain(x):
    if hasattr(x, "tolist"):
        return x.tolist()
    if isinstance(x, dict):
        return {k: plain(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [plain(v) for v in x]
    return x

client = chromadb.PersistentClient(path=sys.argv[1])
params = json.loads(sys.argv[2])
result = None
"""


def chroma(path, code: str, **params):
    """Run Chroma code in a fresh process, as the app that owns a store would, and return `result`.

    The test process never opens a store with chromadb itself: Chroma keeps a store's state in
    memory for the life of the process and can write it back to disk later, which races with `fix`.
    The code sees `client`, `params` and `plain()`, and sets `result` (anything JSON-serialisable)."""
    script = _PREAMBLE + textwrap.dedent(code) + "\nprint('\\n@@result@@' + json.dumps(plain(result)))\n"
    p = subprocess.run([sys.executable, "-c", script, str(path), json.dumps(params)], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"chroma helper failed:\n{p.stderr[-3000:]}")
    return json.loads(p.stdout.rsplit("@@result@@", 1)[1])


def make_chroma(path, n, delete_every=3, after=0, dim=16, seed=1):
    """A Chroma store with n personal notes, every `delete_every`-th deleted, then `after` more adds."""
    chroma(path, """
        import random
        rng = random.Random(params["seed"])
        n, after, dim = params["n"], params["after"], params["dim"]
        col = client.create_collection("mem", embedding_function=None)
        for start in range(0, n, 500):
            ids = range(start, min(n, start + 500))
            col.add(ids=[f"m{i}" for i in ids],
                    documents=[f"note {i}: email person{i}@example.com phone 415-555-{i % 10000:04d}" for i in ids],
                    embeddings=[[rng.random() for _ in range(dim)] for _ in ids])
        col.delete(ids=[f"m{i}" for i in range(0, n, params["delete_every"])])
        for start in range(n, n + after, 500):
            ids = range(start, min(n + after, start + 500))
            col.add(ids=[f"m{i}" for i in ids], documents=[f"plain note {i}" for i in ids],
                    embeddings=[[rng.random() for _ in range(dim)] for _ in ids])
    """, n=n, delete_every=delete_every, after=after, dim=dim, seed=seed)
    return list(range(0, n, delete_every))


def live(path, name="mem"):
    """A collection's live records as sorted (id, document, metadata, embedding) rows, read in a fresh process."""
    g = chroma(path, """
        result = client.get_collection(params["name"], embedding_function=None).get(
            include=["embeddings", "documents", "metadatas"])
    """, name=name)
    return sorted(zip(g["ids"], g["documents"], map(json.dumps, g["metadatas"]), map(tuple, g["embeddings"])))


def make_sqlite(path, n=50, secure_delete=False):
    conn = sqlite3.connect(path)
    # Most SQLite builds default this off; some distributions (e.g. Debian's) turn it on.
    conn.execute(f"pragma secure_delete={'on' if secure_delete else 'off'}")
    conn.execute("create table memories (id integer primary key, user text, note text)")
    conn.executemany("insert into memories values (?, ?, ?)",
                     [(i, f"u{i}", f"remember {email(i)} and 415-555-{i:04d}") for i in range(n)])
    conn.commit()
    conn.execute("delete from memories where id % 2 = 0")
    conn.commit()
    conn.close()
    return list(range(0, n, 2))
