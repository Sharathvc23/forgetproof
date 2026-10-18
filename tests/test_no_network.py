"""forgetproof never phones home — it only ever talks to the database it was told to check.
This is a cheap, static guard against that silently changing: it doesn't prove no HTTP request
is ever made (Chroma's and Postgres's own client libraries are out of scope), but it does prove
forgetproof's own code never imports anything that could make one.
"""

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "forgetproof"
# Modules whose own purpose is a network call to something *other than* the store being checked.
# requests/httpx/aiohttp etc. aren't here because nothing in this package ever imports them.
_FORBIDDEN = {"urllib.request", "http.client", "ftplib", "smtplib", "telnetlib"}


def _imports_in(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(n.name for n in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_no_module_imports_a_generic_network_client():
    offenders = {}
    for path in SRC.rglob("*.py"):
        hit = _imports_in(path) & _FORBIDDEN
        if hit:
            offenders[path.name] = hit
    assert not offenders
