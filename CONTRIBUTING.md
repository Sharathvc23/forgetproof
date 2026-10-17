# Contributing

```bash
uv sync
uv run pytest
```

Tests build real Chroma, Postgres and SQLite stores. Postgres tests start a throwaway server with
`pgserver` (Python ≤ 3.12), or use `FORGETPROOF_TEST_PG_URL` (a superuser URL) if set. The full suite
takes about three minutes.

**Adding a store.** A scanner reports `Finding`s (see `report.py`); a fixer must leave every live record
byte-identical, survive being killed at any step, and never keep a copy of what it erased. Every new
check needs a test that builds a store with real residue, a test that a clean store stays clean, and a
`fix` test that verifies on the raw bytes, not by rescanning.

**Never commit real personal data**, including in test fixtures. Use `example.com` addresses and
`555` phone numbers.
