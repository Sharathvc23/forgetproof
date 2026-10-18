# Changelog

## 0.1.0 — unreleased

Initial release.

- `scan`: Chroma 0.6/1.x, Postgres/pgvector, SQLite. Text, JSON and Markdown output.
- `fix`: Chroma collection rebuild with journaled swap, orphaned index removal, zeroing of unused index
  memory, `VACUUM` with `secure_delete`; Postgres `VACUUM FULL` and WAL switch. `--dry-run`.
- Ed25519-signed receipts; `verify`, `key`.
- MCP server (`forgetproof mcp`, `[mcp]` extra): scan, plan, fix (opt-in) and verify for named stores.
  Subject-scoped `check_if_forgotten` / `forget_me`, gated on `--subject-file`, so the agent itself can
  never name a value to look up or erase. No tool exposes a value-matching parameter to the agent.
- `forget()` / `forgetproof forget` / `forgetproof run-queued`: erase one subject's data immediately,
  or queue it (encrypted at rest) when the store can't be rewritten yet, to finish at the
  application's next start before it reopens the store. A queued entry is kept and retried, not
  dropped, if a drain comes back showing residue; after a few attempts it's parked, and purged
  automatically after 30 days (`forgetproof purge-stale` sooner) rather than kept indefinitely.
- `forgetproof init`: finds likely Chroma, SQLite and Postgres stores under a directory, asks once,
  and pins them by name to `.forgetproof.json`. Every command that takes a store accepts a pinned
  name in place of a path or URL, found by walking up from the current directory. A Postgres entry
  records only an environment variable's name, never its URL. Resolving a pinned entry refuses it
  if what's there no longer matches what was pinned.
- The Ed25519 signing key and the queue's encryption key can be kept in the OS keychain instead of a
  file, with `pip install 'forgetproof[keyring]'` and `FORGETPROOF_USE_KEYRING=1` (opt-in; an
  existing file key is never migrated automatically).
- Composite GitHub Action.
