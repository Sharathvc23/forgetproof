# Changelog

## 0.1.0 — unreleased

Initial release.

- `scan`: Chroma 0.6/1.x, Postgres/pgvector, SQLite. Text, JSON and Markdown output.
- `fix`: Chroma collection rebuild with journaled swap, orphaned index removal, zeroing of unused index
  memory, `VACUUM` with `secure_delete`; Postgres `VACUUM FULL` and WAL switch. `--dry-run`.
- Ed25519-signed receipts; `verify`, `key`.
- MCP server (`forgetproof mcp`, `[mcp]` extra): scan, plan, fix (opt-in) and verify for named stores.
- Composite GitHub Action.
