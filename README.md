# forgetproof

Detects and erases deleted records that remain on disk in Chroma, Postgres/pgvector and SQLite stores.
Issues an Ed25519-signed receipt of the result.

Deletes in these stores are logical. The bytes persist in write logs, index tombstones, page free space
and unzeroed buffers until something rewrites them. `forgetproof` reads the store files directly, reports
what is recoverable, and rewrites the store so it isn't.

forgetproof comes out of stellarminds.ai's research on non-membership proofs and memory erasure for
AI agents.

## Install

```bash
pip install forgetproof              # scan Chroma and SQLite
pip install 'forgetproof[chroma]'    # + fix Chroma (chromadb >= 1.0)
pip install 'forgetproof[postgres]'  # + Postgres/pgvector
pip install 'forgetproof[mcp]'       # + MCP server for agents
```

Python 3.11+.

## Usage

```bash
forgetproof scan ./chroma_dir --canary user3@example.com
forgetproof fix  ./chroma_dir --dry-run
forgetproof fix  ./chroma_dir --canary user3@example.com   # writes a signed receipt
forgetproof verify forgetproof-receipt-*.json --against ./chroma_dir

PGPASSWORD=... forgetproof scan postgresql://app@db:5432/agent
```

`--canary` / `--canary-file` name exact values that must be gone. Output and receipts refer to canaries
by index only; values and hashes are never written. `--format json|markdown` for machine output.
Exit codes: `0` clean, `1` residue found or scan incomplete, `2` error.

## Checks

| Store | Check | Residue |
|---|---|---|
| Chroma | `chroma.write_log` | Deleted records (text + embedding) in `embeddings_queue` |
| Chroma | `chroma.write_log_overwritten` | Pre-`update`/`upsert` versions in `embeddings_queue` |
| Chroma | `chroma.hnsw_tombstones` | Deleted vectors still in `data_level0.bin` (delete only sets a flag) |
| Chroma | `chroma.orphaned_index` | Index directories left by `delete_collection()` |
| Chroma | `chroma.uninitialized_index_memory` | Unzeroed `malloc` memory persisted in unused index capacity, and in all of `length.bin` for `l2`/`ip` spaces |
| SQLite | `sqlite.slack` | Deleted rows in page slack and freelist pages |
| Postgres | `pg.table_residue` | Dead tuples in heap, TOAST and index files after `VACUUM` |
| Postgres | WAL (warning) | Canary values in WAL segments |

Content findings use pattern detectors (email, phone, US SSN, Luhn-valid card numbers, common API key
formats) and count only values not reachable through the store's API. Structural checks (write log,
tombstones, orphans) count records regardless of content.

Postgres scans read relation files via `pg_read_binary_file` after a `CHECKPOINT`, which requires
superuser or `pg_read_server_files`. Without it, the scan falls back to `n_dead_tup` and is reported as
incomplete, never clean.

## Fix

`--dry-run` prints the plan without changing anything.

**Chroma.** Preflight refuses to run if another process has the store open, if free disk is below
2× store size, or if the installed `chromadb` would migrate the store schema (override with
`--allow-upgrade`). Then:

1. Each collection is rebuilt from live records through the chromadb API in a child process: copy,
   verify count, swap. The swap is journaled, so an interrupted run is completed or rolled back on
   the next run. Ids, documents, metadata, embeddings and collection config are preserved; collection
   UUIDs change.
2. Orphaned index directories are deleted. Unused capacity and `l2`/`ip` `length.bin` are zeroed in
   place.
3. Write-log rows for dropped collections are deleted, then `VACUUM` runs with `secure_delete=ON`.
4. The store is rescanned and a receipt is issued.

No backup is kept. Stop the application first: Chroma caches store state per process and may write it
back.

**Postgres.** `VACUUM (FULL, ANALYZE)` on every table with a `vector`, `halfvec` or `sparsevec` column,
then `pg_switch_wal()` and `CHECKPOINT`. Requires table ownership. Takes an `ACCESS EXCLUSIVE` lock per
table, with `lock_timeout` set to 15 s.

**SQLite.** `VACUUM` with `secure_delete=ON`.

## Receipts

JSON with before/after findings, actions taken, canary results, warnings and the SHA-256 of every store
file after the fix (relation files for Postgres). Signed with Ed25519. The key is generated on first use
at `~/.config/forgetproof/signing_key.pem` (override with `$FORGETPROOF_HOME`).
`forgetproof key` prints the public key. `verify --key <fingerprint>` pins the signer, and
`verify --against <store>` rehashes and rescans the store.

A receipt is an operator attestation that anyone can recheck, not a third-party audit.

## MCP server

Exposes forgetproof to agents over MCP (stdio). The operator names the stores; the agent can only
refer to them by name, and can never name a value to look up or erase — it has no `canaries`
parameter anywhere. The one value a subject-scoped call acts on comes from `--subject-file`, a
file the operator's application keeps current with whoever is signed in; the agent cannot set it.

```bash
forgetproof mcp --store memory=./chroma_dir --store pg=postgresql://app@db:5432/agent \
  --allow-fix --subject-file /run/forgetproof/current-user
claude mcp add forgetproof -- forgetproof mcp --store memory=/srv/agent/chroma_dir   # Claude Code
```

| Tool | Needs | Effect |
|---|---|---|
| `list_stores` | – | Configured store names, and whether fix and a subject are configured |
| `scan_store(store_name)` | – | Findings as counts only: never whether a specific value is present |
| `plan_fix(store_name)` | – | Steps `fix` would take; changes nothing |
| `check_if_forgotten(store_name)` | `--subject-file` | Whether *the current subject* still has recoverable data |
| `forget_me(store_name)` | `--subject-file`, `--allow-fix` | Erases the current subject's data; may come back `queued` (below) |
| `fix_store(store_name)` | `--allow-fix` | Erases everything the scan found, with no value argument |
| `get_receipt` / `verify_receipt(receipt_id)` | – | Receipt JSON; signature, file-hash and rescan check |

Responses never contain values or samples, redacted or not. Calls on the same store are serialized,
and subject-scoped calls are rate-limited per store. On Chroma, `forget_me` and `fix_store` return an
error, and `forget_me` queues the erasure instead of failing, while the application has the store
open; call `forgetproof run-queued` (below) at the application's next start, before it reopens the
store, to finish it — the server also does this for its configured stores on its own startup.
Receipts go to `~/.config/forgetproof/receipts` (`--receipts DIR`). Pass the Postgres password
through `PGPASSWORD` in the server's environment.

## Embedding directly

For an application with its own delete flow, call `forget()` instead of running a server:

```python
from forgetproof import forget

receipt = forget.forget(store, subject=user.email)   # erases now, or...
# forget.Queued(target=..., queued_at=...) on Chroma if the app still has the store open

# at the app's next start, before it reopens the store:
for receipt in forget.run_queued(store):
    ...
```

```bash
forgetproof forget ./chroma_dir --subject user3@example.com   # or "queued: …" if Chroma is open
forgetproof run-queued ./chroma_dir --receipts-dir ./receipts  # call before reopening the store
```

A queued request is encrypted at rest under a local key (`~/.config/forgetproof/queue` by default)
and deleted the moment it's drained, so the queue is never a durable list of who asked to be
forgotten.

## GitHub Action

```yaml
- uses: Sharathvc23/forgetproof@v0
  with:
    path: ./chroma_dir                        # or a postgresql:// URL from a secret
    canaries: ${{ secrets.ERASED_VALUES }}    # optional, newline-separated
    fail-on-residue: "true"
```

Writes a counts-only job summary. Outputs: `clean`, `exit-code`.

## Limitations

- Operates on store files only. Filesystem snapshots, copy-on-write blocks, SSD remapping, backups,
  replicas and WAL archives are out of scope.
- Pattern detection misses free-form PII such as names and addresses; use canaries for specific values.
- Compressed values (Postgres TOAST `pglz`/`lz4`) are not visible to byte scanning. `fix` still
  removes them.
- Chroma can persist new uninitialized memory on its next index write. Run `scan` periodically or in CI.
- Cosine-space embeddings may differ in the last float32 ulp after a rebuild, because Chroma stores
  them normalized.

Tested on Linux, macOS and Windows; Python 3.11 to 3.14; Chroma 0.6.3 to 1.5.9 (`fix` needs 1.x);
Postgres 16 to 18 with pgvector 0.8.

## References

Chakraborttii, García Alvarado, Abdulofizova, Dwivedi. *Ghost Vectors: Soft-Deleted Embeddings Remain
Reconstructible in HNSW Vector Databases.* 2026. [arXiv:2606.18497](https://arxiv.org/abs/2606.18497)

## Development

```bash
uv sync
uv run pytest   # Postgres tests use pgserver, or FORGETPROOF_TEST_PG_URL
```

## License

MIT © 2026 stellarminds.ai
