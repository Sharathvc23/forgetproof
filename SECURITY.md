# Security

forgetproof handles personal data and rewrites databases, so we take reports seriously.

**Report a vulnerability privately** through GitHub's "Report a vulnerability" button on this
repository's Security tab. Please don't open a public issue. We aim to reply within 3 working days.

In scope: anything that makes forgetproof leak personal data (in output, receipts or temporary files),
lose or corrupt live data during `fix`, report a store as clean when it isn't, or accept a forged receipt.

If you find a residue problem in a *vector database* rather than in forgetproof, please report it to that
project first. We're happy to help coordinate and to add a check once it's public.

## Dependencies

`chromadb` (the optional `[chroma]` extra) has open advisories, as of October 2026 with no patched release,
for its **HTTP server**: missing tenant checks and code injection through remote embedding-model code.
forgetproof never runs or connects to a Chroma server. `scan` doesn't load chromadb at all; `fix` uses
the embedded client in a child process with model hubs offline (`HF_HUB_OFFLINE`, `TRANSFORMERS_OFFLINE`)
and Chroma telemetry off, and only copies stored embeddings. If you run a Chroma server yourself, follow
Chroma's advisories for it.
