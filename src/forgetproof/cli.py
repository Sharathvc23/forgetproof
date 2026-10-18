"""forgetproof command line."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, forget as forget_mod, postgres, receipt
from .fixer import FixError, Options, fix, plan
from .report import Report
from .scanner import UnsupportedStore, scan

EXIT_CLEAN, EXIT_RESIDUE, EXIT_ERROR = 0, 1, 2


def _style(code: str):
    def apply(text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text
    return apply


red, green, bold, dim = _style("31"), _style("32"), _style("1"), _style("2")


def _target(arg: str) -> Path | str:
    return arg if postgres.is_postgres(arg) else Path(arg).resolve()


def _canaries(args) -> list[str]:
    values = list(args.canary or [])
    if args.canary_file:
        values += [line.strip() for line in Path(args.canary_file).read_text().splitlines() if line.strip()]
    return values


def _print_report(r: Report) -> None:
    print(f"{bold('forgetproof')} {dim(__version__)}  {r.store} store at {r.target}")
    if r.stats:
        print(dim("  " + ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in r.stats.items())))
    print()
    for w in r.warnings:
        print(f"{bold('!')} {w}\n")
    if r.incomplete:
        print(f"{red('!')} {bold('Incomplete scan:')} {r.incomplete}\n")
    for f in r.findings:
        print(f"{red('✗')} {bold(f.title)}")
        print(f"    {f.records} {f.unit} in {f.location}")
        if f.pii:
            print("    contains: " + ", ".join(f"{n} {k}" for k, n in sorted(f.pii.items())))
        for s in f.samples:
            print(dim(f"      {s}"))
        print(dim(f"    why it matters: {f.why}"))
        print()
    for i, c in enumerate(r.canaries, 1):
        if c.found_in:
            print(f"{red('✗')} canary #{i} still on disk in: {', '.join(c.found_in)}")
        else:
            print(f"{green('✓')} canary #{i} not found anywhere in the store's files")
    if r.canaries:
        print()
    if r.clean:
        print(green("✓ No deleted data found on disk."))
    elif r.incomplete and not r.findings:
        print(red("Not verified clean: see the incomplete-scan note above."))
    else:
        print(red(f"Deleted data is still recoverable. Run `forgetproof fix {r.target}` to erase it."))


def _markdown(r: Report) -> str:
    """For CI job summaries. Counts only: no samples, even redacted ones, since CI logs can be public."""
    status = "✅ No deleted data found on disk" if r.clean else (
        "⚠️ Not verified clean" if r.incomplete and not r.findings else "❌ Deleted data is still recoverable")
    lines = [f"### forgetproof: {status}", "", f"`{r.store}` store · " + ", ".join(
        f"{k.replace('_', ' ')}: {v}" for k, v in r.stats.items()), ""]
    if r.findings:
        lines += ["| Check | What's left | Amount | Personal data |", "|---|---|---|---|"]
        for f in r.findings:
            pii = ", ".join(f"{n} {k}" for k, n in sorted(f.pii.items())) or "–"
            lines.append(f"| `{f.check}` | {f.title} | {f.records} {f.unit} | {pii} |")
        lines.append("")
    for c in r.canaries:
        lines.append(f"- canary #{c.number}: " + (f"**still on disk** in {', '.join(c.found_in)}" if c.found_in else "not found"))
    for w in r.warnings:
        lines.append(f"- ⚠️ {w}")
    if r.incomplete:
        lines.append(f"- ⚠️ **Incomplete scan:** {r.incomplete}")
    if not r.clean and r.findings:
        lines += ["", "Run `forgetproof fix` on the store to erase it ([how fix works](https://github.com/Sharathvc23/forgetproof#how-fix-works))."]
    return "\n".join(lines) + "\n"


def cmd_scan(args) -> int:
    r = scan(_target(args.path), _canaries(args))
    fmt = "json" if args.json else args.format
    if fmt == "json":
        print(json.dumps(r.to_dict(), indent=2))
    elif fmt == "markdown":
        print(_markdown(r), end="")
    else:
        _print_report(r)
    return EXIT_CLEAN if r.clean else EXIT_RESIDUE


def cmd_fix(args) -> int:
    target = _target(args.path)
    canaries = _canaries(args)
    if args.dry_run:
        r = scan(target, canaries)
        _print_report(r)
        print(f"\n{bold('fix would:')}")
        for step in plan(r):
            print(f"  • {step}")
        print(dim("Dry run: nothing was changed."))
        return EXIT_CLEAN if r.clean else EXIT_RESIDUE
    if not args.yes and postgres.is_postgres(target):
        print(
            f"This runs VACUUM FULL on every table with a pgvector column in {postgres.display(target)}.\n"
            "  - Each table is locked while it is rewritten: your app's reads and writes on it wait.\n"
            "  - It needs free disk space on the server about the size of the largest table.\n"
            "  Run with --dry-run to see the plan first."
        )
        if input("Continue? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return EXIT_ERROR
    elif not args.yes:
        print(
            f"This rewrites the store at {target} in place.\n"
            "  - Stop every process using it first.\n"
            "  - No backup is kept: a backup would defeat the erasure. Make your own if you need one.\n"
            "  - Chroma collections are rebuilt and get new internal IDs (names are kept).\n"
            "  Run with --dry-run to see the plan first."
        )
        if input("Continue? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return EXIT_ERROR
    result = fix(target, canaries, Options(force=args.force, allow_upgrade=args.allow_upgrade))
    before, after = result.before.summary(), result.after.summary()
    for a in result.actions:
        print(f"  • {a}")
    canary_results = [{"canary": c.number, "found_in": c.found_in} for c in result.after.canaries]
    rec = receipt.issue(target, before, after, result.actions, canary_results, label=result.before.target)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.receipt or f"forgetproof-receipt-{stamp}.json")
    out.write_text(json.dumps(rec, indent=2) + "\n")
    resolved = len(set(before["findings"]) - set(after["findings"]))
    for w in result.after.warnings:
        print(f"{bold('!')} {w}")
    if after["clean"]:
        print(green(f"✓ Erased. {resolved} of {len(before['findings'])} finding(s) resolved; rescan is clean."))
    else:
        print(red("Residue remains after fix:"))
        _print_report(result.after)
    print(f"Signed receipt: {out}  (key {receipt.fingerprint(rec['public_key'])})")
    return EXIT_CLEAN if after["clean"] else EXIT_RESIDUE


def cmd_verify(args) -> int:
    rec = json.loads(Path(args.receipt).read_text())
    receipt.verify_signature(rec, args.key)
    print(f"{green('✓')} signature valid — issued {rec['issued_at']} by key {receipt.fingerprint(rec['public_key'])}")
    print(f"  verdict at issue: {rec['verdict']}")
    if not args.against:
        return EXIT_CLEAN if rec["verdict"] == "CLEAN" else EXIT_RESIDUE
    target = _target(args.against)
    current = receipt.file_hashes(target)
    if current != rec["files"]:
        changed = sorted(set(current) ^ set(rec["files"]) | {k for k in current if rec["files"].get(k) != current[k]})
        print(f"{dim('•')} store changed since the receipt was issued ({len(changed)} file(s)); rescanning")
    else:
        print(f"{green('✓')} store files are byte-identical to the receipt")
    r = scan(target)
    print(f"{green('✓') if r.clean else red('✗')} rescan now: {'clean' if r.clean else 'RESIDUE FOUND'}")
    return EXIT_CLEAN if r.clean and rec["verdict"] == "CLEAN" else EXIT_RESIDUE


def cmd_key(args) -> int:
    key = receipt.load_or_create_key()
    pub = receipt.public_key_b64(key)
    print(f"public key:  {pub}\nfingerprint: {receipt.fingerprint(pub)}\nstored at:   {receipt.key_path()}")
    return EXIT_CLEAN


def cmd_forget(args) -> int:
    target = _target(args.path)
    result = forget_mod.forget(target, args.subject, options=Options(allow_upgrade=args.allow_upgrade))
    if isinstance(result, forget_mod.Queued):
        print(f"{bold('queued')}: {result.target} is open elsewhere right now (Chroma can't be rewritten while "
              f"that's true).\nRun `forgetproof run-queued {args.path}` once nothing has it open, "
              "typically at your app's next start before it reopens the store.")
        return EXIT_RESIDUE
    out = Path(args.receipt or f"forgetproof-receipt-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json")
    out.write_text(json.dumps(result, indent=2) + "\n")
    if result["verdict"] == "CLEAN":
        print(green(f"✓ Erased. Signed receipt: {out}"))
    else:
        print(red(f"canary still on disk after fix — see {out}"))
    return EXIT_CLEAN if result["verdict"] == "CLEAN" else EXIT_RESIDUE


def cmd_run_queued(args) -> int:
    target = _target(args.path)
    receipts = forget_mod.run_queued(target, options=Options(allow_upgrade=args.allow_upgrade))
    if not receipts:
        print(dim("nothing queued for this store."))
        return EXIT_CLEAN
    out_dir = Path(args.receipts_dir) if args.receipts_dir else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)
    for i, rec in enumerate(receipts, 1):
        path = out_dir / f"forgetproof-receipt-{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{i}.json"
        path.write_text(json.dumps(rec, indent=2) + "\n")
        print(f"  • {rec['verdict']}: {path}")
    print(green(f"✓ {len(receipts)} queued erasure(s) finished."))
    return EXIT_CLEAN


def cmd_mcp(args) -> int:
    try:
        from . import mcp_server
    except ImportError:
        print(red("error: the MCP server needs the mcp extra: pip install 'forgetproof[mcp]'"), file=sys.stderr)
        return EXIT_ERROR
    stores = [mcp_server.parse_store(spec) for spec in args.store]
    receipts = Path(args.receipts).expanduser().resolve() if args.receipts else None
    queue_dir = Path(args.queue_dir).expanduser().resolve() if args.queue_dir else None
    mcp_server.build(stores, allow_fix=args.allow_fix, receipts_dir=receipts,
                      subject_file=args.subject_file, queue_dir=queue_dir).run()
    return EXIT_CLEAN


def _utf8_output() -> None:
    """Windows consoles and redirects default to a legacy code page that can't encode ✓ and ✗."""
    for stream in (sys.stdout, sys.stderr):
        if (getattr(stream, "encoding", "") or "").lower().replace("-", "") != "utf8" and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    _utf8_output()
    p = argparse.ArgumentParser(prog="forgetproof", description="Detect and erase deleted records left on disk by agent memory stores.")
    p.add_argument("--version", action="version", version=f"forgetproof {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def canary_args(sp):
        sp.add_argument("--canary", action="append", metavar="VALUE", help="a value you deleted (repeatable), e.g. a user's email")
        sp.add_argument("--canary-file", metavar="FILE", help="file with one canary value per line")

    s = sub.add_parser("scan", help="find deleted data still on disk (exit 1 if any)")
    s.add_argument("path", help="Chroma persist directory, SQLite file, or postgresql:// URL (put the password in PGPASSWORD)")
    canary_args(s)
    s.add_argument("--format", choices=["text", "json", "markdown"], default="text",
                   help="markdown is for CI job summaries and leaves out samples")
    s.add_argument("--json", action="store_true", help="same as --format json")
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("fix", help="erase residue in place and issue a signed receipt")
    f.add_argument("path")
    canary_args(f)
    f.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    f.add_argument("--receipt", metavar="FILE", help="where to write the receipt")
    f.add_argument("--dry-run", action="store_true", help="show what fix would do and change nothing")
    f.add_argument("--force", action="store_true", help="skip the open-process and free-space checks")
    f.add_argument("--allow-upgrade", action="store_true",
                   help="let the installed chromadb upgrade an older store to its own format")
    f.set_defaults(func=cmd_fix)

    g = sub.add_parser("forget", help="erase one subject's data now, or queue it if the store can't be rewritten yet")
    g.add_argument("path")
    g.add_argument("--subject", required=True, metavar="VALUE", help="the value to erase, e.g. a user's email")
    g.add_argument("--receipt", metavar="FILE", help="where to write the receipt")
    g.add_argument("--allow-upgrade", action="store_true",
                   help="let the installed chromadb upgrade an older store to its own format")
    g.set_defaults(func=cmd_forget)

    rq = sub.add_parser("run-queued", help="finish forget() calls queued for a store (run before reopening it)")
    rq.add_argument("path")
    rq.add_argument("--receipts-dir", metavar="DIR", help="where to write the receipts (default: current directory)")
    rq.add_argument("--allow-upgrade", action="store_true",
                    help="let the installed chromadb upgrade an older store to its own format")
    rq.set_defaults(func=cmd_run_queued)

    v = sub.add_parser("verify", help="check a receipt's signature, optionally against the store")
    v.add_argument("receipt")
    v.add_argument("--against", metavar="PATH", help="rescan this store and compare")
    v.add_argument("--key", metavar="PUBKEY", help="require this signing key: its fingerprint or public key (from `forgetproof key`)")
    v.set_defaults(func=cmd_verify)

    k = sub.add_parser("key", help="show this machine's receipt signing key")
    k.set_defaults(func=cmd_key)

    m = sub.add_parser("mcp", help="run an MCP server (stdio) that lets an agent scan, fix and verify named stores")
    m.add_argument("--store", action="append", required=True, metavar="NAME=PATH_OR_URL",
                   help="a store the agent may use (repeatable); the agent only ever sees NAME")
    m.add_argument("--allow-fix", action="store_true", help="offer fix_store and forget_me (off by default)")
    m.add_argument("--receipts", metavar="DIR", help="where receipts are written (default: next to the signing key)")
    m.add_argument("--subject-file", metavar="FILE",
                   help="file holding the current user's identity, kept current by your application; "
                        "enables check_if_forgotten and forget_me, scoped to that value only")
    m.add_argument("--queue-dir", metavar="DIR", help="where forget_me queues a Chroma erasure it can't do yet")
    m.set_defaults(func=cmd_mcp)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except (UnsupportedStore, FixError, postgres.PostgresError, ValueError, OSError, sqlite3.DatabaseError) as e:
        print(red(f"error: {e}"), file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
