"""Signed erasure receipts.

A receipt records what a scan found before the fix, what it found after, and
the SHA-256 of every file in the store afterwards — counts and hashes only,
never the erased values. It is signed with an Ed25519 key kept on this machine.

Signing proves the receipt hasn't been altered since it was issued and which
key issued it. It is the operator's attestation plus a check anyone can rerun
(`forgetproof verify --against`), not a third-party audit.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import __version__, keystore

FORMAT = "forgetproof-receipt/0.1"


def key_path() -> Path:
    home = os.environ.get("FORGETPROOF_HOME") or Path.home() / ".config" / "forgetproof"
    return Path(home) / "signing_key.pem"


def _generate_pem() -> bytes:
    key = Ed25519PrivateKey.generate()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def load_or_create_key() -> Ed25519PrivateKey:
    pem = keystore.get_or_create("signing_key", key_path(), _generate_pem)
    key = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(key, Ed25519PrivateKey)
    return key


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def public_key_b64(key: Ed25519PrivateKey) -> str:
    return _b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def fingerprint(public_b64: str) -> str:
    return hashlib.sha256(_unb64(public_b64)).hexdigest()[:32]


def file_hashes(target: Path | str) -> dict[str, str]:
    from . import postgres

    if postgres.is_postgres(target):
        return postgres.fingerprints(str(target))
    target = Path(target)
    files = sorted(p for p in target.rglob("*") if p.is_file()) if target.is_dir() else [target]
    out = {}
    for p in files:
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        out[str(p.relative_to(target)) if target.is_dir() else p.name] = h.hexdigest()
    return out


def issue(target: Path | str, before: dict, after: dict, actions: list[str], canaries: list[dict], label: str | None = None,
          correlation_id: str | None = None) -> dict:
    key = load_or_create_key()
    body = {
        "format": FORMAT,
        "tool": f"forgetproof {__version__}",
        "issued_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": label or str(target),  # for a database: the URL without its password
        "verdict": "CLEAN" if after["clean"] else "RESIDUE_REMAINS",
        "before": before,
        "after": after,
        "actions": actions,
        "canaries": canaries,  # per canary: where, if anywhere, it was still found; never the value or its hash
        "correlation_id": correlation_id,  # an opaque caller-supplied label; carried through a queued forget() too
        "files": file_hashes(target),
        "public_key": public_key_b64(key),
    }
    body["signature"] = _b64(key.sign(canonical(body)))
    return body


def verify_signature(receipt: dict, expected_key: str | None = None) -> None:
    """Raise ValueError if the receipt was altered or signed by an unexpected key."""
    body = {k: v for k, v in receipt.items() if k != "signature"}
    if receipt.get("format") != FORMAT:
        raise ValueError(f"unknown receipt format {receipt.get('format')!r}")
    if expected_key and expected_key not in (receipt["public_key"], fingerprint(receipt["public_key"])):
        raise ValueError("receipt was signed by a different key than expected")
    pub = Ed25519PublicKey.from_public_bytes(_unb64(receipt["public_key"]))
    try:
        pub.verify(_unb64(receipt["signature"]), canonical(body))
    except InvalidSignature:
        raise ValueError("signature does not match — the receipt was altered") from None
