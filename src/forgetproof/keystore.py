"""Where forgetproof keeps the secrets it generates for itself: the Ed25519 signing key, and the
key that encrypts a forget() request queued for later. By default that's a file under
FORGETPROOF_HOME with owner-only permissions, same as every release before this one.

Set FORGETPROOF_USE_KEYRING=1 to store them in the OS keychain instead — macOS Keychain, Windows
Credential Locker, the Secret Service on Linux — via the optional `keyring` package. This is
opt-in, never auto-detected: a keychain backend that needs an interactive unlock (most do, the
first time a new process touches them) would otherwise silently hang a non-interactive process the
first time it runs — a CI job or a backend service as much as a test suite. Decide to turn it on;
don't let a desktop session you happened to be running in decide it for you.

An existing file is never moved into the keychain automatically: if one is already there,
forgetproof keeps using it, so turning this on after the fact doesn't change which key a machine
signs with, or stop it from decrypting a queue entry a file key already encrypted.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

try:
    import keyring
    import keyring.errors
except ImportError:
    keyring = None  # the [keyring] extra isn't installed; the file fallback is what forgetproof always did

SERVICE = "forgetproof"


def use_keyring() -> bool:
    return os.environ.get("FORGETPROOF_USE_KEYRING", "") == "1"


def get_or_create(name: str, path: Path, generate: Callable[[], bytes]) -> bytes:
    """Return the secret kept at `path`, or under `name` in the OS keychain if
    FORGETPROOF_USE_KEYRING=1 and `path` doesn't already hold one — creating it with
    `generate()` on first use either way.
    """
    if path.exists():
        return path.read_bytes()
    if use_keyring() and keyring is not None:
        try:
            existing = keyring.get_password(SERVICE, name)
            if existing is not None:
                return bytes.fromhex(existing)
            value = generate()
            keyring.set_password(SERVICE, name, value.hex())
            return value
        except keyring.errors.KeyringError:
            pass  # no backend usable right now (e.g. no desktop session) — fall back to the file
    value = generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(value)
    return value
