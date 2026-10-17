"""Detectors for personal data and secrets in raw bytes, plus redaction for display."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

# Patterns run over bytes so they work on raw database pages, not just decoded text.
PATTERNS: dict[str, re.Pattern[bytes]] = {
    "email": re.compile(rb"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}"),
    "phone": re.compile(rb"(?<![\d-])(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?![\d-])"),
    "ssn": re.compile(rb"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])"),
    # Grouped like a printed card number; bare digit runs in binary pages are mostly noise.
    "card": re.compile(rb"(?<![0-9A-Za-z])\d{4}(?:[ -]\d{4}){2}[ -]\d{1,7}(?![0-9A-Za-z-])"),
    "api_key": re.compile(
        rb"(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,})"
    ),
}


# Raw database pages put values next to unrelated bytes, so `user@example.com` followed by a stray
# letter reads as `user@example.comC`. When the last label isn't a known TLD but starts with one, cut
# it back. Covers the TLDs most addresses use; others are left as matched.
_COMMON_TLDS = frozenset(
    b"com org net edu gov mil int io ai co dev app me us uk de fr nl es it ca au in jp cn br ru ch se no "
    b"dk fi pl be at ie nz sg hk kr tw mx ar za il tr pt gr cz hu ro info biz xyz tech cloud online site".split()
)


def _trim_email(value: bytes) -> bytes:
    head, _, tld = value.rpartition(b".")
    if tld.lower() in _COMMON_TLDS:
        return value
    for n in range(len(tld) - 1, 1, -1):
        if tld[:n].lower() in _COMMON_TLDS:
            return head + b"." + tld[:n]
    return value


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def find_pii(data: bytes) -> Iterator[tuple[str, bytes]]:
    """Yield (kind, value) for every match in data."""
    for kind, pattern in PATTERNS.items():
        for m in pattern.finditer(data):
            value = m.group(0)
            if kind == "email":
                value = _trim_email(value)
            if kind == "card":
                digits = re.sub(rb"\D", b"", value).decode()
                if not (13 <= len(digits) <= 19 and _luhn(digits)):
                    continue
            yield kind, value


def pii_set(chunks: Iterable[bytes]) -> set[tuple[str, bytes]]:
    found: set[tuple[str, bytes]] = set()
    for chunk in chunks:
        found.update(find_pii(chunk))
    return found


def redact(kind: str, value: bytes) -> str:
    """Show enough to recognise a value in a screenshot, not enough to leak it."""
    text = value.decode("utf-8", "replace")
    if kind == "email":
        local, _, domain = text.partition("@")
        shown = local[0] + "*" * max(len(local) - 2, 1) + (local[-1] if len(local) > 1 else "")
        return f"{shown}@{domain}"
    if kind in ("phone", "ssn", "card"):
        digits = re.sub(r"\D", "", text)
        return "*" * (len(digits) - 4) + digits[-4:]
    return text[:6] + "…"


def _explained_by_live(kind: str, value: bytes, live: set[tuple[str, bytes]], locals_: set[bytes], domains: set[bytes]) -> bool:
    """Raw pages pack values next to unrelated bytes, so a pattern can run into a neighbour
    (`a@b.comX`, `Xa@b.com`). A raw match is live if it contains a live value of its kind."""
    if (kind, value) in live:
        return True
    if kind == "email":
        local, _, domain = value.partition(b"@")
        heads = [domain[:i] for i in range(len(domain), 0, -1) if domain[:i] in domains]
        tails = [local[i:] for i in range(len(local)) if local[i:] in locals_]
        return any(("email", t + b"@" + h) in live for t in tails for h in heads)
    n = len(value)
    return any((kind, value[a:b]) in live for a in range(n) for b in range(n, a, -1))


class LivePii:
    """Personal data still reachable through the store's API, for deciding whether a raw match is live."""

    def __init__(self, values: set[tuple[str, bytes]]):
        self.values = values
        emails = [v for k, v in values if k == "email"]
        self._locals = {v.partition(b"@")[0] for v in emails}
        self._domains = {v.partition(b"@")[2] for v in emails}

    def not_live(self, found: set[tuple[str, bytes]]) -> set[tuple[str, bytes]]:
        return {(k, v) for k, v in found if not _explained_by_live(k, v, self.values, self._locals, self._domains)}


class ByteScanner:
    """Find PII and canary values in a stream of chunks, including values split across chunks."""

    OVERLAP = 512

    def __init__(self, canaries: list[str] = ()):
        self.pii: set[tuple[str, bytes]] = set()
        self._needles = [{c.encode(), c.lower().encode()} for c in canaries]
        self.canary_hits: list[bool] = [False] * len(self._needles)

    def feed(self, chunks: Iterable[bytes]) -> bool:
        """Scan one file's chunks. Returns True if any canary was seen in it."""
        seen = [False] * len(self._needles)
        carry = b""
        for chunk in chunks:
            window = carry + chunk
            if window.count(0) != len(window):
                self.pii.update(find_pii(window))
                for i, needles in enumerate(self._needles):
                    seen[i] = seen[i] or any(n in window for n in needles)
            carry = window[-self.OVERLAP:]
        for i, s in enumerate(seen):
            self.canary_hits[i] |= s
        self.last_seen = seen
        return any(seen)
