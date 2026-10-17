"""Result types shared by the scanners, the fixer and the CLI."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    check: str  # stable id, e.g. "chroma.write_log"
    title: str
    location: str  # path relative to the scanned target
    records: int  # how many leftover units this finding covers
    why: str  # one line on why this matters
    unit: str = "records"  # what `records` counts: records, vectors, values, bytes
    pii: dict[str, int] = field(default_factory=dict)  # kind -> distinct values
    samples: list[str] = field(default_factory=list)  # redacted, safe to print


@dataclass
class CanaryResult:
    number: int  # 1-based position on the command line. The value itself is never stored or hashed:
    found_in: list[str]  # a hash of an email address can be confirmed by guessing.


@dataclass
class Report:
    target: str
    store: str
    findings: list[Finding] = field(default_factory=list)
    canaries: list[CanaryResult] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)  # problems that aren't residue, e.g. an interrupted fix
    incomplete: str | None = None  # why the scan couldn't check everything; such a store is never "clean"

    @property
    def clean(self) -> bool:
        return not self.findings and not any(c.found_in for c in self.canaries) and self.incomplete is None

    def summary(self) -> dict:
        """Counts only — safe to put in a receipt. No samples, no values."""
        return {
            "store": self.store,
            "clean": self.clean,
            "findings": {f.check: f.records for f in self.findings},
            "pii": {
                kind: sum(f.pii.get(kind, 0) for f in self.findings)
                for kind in sorted({k for f in self.findings for k in f.pii})
            },
            "canaries_found": sum(1 for c in self.canaries if c.found_in),
            "incomplete": self.incomplete,
            "warnings": self.warnings,
            "stats": self.stats,
        }

    def to_dict(self) -> dict:
        d = asdict(self)
        d["clean"] = self.clean
        return d
