"""Group findings into migration waves."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding, Kind, ScanResult, Severity

# Regulatory milestones. Sources are listed in the README.
DEADLINES = [
    ("NIST IR 8547 (final, Oct 2026)", "after 2030",
     "RSA, ECDSA, EdDSA, (EC)DH deprecated at every key size"),
    ("NIST IR 8547 (final, Oct 2026)", "after 2035",
     "quantum-vulnerable public-key algorithms disallowed"),
    ("UK NCSC", "2028", "discovery and inventory complete, migration plan in place"),
    ("UK NCSC", "2031", "high-priority migration done"),
    ("UK NCSC", "2035", "migration complete for all systems"),
    ("EU coordinated roadmap", "end of 2026", "national roadmaps and first steps (inventory)"),
    ("EU coordinated roadmap", "end of 2030", "high-risk use cases migrated"),
    ("EU coordinated roadmap", "end of 2035", "full transition as far as feasible"),
]


@dataclass
class PlanItem:
    title: str
    algorithm: str
    kind: Kind
    severity: Severity
    remediation: str
    locations: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.locations)


@dataclass
class Wave:
    key: str
    title: str
    when: str
    why: str
    items: list[PlanItem] = field(default_factory=list)


_USAGE = {
    Kind.QUANTUM_KEX: "key exchange / encryption",
    Kind.QUANTUM_SIG: "signatures",
    Kind.QUANTUM_KEY: "key pairs (usage to confirm)",
}


def _family(algorithm: str) -> str:
    """'RSA-OAEP' -> 'RSA', 'ECDSA-secp256r1' -> 'ECDSA', 'ECDH/DH' -> 'ECDH/DH'."""
    a = algorithm.strip()
    up = a.upper()
    for fam in ("RSA", "ECDSA", "ECDHE", "ECDH", "X25519", "ED25519", "DSA", "DH",
                "ECC"):
        if up == fam or up.startswith(fam + "-") or up.startswith(fam + "/"):
            return "Ed25519" if fam == "ED25519" else fam
    if up.startswith("SSH-") or up.startswith("ECDSA-SHA2") or up.startswith("SK-"):
        return "SSH keys"
    return a


def _wave_for(f: Finding) -> str | None:
    if f.kind in (Kind.SECRET, Kind.CLASSICAL_WEAK):
        return "fix-now"
    if f.kind in (Kind.QUANTUM_KEX, Kind.QUANTUM_KEY):
        return "wave-1"
    if f.kind == Kind.QUANTUM_SIG:
        return "wave-2"
    if f.kind == Kind.PQC:
        return "verify"
    return None   # inventory only


def build_plan(result: ScanResult) -> list[Wave]:
    waves = {
        "fix-now": Wave("fix-now", "Fix now (classical problems)", "immediately",
                        "These are broken already, quantum computer or not: private keys "
                        "in the repo, MD5/SHA-1, DES/RC4/ECB, TLS 1.0/1.1."),
        "wave-1": Wave("wave-1", "Wave 1: key exchange and encryption", "start now, done by 2030",
                       "Data encrypted with RSA or ECDH today can be stored and decrypted "
                       "later, so this goes first. The usual fix is hybrid ML-KEM."),
        "wave-2": Wave("wave-2", "Wave 2: signatures and authentication", "plan now, done by 2035",
                       "To forge a signature you need the quantum computer at the time of "
                       "the attack, so this can come after key exchange. Start with the "
                       "long-lived stuff: root certificates, firmware and code signing."),
        "verify": Wave("verify", "Verify existing post-quantum usage", "next review",
                       "Some post-quantum code is already in place. Check the parameter "
                       "sets, that it follows the final FIPS versions, and hybrid mode."),
    }
    groups: dict[tuple[str, str, str], PlanItem] = {}
    for f in result.sorted():
        w = _wave_for(f)
        if w is None:
            continue
        fam = _family(f.algorithm)
        key = (w, f.kind.value, fam)
        item = groups.get(key)
        if item is None:
            title = f"{fam}: {_USAGE[f.kind]}" if f.kind in _USAGE else f.title
            item = PlanItem(title, f.algorithm, f.kind, f.severity, f.remediation)
            groups[key] = item
            waves[w].items.append(item)
        loc = f"{f.location}:{f.line}" if f.line else f.location
        if f.context == "test":
            loc += " (test)"
        item.locations.append(loc)
    for w in waves.values():
        w.items.sort(key=lambda i: (-i.severity.rank, -i.count, i.title))
    return [w for w in waves.values() if w.items]
