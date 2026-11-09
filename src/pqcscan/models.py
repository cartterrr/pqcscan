"""Data classes shared by the scanners and the report writers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class Kind(str, Enum):
    """What sort of problem a finding is.

    Key exchange and encryption are separate from signatures on purpose:
    encrypted data can be recorded now and broken later, while a signature
    only matters if someone can forge it once a quantum computer exists.
    """

    QUANTUM_KEX = "quantum-kex"          # RSA encryption, (EC)DH, X25519 ...
    QUANTUM_SIG = "quantum-sig"          # RSA/ECDSA/EdDSA/DSA signatures
    QUANTUM_KEY = "quantum-key"          # key generation, use unknown
    CLASSICAL_WEAK = "classical-weak"    # MD5, SHA-1, DES, RC4, TLS 1.0 ...
    SECRET = "secret"                    # private key committed to the repo
    PQC = "pqc"                          # post-quantum algorithm in use
    INVENTORY = "inventory"              # crypto library present (dependency)


KIND_LABELS = {
    Kind.QUANTUM_KEX: "Quantum-vulnerable key exchange / encryption",
    Kind.QUANTUM_SIG: "Quantum-vulnerable signature",
    Kind.QUANTUM_KEY: "Quantum-vulnerable key (use unknown)",
    Kind.CLASSICAL_WEAK: "Classically weak cryptography",
    Kind.SECRET: "Private key material in repository",
    Kind.PQC: "Post-quantum cryptography in use",
    Kind.INVENTORY: "Cryptographic library dependency",
}


@dataclass
class Finding:
    rule_id: str
    title: str
    kind: Kind
    severity: Severity
    algorithm: str
    primitive: str              # CycloneDX primitive: pke, signature, kem, key-agree, hash, ...
    location: str               # relative file path or tls://host:port
    line: int = 0
    snippet: str = ""
    language: str = ""
    confidence: str = "high"    # high | medium | low
    context: str = "code"       # code | test | config | dependency | key-file | endpoint
    detail: str = ""
    remediation: str = ""
    quantum_level: int | None = 0   # NIST quantum security level (0 = broken by CRQC)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["severity"] = self.severity.value
        return d

    @property
    def sort_key(self):
        return (-self.severity.rank, self.location, self.line, self.rule_id)


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors: list[str] = field(default_factory=list)
    unit: str = "files"

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key)

    def count_by(self, attr: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            v = getattr(f, attr)
            key = v.value if isinstance(v, Enum) else str(v)
            out[key] = out.get(key, 0) + 1
        return out
