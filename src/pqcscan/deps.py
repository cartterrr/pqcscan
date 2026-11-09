"""Find crypto libraries in dependency files."""

from __future__ import annotations

import re

from .models import Finding, Kind, Severity
from .rules import REMEDIATION

MANIFESTS = {
    "requirements.txt": "pypi", "requirements-dev.txt": "pypi", "pyproject.toml": "pypi",
    "setup.py": "pypi", "setup.cfg": "pypi", "pipfile": "pypi", "poetry.lock": "pypi",
    "package.json": "npm",
    "go.mod": "go",
    "pom.xml": "maven", "build.gradle": "maven", "build.gradle.kts": "maven",
    "cargo.toml": "cargo",
    "gemfile": "gem", "composer.json": "composer",
}

# (ecosystem, package) -> (description, is_pqc)
LIBRARIES: dict[str, dict[str, tuple[str, bool]]] = {
    "pypi": {
        "cryptography": ("pyca/cryptography (RSA, ECC, X25519, ...)", False),
        "pycryptodome": ("PyCryptodome", False),
        "pycryptodomex": ("PyCryptodome", False),
        "pycrypto": ("PyCrypto (unmaintained)", False),
        "pyopenssl": ("pyOpenSSL", False),
        "rsa": ("python-rsa", False),
        "ecdsa": ("python-ecdsa", False),
        "pynacl": ("PyNaCl (X25519/Ed25519)", False),
        "paramiko": ("Paramiko SSH", False),
        "pyjwt": ("PyJWT", False),
        "python-jose": ("python-jose", False),
        "jwcrypto": ("jwcrypto", False),
        "liboqs-python": ("liboqs-python (Open Quantum Safe)", True),
        "oqs": ("liboqs-python (Open Quantum Safe)", True),
        "pqcrypto": ("pqcrypto", True),
        "kyber-py": ("kyber-py", True),
        "dilithium-py": ("dilithium-py", True),
    },
    "npm": {
        "node-forge": ("node-forge", False),
        "jsrsasign": ("jsrsasign", False),
        "node-rsa": ("node-rsa", False),
        "elliptic": ("elliptic", False),
        "tweetnacl": ("TweetNaCl (X25519/Ed25519)", False),
        "jsonwebtoken": ("jsonwebtoken", False),
        "jose": ("jose", False),
        "@noble/curves": ("@noble/curves", False),
        "@noble/ed25519": ("@noble/ed25519", False),
        "@noble/secp256k1": ("@noble/secp256k1", False),
        "crypto-js": ("crypto-js", False),
        "@noble/post-quantum": ("@noble/post-quantum (ML-KEM/ML-DSA/SLH-DSA)", True),
        "crystals-kyber": ("crystals-kyber", True),
        "mlkem": ("mlkem", True),
    },
    "go": {
        "golang.org/x/crypto": ("golang.org/x/crypto", False),
        "github.com/golang-jwt/jwt": ("golang-jwt", False),
        "github.com/cloudflare/circl": ("Cloudflare CIRCL (incl. ML-KEM/ML-DSA)", True),
        "github.com/open-quantum-safe/liboqs-go": ("liboqs-go", True),
    },
    "maven": {
        "bcprov": ("Bouncy Castle provider", False),
        "bcpkix": ("Bouncy Castle PKIX", False),
        "bcpqc": ("Bouncy Castle PQC", True),
        "jjwt": ("JJWT", False),
        "nimbus-jose-jwt": ("Nimbus JOSE+JWT", False),
        "liboqs-java": ("liboqs-java", True),
    },
    "cargo": {
        "rsa": ("RustCrypto rsa", False),
        "ring": ("ring", False),
        "p256": ("RustCrypto p256", False),
        "k256": ("RustCrypto k256", False),
        "ed25519-dalek": ("ed25519-dalek", False),
        "x25519-dalek": ("x25519-dalek", False),
        "openssl": ("rust-openssl", False),
        "rustls": ("rustls", False),
        "ml-kem": ("RustCrypto ml-kem", True),
        "ml-dsa": ("RustCrypto ml-dsa", True),
        "pqcrypto": ("pqcrypto", True),
        "oqs": ("liboqs-rust", True),
    },
    "gem": {"openssl": ("Ruby OpenSSL", False), "jwt": ("ruby-jwt", False)},
    "composer": {"phpseclib/phpseclib": ("phpseclib", False),
                 "firebase/php-jwt": ("php-jwt", False)},
}


def is_manifest(path: str) -> bool:
    return path.rsplit("/", 1)[-1].lower() in MANIFESTS


def scan_manifest(path: str, text: str) -> list[Finding]:
    eco = MANIFESTS[path.rsplit("/", 1)[-1].lower()]
    findings: list[Finding] = []
    for pkg, (desc, is_pqc) in LIBRARIES.get(eco, {}).items():
        flags = re.IGNORECASE if eco == "pypi" else 0
        # Maven artifacts carry suffixes (bcprov-jdk18on), others must match exactly.
        tail = r"(?=[-<\"':\s]|$)" if eco == "maven" else r"(?![\w-])"
        pat = re.compile(r"(?<![\w./@-])" + re.escape(pkg) + tail, flags)
        if eco == "pypi" and pkg == "rsa":
            # 'rsa' shows up inside lots of other names, so only accept it as a whole requirement line
            pat = re.compile(r"(?im)^\s*['\"]?rsa(?:\s*[<>=~!;\[]|['\"]|\s*$)")
        m = pat.search(text)
        if not m:
            continue
        line = text.count("\n", 0, m.start()) + 1
        snippet = text.split("\n")[line - 1].strip()[:160]
        findings.append(Finding(
            rule_id="dep.pqc-library" if is_pqc else "dep.crypto-library",
            title=f"{'Post-quantum' if is_pqc else 'Cryptographic'} library: {desc}",
            kind=Kind.PQC if is_pqc else Kind.INVENTORY,
            severity=Severity.INFO,
            algorithm=pkg,
            primitive="other",
            location=path,
            line=line,
            snippet=snippet,
            context="dependency",
            detail=f"{eco} package '{pkg}'",
            remediation=REMEDIATION["pqc"] if is_pqc else
            "Just for the inventory. The code findings show which parts of this library "
            "the project actually uses.",
            quantum_level=None,
        ))
    return findings
