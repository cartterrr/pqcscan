"""Look inside key and certificate files (PEM, DER, SSH public keys)."""

from __future__ import annotations

import datetime as dt
import re

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519

from .models import Finding, Kind, Severity
from .rules import REMEDIATION

KEY_EXTS = (".pem", ".crt", ".cer", ".der", ".key", ".pub", ".p8", ".pk8")
KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts"}
NIST_DEPRECATION = dt.datetime(2031, 1, 1, tzinfo=dt.timezone.utc)   # "deprecated after 2030"
NIST_DISALLOW = dt.datetime(2036, 1, 1, tzinfo=dt.timezone.utc)      # "disallowed after 2035"
BUNDLE_THRESHOLD = 10

PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.S)
SSH_PUB = re.compile(
    r"^(?:\S+\s+)?(ssh-rsa|ssh-dss|ecdsa-sha2-nistp(?:256|384|521)|ssh-ed25519|"
    r"sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+([A-Za-z0-9+/=]+)",
    re.M)


def is_key_file(path: str, data: bytes) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    if name in KEY_NAMES or name.endswith(KEY_EXTS):
        return True
    return False


def describe_public_key(key) -> tuple[str, str, int | None]:
    """Return (algorithm label, primitive, size)."""
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return f"RSA-{key.key_size}", "pke", key.key_size
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return f"ECDSA-{key.curve.name}", "signature", key.curve.key_size
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "Ed25519", "signature", 256
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return "Ed448", "signature", 448
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return "X25519", "key-agree", 256
    if isinstance(key, (x448.X448PublicKey, x448.X448PrivateKey)):
        return "X448", "key-agree", 448
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return f"DSA-{key.key_size}", "signature", key.key_size
    name = type(key).__name__
    if "MLKEM" in name.upper() or "MLDSA" in name.upper():
        return name, "kem", None
    return name, "other", None


def _cert_findings(path: str, cert: x509.Certificate, index: int) -> list[Finding]:
    try:
        pub = cert.public_key()
        alg, primitive, size = describe_public_key(pub)
    except Exception:  # unsupported key type (e.g. a PQC certificate on an old library)
        alg, primitive, size = "unknown", "other", None
    try:
        sig = cert.signature_algorithm_oid._name  # e.g. sha256WithRSAEncryption
    except Exception:
        sig = cert.signature_algorithm_oid.dotted_string
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        not_after = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except (IndexError, ValueError):
        cn = cert.subject.rfc4514_string() or "(no subject)"
    is_ca = False
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        pass

    quantum_safe = primitive == "kem" or alg.upper().startswith(("ML-DSA", "SLH-DSA", "MLDSA"))
    notes = [f"subject CN={cn}", f"signature={sig}", f"expires {not_after:%Y-%m-%d}"]
    if is_ca:
        notes.append("CA certificate, likely long-lived, so worth moving to ML-DSA/SLH-DSA early")
    sev = Severity.MEDIUM
    if not quantum_safe and not_after >= NIST_DISALLOW:
        sev = Severity.HIGH
        notes.append("still valid after 2035, when NIST disallows these algorithms")
    elif not quantum_safe and not_after >= NIST_DEPRECATION:
        notes.append("still valid after 2030, when NIST deprecates these algorithms")
    if size and alg.startswith("RSA") and size < 2048:
        sev = Severity.HIGH
        notes.append("RSA key shorter than 2048 bits is classically weak")
    return [Finding(
        rule_id="key.certificate",
        title="X.509 certificate with quantum-vulnerable key" if not quantum_safe
        else "X.509 certificate with post-quantum key",
        kind=Kind.PQC if quantum_safe else Kind.QUANTUM_SIG,
        severity=Severity.INFO if quantum_safe else sev,
        algorithm=alg,
        primitive="signature" if primitive == "pke" else primitive,
        location=path,
        line=0,
        snippet=f"certificate #{index + 1}: {cn}",
        context="key-file",
        detail="; ".join(notes),
        remediation=REMEDIATION["pqc" if quantum_safe else "sig"],
        quantum_level=None if quantum_safe else 0,
        extra={"not_after": not_after.date().isoformat(), "signature_algorithm": sig,
               "subject_cn": str(cn), "is_ca": is_ca, "key_size": size},
    )]


def _private_key_finding(path: str, label: str, key=None) -> Finding:
    if key is not None:
        alg, primitive, size = describe_public_key(key)
    else:
        alg = {"RSA PRIVATE KEY": "RSA", "EC PRIVATE KEY": "ECC", "DSA PRIVATE KEY": "DSA",
               "OPENSSH PRIVATE KEY": "SSH key", "ENCRYPTED PRIVATE KEY": "encrypted key"}.get(
            label, "unknown")
        primitive, size = "pke", None
    return Finding(
        rule_id="key.private-key",
        title="Private key file in repository",
        kind=Kind.SECRET,
        severity=Severity.HIGH,
        algorithm=alg,
        primitive=primitive,
        location=path,
        snippet=f"-----BEGIN {label}-----",
        context="key-file",
        detail=f"{alg} private key" + (f", {size} bits" if size else ""),
        remediation=REMEDIATION["secret"],
        extra={"key_size": size},
    )


def scan_key_file(path: str, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    blocks = list(PEM_BLOCK.finditer(data))
    n_certs = sum(1 for m in blocks if m.group(1) in (b"CERTIFICATE", b"TRUSTED CERTIFICATE"))
    bundle = n_certs > BUNDLE_THRESHOLD      # e.g. certifi's cacert.pem: summarise, don't list
    bundle_algs: dict[str, int] = {}
    cert_index = 0
    for m in blocks:
        label = m.group(1).decode()
        block = m.group(0)
        if label in ("CERTIFICATE", "TRUSTED CERTIFICATE"):
            try:
                cert = x509.load_pem_x509_certificate(block)
                if bundle:
                    try:
                        alg = describe_public_key(cert.public_key())[0]
                    except Exception:
                        alg = "unknown"
                    bundle_algs[alg] = bundle_algs.get(alg, 0) + 1
                else:
                    findings.extend(_cert_findings(path, cert, cert_index))
            except ValueError:
                pass
            cert_index += 1
        elif label.endswith("PRIVATE KEY"):
            key = None
            if label != "ENCRYPTED PRIVATE KEY":
                try:
                    if label == "OPENSSH PRIVATE KEY":
                        key = serialization.load_ssh_private_key(block, password=None)
                    else:
                        key = serialization.load_pem_private_key(block, password=None)
                except (ValueError, TypeError, Exception):
                    key = None
            findings.append(_private_key_finding(path, label, key))
        elif label in ("PUBLIC KEY", "RSA PUBLIC KEY"):
            try:
                key = serialization.load_pem_public_key(block)
                alg, primitive, size = describe_public_key(key)
            except Exception:
                alg, primitive, size = "unknown", "pke", None
            findings.append(Finding(
                rule_id="key.public-key", title="Public key file", kind=Kind.QUANTUM_KEY,
                severity=Severity.MEDIUM, algorithm=alg, primitive=primitive, location=path,
                snippet=f"-----BEGIN {label}-----", context="key-file",
                detail=f"{alg}" + (f", {size} bits" if size else ""),
                remediation=REMEDIATION["key"], extra={"key_size": size}))

    if bundle:
        summary = ", ".join(f"{n} {a}" for a, n in sorted(bundle_algs.items(), key=lambda x: -x[1]))
        findings.insert(0, Finding(
            rule_id="key.trust-bundle", title=f"CA trust bundle ({n_certs} certificates)",
            kind=Kind.INVENTORY, severity=Severity.INFO, algorithm="X.509 bundle",
            primitive="signature", location=path, context="key-file",
            detail=f"root certificates by key type: {summary}. Whoever ships the bundle "
                   "handles the migration; you just need to keep it updated.",
            remediation="Keep the bundle up to date (certifi or the OS package). Post-quantum "
                        "roots will come in through those updates.", quantum_level=None))

    if not blocks:
        # DER certificate?
        if path.lower().endswith((".der", ".cer", ".crt")):
            try:
                cert = x509.load_der_x509_certificate(data)
                findings.extend(_cert_findings(path, cert, 0))
            except ValueError:
                pass
        # SSH public keys (authorized_keys, *.pub, known_hosts)
        text = data.decode("utf-8", errors="ignore")
        for i, m in enumerate(SSH_PUB.finditer(text)):
            ktype = m.group(1)
            line = text.count("\n", 0, m.start()) + 1
            size = None
            try:
                key = serialization.load_ssh_public_key(f"{ktype} {m.group(2)}".encode())
                _, _, size = describe_public_key(key)
            except Exception:
                pass
            weak = ktype == "ssh-dss" or (ktype == "ssh-rsa" and size is not None and size < 2048)
            findings.append(Finding(
                rule_id="key.ssh-public-key", title="SSH public key", kind=Kind.QUANTUM_SIG,
                severity=Severity.HIGH if weak else Severity.MEDIUM, algorithm=ktype,
                primitive="signature", location=path, line=line,
                snippet=f"{ktype} {m.group(2)[:16]}...", context="key-file",
                detail=f"{ktype}" + (f", {size} bits" if size else "") +
                ("; classically weak (DSA or RSA < 2048)" if weak else ""),
                remediation=REMEDIATION["sig"], extra={"key_size": size}))
    return findings
