"""Check a live TLS server.

First a normal handshake through Python's ``ssl`` module, which gives the
protocol version, cipher and certificate.

Then the hybrid post-quantum check. ``ssl`` doesn't expose the negotiated
group, so we send our own TLS 1.3 ClientHello that lists only the hybrid
groups and carries no key share. If the server supports one of them it has to
answer with a HelloRetryRequest naming it; if not, it sends a
handshake_failure alert. We never compute any ML-KEM ourselves, which is why
this works on old Python and OpenSSL versions too.

Last, unless told not to, we try TLS 1.0/1.1 to see if they're still on.
"""

from __future__ import annotations

import os
import socket
import ssl
import struct
import warnings
from dataclasses import dataclass, field

from cryptography import x509

from .keys import _cert_findings
from .models import Finding, Kind, ScanResult, Severity
from .rules import REMEDIATION

PQ_GROUPS = {
    0x11EC: "X25519MLKEM768",
    0x11EB: "SecP256r1MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00 (pre-standard)",
}
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167BBB8C5E079E09E2C8A8339C")
SIG_ALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808,
            0x0401, 0x0501, 0x0601]


@dataclass
class TlsReport:
    host: str
    port: int
    reachable: bool = False
    error: str = ""
    version: str = ""
    cipher: str = ""
    cert_verified: bool | None = None
    pq_group: str | None = None          # name of hybrid group the server selected
    pq_probe: str = "not run"            # supported | not supported | error: ...
    legacy_tls: bool | None = None
    findings: list[Finding] = field(default_factory=list)


# Raw ClientHello probe

def _ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(body)) + body


def build_client_hello(server_name: str | None, groups: list[int]) -> bytes:
    exts = b""
    if server_name and not _is_ip(server_name):
        name = server_name.encode("idna")
        entry = b"\x00" + struct.pack("!H", len(name)) + name
        exts += _ext(0x0000, struct.pack("!H", len(entry)) + entry)
    exts += _ext(0x002B, b"\x02\x03\x04")                                   # TLS 1.3 only
    g = b"".join(struct.pack("!H", x) for x in groups)
    exts += _ext(0x000A, struct.pack("!H", len(g)) + g)                      # supported_groups
    s = b"".join(struct.pack("!H", x) for x in SIG_ALGS)
    exts += _ext(0x000D, struct.pack("!H", len(s)) + s)                      # signature_algorithms
    exts += _ext(0x0033, b"\x00\x00")                                        # key_share: empty
    exts += _ext(0x002D, b"\x01\x01")                                        # psk_key_exchange_modes

    suites = struct.pack("!HHHH", 6, 0x1301, 0x1302, 0x1303)
    body = (b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32) + suites + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _is_ip(name: str) -> bool:
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, name)
            return True
        except OSError:
            pass
    return False


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed by server")
        buf += chunk
    return buf


def parse_server_response(data_reader) -> tuple[str, int | None]:
    """Return ('hrr'|'server_hello'|'alert', group). ``data_reader(n)`` returns n bytes."""
    header = data_reader(5)
    ctype, _ver, length = header[0], header[1:3], struct.unpack("!H", header[3:5])[0]
    payload = data_reader(length)
    if ctype == 0x15:
        return "alert", payload[1] if len(payload) > 1 else None
    if ctype != 0x16 or payload[0] != 0x02:
        return "unexpected", None
    p = payload[4:]
    random = p[2:34]
    sid_len = p[34]
    off = 35 + sid_len + 3            # session id, cipher suite (2), compression (1)
    ext_len = struct.unpack("!H", p[off:off + 2])[0]
    off += 2
    end = off + ext_len
    group = None
    while off + 4 <= end:
        etype, elen = struct.unpack("!HH", p[off:off + 4])
        ebody = p[off + 4:off + 4 + elen]
        if etype == 0x0033 and len(ebody) >= 2:
            group = struct.unpack("!H", ebody[:2])[0]
        off += 4 + elen
    return ("hrr" if random == HRR_RANDOM else "server_hello"), group


def probe_pq_groups(host: str, port: int, timeout: float, sni: str | None) -> tuple[str, int | None]:
    hello = build_client_hello(sni or host, list(PQ_GROUPS))
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(hello)
        return parse_server_response(lambda n: _recv_exact(sock, n))


# Standard handshake

def _handshake(host, port, timeout, sni, verify: bool, max_version=None):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if max_version is not None:
        with warnings.catch_warnings():          # deliberately probing deprecated versions
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = max_version
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni or host) as tls:
            return tls.version(), tls.cipher(), tls.getpeercert(binary_form=True)


def check_endpoint(target: str, timeout: float = 8.0, sni: str | None = None,
                   check_legacy: bool = True) -> TlsReport:
    host, port = _split_target(target)
    rep = TlsReport(host, port)
    loc = f"tls://{host}:{port}"

    der = None
    try:
        try:
            rep.version, cipher, der = _handshake(host, port, timeout, sni, verify=True)
            rep.cert_verified = True
        except ssl.SSLCertVerificationError:
            rep.version, cipher, der = _handshake(host, port, timeout, sni, verify=False)
            rep.cert_verified = False
        rep.cipher = cipher[0] if cipher else ""
        rep.reachable = True
    except (OSError, ssl.SSLError) as exc:
        rep.error = f"{type(exc).__name__}: {exc}"
        return rep

    # --- post-quantum hybrid key exchange ---
    try:
        kind, group = probe_pq_groups(host, port, timeout, sni)
        if kind in ("hrr", "server_hello") and group in PQ_GROUPS:
            rep.pq_group = PQ_GROUPS[group]
            rep.pq_probe = "supported"
        elif kind == "alert":
            rep.pq_probe = "not supported"
        else:
            rep.pq_probe = f"inconclusive ({kind})"
    except (OSError, ConnectionError, IndexError, struct.error) as exc:
        rep.pq_probe = f"error: {exc}"

    if rep.pq_probe == "supported":
        pre_standard = "pre-standard" in (rep.pq_group or "")
        rep.findings.append(Finding(
            rule_id="tls.pq-hybrid", title="Post-quantum hybrid key exchange supported",
            kind=Kind.PQC, severity=Severity.LOW if pre_standard else Severity.INFO,
            algorithm=rep.pq_group or "", primitive="kem", location=loc, context="endpoint",
            detail=f"server selected {rep.pq_group} when only hybrid groups were offered"
                   + ("; that's the old Kyber draft, X25519MLKEM768 replaced it"
                      if pre_standard else ""),
            remediation=REMEDIATION["pqc"], quantum_level=3))
    else:
        unknown = rep.pq_probe != "not supported"
        rep.findings.append(Finding(
            rule_id="tls.classical-kex",
            title="Classical-only TLS key exchange" if not unknown
            else "Post-quantum key exchange support unknown",
            kind=Kind.QUANTUM_KEX, severity=Severity.MEDIUM if unknown else Severity.HIGH,
            algorithm="ECDHE/DHE", primitive="key-agree", location=loc, context="endpoint",
            confidence="low" if unknown else "high",
            detail=f"{rep.version} {rep.cipher}; hybrid probe: {rep.pq_probe}",
            remediation=REMEDIATION["kex"]))

    # --- certificate ---
    if der:
        try:
            cert = x509.load_der_x509_certificate(der)
            for f in _cert_findings(loc, cert, 0):
                f.context = "endpoint"
                f.title = f.title.replace("X.509 certificate", "Server certificate")
                if rep.cert_verified is False:
                    f.detail += "; the certificate didn't verify against the system trust store"
                rep.findings.append(f)
        except ValueError:
            pass

    # --- legacy protocol versions ---
    if check_legacy:
        try:
            v, _, _ = _handshake(host, port, timeout, sni, verify=False,
                                 max_version=ssl.TLSVersion.TLSv1_1)
            rep.legacy_tls = True
            rep.findings.append(Finding(
                rule_id="tls.legacy-version", title=f"Server accepts {v}",
                kind=Kind.CLASSICAL_WEAK, severity=Severity.MEDIUM, algorithm=v or "TLS1.0/1.1",
                primitive="other", location=loc, context="endpoint",
                detail="TLS 1.0/1.1 are deprecated (RFC 8996)", remediation=REMEDIATION["weak"]))
        except (OSError, ssl.SSLError, ValueError):
            rep.legacy_tls = False
    return rep


def _split_target(target: str) -> tuple[str, int]:
    t = target.strip()
    for prefix in ("https://", "tls://"):
        if t.startswith(prefix):
            t = t[len(prefix):]
    t = t.split("/", 1)[0]
    if t.startswith("["):                      # [ipv6]:port
        host, _, rest = t[1:].partition("]")
        return host, int(rest.lstrip(":") or 443)
    if t.count(":") == 1:
        host, port = t.split(":")
        return host, int(port)
    return t, 443


def scan_endpoints(targets: list[str], timeout: float = 8.0, check_legacy: bool = True) -> ScanResult:
    result = ScanResult(target=", ".join(targets), unit="endpoints")
    for t in targets:
        rep = check_endpoint(t, timeout=timeout, check_legacy=check_legacy)
        if not rep.reachable:
            result.errors.append(f"{t}: {rep.error}")
            continue
        result.files_scanned += 1
        result.findings.extend(rep.findings)
    return result
