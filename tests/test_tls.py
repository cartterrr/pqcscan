"""TLS probe tests against local servers (no network needed)."""

import datetime as dt
import socket
import ssl
import struct
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pqcscan.tls import (HRR_RANDOM, _split_target, build_client_hello, check_endpoint,
                         parse_server_response)


def _supports_hybrid() -> bool:
    """Does the local OpenSSL (used by the test server) know X25519MLKEM768?"""
    return ssl.OPENSSL_VERSION_INFO >= (3, 5)


@pytest.fixture(scope="module")
def cert_files(tmp_path_factory):
    d = tmp_path_factory.mktemp("tls")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(7)
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=90)).sign(key, hashes.SHA256()))
    (d / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    return str(d / "c.pem"), str(d / "k.pem")


def _serve(cert_files, classical_only: bool) -> int:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*cert_files)
    if classical_only:
        ctx.set_ecdh_curve("X25519")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                ctx.wrap_socket(conn, server_side=True).close()
            except (ssl.SSLError, OSError):
                conn.close()

    threading.Thread(target=loop, daemon=True).start()
    return port


@pytest.mark.skipif(not _supports_hybrid(), reason="needs OpenSSL 3.5+ for the test server")
def test_hybrid_server_detected(cert_files):
    port = _serve(cert_files, classical_only=False)
    rep = check_endpoint(f"127.0.0.1:{port}", timeout=5)
    assert rep.reachable and rep.version == "TLSv1.3"
    assert rep.pq_probe == "supported" and rep.pq_group == "X25519MLKEM768"
    assert "tls.pq-hybrid" in {f.rule_id for f in rep.findings}


def test_classical_server_flagged(cert_files):
    port = _serve(cert_files, classical_only=True)
    rep = check_endpoint(f"127.0.0.1:{port}", timeout=5)
    assert rep.pq_probe == "not supported"
    kex = next(f for f in rep.findings if f.rule_id == "tls.classical-kex")
    assert kex.severity.value == "high"
    cert = next(f for f in rep.findings if f.rule_id == "key.certificate")
    assert cert.algorithm == "ECDSA-secp256r1"
    assert rep.legacy_tls is False


def test_unreachable_endpoint():
    rep = check_endpoint("127.0.0.1:1", timeout=1)
    assert not rep.reachable and rep.error


def test_client_hello_is_well_formed():
    hello = build_client_hello("example.com", [0x11EC])
    assert hello[0] == 0x16 and struct.unpack("!H", hello[3:5])[0] == len(hello) - 5
    assert b"example.com" in hello
    assert build_client_hello("10.0.0.1", [0x11EC]).find(b"10.0.0.1") == -1   # no SNI for IPs


def test_parse_hello_retry_request():
    exts = struct.pack("!HHH", 0x002B, 2, 0x0304) + struct.pack("!HHH", 0x0033, 2, 0x11EC)
    sh = (b"\x03\x03" + HRR_RANDOM + b"\x00" + b"\x13\x01" + b"\x00"
          + struct.pack("!H", len(exts)) + exts)
    hs = b"\x02" + struct.pack("!I", len(sh))[1:] + sh
    record = b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs
    buf = bytearray(record)

    def reader(n):
        out = bytes(buf[:n])
        del buf[:n]
        return out
    assert parse_server_response(reader) == ("hrr", 0x11EC)


@pytest.mark.parametrize("target,expected", [
    ("example.com", ("example.com", 443)),
    ("https://example.com/path", ("example.com", 443)),
    ("example.com:8443", ("example.com", 8443)),
    ("[::1]:9443", ("::1", 9443)),
])
def test_split_target(target, expected):
    assert _split_target(target) == expected
