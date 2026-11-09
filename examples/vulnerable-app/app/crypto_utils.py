"""Envelope encryption helpers (demo: classical-only on purpose)."""
import hashlib
import ssl

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def new_wrapping_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def wrap_data_key(public_key, data_key: bytes) -> bytes:
    return public_key.encrypt(
        data_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def sign_receipt(private_key, receipt: bytes) -> bytes:
    return private_key.sign(receipt, ec.ECDSA(hashes.SHA256()))


def session_secret(peer_public):
    me = X25519PrivateKey.generate()
    return me.exchange(peer_public)


def cache_key(payload: bytes) -> str:
    return hashlib.md5(payload).hexdigest()


def legacy_context():
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)
