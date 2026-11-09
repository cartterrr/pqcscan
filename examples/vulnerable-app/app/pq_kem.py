"""Experimental post-quantum key encapsulation (liboqs-python)."""
import oqs


def encapsulate(public_key: bytes):
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        return kem.encap_secret(public_key)
