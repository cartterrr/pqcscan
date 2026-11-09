from cryptography.hazmat.primitives.asymmetric import rsa


def test_wrap_roundtrip():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert key.key_size == 2048
