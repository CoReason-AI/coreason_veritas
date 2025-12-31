import jcs
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


@pytest.fixture(scope="session")
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def public_key(private_key):
    return private_key.public_key()


@pytest.fixture(scope="session")
def pem_public(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


@pytest.fixture
def sign_payload_func(private_key):
    def _sign(payload, p_key=None):
        key_to_use = p_key or private_key
        canonical = jcs.canonicalize(payload)
        signature = key_to_use.sign(
            canonical,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return signature.hex()

    return _sign
