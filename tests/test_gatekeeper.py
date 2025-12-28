# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import json
from typing import Any, Dict, Tuple

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from coreason_veritas.exceptions import AssetTamperedError
from coreason_veritas.gatekeeper import SignatureValidator


@pytest.fixture  # type: ignore[misc]
def key_pair() -> Tuple[RSAPrivateKey, str]:
    """Generates a private/public key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return private_key, pem_public


def sign_payload(payload: Dict[str, Any], private_key: RSAPrivateKey) -> str:
    """Helper to sign a payload."""
    canonical_payload = json.dumps(payload, sort_keys=True).encode()
    signature = private_key.sign(
        canonical_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return str(signature.hex())


def test_verify_asset_success(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test successful verification of a valid signature."""
    private_key, public_key_pem = key_pair
    payload = {"agent": "veritas", "version": 1}
    signature = sign_payload(payload, private_key)

    validator = SignatureValidator(public_key_pem)
    assert validator.verify_asset(payload, signature) is True


def test_verify_asset_tampered_payload(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test verification fails when payload is modified."""
    private_key, public_key_pem = key_pair
    payload = {"agent": "veritas", "version": 1}
    signature = sign_payload(payload, private_key)

    # Modify payload
    tampered_payload = {"agent": "veritas", "version": 2}

    validator = SignatureValidator(public_key_pem)
    with pytest.raises(AssetTamperedError) as excinfo:
        validator.verify_asset(tampered_payload, signature)
    assert "Signature verification failed" in str(excinfo.value)


def test_verify_asset_invalid_signature(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test verification fails with an invalid signature string."""
    _, public_key_pem = key_pair
    payload = {"agent": "veritas"}

    validator = SignatureValidator(public_key_pem)
    with pytest.raises(AssetTamperedError):
        validator.verify_asset(payload, "deadbeef")  # Invalid hex/signature


def test_verify_asset_wrong_key(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test verification fails when signed with a different key."""
    # Key 1
    _, public_key_pem_1 = key_pair

    # Key 2
    private_key_2 = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    payload = {"agent": "veritas"}
    # Signed with Key 2
    signature = sign_payload(payload, private_key_2)

    # Verified with Key 1
    validator = SignatureValidator(public_key_pem_1)
    with pytest.raises(AssetTamperedError):
        validator.verify_asset(payload, signature)


def test_verify_asset_malformed_key() -> None:
    """Test initialization/verification with a malformed public key."""
    validator = SignatureValidator("not-a-pem-key")
    with pytest.raises(AssetTamperedError):
        validator.verify_asset({"a": 1}, "deadbeef")
