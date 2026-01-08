# Copyright (c) 2025 CoReason, Inc.

from typing import Tuple
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from coreason_veritas.gatekeeper import SignatureValidator

@pytest.fixture
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

def test_get_policy_instruction_for_llm(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test that get_policy_instruction_for_llm returns the expected policies."""
    _, public_key_pem = key_pair
    validator = SignatureValidator(public_key_pem)

    policies = validator.get_policy_instruction_for_llm()

    assert isinstance(policies, list)
    assert "No use of 'eval'" in policies
    assert len(policies) == 1
