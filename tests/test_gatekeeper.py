# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Tuple

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
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
    """Helper to sign a payload using JWS (PyJWT)."""
    # PyJWT expects the key as bytes in PEM format or an object.
    # We can pass the private_key object directly.
    return jwt.encode(payload, private_key, algorithm="RS256")


def test_verify_asset_success(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test successful verification of a valid signature."""
    private_key, public_key_pem = key_pair
    # Add timestamp for replay protection
    payload = {"agent": "veritas", "version": 1, "timestamp": datetime.now(timezone.utc).isoformat()}
    signature = sign_payload(payload, private_key)

    validator = SignatureValidator(public_key_pem)
    assert validator.verify_asset(payload, signature) is True


def test_verify_asset_tampered_payload(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test verification fails when payload is modified."""
    private_key, public_key_pem = key_pair
    payload = {"agent": "veritas", "version": 1, "timestamp": datetime.now(timezone.utc).isoformat()}
    signature = sign_payload(payload, private_key)

    # Modify payload (timestamp also matches but other fields tampered)
    tampered_payload = {"agent": "veritas", "version": 2, "timestamp": payload["timestamp"]}

    validator = SignatureValidator(public_key_pem)
    with pytest.raises(AssetTamperedError) as excinfo:
        validator.verify_asset(tampered_payload, signature)
    # The error might be "Signature verification failed" or "Payload mismatch" wrapped in AssetTamperedError
    assert "Signature verification failed" in str(excinfo.value)


def test_verify_asset_invalid_signature(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test verification fails with an invalid signature string."""
    _, public_key_pem = key_pair
    payload = {"agent": "veritas", "timestamp": datetime.now(timezone.utc).isoformat()}

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

    payload = {"agent": "veritas", "timestamp": datetime.now(timezone.utc).isoformat()}
    # Signed with Key 2
    signature = sign_payload(payload, private_key_2)

    # Verified with Key 1
    validator = SignatureValidator(public_key_pem_1)
    with pytest.raises(AssetTamperedError):
        validator.verify_asset(payload, signature)


def test_verify_asset_malformed_key() -> None:
    """Test initialization fails with a malformed public key."""
    with pytest.raises(ValueError, match="Invalid public key provided"):
        SignatureValidator("not-a-pem-key")


def test_verify_asset_complex_nested_payload(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test verification of a deeply nested and complex JSON payload.
    Ensures that canonicalization works consistently for complex structures.
    """
    private_key, public_key_pem = key_pair

    # Complex payload with lists, nested dicts, different types
    payload = {
        "agent": "complex_veritas",
        "config": {
            "parameters": {"temperature": 0.0, "stop_sequences": ["\n", "User:"], "max_tokens": 1024},
            "tools": [
                {"name": "calculator", "enabled": True},
                {"name": "search", "enabled": False, "details": {"provider": "google"}},
            ],
        },
        "metadata": {"version": 2, "tags": ["gxp", "audit"], "extra": None},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    signature = sign_payload(payload, private_key)

    validator = SignatureValidator(public_key_pem)
    assert validator.verify_asset(payload, signature) is True

    # Verify that changing order of keys in dict (logic-wise same, but python dicts are ordered)
    # or ensuring stability is handled by json.dumps(sort_keys=True)

    # Create a new dict with same data but inserted in different order (if possible to simulate)
    # Python 3.7+ preserves insertion order, so we can try constructing it differently.

    payload_reordered = {}
    payload_reordered["metadata"] = payload["metadata"]
    payload_reordered["agent"] = payload["agent"]
    payload_reordered["config"] = payload["config"]
    payload_reordered["timestamp"] = payload["timestamp"]

    assert validator.verify_asset(payload_reordered, signature) is True


def test_verify_asset_empty_payload(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test verification of an empty dictionary payload (plus timestamp)."""
    private_key, public_key_pem = key_pair
    # Even 'empty' payload requires timestamp for replay protection
    payload = {"timestamp": datetime.now(timezone.utc).isoformat()}
    signature = sign_payload(payload, private_key)

    validator = SignatureValidator(public_key_pem)
    assert validator.verify_asset(payload, signature) is True


def test_verify_asset_none_values(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test verification of a payload containing None values."""
    private_key, public_key_pem = key_pair
    payload = {"key": None, "nested": {"inner": None}, "timestamp": datetime.now(timezone.utc).isoformat()}
    signature = sign_payload(payload, private_key)

    validator = SignatureValidator(public_key_pem)
    assert validator.verify_asset(payload, signature) is True


def test_verify_asset_whitespace_key(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test verification with a public key containing extra whitespace."""
    private_key, public_key_pem = key_pair
    payload = {"agent": "veritas", "timestamp": datetime.now(timezone.utc).isoformat()}
    signature = sign_payload(payload, private_key)

    # Add extra newlines and spaces to the key
    messy_key = f"\n  {public_key_pem}  \n\n"
    validator = SignatureValidator(messy_key)
    assert validator.verify_asset(payload, signature) is True


def test_verify_asset_malformed_signature(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test verification fails with a malformed JWS."""
    _, public_key_pem = key_pair
    payload = {"agent": "veritas", "timestamp": datetime.now(timezone.utc).isoformat()}

    validator = SignatureValidator(public_key_pem)
    with pytest.raises(AssetTamperedError) as excinfo:
        validator.verify_asset(payload, "invalid.jws.token")
    assert "Signature verification failed" in str(excinfo.value)


def test_verify_asset_replay_missing_timestamp(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test failure when timestamp is missing."""
    private_key, public_key_pem = key_pair
    payload = {"agent": "veritas"}
    signature = sign_payload(payload, private_key)

    validator = SignatureValidator(public_key_pem)
    with pytest.raises(AssetTamperedError, match="Missing 'timestamp' in payload"):
        validator.verify_asset(payload, signature)


def test_verify_asset_replay_old_timestamp(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test failure when timestamp is too old."""
    private_key, public_key_pem = key_pair
    old_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    payload = {"agent": "veritas", "timestamp": old_time.isoformat()}
    signature = sign_payload(payload, private_key)

    validator = SignatureValidator(public_key_pem)
    with pytest.raises(AssetTamperedError, match="Timestamp out of bounds"):
        validator.verify_asset(payload, signature)


def test_verify_asset_malformed_timestamp(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test failure when timestamp is malformed."""
    private_key, public_key_pem = key_pair
    payload = {"agent": "veritas", "timestamp": "invalid-date"}
    signature = sign_payload(payload, private_key)

    validator = SignatureValidator(public_key_pem)
    with pytest.raises(AssetTamperedError, match="Invalid 'timestamp' format"):
        validator.verify_asset(payload, signature)


def test_verify_asset_naive_timestamp(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test verification with a naive timestamp (should be treated as UTC)."""
    private_key, public_key_pem = key_pair
    # Naive timestamp (no Z or offset)
    naive_ts = datetime.now().isoformat()
    payload = {"agent": "veritas", "timestamp": naive_ts}
    signature = sign_payload(payload, private_key)

    validator = SignatureValidator(public_key_pem)
    # This should succeed if timezone is added correctly inside, assuming local time vs UTC handling is robust.
    # Note: datetime.now() returns local time if not timezone aware.
    # If the code assumes input is UTC when naive, datetime.now() might be offset.
    # Safe bet: datetime.utcnow().isoformat() (deprecated but returns naive UTC)
    # or datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

    # Let's ensure it passes by using a recent naive UTC time.
    naive_utc = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    payload["timestamp"] = naive_utc
    signature = sign_payload(payload, private_key)

    assert validator.verify_asset(payload, signature) is True


def test_verify_asset_replay_future_timestamp(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test failure when timestamp is too far in future."""
    private_key, public_key_pem = key_pair
    future_time = datetime.now(timezone.utc) + timedelta(minutes=10)
    payload = {"agent": "veritas", "timestamp": future_time.isoformat()}
    signature = sign_payload(payload, private_key)

    validator = SignatureValidator(public_key_pem)
    with pytest.raises(AssetTamperedError, match="Timestamp out of bounds"):
        validator.verify_asset(payload, signature)
