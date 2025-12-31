from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from coreason_veritas.exceptions import AssetTamperedError
from coreason_veritas.gatekeeper import SignatureValidator


def test_signature_validator_init_invalid_key():
    """Test initialization with an invalid public key."""
    with pytest.raises(ValueError, match="Invalid public key provided"):
        SignatureValidator("INVALID_KEY_STRING")


def test_verify_asset_missing_timestamp(pem_public, sign_payload_func):
    """Test verification when timestamp is missing."""
    validator = SignatureValidator(pem_public)
    payload = {"data": "test"}
    sig = sign_payload_func(payload)

    with pytest.raises(AssetTamperedError, match="Missing 'timestamp' in payload"):
        validator.verify_asset(payload, sig)


def test_verify_asset_invalid_timestamp_format(pem_public, sign_payload_func):
    """Test verification with malformed timestamp."""
    validator = SignatureValidator(pem_public)
    payload = {"data": "test", "timestamp": "not-a-date"}
    sig = sign_payload_func(payload)

    with pytest.raises(AssetTamperedError, match="Invalid 'timestamp' format"):
        validator.verify_asset(payload, sig)


def test_verify_asset_timestamp_too_old(pem_public, sign_payload_func):
    """Test verification with expired timestamp."""
    validator = SignatureValidator(pem_public)
    old_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    payload = {"data": "test", "timestamp": old_time}
    sig = sign_payload_func(payload)

    with pytest.raises(AssetTamperedError, match="Timestamp out of bounds"):
        validator.verify_asset(payload, sig)


def test_verify_asset_timestamp_future(pem_public, sign_payload_func):
    """Test verification with future timestamp (clock skew)."""
    validator = SignatureValidator(pem_public)
    future_time = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    payload = {"data": "test", "timestamp": future_time}
    sig = sign_payload_func(payload)

    with pytest.raises(AssetTamperedError, match="Timestamp out of bounds"):
        validator.verify_asset(payload, sig)


def test_verify_asset_wrong_signature(pem_public, sign_payload_func):
    """Test verification with signature from different key."""
    other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    validator = SignatureValidator(pem_public)

    payload = {"data": "test", "timestamp": datetime.now(timezone.utc).isoformat()}
    # Sign with WRONG key
    sig = sign_payload_func(payload, p_key=other_private_key)

    with pytest.raises(AssetTamperedError, match="Signature verification failed"):
        validator.verify_asset(payload, sig)


def test_verify_asset_malformed_signature_string(pem_public):
    """Test verification with non-hex signature string."""
    validator = SignatureValidator(pem_public)
    payload = {"data": "test", "timestamp": datetime.now(timezone.utc).isoformat()}

    with pytest.raises(AssetTamperedError, match="Signature verification failed"):
        validator.verify_asset(payload, "not-hex-string")


def test_verify_asset_large_payload(pem_public, sign_payload_func):
    """Test verification with a large payload."""
    validator = SignatureValidator(pem_public)
    large_data = "x" * 1000000  # 1MB string
    payload = {"data": large_data, "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload_func(payload)

    assert validator.verify_asset(payload, sig) is True


def test_verify_asset_nested_json(pem_public, sign_payload_func):
    """Test verification with deeply nested JSON."""
    validator = SignatureValidator(pem_public)
    nested = {"a": {"b": {"c": [1, 2, {"d": "val"}]}}}
    payload = {"structure": nested, "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload_func(payload)

    assert validator.verify_asset(payload, sig) is True


def test_verify_asset_unicode_characters(pem_public, sign_payload_func):
    """Test verification with Unicode characters."""
    validator = SignatureValidator(pem_public)
    payload = {"data": "こんにちは", "emoji": "👍", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload_func(payload)

    assert validator.verify_asset(payload, sig) is True


def test_verify_asset_naive_timestamp_assumed_utc(pem_public, sign_payload_func):
    """Test that naive timestamp is assumed UTC and accepted if within range."""
    validator = SignatureValidator(pem_public)
    # create naive datetime representing now (UTC)
    naive_now = datetime.utcnow()
    payload = {"data": "test", "timestamp": naive_now.isoformat()}
    sig = sign_payload_func(payload)

    # This might fail if the code doesn't handle naive correctly, but the code says:
    # if ts.tzinfo is None: ts = ts.replace(tzinfo=timezone.utc)
    # So it should pass if we construct it to match UTC now
    assert validator.verify_asset(payload, sig) is True
