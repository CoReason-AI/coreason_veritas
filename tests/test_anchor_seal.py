import os
import pytest
from coreason_veritas.anchor import DeterminismInterceptor
from coreason_veritas.gatekeeper import SignatureValidator
from coreason_veritas.exceptions import AssetTamperedError
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone

def test_seal_missing_key(monkeypatch):
    """Test that seal raises error if private key env var is missing."""
    interceptor = DeterminismInterceptor()
    # Ensure env var is unset using monkeypatch
    monkeypatch.delenv("COREASON_VERITAS_PRIVATE_KEY", raising=False)

    with pytest.raises(ValueError, match="COREASON_VERITAS_PRIVATE_KEY environment variable is not set"):
        interceptor.seal({"foo": "bar"})

def test_seal_success(monkeypatch, private_key, pem_public):
    """Test that seal produces a valid signature."""
    # Serialize private key to PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    # Set env var using monkeypatch
    monkeypatch.setenv("COREASON_VERITAS_PRIVATE_KEY", private_pem)

    interceptor = DeterminismInterceptor()
    # Use current timestamp for successful verification
    payload = {"foo": "bar", "timestamp": datetime.now(timezone.utc).isoformat()}

    signature = interceptor.seal(payload)
    assert isinstance(signature, str)
    assert len(signature) > 0

    # Verify the signature using SignatureValidator
    validator = SignatureValidator(pem_public)
    assert validator.verify_asset(payload, signature)

def test_seal_tampered(monkeypatch, private_key, pem_public):
    """Test that tampered payload fails verification."""
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    monkeypatch.setenv("COREASON_VERITAS_PRIVATE_KEY", private_pem)

    interceptor = DeterminismInterceptor()
    payload = {"foo": "bar", "timestamp": datetime.now(timezone.utc).isoformat()}

    signature = interceptor.seal(payload)

    # Tamper with payload
    payload["foo"] = "baz"

    validator = SignatureValidator(pem_public)
    with pytest.raises(AssetTamperedError):
        validator.verify_asset(payload, signature)

def test_load_private_key_fail(monkeypatch):
    """Test that loading an invalid private key logs an error but does not raise."""
    monkeypatch.setenv("COREASON_VERITAS_PRIVATE_KEY", "invalid_key")

    # This should not raise
    interceptor = DeterminismInterceptor()
    assert interceptor._private_key is None

    # But seal should raise
    with pytest.raises(ValueError, match="COREASON_VERITAS_PRIVATE_KEY environment variable is not set or invalid"):
        interceptor.seal({"foo": "bar"})
