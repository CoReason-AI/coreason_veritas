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
import os
from typing import Any, Dict, Tuple
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from coreason_veritas.anchor import is_anchor_active
from coreason_veritas.exceptions import AssetTamperedError
from coreason_veritas.wrapper import governed_execution


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


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_success(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test the full flow of governed execution."""
    private_key, public_key_pem = key_pair

    # Set Env Var for Key Store
    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        payload = {"data": "secure"}
        signature = sign_payload(payload, private_key)

        # Mock IERLogger to avoid needing OTel setup (covered in other tests)
        # However, we want to verify the integration, so we'll mock the internal tracer
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_span = MagicMock()
            mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

            @governed_execution(asset_id_arg="spec", signature_arg="sig")
            async def protected_function(spec: Dict[str, Any], sig: str, other_arg: str) -> str:
                # Verify Anchor is active inside
                assert is_anchor_active() is True
                return f"Processed {other_arg}"

            result = await protected_function(spec=payload, sig=signature, other_arg="test")

            assert result == "Processed test"

            # Verify Auditor was called
            mock_tracer.start_as_current_span.assert_called_once()
            args, kwargs = mock_tracer.start_as_current_span.call_args
            assert args[0] == "protected_function"
            assert kwargs["attributes"]["co.asset_id"] == str(payload)
            # Anchor active check happens inside IERLogger.start_governed_span
            # We can't easily check it here without more mocking, but we checked is_anchor_active() inside the function.


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_tampered(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test that execution is blocked if signature fails."""
    private_key, public_key_pem = key_pair

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        payload = {"data": "secure"}
        signature = sign_payload(payload, private_key)
        tampered_payload = {"data": "hacked"}

        @governed_execution(asset_id_arg="spec", signature_arg="sig")
        async def protected_function(spec: Dict[str, Any], sig: str) -> str:
            return "Should not reach here"

        with pytest.raises(AssetTamperedError):
            await protected_function(spec=tampered_payload, sig=signature)


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_missing_key_store(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test failure if key store env var is missing."""
    private_key, _ = key_pair
    payload = {"data": "secure"}
    signature = sign_payload(payload, private_key)

    # Ensure env var is unset
    with patch.dict(os.environ, {}, clear=True):

        @governed_execution(asset_id_arg="spec", signature_arg="sig")
        async def protected_function(spec: Dict[str, Any], sig: str) -> str:
            return "Should not reach here"

        with pytest.raises(ValueError, match="COREASON_VERITAS_PUBLIC_KEY"):
            await protected_function(spec=payload, sig=signature)


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_missing_args(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test failure if required arguments are missing."""

    @governed_execution(asset_id_arg="spec", signature_arg="sig")
    async def protected_function(spec: Any, sig: Any) -> str:
        return "Should not reach here"

    with pytest.raises(ValueError, match="Missing signature argument"):
        await protected_function(spec={"a": 1})  # Missing sig

    with pytest.raises(ValueError, match="Missing asset argument"):
        await protected_function(sig="abc")  # Missing spec
