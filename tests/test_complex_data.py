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
from datetime import datetime, timezone
from typing import Any, Dict, Tuple
from unittest.mock import MagicMock, patch

import jcs
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from coreason_veritas.gatekeeper import SignatureValidator
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
    canonical_payload = jcs.canonicalize(payload)
    signature = private_key.sign(
        canonical_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return str(signature.hex())


def test_verify_deeply_nested_payload(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test verification of a deeply nested JSON payload."""
    private_key, public_key_pem = key_pair

    # Create nesting 100 levels deep
    depth = 100
    payload: Dict[str, Any] = {"level": "bottom"}
    for i in range(depth):
        payload = {f"level_{i}": payload}

    payload["timestamp"] = datetime.now(timezone.utc).isoformat()

    signature = sign_payload(payload, private_key)

    validator = SignatureValidator(public_key_pem)
    assert validator.verify_asset(payload, signature) is True


def test_verify_large_payload(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test verification of a large payload (approx 1MB)."""
    private_key, public_key_pem = key_pair

    # Create a large list of dicts
    # 1000 items, each item is approx 100 bytes -> 100KB
    # Let's go bigger: 10,000 items
    large_list = [{"id": i, "data": "x" * 50} for i in range(10000)]
    payload = {"data": large_list, "meta": "large_payload_test", "timestamp": datetime.now(timezone.utc).isoformat()}

    signature = sign_payload(payload, private_key)

    validator = SignatureValidator(public_key_pem)
    assert validator.verify_asset(payload, signature) is True


def test_verify_unicode_payload(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test verification of a payload containing various Unicode characters."""
    private_key, public_key_pem = key_pair

    # CJK, Emojis, Special Symbols
    payload = {
        "en": "Hello World",
        "jp": "こんにちは世界",
        "emoji": "👋 🌍 🚀",
        "symbols": "≤≥≠≈∞",
        "mixed": "A string with unique chars: \u00e9 \u00f1 \u00ae",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    signature = sign_payload(payload, private_key)

    validator = SignatureValidator(public_key_pem)
    assert validator.verify_asset(payload, signature) is True


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_heavy_data(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test governed execution with a heavy payload to ensure no timeout/blocking issues."""
    private_key, public_key_pem = key_pair

    # Create a reasonably heavy payload
    large_list = [{"id": i} for i in range(5000)]
    payload = {"data": large_list, "timestamp": datetime.now(timezone.utc).isoformat()}
    signature = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        # Mock OTel to avoid actual export overhead
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_span = MagicMock()
            mock_tracer.start_span.return_value = mock_span

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def process_data(spec: Dict[str, Any], sig: str, user: str) -> int:
                return len(spec["data"])

            result = await process_data(spec=payload, sig=signature, user="heavy-user")
            assert result == 5000
