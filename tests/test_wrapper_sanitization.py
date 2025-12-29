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
from typing import Any, AsyncGenerator, Dict, Generator, Tuple
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from coreason_veritas.wrapper import governed_execution


@pytest.fixture  # type: ignore[misc]
def mock_keys() -> Tuple[RSAPrivateKey, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_key, pem_public


def sign_payload(payload: Dict[str, Any], private_key: RSAPrivateKey) -> str:
    """Helper to sign a payload."""
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = private_key.sign(
        canonical_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return str(signature.hex())


@pytest.fixture  # type: ignore[misc]
def mock_env(mock_keys: Tuple[RSAPrivateKey, str]) -> Generator[RSAPrivateKey, None, None]:
    private_key, pem_public = mock_keys
    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": pem_public}):
        with patch("coreason_veritas.wrapper.IERLogger") as mock_logger:
            # Mock Logger
            mock_span = MagicMock()
            mock_logger.return_value.start_governed_span.return_value.__enter__.return_value = mock_span
            yield private_key


@pytest.mark.asyncio  # type: ignore[misc]
async def test_wrapper_sanitization_async(mock_env: RSAPrivateKey) -> None:
    """Test sanitization in async function."""
    private_key = mock_env
    unsafe_config = {"temperature": 0.9, "top_p": 0.5, "seed": 123}
    spec = {"id": "1"}
    sig = sign_payload(spec, private_key)

    @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user", config_arg="config")
    async def run_agent(spec: Dict[str, Any], sig: str, user: str, config: Dict[str, Any]) -> Dict[str, Any]:
        return config

    result = await run_agent(spec=spec, sig=sig, user="u1", config=unsafe_config)

    assert result["temperature"] == 0.0
    assert result["top_p"] == 1.0
    assert result["seed"] == 42
    # Ensure original didn't change (shallow copy behavior checked in unit tests, but good to know)
    assert unsafe_config["temperature"] == 0.9


def test_wrapper_sanitization_sync(mock_env: RSAPrivateKey) -> None:
    """Test sanitization in sync function."""
    private_key = mock_env
    unsafe_config = {"temperature": 0.9}
    spec = {"id": "1"}
    sig = sign_payload(spec, private_key)

    @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user", config_arg="config")
    def run_agent(spec: Dict[str, Any], sig: str, user: str, config: Dict[str, Any]) -> Dict[str, Any]:
        return config

    result = run_agent(spec=spec, sig=sig, user="u1", config=unsafe_config)

    assert result["temperature"] == 0.0


@pytest.mark.asyncio  # type: ignore[misc]
async def test_wrapper_sanitization_async_gen(mock_env: RSAPrivateKey) -> None:
    """Test sanitization in async generator."""
    private_key = mock_env
    unsafe_config = {"temperature": 0.9}
    spec = {"id": "1"}
    sig = sign_payload(spec, private_key)

    @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user", config_arg="config")
    async def run_agent(
        spec: Dict[str, Any], sig: str, user: str, config: Dict[str, Any]
    ) -> AsyncGenerator[Dict[str, Any], None]:
        yield config

    async for result in run_agent(spec=spec, sig=sig, user="u1", config=unsafe_config):
        assert result["temperature"] == 0.0


def test_wrapper_sanitization_sync_gen(mock_env: RSAPrivateKey) -> None:
    """Test sanitization in sync generator."""
    private_key = mock_env
    unsafe_config = {"temperature": 0.9}
    spec = {"id": "1"}
    sig = sign_payload(spec, private_key)

    @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user", config_arg="config")
    def run_agent(
        spec: Dict[str, Any], sig: str, user: str, config: Dict[str, Any]
    ) -> Generator[Dict[str, Any], None, None]:
        yield config

    for result in run_agent(spec=spec, sig=sig, user="u1", config=unsafe_config):
        assert result["temperature"] == 0.0
