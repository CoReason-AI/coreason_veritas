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
from coreason_veritas.anchor import DeterminismInterceptor, is_anchor_active
from coreason_veritas.auditor import IERLogger
from coreason_veritas.wrapper import governed_execution
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from loguru import logger


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


def sign_payload(payload: Dict[str, Any], private_key: RSAPrivateKey) -> str:
    """Helper to sign a payload."""
    canonical_payload = json.dumps(payload, sort_keys=True).encode()
    signature = private_key.sign(
        canonical_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return str(signature.hex())


@pytest.mark.asyncio
async def test_nested_governed_execution(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test nested governed execution to verify side effects:
    1. Span creation for both outer and inner functions.
    2. co.determinism_verified state (False for outer, True for inner).
    3. Anchor activation maintenance.
    """
    private_key, public_key_pem = key_pair
    payload = {"data": "nested_test"}
    signature = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            # Setup Mock Tracer
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer

            # We need to capture the spans to inspect their attributes
            # The wrapper calls: with tracer.start_as_current_span(...) as span:

            # To do this robustly with mocks, we can inspect the `start_as_current_span` call args.

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def inner_task(spec: Dict[str, Any], sig: str, user: str) -> bool:
                # Inside inner task, anchor should be active
                return is_anchor_active()

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def outer_task(spec: Dict[str, Any], sig: str, user: str) -> bool:
                # Inside outer task, anchor should be active
                outer_active = is_anchor_active()
                inner_active = await inner_task(spec=spec, sig=sig, user=user)
                return outer_active and inner_active

            # Execute
            result = await outer_task(spec=payload, sig=signature, user="nested-user")

            assert result is True, "Anchor should be active in both scopes"

            # Verify Spans
            # We expect 2 calls to start_as_current_span
            assert mock_tracer.start_as_current_span.call_count == 2

            calls = mock_tracer.start_as_current_span.call_args_list

            # The calls happen in order: Outer, then Inner.
            outer_call = calls[0]
            inner_call = calls[1]

            # Check Outer Attributes
            # Outer: Called BEFORE anchor scope, so determinism_verified should be "False"
            outer_attrs = outer_call.kwargs['attributes']
            assert outer_attrs['co.asset_id'] == str(payload)
            assert outer_attrs['co.determinism_verified'] == 'False'

            # Check Inner Attributes
            # Inner: Called INSIDE outer's anchor scope, so determinism_verified should be "True"
            inner_attrs = inner_call.kwargs['attributes']
            assert inner_attrs['co.asset_id'] == str(payload)
            assert inner_attrs['co.determinism_verified'] == 'True'


@pytest.mark.asyncio
async def test_exception_state_recovery(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test that the anchor state is correctly reset when a governed function raises an exception.
    """
    private_key, public_key_pem = key_pair
    payload = {"data": "fail_test"}
    signature = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer"): # Mock to suppress actual OTel

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def failing_task(spec: Dict[str, Any], sig: str, user: str) -> None:
                raise ValueError("Intentional Failure")

            # Ensure we are not active before
            assert not is_anchor_active()

            with pytest.raises(ValueError, match="Intentional Failure"):
                await failing_task(spec=payload, sig=signature, user="fail-user")

            # Ensure we are not active after
            assert not is_anchor_active()


def test_audit_attribute_enforcement() -> None:
    """
    Test that IERLogger strictly enforces mandatory attributes.
    """
    logger = IERLogger()

    # Missing all mandatory attributes
    with pytest.raises(ValueError, match="Audit Failure: Missing mandatory attributes"):
        with logger.start_governed_span("test_span", attributes={"optional": "val"}):
            pass

    # Missing one mandatory attribute (e.g., co.srb_sig)
    with pytest.raises(ValueError, match="Audit Failure: Missing mandatory attributes"):
        attributes = {
            "co.user_id": "u1",
            "co.asset_id": "a1",
            # "co.srb_sig" missing
        }
        with logger.start_governed_span("test_span", attributes=attributes):
            pass

    # Success case
    with patch("coreason_veritas.auditor.trace.get_tracer"): # Suppress OTel
        attributes = {
            "co.user_id": "u1",
            "co.asset_id": "a1",
            "co.srb_sig": "s1",
        }
        with logger.start_governed_span("test_span", attributes=attributes):
            pass


def test_anchor_config_enforcement() -> None:
    """
    Test the 'Lobotomy' Protocol enforcement in DeterminismInterceptor.
    """
    # Setup Log Capture
    logs = []
    handler_id = logger.add(lambda msg: logs.append(msg), format="{message}", level="WARNING")

    try:
        interceptor = DeterminismInterceptor()

        # Unsafe Config
        unsafe_config = {
            "temperature": 0.9,
            "top_p": 0.5,
            "seed": 12345,
            "model": "gpt-4",  # Should be preserved
        }

        sanitized = interceptor.enforce_config(unsafe_config)

        # Check Enforcements
        assert sanitized["temperature"] == 0.0
        assert sanitized["top_p"] == 1.0
        assert sanitized["seed"] == 42
        assert sanitized["model"] == "gpt-4"

        # Check Side Effect: Warnings Logged
        log_text = "".join(str(m) for m in logs)
        assert "Overriding unsafe temperature 0.9 to 0.0" in log_text
        assert "Overriding unsafe top_p 0.5 to 1.0" in log_text
        assert "Overriding seed 12345 to 42" in log_text

    finally:
        logger.remove(handler_id)
