# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import asyncio
import json
import os
from typing import Any, AsyncGenerator, Dict, Tuple
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from coreason_veritas.anchor import is_anchor_active
from coreason_veritas.exceptions import AssetTamperedError
from coreason_veritas.wrapper import governed_execution

# --- Fixtures & Helpers ---


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


# --- Tests ---


@pytest.mark.asyncio  # type: ignore[misc]
async def test_sandwich_execution(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test 'Sandwich' execution: Governed -> Ungoverned -> Governed.
    Verifies that Anchor context persists through the ungoverned layer.
    """
    private_key, public_key_pem = key_pair
    payload = {"layer": "sandwich"}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_as_current_span.return_value.__enter__.return_value = MagicMock()

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def inner_governed(spec: Dict[str, Any], sig: str, user: str) -> bool:
                # 3. Inner Governed: Anchor should be active
                return is_anchor_active()

            async def middle_ungoverned(spec: Dict[str, Any], sig: str, user: str) -> bool:
                # 2. Middle Ungoverned: Anchor should STILL be active (propagated)
                middle_active = is_anchor_active()
                inner_active = await inner_governed(spec=spec, sig=sig, user=user)
                return middle_active and inner_active

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def outer_governed(spec: Dict[str, Any], sig: str, user: str) -> bool:
                # 1. Outer Governed: Anchor starts here
                outer_active = is_anchor_active()
                nested_active = await middle_ungoverned(spec=spec, sig=sig, user=user)
                return outer_active and nested_active

            result = await outer_governed(spec=payload, sig=sig, user="sandwich-user")
            assert result is True, "Anchor context failed to persist through sandwich execution"


@pytest.mark.asyncio  # type: ignore[misc]
async def test_detached_task_propagation(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test that asyncio.create_task inherits the Anchor context from the governed scope.
    """
    private_key, public_key_pem = key_pair
    payload = {"layer": "detached"}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_as_current_span.return_value.__enter__.return_value = MagicMock()

            async def background_worker() -> bool:
                # Should inherit context
                return is_anchor_active()

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def main_task(spec: Dict[str, Any], sig: str, user: str) -> bool:
                # Spawn detached task
                task = asyncio.create_task(background_worker())
                return await task

            result = await main_task(spec=payload, sig=sig, user="detached-user")
            assert result is True, "Detached task did not inherit Anchor context"


@pytest.mark.asyncio  # type: ignore[misc]
async def test_blast_radius_error_tracing(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test 'Blast Radius': Inner failure is recorded in Inner span, Outer span also records it.
    """
    private_key, public_key_pem = key_pair
    payload = {"data": "boom"}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        # We need a real-ish mock to verify span recording
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer

            # Create separate mock objects for the context managers
            outer_span_ctx = MagicMock()
            outer_span_ctx.__enter__.return_value = MagicMock(name="outer_span")
            outer_span_ctx.__exit__.return_value = None  # Allow propagation

            inner_span_ctx = MagicMock()
            inner_span_ctx.__enter__.return_value = MagicMock(name="inner_span")
            inner_span_ctx.__exit__.return_value = None  # Allow propagation

            # IMPORTANT: Define the sequence of returned context managers
            # 1st call -> Outer, 2nd call -> Inner
            mock_tracer.start_as_current_span.side_effect = [outer_span_ctx, inner_span_ctx]

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def inner_fail(spec: Dict[str, Any], sig: str, user: str) -> None:
                raise ValueError("Core Meltdown")

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def outer_call(spec: Dict[str, Any], sig: str, user: str) -> None:
                await inner_fail(spec=spec, sig=sig, user=user)

            with pytest.raises(ValueError, match="Core Meltdown"):
                await outer_call(spec=payload, sig=sig, user="blast-user")

            # Verification
            assert mock_tracer.start_as_current_span.call_count == 2

            # Verify Outer Span exited with exception
            outer_exit_args = outer_span_ctx.__exit__.call_args
            assert outer_exit_args is not None
            assert outer_exit_args[0][0] is ValueError  # exc_type

            # Verify Inner Span exited with exception
            inner_exit_args = inner_span_ctx.__exit__.call_args
            assert inner_exit_args is not None
            assert inner_exit_args[0][0] is ValueError  # exc_type


@pytest.mark.asyncio  # type: ignore[misc]
async def test_generator_interruption_cleanup(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test that breaking out of a governed generator correctly closes the Audit Span and Anchor scope.
    """
    private_key, public_key_pem = key_pair
    payload = {"data": "stream"}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with (
            patch("coreason_veritas.wrapper.IERLogger") as MockIERLogger,
            patch("coreason_veritas.wrapper._ANCHOR_ACTIVE") as MockAnchorVar,
        ):
            mock_span = MagicMock()
            # For async generator, we use create_governed_span and manual span.end()
            MockIERLogger.return_value.create_governed_span.return_value = mock_span

            # For Anchor, we use manual set/reset on _ANCHOR_ACTIVE contextvar
            mock_token = MagicMock()
            MockAnchorVar.set.return_value = mock_token

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def stream_data(spec: Dict[str, Any], sig: str, user: str) -> AsyncGenerator[int, None]:
                yield 1
                yield 2
                yield 3

            # Use a manual close to force cleanup deterministically
            gen = stream_data(spec=payload, sig=sig, user="stream-user")

            try:
                async for item in gen:
                    if item == 1:
                        break
            finally:
                # Force close the generator if it wasn't already closed by the break
                # In many cases, break triggers aclose() automatically in async for,
                # but explicit closing ensures the test doesn't rely on GC timing.
                await gen.aclose()

            # Verification
            # Check if span.end() was called (manual management)
            mock_span.end.assert_called_once()

            # Check if Anchor was reset
            MockAnchorVar.reset.assert_called_with(mock_token)


@pytest.mark.asyncio  # type: ignore[misc]
async def test_dynamic_key_rotation(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test that the system respects dynamic changes to the Public Key environment variable.
    """
    # Key A
    priv_a, pub_a = key_pair
    # Key B
    priv_b, pub_b = rsa.generate_private_key(public_exponent=65537, key_size=2048), ""
    pub_b_obj = priv_b.public_key()
    pub_b = pub_b_obj.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    payload = {"data": "rotation"}

    # Signatures
    sig_a = sign_payload(payload, priv_a)
    sig_b = sign_payload(payload, priv_b)

    # Mock Tracer
    with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
        mock_tracer = MagicMock()
        mock_get_tracer.return_value = mock_tracer
        mock_tracer.start_as_current_span.return_value.__enter__.return_value = MagicMock()

        @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
        async def protected_op(spec: Dict[str, Any], sig: str, user: str) -> str:
            return "success"

        # 1. Start with Key A
        with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": pub_a}):
            # A should pass
            assert await protected_op(spec=payload, sig=sig_a, user="u") == "success"
            # B should fail
            with pytest.raises(AssetTamperedError):
                await protected_op(spec=payload, sig=sig_b, user="u")

        # 2. Rotate to Key B
        with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": pub_b}):
            # B should pass now
            assert await protected_op(spec=payload, sig=sig_b, user="u") == "success"
            # A should fail now
            with pytest.raises(AssetTamperedError):
                await protected_op(spec=payload, sig=sig_a, user="u")
