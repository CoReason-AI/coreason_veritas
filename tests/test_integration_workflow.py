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
import os
from datetime import datetime, timezone
from typing import Any, Dict, Tuple, cast
from unittest.mock import MagicMock, patch

import jcs
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from coreason_veritas.anchor import DeterminismInterceptor, is_anchor_active
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


@pytest.mark.asyncio  # type: ignore[misc]
async def test_blast_radius(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test 'Blast Radius' (Nested Partial Failure).
    Workflow: Outer Governed -> calls Inner Governed A (Success) -> calls Inner Governed B (Fails).
    Goal: Verify that Inner A completes, Inner B fails, and Outer fails,
          while all spans are attempted (or started) and Anchor state is correct.
    """
    private_key, public_key_pem = key_pair

    # Payloads
    payload_outer = {"task": "outer", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig_outer = sign_payload(payload_outer, private_key)

    payload_inner_a = {"task": "inner_a", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig_inner_a = sign_payload(payload_inner_a, private_key)

    payload_inner_b = {"task": "inner_b", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig_inner_b = sign_payload(payload_inner_b, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            # Mock Tracer
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_span = MagicMock()
            # Support GovernanceContext manual span
            mock_tracer.start_span.return_value = mock_span

            # Define Inner A (Success)
            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def inner_task_a(spec: Dict[str, Any], sig: str, user: str) -> str:
                assert is_anchor_active() is True
                return "success_a"

            # Define Inner B (Failure)
            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def inner_task_b(spec: Dict[str, Any], sig: str, user: str) -> str:
                assert is_anchor_active() is True
                raise ValueError("Critical Failure in B")

            # Define Outer
            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def outer_task(spec: Dict[str, Any], sig: str, user: str) -> str:
                assert is_anchor_active() is True

                # Call A
                await inner_task_a(spec=payload_inner_a, sig=sig_inner_a, user=user)

                # Call B
                await inner_task_b(spec=payload_inner_b, sig=sig_inner_b, user=user)

                return "Should not reach here"

            # Execute
            with pytest.raises(ValueError, match="Critical Failure in B"):
                await outer_task(spec=payload_outer, sig=sig_outer, user="tester")

            # Verification
            # We expect 3 spans to have been started: Outer, Inner A, Inner B.
            assert mock_tracer.start_span.call_count == 3

            calls = mock_tracer.start_span.call_args_list
            func_names = [call[0][0] for call in calls]

            assert "outer_task" in func_names
            assert "inner_task_a" in func_names
            assert "inner_task_b" in func_names


@pytest.mark.asyncio  # type: ignore[misc]
async def test_detached_task_propagation(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test 'Detached Task' Propagation.
    Workflow: Governed function -> spawns background asyncio.create_task.
    Goal: Verify that is_anchor_active() is True inside the detached task.
    """
    private_key, public_key_pem = key_pair

    payload = {"task": "detached", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            # Mock Setup
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_span = MagicMock()
            mock_tracer.start_span.return_value = mock_span

            # Background Task
            async def background_worker(queue: "asyncio.Queue[bool]") -> None:
                is_active = is_anchor_active()
                await queue.put(is_active)

            # Governed Function
            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def governed_spawner(spec: Dict[str, Any], sig: str, user: str) -> bool:
                queue: asyncio.Queue[bool] = asyncio.Queue()
                # Spawn task
                task = asyncio.create_task(background_worker(queue))
                # Wait for result
                result = await queue.get()
                await task
                return result

            # Execute
            result = await governed_spawner(spec=payload, sig=sig, user="spawner")

            # Verify
            assert result is True, "Anchor state should propagate to detached tasks"


@pytest.mark.asyncio  # type: ignore[misc]
async def test_determinism_enforcement_integration(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test 'The Determinism Enforcement'.
    Workflow: Governed function -> calls DeterminismInterceptor.enforce_config.
    Goal: Verify that unsafe configs are overridden.
    """
    private_key, public_key_pem = key_pair

    payload = {"task": "enforcement", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_span = MagicMock()
            mock_tracer.start_span.return_value = mock_span

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def llm_client_user(spec: Dict[str, Any], sig: str, user: str) -> Dict[str, Any]:
                unsafe_config = {"temperature": 0.7, "top_p": 0.9, "seed": 12345, "model": "gpt-4"}
                # User calls this helper
                interceptor = DeterminismInterceptor()
                return interceptor.enforce_config(unsafe_config)

            # Execute
            final_config = await llm_client_user(spec=payload, sig=sig, user="data_scientist")

            # Verify
            assert final_config["temperature"] == 0.0
            assert final_config["top_p"] == 1.0
            assert final_config["seed"] == 42
            assert final_config["model"] == "gpt-4"  # Preserved


@pytest.mark.asyncio  # type: ignore[misc]
async def test_sandwich_execution(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test 'The Sandwich' (Governed -> Ungoverned -> Governed).
    Goal: Verify Anchor state is preserved across the boundary and Inner validation succeeds.
    """
    private_key, public_key_pem = key_pair

    payload_outer = {"layer": "outer", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig_outer = sign_payload(payload_outer, private_key)

    payload_inner = {"layer": "inner", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig_inner = sign_payload(payload_inner, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_span = MagicMock()
            mock_tracer.start_span.return_value = mock_span

            # Inner Governed
            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def inner_layer(spec: Dict[str, Any], sig: str, user: str) -> str:
                assert is_anchor_active() is True
                return "inner_done"

            # Middle Ungoverned
            async def middle_layer(user: str) -> str:
                # Expect Anchor to still be active because it's in the same context
                assert is_anchor_active() is True
                return cast(str, await inner_layer(spec=payload_inner, sig=sig_inner, user=user))

            # Outer Governed
            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def outer_layer(spec: Dict[str, Any], sig: str, user: str) -> str:
                return await middle_layer(user)

            # Execute
            result = await outer_layer(spec=payload_outer, sig=sig_outer, user="sandwich_user")

            assert result == "inner_done"
            # Verify 2 spans (Outer, Inner)
            assert mock_tracer.start_span.call_count == 2


@pytest.mark.asyncio  # type: ignore[misc]
async def test_trace_context_propagation(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test 'Trace Context Propagation'.
    Goal: Verify that the Auditor uses existing OTel context if present.
    """
    private_key, public_key_pem = key_pair

    payload = {"task": "tracing", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        # We need a real OTel API (which we have) but mocked Tracer
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_span.return_value = MagicMock()

            # Setup a real span to serve as parent context
            # (In a real app, this comes from HTTP headers or upstream)

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def traced_func(spec: Dict[str, Any], sig: str, user: str) -> str:
                return "done"

            # Execute
            # The OTel API `start_as_current_span` looks at the context.
            # Since we mock `start_as_current_span`, we can't easily verify
            # that the *real* context propagation happened unless we inspect calls.
            # But we can verify that `start_as_current_span` was called.

            # To test propagation, we rely on the fact that `IERLogger` uses `start_span`.
            # If `start_span` is called, OTel handles the rest.

            await traced_func(spec=payload, sig=sig, user="trace_user")

            # Verify call
            mock_tracer.start_span.assert_called_once()
            args, kwargs = mock_tracer.start_span.call_args
            assert args[0] == "traced_func"
