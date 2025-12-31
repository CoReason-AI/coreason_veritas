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
from typing import Any, Dict, Tuple
from unittest.mock import MagicMock, patch

import jcs
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from coreason_veritas.anchor import DeterminismInterceptor, is_anchor_active
from coreason_veritas.sanitizer import scrub_pii_recursive
from coreason_veritas.wrapper import governed_execution

# --- Helpers ---


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


# --- Tests ---


@pytest.mark.asyncio  # type: ignore[misc]
async def test_holistic_full_lifecycle(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Holistic Test: Full Lifecycle
    Verifies the entire flow:
    1. Signed input verification (Gatekeeper)
    2. Execution tracing (Auditor)
    3. Environment lockdown (Anchor)
    4. Deterministic config enforcement inside the governed function
    5. Output generation
    """
    private_key, public_key_pem = key_pair
    payload = {"mission": "holistic_check", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload(payload, private_key)

    # Mock Tracer to verify spans
    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_span = MagicMock()
            mock_tracer.start_span.return_value = mock_span

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def critical_operation(spec: Dict[str, Any], sig: str, user: str, config: Dict[str, Any]) -> str:
                # 1. Verify Anchor
                assert is_anchor_active() is True, "Anchor must be active"

                # 2. Verify Config Sanitization (Manual invocation inside governed function as per docs)
                interceptor = DeterminismInterceptor()
                sanitized = interceptor.enforce_config(config)
                assert sanitized["temperature"] == 0.0, "Temperature must be zeroed"
                assert sanitized["seed"] == 42, "Seed must be fixed"

                return "Operation Safe"

            unsafe_config = {"temperature": 0.9, "seed": 999}

            # Execute
            result = await critical_operation(spec=payload, sig=sig, user="holistic_user", config=unsafe_config)

            # Verifications
            assert result == "Operation Safe"

            # Verify Span Attributes (Auditor)
            mock_tracer.start_span.assert_called_once()
            call_args = mock_tracer.start_span.call_args

            # Robustly extract attributes whether passed as args or kwargs
            if len(call_args.args) > 1:
                attributes = call_args.args[1].get("attributes", {})
            elif "attributes" in call_args.kwargs:
                attributes = call_args.kwargs["attributes"]
            else:
                attributes = {}

            assert attributes["co.user_id"] == "holistic_user"
            # Verify asset is sanitized in attributes
            assert attributes["co.asset_id"] == str(scrub_pii_recursive(payload))
            assert attributes["co.srb_sig"] == sig


@pytest.mark.asyncio  # type: ignore[misc]
async def test_holistic_concurrent_isolation(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Holistic Test: Concurrent Isolation
    Ensures that parallel governed executions do not interfere with each other's state,
    and ungoverned execution in parallel remains unaffected (not anchored).
    """
    private_key, public_key_pem = key_pair
    payload = {"mission": "concurrency", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_span.return_value = MagicMock()

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def governed_task(spec: Dict[str, Any], sig: str, user: str) -> bool:
                await asyncio.sleep(0.01)  # Simulate work
                return is_anchor_active()

            async def ungoverned_task() -> bool:
                await asyncio.sleep(0.01)
                return is_anchor_active()

            # Run both in parallel
            governed_result, ungoverned_result = await asyncio.gather(
                governed_task(spec=payload, sig=sig, user="user1"), ungoverned_task()
            )

            assert governed_result is True, "Governed task must be anchored"
            assert ungoverned_result is False, "Ungoverned task must NOT be anchored"


@pytest.mark.asyncio  # type: ignore[misc]
async def test_holistic_thread_safety(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Holistic Test: Thread Safety
    Verifies that contextvars (Anchor) work correctly across threads when using run_in_executor.
    Standard contextvars should propagate to threads if copied (default in Py3.7+ via asyncio.to_thread).
    """
    private_key, public_key_pem = key_pair
    payload = {"mission": "threading", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_span.return_value = MagicMock()

            def blocking_check() -> bool:
                return is_anchor_active()

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def thread_spawner(spec: Dict[str, Any], sig: str, user: str) -> bool:
                return await asyncio.to_thread(blocking_check)

            # Execute
            result = await thread_spawner(spec=payload, sig=sig, user="thread_user")

            # Expectation: In Python 3.12, asyncio.to_thread propagates contextvars.
            assert result is True, "Anchor should propagate to worker threads via asyncio.to_thread"


@pytest.mark.asyncio  # type: ignore[misc]
async def test_holistic_sanitization_integration(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Holistic Test: Automatic Sanitization Integration
    Verifies that passing `config_arg` to `@governed_execution` automatically sanitizes inputs
    BEFORE the function body is entered.
    """
    private_key, public_key_pem = key_pair
    payload = {"mission": "auto_sanitize", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_span.return_value = MagicMock()

            @governed_execution(
                asset_id_arg="spec",
                signature_arg="sig",
                user_id_arg="user",
                config_arg="llm_config",  # Enable auto-sanitization
            )
            async def auto_sanitized_func(
                spec: Dict[str, Any], sig: str, user: str, llm_config: Dict[str, Any]
            ) -> Dict[str, Any]:
                return llm_config

            unsafe = {"temperature": 0.8, "top_p": 0.95, "seed": 100}

            # Execute
            sanitized = await auto_sanitized_func(spec=payload, sig=sig, user="sanitize_user", llm_config=unsafe)

            assert sanitized["temperature"] == 0.0
            assert sanitized["top_p"] == 1.0
            assert sanitized["seed"] == 42
            # Verify original object wasn't mutated in place
            assert unsafe["temperature"] == 0.8, "Original config dict should not be mutated"


def test_holistic_sync_wrapper(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Holistic Test: Synchronous Wrapper Support
    Verifies that the decorator works for synchronous functions too.
    """
    private_key, public_key_pem = key_pair
    payload = {"mission": "sync_check", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_span.return_value = MagicMock()

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            def sync_critical_task(spec: Dict[str, Any], sig: str, user: str) -> bool:
                return is_anchor_active()

            result = sync_critical_task(spec=payload, sig=sig, user="sync_user")
            assert result is True
