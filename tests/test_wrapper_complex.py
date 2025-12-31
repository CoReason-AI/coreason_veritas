import concurrent.futures
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Tuple
from unittest.mock import MagicMock, patch

import jcs
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from coreason_veritas.anchor import is_anchor_active
from coreason_veritas.wrapper import governed_execution


@pytest.fixture  # type: ignore[misc]
def key_pair() -> Tuple[RSAPrivateKey, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_key, pem_public


def sign_payload(payload: Dict[str, Any], private_key: RSAPrivateKey) -> str:
    canonical_payload = jcs.canonicalize(payload)
    signature = private_key.sign(
        canonical_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return str(signature.hex())


def test_threaded_sync_execution(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test that governed synchronous functions work correctly in multiple threads."""
    private_key, public_key_pem = key_pair
    payload = {"data": "thread", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_span.return_value = MagicMock()

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            def work(spec: Dict[str, Any], sig: str, user: str) -> int:
                assert is_anchor_active()
                return threading.get_ident()

            # Run in 5 threads
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(work, spec=payload, sig=sig, user=f"u{i}") for i in range(10)]
                results = [f.result() for f in futures]

            # Verify we got results (thread IDs)
            assert len(results) == 10
            assert len(set(results)) > 1  # Should use multiple threads


@pytest.mark.asyncio  # type: ignore[misc]
async def test_mixed_nesting_sync_calls_async(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test Sync function calling Async governed function.

    (needs special handling by caller, but verifies wrapper compatibility).
    """
    private_key, public_key_pem = key_pair
    payload = {"d": 1, "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_span.return_value = MagicMock()

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def inner_async(spec: Dict[str, Any], sig: str, user: str) -> str:
                assert is_anchor_active()
                return "inner"

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            def outer_sync(spec: Dict[str, Any], sig: str, user: str) -> Any:
                assert is_anchor_active()
                # Return the coroutine to be awaited by the test.
                # MUST pass kwargs for governed parameters!
                return inner_async(spec=spec, sig=sig, user=user)

            # Execution
            coro = outer_sync(spec=payload, sig=sig, user="u")

            # Now we await it
            res = await coro
            assert res == "inner"


def test_evil_str_attribute(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test resilience against objects that raise exceptions in __str__ during attribute capture."""
    private_key, public_key_pem = key_pair

    class Evil:
        def __str__(self) -> str:
            raise ValueError("I am evil")

    payload = {"d": 1, "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            def safe_func(spec: Dict[str, Any], sig: str, user: Any) -> str:
                return "ok"

            with pytest.raises(ValueError, match="I am evil"):
                safe_func(spec=payload, sig=sig, user=Evil())


def test_governed_sync_generator(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test governance of synchronous generators."""
    private_key, public_key_pem = key_pair
    payload = {"d": 1, "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_span.return_value = MagicMock()

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            def my_gen(spec: Dict[str, Any], sig: str, user: str) -> Any:
                yield 1
                # At this point, wrapper context MUST be active
                if not is_anchor_active():
                    raise RuntimeError("Anchor lost in sync generator!")
                yield 2

            gen = my_gen(spec=payload, sig=sig, user="u")

            # Iterate
            results = list(gen)
            assert results == [1, 2]


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_async_generator(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test governance of asynchronous generators."""
    private_key, public_key_pem = key_pair
    payload = {"d": 1, "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_span.return_value = MagicMock()

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def my_agen(spec: Dict[str, Any], sig: str, user: str) -> Any:
                yield 1
                if not is_anchor_active():
                    raise RuntimeError("Anchor lost in async generator!")
                yield 2

            agen = my_agen(spec=payload, sig=sig, user="u")

            results = []
            async for item in agen:
                results.append(item)
            assert results == [1, 2]
