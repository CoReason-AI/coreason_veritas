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
from typing import Any, Dict, Optional, Tuple
from unittest.mock import MagicMock, patch

import jcs
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from coreason_veritas.anchor import is_anchor_active
from coreason_veritas.exceptions import AssetTamperedError
from coreason_veritas.wrapper import _prepare_governance, governed_execution


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
async def test_governed_execution_missing_key_store_real(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test failure if key store env var is missing (without mocking the helper)."""
    private_key, _ = key_pair
    payload = {"data": "secure", "timestamp": datetime.now(timezone.utc).isoformat()}
    signature = sign_payload(payload, private_key)

    # Ensure Env Var is missing
    with patch.dict(os.environ, {}, clear=True):
        # We need to restore specific env vars if needed, but for this test simple clear might be too aggressive if pytest depends on env?
        # Better to just pop the key.
        pass

    with patch.dict(os.environ):
        if "COREASON_VERITAS_PUBLIC_KEY" in os.environ:
            del os.environ["COREASON_VERITAS_PUBLIC_KEY"]

        @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
        async def protected_function(spec: Dict[str, Any], sig: str, user: str) -> str:
            return "Should not reach here"

        with pytest.raises(ValueError, match="COREASON_VERITAS_PUBLIC_KEY environment variable is not set"):
            await protected_function(spec=payload, sig=signature, user="user-123")


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_success(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test the full flow of governed execution."""
    private_key, public_key_pem = key_pair

    # Set Env Var for Key Store
    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        payload = {"data": "secure", "timestamp": datetime.now(timezone.utc).isoformat()}
        signature = sign_payload(payload, private_key)

        # Mock IERLogger to avoid needing OTel setup
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_span = MagicMock()
            # For sync/async, we now use start_span (manual context management)
            mock_tracer.start_span.return_value = mock_span
            # For generators (legacy path for now), we use start_as_current_span
            mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def protected_function(spec: Dict[str, Any], sig: str, user: str, other_arg: str) -> str:
                # Verify Anchor is active inside
                assert is_anchor_active() is True
                return f"Processed {other_arg}"

            result = await protected_function(spec=payload, sig=signature, user="user-123", other_arg="test")

            assert result == "Processed test"

            # Verify Auditor was called via start_span (GovernanceContext)
            mock_tracer.start_span.assert_called_once()
            args, kwargs = mock_tracer.start_span.call_args
            assert args[0] == "protected_function"
            attributes = kwargs["attributes"]
            assert attributes["co.asset_id"] == str(payload)
            assert attributes["co.user_id"] == "user-123"
            assert attributes["co.srb_sig"] == signature


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_tampered(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test that execution is blocked if signature fails."""
    private_key, public_key_pem = key_pair

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        payload = {"data": "secure", "timestamp": datetime.now(timezone.utc).isoformat()}
        signature = sign_payload(payload, private_key)
        tampered_payload = {"data": "hacked", "timestamp": payload["timestamp"]}

        @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
        async def protected_function(spec: Dict[str, Any], sig: str, user: str) -> str:
            return "Should not reach here"

        with pytest.raises(AssetTamperedError):
            await protected_function(spec=tampered_payload, sig=signature, user="user-123")


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_missing_key_store(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test failure if key store env var is missing."""
    private_key, _ = key_pair
    payload = {"data": "secure", "timestamp": datetime.now(timezone.utc).isoformat()}
    signature = sign_payload(payload, private_key)

    # Explicitly patch get_public_key_from_store to simulate missing env var, avoiding cache issues
    with patch(
        "coreason_veritas.wrapper.get_public_key_from_store", side_effect=ValueError("COREASON_VERITAS_PUBLIC_KEY")
    ):

        @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
        async def protected_function(spec: Dict[str, Any], sig: str, user: str) -> str:
            return "Should not reach here"

        with pytest.raises(ValueError, match="COREASON_VERITAS_PUBLIC_KEY"):
            await protected_function(spec=payload, sig=signature, user="user-123")


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_missing_args(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test failure if required arguments are missing."""

    @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
    async def protected_function(spec: Any, sig: Any, user: Any) -> str:
        return "Should not reach here"

    # Now raises TypeError because bind() fails when required args are missing
    with pytest.raises(TypeError):
        await protected_function(spec={"a": 1}, user="u")  # Missing sig

    with pytest.raises(TypeError):
        await protected_function(sig="abc", user="u")  # Missing spec

    with pytest.raises(TypeError):
        await protected_function(spec={"a": 1}, sig="abc")  # Missing user


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_missing_args_defaults(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test failure when required args are missing but have defaults (None)."""

    @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
    async def protected_function(spec: Any = None, sig: Any = None, user: Any = None) -> str:
        return "Should not reach here"

    # bind() succeeds, so our manual checks run
    with pytest.raises(ValueError, match="Missing asset argument"):
        await protected_function(sig="s", user="u")

    with pytest.raises(ValueError, match="Missing user ID argument"):
        await protected_function(spec="a", sig="s")


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_asyncgen_missing_args(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test failure when required args are missing for async generator."""

    @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
    async def protected_asyncgen(spec: Any, sig: Any, user: Any) -> Any:
        yield "should not reach"

    # Testing missing args failure which happens in _prepare_governance
    # This triggers the exception handler in the async generator wrapper path
    with pytest.raises(TypeError):
        async for _ in protected_asyncgen(spec={"a": 1}, user="u"):
            pass


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_concurrency(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test that concurrent executions maintain isolated Anchor states.
    """
    private_key, public_key_pem = key_pair

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        payload = {"data": "concurrent", "timestamp": datetime.now(timezone.utc).isoformat()}
        signature = sign_payload(payload, private_key)

        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_span = MagicMock()
            mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def governed_task(spec: Dict[str, Any], sig: str, user: str) -> bool:
                await asyncio.sleep(0.05)  # Yield control
                return is_anchor_active()

            async def ungoverned_task() -> bool:
                await asyncio.sleep(0.05)  # Yield control
                return is_anchor_active()

            # Run both concurrently
            task1 = asyncio.create_task(governed_task(spec=payload, sig=signature, user="u1"))
            task2 = asyncio.create_task(ungoverned_task())

            is_active_governed, is_active_ungoverned = await asyncio.gather(task1, task2)

            # Verification
            assert is_active_governed is True, "Governed task should have Anchor active"
            assert is_active_ungoverned is False, "Ungoverned task should NOT have Anchor active"


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_exception_handling(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test that spans are closed/recorded even if the wrapped function raises an exception."""
    private_key, public_key_pem = key_pair

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        payload = {"data": "error", "timestamp": datetime.now(timezone.utc).isoformat()}
        signature = sign_payload(payload, private_key)

        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_span = MagicMock()
            mock_tracer.start_span.return_value = mock_span

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def failing_function(spec: Dict[str, Any], sig: str, user: str) -> None:
                raise RuntimeError("Planned failure")

            with pytest.raises(RuntimeError, match="Planned failure"):
                await failing_function(spec=payload, sig=signature, user="u1")

            # Verify Auditor was still called (span started)
            mock_tracer.start_span.assert_called_once()


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_nested(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test nested governed executions (Outer -> Inner).
    Verifies that both layers perform Gatekeeper checks, maintain Anchor state,
    and generate independent Audit spans.
    """
    private_key, public_key_pem = key_pair

    # 1. Prepare Data for Outer and Inner layers
    payload_outer = {"layer": "outer", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig_outer = sign_payload(payload_outer, private_key)

    payload_inner = {"layer": "inner", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig_inner = sign_payload(payload_inner, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        # Mock Tracer
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_span = MagicMock()
            # Support manual span (GovernanceContext)
            mock_tracer.start_span.return_value = mock_span

            # 2. Define Nested Functions
            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def inner_function(spec: Dict[str, Any], sig: str, user: str) -> str:
                assert is_anchor_active() is True
                return "inner_result"

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def outer_function(spec: Dict[str, Any], sig: str, user: str) -> str:
                assert is_anchor_active() is True
                # Call Inner
                inner_res = await inner_function(spec=payload_inner, sig=sig_inner, user=user)
                return f"outer_processed_{inner_res}"

            # 3. Execute
            result = await outer_function(spec=payload_outer, sig=sig_outer, user="user-nested")

            # 4. Verification
            assert result == "outer_processed_inner_result"

            # Expecting 2 calls to start_span
            assert mock_tracer.start_span.call_count == 2


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_positional_args_mixed(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test that calling the governed function with positional arguments works.
    """
    private_key, public_key_pem = key_pair
    payload = {"data": "secure", "timestamp": datetime.now(timezone.utc).isoformat()}
    signature = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_as_current_span.return_value.__enter__.return_value = MagicMock()

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def protected_function(spec: Dict[str, Any], sig: str, user: str) -> str:
                return "OK"

            # Passing arguments positionally should now succeed
            result = await protected_function(payload, signature, "user-123")
            assert result == "OK"

            # Mixed positional and keyword
            result_mixed = await protected_function(payload, sig=signature, user="user-mixed")
            assert result_mixed == "OK"


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_recursive(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test recursive calls to a governed function.
    """
    private_key, public_key_pem = key_pair

    # We need a payload that can decrease to base case
    payload = {"count": 3, "timestamp": datetime.now(timezone.utc).isoformat()}
    signature = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_span.return_value = MagicMock()

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def recursive_function(spec: Dict[str, Any], sig: str, user: str) -> int:
                count = spec["count"]
                if count <= 0:
                    return 0

                # Create next payload
                next_payload = {"count": count - 1, "timestamp": datetime.now(timezone.utc).isoformat()}
                next_sig = sign_payload(next_payload, private_key)

                # Recursive call
                res: int = await recursive_function(spec=next_payload, sig=next_sig, user=user)
                return 1 + res

            result = await recursive_function(spec=payload, sig=signature, user="recurse-user")
            assert result == 3

            # Verify spans: 3 (recursive) + 1 (initial) = 4 calls
            assert mock_tracer.start_span.call_count == 4


def test_governed_execution_sync_support(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test that governed_execution supports synchronous functions.
    """
    private_key, public_key_pem = key_pair

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        payload = {"data": "sync", "timestamp": datetime.now(timezone.utc).isoformat()}
        signature = sign_payload(payload, private_key)

        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_span = MagicMock()
            mock_tracer.start_span.return_value = mock_span

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            def sync_function(spec: Dict[str, Any], sig: str, user: str) -> str:
                # Ensure Anchor is active
                assert is_anchor_active() is True
                return "sync_result"

            # Call synchronously
            result = sync_function(spec=payload, sig=signature, user="user-sync")
            assert result == "sync_result"

            # Verify Auditor
            mock_tracer.start_span.assert_called_once()


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_draft_mode(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test Draft Mode execution where signatures are bypassed.
    """
    _, public_key_pem = key_pair
    payload = {"data": "draft"}

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_span.return_value = MagicMock()

            @governed_execution(
                asset_id_arg="spec",
                signature_arg="sig",
                user_id_arg="user",
                allow_unsigned=True,  # Enable Draft Mode
            )
            async def draft_function(spec: Dict[str, Any], sig: Optional[str], user: str) -> str:
                return "draft_success"

            # Execute without signature (None)
            result = await draft_function(spec=payload, sig=None, user="draft-user")

            assert result == "draft_success"

            # Verify Span Attributes contain DRAFT tag
            mock_tracer.start_span.assert_called_once()
            _, kwargs = mock_tracer.start_span.call_args
            attributes = kwargs["attributes"]
            assert attributes["co.compliance_mode"] == "DRAFT"


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_strict_mode_enforced(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Test that strict mode (allow_unsigned=False) still enforces signatures.
    """
    _, public_key_pem = key_pair
    payload = {"data": "strict"}

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):

        @governed_execution(
            asset_id_arg="spec",
            signature_arg="sig",
            user_id_arg="user",
            allow_unsigned=False,  # Strict Mode (Explicit)
        )
        async def strict_function(spec: Dict[str, Any], sig: Optional[str], user: str) -> str:
            return "should_fail"

        # Execute without signature
        with pytest.raises(ValueError, match="Missing signature argument"):
            await strict_function(spec=payload, sig=None, user="strict-user")


# --- Helper Function Tests (Integrated) ---


def test_prepare_governance_helper(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test the helper function independently."""
    private_key, public_key_pem = key_pair

    # Mock func signature
    def mock_func(a: int, b: int, asset: Dict[str, Any], sig: str, user: str) -> None:
        pass

    asset = {"id": 1, "timestamp": datetime.now(timezone.utc).isoformat()}
    # Use real key/signature to ensure verification logic passes in 'test mode'
    sig_val = sign_payload(asset, private_key)
    user_val = "user1"

    # Args and kwargs
    args = (1, 2)
    kwargs = {"asset": asset, "sig": sig_val, "user": user_val}

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        attributes, bound = _prepare_governance(
            func=mock_func,
            args=args,
            kwargs=kwargs,
            asset_id_arg="asset",
            signature_arg="sig",
            user_id_arg="user",
            config_arg=None,
            allow_unsigned=False,
        )

        # Verify attributes
        assert attributes["co.asset_id"] == str(asset)
        assert attributes["co.user_id"] == user_val
        assert attributes["co.srb_sig"] == sig_val

        # Verify bound arguments
        assert bound.arguments["a"] == 1
        assert bound.arguments["asset"] == asset


def test_prepare_governance_positional_args(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test helper with positional arguments."""
    private_key, public_key_pem = key_pair

    def mock_func(asset: Dict[str, Any], sig: str, user: str) -> None:
        pass

    asset = {"id": 1, "timestamp": datetime.now(timezone.utc).isoformat()}
    sig_val = sign_payload(asset, private_key)
    user_val = "user1"

    # All positional
    args = (asset, sig_val, user_val)
    kwargs: Dict[str, Any] = {}

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        attributes, bound = _prepare_governance(
            func=mock_func,
            args=args,
            kwargs=kwargs,
            asset_id_arg="asset",
            signature_arg="sig",
            user_id_arg="user",
            config_arg=None,
            allow_unsigned=False,
        )

        assert attributes["co.asset_id"] == str(asset)
        assert bound.arguments["asset"] == asset


def test_prepare_governance_sanitization(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test helper config sanitization."""
    private_key, public_key_pem = key_pair

    def mock_func(config: Dict[str, Any], asset: Any, sig: Any, user: Any) -> None:
        pass

    risky_config = {"temperature": 0.9, "seed": 999}
    asset = {"id": 1, "timestamp": datetime.now(timezone.utc).isoformat()}
    sig_val = sign_payload(asset, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        attributes, bound = _prepare_governance(
            func=mock_func,
            args=(),
            kwargs={"config": risky_config, "asset": asset, "sig": sig_val, "user": "u"},
            asset_id_arg="asset",
            signature_arg="sig",
            user_id_arg="user",
            config_arg="config",
            allow_unsigned=False,
        )

        sanitized = bound.arguments["config"]
        assert sanitized["temperature"] == 0.0
        assert sanitized["seed"] == 42


def test_governed_execution_sync_exception_handling(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test that spans are closed/recorded even if the wrapped sync function raises an exception."""
    private_key, public_key_pem = key_pair

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        payload = {"data": "error", "timestamp": datetime.now(timezone.utc).isoformat()}
        signature = sign_payload(payload, private_key)

        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_span = MagicMock()
            mock_tracer.start_span.return_value = mock_span

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            def failing_sync_function(spec: Dict[str, Any], sig: str, user: str) -> None:
                raise RuntimeError("Planned sync failure")

            with pytest.raises(RuntimeError, match="Planned sync failure"):
                failing_sync_function(spec=payload, sig=signature, user="u1")

            # Verify Auditor was still called (span started)
            mock_tracer.start_span.assert_called_once()


def test_governed_execution_generator_exception_handling(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test exception handling in governed generator functions."""
    private_key, public_key_pem = key_pair

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        payload = {"data": "gen_error", "timestamp": datetime.now(timezone.utc).isoformat()}
        signature = sign_payload(payload, private_key)

        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_span.return_value = MagicMock()

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            def failing_generator(spec: Dict[str, Any], sig: str, user: str) -> Any:
                yield "start"
                raise RuntimeError("Planned generator failure")

            gen = failing_generator(spec=payload, sig=signature, user="u_gen")

            assert next(gen) == "start"

            with pytest.raises(RuntimeError, match="Planned generator failure"):
                next(gen)

            # Verify Span started
            mock_tracer.start_span.assert_called_once()


@pytest.mark.asyncio  # type: ignore[misc]
async def test_governed_execution_asyncgen_exception_handling(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test exception handling in governed async generator functions."""
    private_key, public_key_pem = key_pair

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        payload = {"data": "asyncgen_error", "timestamp": datetime.now(timezone.utc).isoformat()}
        signature = sign_payload(payload, private_key)

        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_as_current_span.return_value.__enter__.return_value = MagicMock()

            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def failing_asyncgen(spec: Dict[str, Any], sig: str, user: str) -> Any:
                yield "start"
                raise RuntimeError("Planned asyncgen failure")

            gen = failing_asyncgen(spec=payload, sig=signature, user="u_agen")

            assert await anext(gen) == "start"

            with pytest.raises(RuntimeError, match="Planned asyncgen failure"):
                await anext(gen)

            # Verify Span started (using start_span for async generators now)
            mock_tracer.start_span.assert_called_once()


def test_governance_context_cleanup_exceptions(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """Test that exceptions during cleanup (reset/detach) are suppressed using dependency injection."""
    from coreason_veritas.wrapper import GovernanceContext

    private_key, public_key_pem = key_pair
    payload = {"data": "cleanup", "timestamp": datetime.now(timezone.utc).isoformat()}
    signature = sign_payload(payload, private_key)

    # Mock Anchor Variable
    mock_anchor_var = MagicMock()
    mock_anchor_var.set.return_value = "mock_token"
    mock_anchor_var.reset.side_effect = ValueError("Context diverged")

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_span.return_value = MagicMock()

            # Mock IERLogger to avoid interference from other tests or real init
            with patch("coreason_veritas.wrapper.IERLogger") as mock_logger_cls:
                mock_logger_cls.return_value.create_governed_span.return_value = mock_tracer.start_span.return_value

                # Mock detach failure
                with patch("opentelemetry.context.detach", side_effect=RuntimeError("Detach failed")):

                    def dummy_func(spec: Dict[str, Any], sig: str, user: str) -> str:
                        return "ok"

                    ctx = GovernanceContext(
                        func=dummy_func,
                        args=(),
                        kwargs={"spec": payload, "sig": signature, "user": "cleanup-user"},
                        asset_id_arg="spec",
                        signature_arg="sig",
                        user_id_arg="user",
                        config_arg=None,
                        allow_unsigned=False,
                        anchor_var=mock_anchor_var  # Inject mock
                    )

                    ctx.prepare()

                    # Run context manager
                    with ctx:
                        pass

                    # If we reached here without exception, success.

                    # Verify reset was called
                    mock_anchor_var.reset.assert_called_with("mock_token")
