import os
from datetime import datetime, timezone

import pytest

from coreason_veritas.exceptions import AssetTamperedError
from coreason_veritas.wrapper import governed_execution


# We need to set the environment variable for the public key
@pytest.fixture(autouse=True)
def set_public_key_env(pem_public):
    os.environ["COREASON_VERITAS_PUBLIC_KEY"] = pem_public
    yield
    if "COREASON_VERITAS_PUBLIC_KEY" in os.environ:
        del os.environ["COREASON_VERITAS_PUBLIC_KEY"]


def test_missing_env_var_public_key(sign_payload_func):
    """Test behavior when COREASON_VERITAS_PUBLIC_KEY is missing."""
    del os.environ["COREASON_VERITAS_PUBLIC_KEY"]

    @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
    def my_func(spec, sig, user):
        return True

    payload = {"data": "test", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload_func(payload)

    with pytest.raises(ValueError, match="COREASON_VERITAS_PUBLIC_KEY environment variable is not set"):
        my_func(spec=payload, sig=sig, user="test_user")


def test_governed_execution_missing_arguments_in_call():
    """Test calling the decorated function with missing required arguments."""

    @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
    def my_func(spec, sig, user):
        return True

    # Missing sig and user
    with pytest.raises(TypeError):  # Python raises TypeError for missing args
        my_func(spec={})


def test_governed_execution_incorrect_argument_names(sign_payload_func):
    """Test decorator configured with wrong argument names."""

    @governed_execution(asset_id_arg="wrong_spec", signature_arg="sig", user_id_arg="user")
    def my_func(spec, sig, user):
        return True

    payload = {"data": "test", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload_func(payload)

    # The wrapper tries to find "wrong_spec" in arguments but it won't be there.
    # The code `asset = arguments.get(asset_id_arg)` will return None.
    # Then `if asset is None: raise ValueError("Missing asset argument...")`

    with pytest.raises(ValueError, match="Missing asset argument: wrong_spec"):
        my_func(spec=payload, sig=sig, user="test_user")


def test_governed_execution_class_method(sign_payload_func):
    """Test usage on a class method."""

    class processor:
        @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
        def process(self, spec, sig, user):
            return "processed"

    p = processor()
    payload = {"data": "test", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload_func(payload)

    assert p.process(spec=payload, sig=sig, user="user") == "processed"


def test_governed_execution_exception_propagation(sign_payload_func):
    """Test that exceptions inside the function are propagated."""

    @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
    def failing_func(spec, sig, user):
        raise RuntimeError("Something went wrong")

    payload = {"data": "test", "timestamp": datetime.now(timezone.utc).isoformat()}
    sig = sign_payload_func(payload)

    with pytest.raises(RuntimeError, match="Something went wrong"):
        failing_func(spec=payload, sig=sig, user="user")


def test_governed_execution_draft_mode_bypass():
    """Test allow_unsigned=True logic."""

    @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user", allow_unsigned=True)
    def draft_func(spec, sig, user):
        return "ok"

    payload = {"data": "test"}  # No timestamp needed if skipping verification?
    # Actually, verification logic is skipped entirely if signature is None.

    assert draft_func(spec=payload, sig=None, user="dev") == "ok"

    # If signature IS provided, it MIGHT still verify it?
    # Let's check code:
    # if allow_unsigned and signature is None:
    #    ... bypass ...
    # else:
    #    if signature is None: raise ...
    #    verify_asset(...)

    # So if we provide a signature in draft mode, it MUST be valid.

    with pytest.raises(AssetTamperedError):
        draft_func(spec=payload, sig="invalid_sig", user="dev")


def test_governed_execution_config_sanitization_integration():
    """Test that config sanitization works via the wrapper."""

    @governed_execution(
        asset_id_arg="spec", signature_arg="sig", user_id_arg="user", config_arg="llm_config", allow_unsigned=True
    )
    def ai_func(spec, sig, user, llm_config):
        return llm_config

    unsafe_config = {"temperature": 0.9, "seed": 100}
    sanitized = ai_func(spec={}, sig=None, user="dev", llm_config=unsafe_config)

    assert sanitized["temperature"] == 0.0
    assert sanitized["seed"] == 42


@pytest.mark.asyncio
async def test_governed_execution_async_generator():
    """Test async generator support."""

    @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user", allow_unsigned=True)
    async def stream_func(spec, sig, user):
        yield 1
        yield 2

    items = []
    async for item in stream_func(spec={}, sig=None, user="dev"):
        items.append(item)

    assert items == [1, 2]


def test_governed_execution_sync_generator():
    """Test sync generator support."""

    @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user", allow_unsigned=True)
    def stream_func(spec, sig, user):
        yield 1
        yield 2

    items = list(stream_func(spec={}, sig=None, user="dev"))
    assert items == [1, 2]


@pytest.mark.asyncio
async def test_governed_execution_async_function():
    """Test async function support."""

    @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user", allow_unsigned=True)
    async def async_func(spec, sig, user):
        return "async_ok"

    res = await async_func(spec={}, sig=None, user="dev")
    assert res == "async_ok"
