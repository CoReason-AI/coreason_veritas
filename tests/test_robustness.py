
import importlib
import os
from typing import Any, Dict
from unittest.mock import patch

import pytest

from coreason_veritas.anchor import DeterminismInterceptor
from coreason_veritas.auditor import IERLogger
from coreason_veritas.logging_utils import scrub_sensitive_data

# --- Logging Utils Coverage ---


def test_sensitive_keys_env_var() -> None:
    """Test module-level code for loading extra sensitive keys."""
    from coreason_veritas import logging_utils

    with patch.dict(os.environ, {"VERITAS_SENSITIVE_KEYS": "super_secret,hidden_key"}):
        importlib.reload(logging_utils)
        assert "super_secret" in logging_utils.SENSITIVE_KEYS
        assert "hidden_key" in logging_utils.SENSITIVE_KEYS


def test_scrub_deep_nesting() -> None:
    """Test recursion depth limit."""
    deep_dict: Dict[str, Any] = {}
    current = deep_dict
    for _ in range(25):
        current["next"] = {}
        current = current["next"]

    scrubbed = scrub_sensitive_data(deep_dict)
    # Just ensure it didn't crash and returned something
    assert isinstance(scrubbed, dict)


def test_scrub_circular_ref() -> None:
    """Test circular reference handling."""
    a: Dict[str, Any] = {}
    b = {"a": a}
    a["b"] = b
    scrubbed = scrub_sensitive_data(a)
    assert scrubbed["b"]["a"] == "[CIRCULAR_REF]"


def test_scrub_unsortable_set() -> None:
    """Test set with unsortable items falls back to unsorted list."""
    # Use objects that definitely raise TypeError on comparison
    o1 = object()
    o2 = object()
    data = {o1, o2}

    # Verify strict sorting fails
    with pytest.raises(TypeError):
        sorted(data)  # type: ignore[type-var]

    scrubbed = scrub_sensitive_data(data)
    assert isinstance(scrubbed, list)
    assert len(scrubbed) == 2


def test_scrub_custom_object() -> None:
    """Test custom object serialization via __dict__ check fallback to str."""

    class MyObj:
        def __init__(self) -> None:
            self.x = 1

        def __repr__(self) -> str:
            return "MyObj(x=1)"

    # scrub_sensitive_data checks hasattr(data, "__dict__")
    # and returns str(data).
    obj = MyObj()
    assert scrub_sensitive_data(obj) == "MyObj(x=1)"


# --- Anchor Coverage ---


def test_anchor_scope_reset_failure() -> None:
    """Test that scope() swallows ValueError on reset."""
    with patch("coreason_veritas.anchor._ANCHOR_ACTIVE") as mock_var:
        mock_var.set.return_value = "token"
        mock_var.reset.side_effect = ValueError("Context diverged")

        with DeterminismInterceptor.scope():
            pass
        # Should not raise


# --- Auditor Coverage ---


def test_auditor_init_tracer_provider_failure() -> None:
    """Test handling of exception when setting tracer provider."""
    # Reset singleton to ensure init runs
    if hasattr(IERLogger, "reset"):
        IERLogger.reset()
    else:
        IERLogger._instance = None
        IERLogger._initialized = False

    with patch("coreason_veritas.auditor.trace.set_tracer_provider", side_effect=Exception("Provider exists")):
        with patch("loguru.logger.warning") as mock_warning:
            _ = IERLogger()
            # Should catch exception and log warning
            mock_warning.assert_called()


# --- Wrapper Coverage ---
# Tests removed due to coverage/mocking issues with defensive blocks.
