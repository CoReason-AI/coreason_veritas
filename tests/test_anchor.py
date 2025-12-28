# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas
import threading
import time
from typing import Any, Dict

import pytest

from coreason_veritas.anchor import DeterminismInterceptor, is_anchor_active


def test_enforce_config_defaults() -> None:
    """Test that enforce_config applies defaults to an empty config."""
    interceptor = DeterminismInterceptor()
    config: Dict[str, Any] = {}
    sanitized = interceptor.enforce_config(config)

    assert sanitized["temperature"] == 0.0
    assert sanitized["top_p"] == 1.0
    assert sanitized["seed"] == 42
    # Ensure original is not modified
    assert config == {}


def test_enforce_config_override() -> None:
    """Test that enforce_config overrides unsafe values."""
    interceptor = DeterminismInterceptor()
    config = {"temperature": 0.7, "top_p": 0.9, "seed": 123, "other_param": "value"}
    sanitized = interceptor.enforce_config(config)

    assert sanitized["temperature"] == 0.0
    assert sanitized["top_p"] == 1.0
    assert sanitized["seed"] == 42
    assert sanitized["other_param"] == "value"


def test_enforce_config_compliant() -> None:
    """Test that enforce_config handles already compliant values without change."""
    interceptor = DeterminismInterceptor()
    config = {"temperature": 0.0, "top_p": 1.0, "seed": 42}
    sanitized = interceptor.enforce_config(config)

    assert sanitized["temperature"] == 0.0
    assert sanitized["top_p"] == 1.0
    assert sanitized["seed"] == 42


def test_scope_activation() -> None:
    """Test that the scope context manager sets the active flag."""
    interceptor = DeterminismInterceptor()

    assert is_anchor_active() is False

    with interceptor.scope():
        assert is_anchor_active() is True

    assert is_anchor_active() is False


def test_scope_nested() -> None:
    """Test nested scopes work correctly."""
    interceptor = DeterminismInterceptor()

    assert is_anchor_active() is False

    with interceptor.scope():
        assert is_anchor_active() is True
        with interceptor.scope():
            assert is_anchor_active() is True
        assert is_anchor_active() is True

    assert is_anchor_active() is False


def test_scope_exception() -> None:
    """Test that the flag is reset even if an exception occurs."""
    interceptor = DeterminismInterceptor()

    assert is_anchor_active() is False

    try:
        with interceptor.scope():
            assert is_anchor_active() is True
            raise ValueError("Test error")
    except ValueError:
        pass

    assert is_anchor_active() is False


def test_enforce_config_invalid_types() -> None:
    """Test enforce_config behavior when config contains invalid types."""
    interceptor = DeterminismInterceptor()
    # User might pass "0.7" as string, but we want 0.0 float
    config = {"temperature": "0.7", "top_p": "0.9", "seed": "123"}
    # The interceptor doesn't validate input types, but it forcefully sets valid types.
    sanitized = interceptor.enforce_config(config)

    assert sanitized["temperature"] == 0.0
    assert isinstance(sanitized["temperature"], float)
    assert sanitized["top_p"] == 1.0
    assert isinstance(sanitized["top_p"], float)
    assert sanitized["seed"] == 42
    assert isinstance(sanitized["seed"], int)


def test_enforce_config_none_input() -> None:
    """
    Test enforce_config with None or empty inputs.
    Assuming types are enforced elsewhere, but if user passes None as config, copy() will fail.
    The type hint says Dict[str, Any], so None is theoretically invalid, but we should check robustness.
    """
    interceptor = DeterminismInterceptor()

    # Empty dict is handled
    assert interceptor.enforce_config({}) == {"temperature": 0.0, "top_p": 1.0, "seed": 42}

    # If None is passed, it would raise AttributeError.
    # We can either let it raise or handle it. Based on existing code `raw_config.copy()`, it will raise.
    # Let's verify that it raises AttributeError.
    with pytest.raises(AttributeError):
        interceptor.enforce_config(None)  # type: ignore


def test_scope_threading() -> None:
    """
    Test that contextvars work correctly across threads.
    Each thread should have its own context.
    """
    interceptor = DeterminismInterceptor()

    # Event to sync threads
    event = threading.Event()

    results = {"thread_1": False, "thread_2": False}

    def thread_task(name: str, enable_scope: bool) -> None:
        if enable_scope:
            with interceptor.scope():
                # Signal we are inside scope
                event.wait()  # Wait for other thread
                results[name] = is_anchor_active()
        else:
            # Signal we are ready
            event.wait()
            results[name] = is_anchor_active()

    t1 = threading.Thread(target=thread_task, args=("thread_1", True))
    t2 = threading.Thread(target=thread_task, args=("thread_2", False))

    t1.start()
    t2.start()

    # Let them start
    time.sleep(0.1)
    # Release both
    event.set()

    t1.join()
    t2.join()

    assert results["thread_1"] is True
    assert results["thread_2"] is False
