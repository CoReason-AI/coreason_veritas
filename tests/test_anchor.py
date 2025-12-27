# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import pytest
from typing import Dict, Any
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
    config = {
        "temperature": 0.7,
        "top_p": 0.9,
        "seed": 123,
        "other_param": "value"
    }
    sanitized = interceptor.enforce_config(config)

    assert sanitized["temperature"] == 0.0
    assert sanitized["top_p"] == 1.0
    assert sanitized["seed"] == 42
    assert sanitized["other_param"] == "value"

def test_enforce_config_compliant() -> None:
    """Test that enforce_config handles already compliant values without change."""
    interceptor = DeterminismInterceptor()
    config = {
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": 42
    }
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
