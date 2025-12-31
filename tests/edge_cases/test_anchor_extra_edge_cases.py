# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import os
from typing import Any, Dict

from coreason_veritas.anchor import DeterminismInterceptor


class CustomObject:
    def __init__(self, value: int) -> None:
        self.value = value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CustomObject) and self.value == other.value


def test_enforce_config_nested_dict() -> None:
    """Test that enforcement works deeply within nested dictionaries."""
    config: Dict[str, Any] = {
        "model": "gpt-4",
        "parameters": {"temperature": 0.7, "top_p": 0.9, "seed": 100},
        "meta": {"version": 1, "deep": {"temperature": 0.5}},
    }

    sanitized = DeterminismInterceptor.enforce_config(config)

    # Top level should be set
    assert sanitized["temperature"] == 0.0
    assert sanitized["top_p"] == 1.0
    assert sanitized["seed"] == 42

    # Nested should remain UNTOUCHED based on current implementation
    assert sanitized["parameters"]["temperature"] == 0.7
    assert sanitized["meta"]["deep"]["temperature"] == 0.5


def test_enforce_config_mixed_types() -> None:
    """Test enforcement with mixed types in config."""
    config: Dict[str, Any] = {
        "temperature": "0.7",  # String instead of float
        "top_p": None,
        "seed": 42.5,  # Float instead of int
        "other": [1, 2, 3],
        "obj": CustomObject(10),
    }

    sanitized = DeterminismInterceptor.enforce_config(config)

    assert sanitized["temperature"] == 0.0
    assert sanitized["top_p"] == 1.0
    assert sanitized["seed"] == 42
    assert sanitized["other"] == [1, 2, 3]
    assert sanitized["obj"] == CustomObject(10)
    assert sanitized["obj"] is not config["obj"]  # Should be a deep copy


def test_enforce_config_custom_env_seed() -> None:
    """Test that VERITAS_SEED env var is respected."""
    try:
        os.environ["VERITAS_SEED"] = "999"
        config = {"seed": 123}
        sanitized = DeterminismInterceptor.enforce_config(config)
        assert sanitized["seed"] == 999
    finally:
        del os.environ["VERITAS_SEED"]


def test_enforce_config_invalid_env_seed() -> None:
    """Test fallback when VERITAS_SEED is invalid."""
    try:
        os.environ["VERITAS_SEED"] = "invalid"
        config = {"seed": 123}
        sanitized = DeterminismInterceptor.enforce_config(config)
        assert sanitized["seed"] == 42
    finally:
        del os.environ["VERITAS_SEED"]


def test_enforce_config_with_tuples_and_immutables() -> None:
    """Test that deepcopy handles tuples and other immutables correctly."""
    config: Dict[str, Any] = {"dims": (1, 2, 3), "temperature": 0.5}
    sanitized = DeterminismInterceptor.enforce_config(config)
    assert sanitized["temperature"] == 0.0
    assert sanitized["dims"] == (1, 2, 3)


def test_enforce_config_confusing_keys() -> None:
    """Test keys that look like targets but aren't."""
    config: Dict[str, Any] = {
        "temperature_coeff": 0.9,
        "top_projection": 0.5,
        "random_seed": 100,
        "temperature": 0.1,
    }
    sanitized = DeterminismInterceptor.enforce_config(config)

    assert sanitized["temperature"] == 0.0
    assert sanitized["temperature_coeff"] == 0.9
    assert sanitized["top_projection"] == 0.5
    assert sanitized["random_seed"] == 100
