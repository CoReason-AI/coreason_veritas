# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

from collections import UserDict
from typing import Any, Dict

import pytest

from coreason_veritas.anchor import DeterminismInterceptor, is_anchor_active


def test_enforce_config_shallow_copy_behavior() -> None:
    """
    Test that enforce_config performs a shallow copy.
    This documents expected behavior: top-level keys are independent,
    but nested mutable objects are shared.
    """
    nested_list = [1, 2, 3]
    original_config = {
        "temperature": 0.9,
        "nested": nested_list,
        "metadata": {"key": "value"}
    }

    sanitized = DeterminismInterceptor.enforce_config(original_config)

    # 1. Verify Top-Level Independence
    assert sanitized["temperature"] == 0.0
    assert original_config["temperature"] == 0.9

    # 2. Verify Nested Shared Reference (Shallow Copy)
    # If we modify the nested list in sanitized, it SHOULD reflect in original
    # because .copy() is shallow.
    sanitized["nested"].append(4)  # type: ignore
    assert len(original_config["nested"]) == 4  # type: ignore
    assert original_config["nested"][-1] == 4  # type: ignore


def test_enforce_config_custom_mapping() -> None:
    """
    Test enforce_config with a UserDict (custom mapping).
    Ensures .copy() works on dict-like objects.
    """
    class MyConfig(UserDict):  # type: ignore
        pass

    original = MyConfig({"temperature": 0.5, "top_p": 0.8})
    sanitized = DeterminismInterceptor.enforce_config(original)  # type: ignore

    assert sanitized["temperature"] == 0.0
    assert sanitized["top_p"] == 1.0
    assert sanitized["seed"] == 42
    # The result of .copy() on UserDict is usually the same type
    assert isinstance(sanitized, MyConfig)


def test_scope_as_decorator() -> None:
    """
    Test that the scope context manager can also be used as a decorator.
    """
    assert is_anchor_active() is False

    @DeterminismInterceptor.scope()
    def protected_function() -> bool:
        return is_anchor_active()

    assert protected_function() is True
    assert is_anchor_active() is False
