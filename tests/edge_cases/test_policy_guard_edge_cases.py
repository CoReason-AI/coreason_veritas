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

from coreason_veritas.exceptions import ComplianceViolationError
from coreason_veritas.gatekeeper import PolicyGuard


def test_verify_access_case_sensitivity() -> None:
    """
    Test that username matching is case-sensitive by default.
    'User1' should NOT match 'user1'.
    """
    guard = PolicyGuard(blocklist=["user1"])
    # "User1" != "user1", so it should be allowed
    assert guard.verify_access("agent_1", {"user_id": "User1"}) is True
    # "user1" == "user1", so it should be denied
    with pytest.raises(ComplianceViolationError):
        guard.verify_access("agent_1", {"user_id": "user1"})


def test_verify_access_whitespace_handling() -> None:
    """
    Test that whitespace is significant.
    ' user1 ' should NOT match 'user1'.
    """
    guard = PolicyGuard(blocklist=["user1"])
    # Whitespace makes it different string, so allowed
    assert guard.verify_access("agent_1", {"user_id": " user1 "}) is True
    # Exact match denied
    with pytest.raises(ComplianceViolationError):
        guard.verify_access("agent_1", {"user_id": "user1"})


def test_verify_access_non_string_user_id() -> None:
    """
    Test behavior when user_id is not a string (e.g. integer).
    It should not crash, and should simply not match string blocklist items.
    """
    guard = PolicyGuard(blocklist=["123"])
    # Integer 123 != String "123", so allowed
    assert guard.verify_access("agent_1", {"user_id": 123}) is True

    # If we really blocked the integer 123 (if generic list allowed)
    # Type hint says list[str], but runtime might allow mixed list if passed manually.
    # But let's assume we stick to contract.


def test_verify_access_empty_agent_id() -> None:
    """Test that empty agent_id is processed correctly."""
    guard = PolicyGuard()
    # Should work fine
    assert guard.verify_access("", {"user_id": "valid"}) is True


def test_verify_access_unicode_user_id() -> None:
    """Test with unicode user IDs."""
    guard = PolicyGuard(blocklist=["👾"])
    # Allowed
    assert guard.verify_access("agent_1", {"user_id": "🙂"}) is True
    # Denied
    with pytest.raises(ComplianceViolationError):
        guard.verify_access("agent_1", {"user_id": "👾"})


def test_verify_access_large_blocklist() -> None:
    """Test performance/correctness with a larger blocklist."""
    # Create blocklist with 1000 items
    blocklist = [f"user_{i}" for i in range(1000)]
    blocklist.append("target_user")

    guard = PolicyGuard(blocklist=blocklist)

    # Check allowed
    assert guard.verify_access("agent_1", {"user_id": "safe_user"}) is True

    # Check blocked (last item)
    with pytest.raises(ComplianceViolationError):
        guard.verify_access("agent_1", {"user_id": "target_user"})

    # Check blocked (first item)
    with pytest.raises(ComplianceViolationError):
        guard.verify_access("agent_1", {"user_id": "user_0"})
