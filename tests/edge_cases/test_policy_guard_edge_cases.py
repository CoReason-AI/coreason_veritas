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
from coreason_identity.models import UserContext

from coreason_veritas.exceptions import ComplianceViolationError
from coreason_veritas.gatekeeper import PolicyGuard


def test_verify_access_case_sensitivity() -> None:
    """
    Test that username matching is case-sensitive by default.
    'User1' should NOT match 'user1'.
    """
    guard = PolicyGuard(blocklist=["user1"])
    # "User1" != "user1", so it should be allowed
    ctx1 = UserContext(user_id="User1", email="test@test.com")
    assert guard.verify_access("agent_1", ctx1) is True
    # "user1" == "user1", so it should be denied
    ctx2 = UserContext(user_id="user1", email="test@test.com")
    with pytest.raises(ComplianceViolationError):
        guard.verify_access("agent_1", ctx2)


def test_verify_access_whitespace_handling() -> None:
    """
    Test that whitespace is significant.
    ' user1 ' should NOT match 'user1'.
    """
    guard = PolicyGuard(blocklist=["user1"])
    # Whitespace makes it different string, so allowed
    ctx1 = UserContext(user_id=" user1 ", email="test@test.com")
    assert guard.verify_access("agent_1", ctx1) is True
    # Exact match denied
    ctx2 = UserContext(user_id="user1", email="test@test.com")
    with pytest.raises(ComplianceViolationError):
        guard.verify_access("agent_1", ctx2)


def test_verify_access_non_string_user_id() -> None:
    """
    Test behavior when user_id is not a string (e.g. integer).
    UserContext enforces string type, so it should raise ValidationError.
    """
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        UserContext(user_id=123, email="test@test.com")


def test_verify_access_empty_agent_id() -> None:
    """Test that empty agent_id is processed correctly."""
    guard = PolicyGuard()
    # Should work fine
    ctx = UserContext(user_id="valid", email="test@test.com")
    assert guard.verify_access("", ctx) is True


def test_verify_access_unicode_user_id() -> None:
    """Test with unicode user IDs."""
    guard = PolicyGuard(blocklist=["👾"])
    # Allowed
    ctx1 = UserContext(user_id="🙂", email="test@test.com")
    assert guard.verify_access("agent_1", ctx1) is True
    # Denied
    ctx2 = UserContext(user_id="👾", email="test@test.com")
    with pytest.raises(ComplianceViolationError):
        guard.verify_access("agent_1", ctx2)


def test_verify_access_large_blocklist() -> None:
    """Test performance/correctness with a larger blocklist."""
    # Create blocklist with 1000 items
    blocklist = [f"user_{i}" for i in range(1000)]
    blocklist.append("target_user")

    guard = PolicyGuard(blocklist=blocklist)

    # Check allowed
    ctx_safe = UserContext(user_id="safe_user", email="test@test.com")
    assert guard.verify_access("agent_1", ctx_safe) is True

    # Check blocked (last item)
    ctx_target = UserContext(user_id="target_user", email="test@test.com")
    with pytest.raises(ComplianceViolationError):
        guard.verify_access("agent_1", ctx_target)

    # Check blocked (first item)
    ctx_first = UserContext(user_id="user_0", email="test@test.com")
    with pytest.raises(ComplianceViolationError):
        guard.verify_access("agent_1", ctx_first)
