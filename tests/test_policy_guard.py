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


def test_verify_access_allowed() -> None:
    """Test successful access verification for a valid user."""
    guard = PolicyGuard()
    user_context = {"user_id": "valid_user", "role": "admin"}
    assert guard.verify_access("agent_123", user_context) is True


def test_verify_access_denied_blocklist() -> None:
    """Test access verification fails for a blocklisted user."""
    guard = PolicyGuard(blocklist=["blocked_user"])
    user_context = {"user_id": "blocked_user", "role": "user"}

    with pytest.raises(ComplianceViolationError) as excinfo:
        guard.verify_access("agent_123", user_context)

    assert "Access denied" in str(excinfo.value)


def test_verify_access_missing_user_id() -> None:
    """Test verification fails gracefully (or handled appropriately) when user_id is missing."""
    guard = PolicyGuard()
    user_context = {"role": "user"}

    # Depending on implementation, this might raise ValueError or similar
    # For now, let's assume strict checking requiring user_id
    with pytest.raises(ValueError) as excinfo:
        guard.verify_access("agent_123", user_context)

    assert "Missing 'user_id'" in str(excinfo.value)


def test_verify_access_empty_context() -> None:
    """Test verification with empty context."""
    guard = PolicyGuard()
    with pytest.raises(ValueError, match="Missing 'user_id'"):
        guard.verify_access("agent_123", {})
