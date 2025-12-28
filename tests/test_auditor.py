# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from coreason_veritas.anchor import DeterminismInterceptor
from coreason_veritas.auditor import IERLogger


@pytest.fixture  # type: ignore[misc]
def mock_tracer() -> Generator[MagicMock, None, None]:
    with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
        mock_tracer_instance = MagicMock()
        mock_get_tracer.return_value = mock_tracer_instance
        yield mock_tracer_instance


def test_start_governed_span_attributes(mock_tracer: MagicMock) -> None:
    """Test that start_governed_span adds attributes and creates a span."""
    logger = IERLogger("test-service")

    attributes = {"co.user_id": "user-123", "co.asset_id": "asset-456", "co.srb_sig": "sig-789"}

    # Mock the context manager returned by start_as_current_span
    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    with logger.start_governed_span("test-span", attributes):
        pass

    # Verify start_as_current_span was called with correct args
    mock_tracer.start_as_current_span.assert_called_once()
    call_args = mock_tracer.start_as_current_span.call_args
    assert call_args[0][0] == "test-span"
    called_attributes = call_args[1]["attributes"]

    assert called_attributes["co.user_id"] == "user-123"
    assert called_attributes["co.asset_id"] == "asset-456"
    assert called_attributes["co.srb_sig"] == "sig-789"
    # Anchor is inactive by default
    assert called_attributes["co.determinism_verified"] == "False"


def test_start_governed_span_with_anchor(mock_tracer: MagicMock) -> None:
    """Test that co.determinism_verified is True when Anchor is active."""
    logger = IERLogger("test-service")
    anchor = DeterminismInterceptor()
    attributes = {"co.user_id": "u", "co.asset_id": "a", "co.srb_sig": "s"}

    with anchor.scope():
        with logger.start_governed_span("test-span-anchor", attributes):
            pass

    # Verify determinism flag
    mock_tracer.start_as_current_span.assert_called_once()
    called_attributes = mock_tracer.start_as_current_span.call_args[1]["attributes"]
    assert called_attributes["co.determinism_verified"] == "True"


def test_start_governed_span_missing_attributes(mock_tracer: MagicMock) -> None:
    """Test that missing mandatory attributes raise ValueError."""
    logger = IERLogger("test-service")

    # Missing all
    with pytest.raises(ValueError, match="Missing mandatory attributes"):
        with logger.start_governed_span("test-span", {}):
            pass

    # Missing one
    with pytest.raises(ValueError, match="Missing mandatory attributes"):
        with logger.start_governed_span("test-span", {"co.user_id": "u", "co.asset_id": "a"}):
            pass

    # Ensure no span was started
    mock_tracer.start_as_current_span.assert_not_called()


def test_start_governed_span_non_string_attributes(mock_tracer: MagicMock) -> None:
    """
    Test that start_governed_span handles non-string attribute values.
    The implementation copies attributes and the OTel tracer usually handles conversion,
    but our code assumes strict matching for mandatory attributes.
    """
    logger = IERLogger("test-service")

    # Pass int and bool
    attributes = {"co.user_id": 123, "co.asset_id": "asset-456", "co.srb_sig": "sig-789", "custom": True}

    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    # It takes Dict[str, str] in hint but implementation uses `attributes.copy()`.
    # It should work as long as mandatory keys exist.
    with logger.start_governed_span("test-span", attributes):  # type: ignore
        pass

    mock_tracer.start_as_current_span.assert_called_once()
    called_attributes = mock_tracer.start_as_current_span.call_args[1]["attributes"]

    # Check that mandatory values are preserved (as provided)
    assert called_attributes["co.user_id"] == 123
    assert called_attributes["custom"] is True


def test_start_governed_span_none_attributes(mock_tracer: MagicMock) -> None:
    """Test behavior when attributes contain None."""
    logger = IERLogger("test-service")
    attributes = {"co.user_id": "u", "co.asset_id": "a", "co.srb_sig": "s", "nullable": None}

    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    with logger.start_governed_span("test-span", attributes):  # type: ignore
        pass

    called_attributes = mock_tracer.start_as_current_span.call_args[1]["attributes"]
    assert called_attributes["nullable"] is None


def test_start_governed_span_special_service_name(mock_tracer: MagicMock) -> None:
    """Test initialization with special characters in service name."""
    special_name = "service-with-weird-chars-!@#$%^&*()"
    logger = IERLogger(special_name)

    attributes = {"co.user_id": "u", "co.asset_id": "a", "co.srb_sig": "s"}
    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    with logger.start_governed_span("test", attributes):
        pass

    # The tracer is mocked, but we verify it didn't crash on init
    assert logger.tracer is not None
