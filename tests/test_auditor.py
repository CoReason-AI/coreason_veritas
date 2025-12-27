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
from unittest.mock import MagicMock, patch
from typing import Generator, Any
from coreason_veritas.auditor import IERLogger
from coreason_veritas.anchor import DeterminismInterceptor

@pytest.fixture  # type: ignore[misc]
def mock_tracer() -> Generator[MagicMock, None, None]:
    with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
        mock_tracer_instance = MagicMock()
        mock_get_tracer.return_value = mock_tracer_instance
        yield mock_tracer_instance

def test_start_governed_span_attributes(mock_tracer: MagicMock) -> None:
    """Test that start_governed_span adds attributes and creates a span."""
    logger = IERLogger("test-service")

    attributes = {
        "co.user_id": "user-123",
        "co.asset_id": "asset-456",
        "co.srb_sig": "sig-789"
    }

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

    with anchor.scope():
        with logger.start_governed_span("test-span-anchor", {}):
            pass

    # Verify determinism flag
    mock_tracer.start_as_current_span.assert_called_once()
    called_attributes = mock_tracer.start_as_current_span.call_args[1]["attributes"]
    assert called_attributes["co.determinism_verified"] == "True"
