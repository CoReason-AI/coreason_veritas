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

from coreason_veritas.auditor import IERLogger


@pytest.fixture
def mock_tracer() -> Generator[MagicMock, None, None]:
    """Mock the OpenTelemetry tracer to prevent actual tracing calls."""
    with patch("coreason_veritas.auditor.trace.get_tracer") as mock:
        tracer_instance = mock.return_value
        yield tracer_instance


@pytest.fixture
def mock_logger_bind():
    """Mock loguru logger.bind"""
    with patch("coreason_veritas.auditor.logger.bind") as mock:
        yield mock


@pytest.fixture
def ier_logger(mock_tracer):
    IERLogger.reset()
    return IERLogger()


def test_log_llm_transaction(ier_logger, mock_logger_bind):
    """Test standard logging of LLM transaction."""
    mock_bound_logger = MagicMock()
    mock_logger_bind.return_value = mock_bound_logger

    ier_logger.log_llm_transaction(
        trace_id="test-trace-id",
        user_id="user-123",
        project_id="proj-456",
        model="gpt-4",
        input_tokens=100,
        output_tokens=50,
        cost_usd=0.002,
        latency_ms=150,
    )

    # Check that bind was called with correct attributes
    call_args = mock_logger_bind.call_args[1]
    assert call_args["gen_ai.system"] == "coreason-platform"
    assert call_args["gen_ai.request.model"] == "gpt-4"
    assert call_args["gen_ai.usage.input_tokens"] == 100
    assert call_args["gen_ai.usage.output_tokens"] == 50
    assert call_args["gen_ai.usage.cost"] == 0.002
    assert call_args["co.user_id"] == "user-123"
    assert call_args["co.asset_id"] == "proj-456"
    assert call_args["trace_id"] == "test-trace-id"
    assert call_args["latency_ms"] == 150

    # Check that info was called
    mock_bound_logger.info.assert_called_with("LLM Transaction Recorded")
