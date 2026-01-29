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


@pytest.fixture  # type: ignore[misc]
def mock_logger() -> Generator[MagicMock, None, None]:
    with patch("coreason_veritas.auditor.logger") as mock:
        yield mock


def test_log_llm_transaction(mock_logger: MagicMock) -> None:
    """
    Test that log_llm_transaction correctly binds attributes and logs the event.
    """
    auditor = IERLogger()

    # Test Data
    from coreason_identity.models import UserContext

    trace_id = "test-trace-123"
    context = UserContext(user_id="test-user-456", email="test@coreason.ai")
    project_id = "test-project-789"
    model = "gpt-4"
    input_tokens = 100
    output_tokens = 50
    cost_usd = 0.003
    latency_ms = 1500

    auditor.log_llm_transaction(
        trace_id=trace_id,
        context=context,
        project_id=project_id,
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=cost_usd,
        latency_ms=latency_ms,
    )

    # Verify binding
    mock_logger.bind.assert_called_once()

    # Check arguments passed to bind
    call_kwargs = mock_logger.bind.call_args[1]

    assert call_kwargs["gen_ai.system"] == "coreason-platform"
    assert call_kwargs["gen_ai.request.model"] == model
    assert call_kwargs["gen_ai.usage.input_tokens"] == input_tokens
    assert call_kwargs["gen_ai.usage.output_tokens"] == output_tokens
    assert call_kwargs["gen_ai.usage.cost"] == cost_usd
    assert call_kwargs["co.user_id"] == context.user_id
    assert call_kwargs["co.asset_id"] == project_id
    assert call_kwargs["trace_id"] == trace_id
    assert call_kwargs["latency_ms"] == latency_ms

    # Verify info call
    mock_logger.bind.return_value.info.assert_called_once_with("LLM Transaction Recorded")
