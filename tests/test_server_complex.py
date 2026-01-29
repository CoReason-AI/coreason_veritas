# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import json
import os
import sys
from collections.abc import Generator
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

# Inject mock package into sys.path so coreason_validator can be imported
MOCK_DIR = Path(__file__).parent / "mocks"
sys.path.insert(0, str(MOCK_DIR))

from coreason_veritas.server import app, fail_closed_handler  # noqa: E402

TEST_CONTEXT = {
    "user_id": "test_user",
    "email": "test@coreason.ai",
    "groups": [],
    "scopes": [],
    "claims": {},
}


@pytest.fixture  # type: ignore[misc]
def client() -> Generator[TestClient, None, None]:
    """Fixture to provide TestClient with mocked lifespan dependencies."""
    with patch.dict(os.environ, {"COREASON_SRB_PUBLIC_KEY": "dummy_key"}):
        with (
            patch("coreason_veritas.server.SignatureValidator") as MockValidator,
            patch("coreason_veritas.server.IERLogger") as MockLogger,
        ):
            # Configure Mock Validator
            MockValidator.return_value = MagicMock()

            # Configure Mock Logger
            mock_logger = MockLogger.return_value
            # app.state.logger will be this instance.
            # We need to make sure calls to log_event don't fail.
            # log_event is async.
            mock_logger.log_event = MagicMock()

            async def async_log(*args: object, **kwargs: object) -> None:
                return None

            mock_logger.log_event.side_effect = async_log

            with TestClient(app) as test_client:
                yield test_client


def test_high_volume_audit_requests(client: TestClient) -> None:
    """Simulate high volume of mixed valid/invalid requests."""
    iterations = 100
    for i in range(iterations):
        # Even: Valid
        if i % 2 == 0:
            artifact = {"enrichment_level": "TAGGED", "source_urn": f"urn:job:{i}"}
            payload = {"artifact": artifact, "context": TEST_CONTEXT}
            response = client.post("/audit/artifact", json=payload)
            assert response.status_code == 200, f"Failed on iteration {i} (expected success)"
            assert response.json()["status"] == "APPROVED"
        # Odd: Invalid (RAW)
        else:
            artifact = {"enrichment_level": "RAW", "source_urn": f"urn:job:{i}"}
            payload = {"artifact": artifact, "context": TEST_CONTEXT}
            response = client.post("/audit/artifact", json=payload)
            assert response.status_code == 403, f"Failed on iteration {i} (expected forbidden)"
            assert response.json()["detail"]["status"] == "REJECTED"


def test_fail_closed_on_crash(client: TestClient) -> None:
    """Verify that if code crashes (raises unexpected exception), it returns 403 (Fail-Closed)."""

    # Simulate a crash by forcing the mocked logger to raise an exception.
    # The client fixture sets app.state.logger to a MagicMock.
    mock_logger = cast(MagicMock, app.state.logger)
    original_side_effect = mock_logger.log_event.side_effect

    # We want log_event to raise an exception when awaited.
    # Since log_event is async, side_effect should return a coroutine that raises, or be an exception?
    # If side_effect is an exception, calling the mock raises it immediately (sync).
    # But log_event is awaited.
    # If side_effect is an exception, the `await mock()` call will raise it?
    # No, `await` expects an awaitable.
    # We need side_effect to be a function that raises?
    # Or, since it's a Mock, if we set side_effect to Exception, calling it raises.
    # But the code does `await ier_logger.log_event(...)`.
    # If `log_event(...)` raises sync, `await` never happens.
    # This works for simulating a crash *before* await, which is fine for testing crash handling.
    mock_logger.log_event.side_effect = Exception("Simulated Core Crash")

    try:
        artifact = {"enrichment_level": "TAGGED", "source_urn": "urn:job:123"}
        payload = {"artifact": artifact, "context": TEST_CONTEXT}
        response = client.post("/audit/artifact", json=payload)

        # It should catch the exception and return 403
        assert response.status_code == 403
        data = response.json()
        assert data["detail"]["status"] == "REJECTED"
        assert "Internal Audit Logic Crash" in data["detail"]["reason"]
    finally:
        mock_logger.log_event.side_effect = original_side_effect


@pytest.mark.asyncio  # type: ignore[misc]
async def test_global_exception_handler() -> None:
    """Directly test the global exception handler to ensure coverage."""
    mock_request = MagicMock(spec=Request)
    exc = Exception("Catastrophic Failure")

    response = await fail_closed_handler(mock_request, exc)

    assert response.status_code == 403
    body = json.loads(response.body)
    assert body["detail"]["status"] == "REJECTED"
    assert "Internal System Error (Fail-Closed)" in body["detail"]["reason"]
