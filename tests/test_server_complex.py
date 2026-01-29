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
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Inject mock package into sys.path so coreason_validator can be imported
MOCK_DIR = Path(__file__).parent / "mocks"
sys.path.insert(0, str(MOCK_DIR))

import pytest  # noqa: E402
from fastapi import Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from coreason_veritas.server import app, fail_closed_handler  # noqa: E402

client = TestClient(app)
TEST_CONTEXT = {"user_id": "test_user", "email": "test@coreason.ai", "groups": [], "scopes": [], "claims": {}}


def test_high_volume_audit_requests() -> None:
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


def test_fail_closed_on_crash() -> None:
    """Verify that if code crashes (raises unexpected exception), it returns 403 (Fail-Closed)."""

    # We simulate a crash by mocking the logger.bind to raise an exception
    # (since that's called inside the route).
    with patch("coreason_veritas.server.logger.bind") as mock_bind:
        mock_bind.side_effect = Exception("Simulated Core Crash")

        artifact = {"enrichment_level": "TAGGED", "source_urn": "urn:job:123"}
        payload = {"artifact": artifact, "context": TEST_CONTEXT}
        response = client.post("/audit/artifact", json=payload)

        # It should catch the exception and return 403
        assert response.status_code == 403
        data = response.json()
        assert data["detail"]["status"] == "REJECTED"
        assert "Internal Audit Logic Crash" in data["detail"]["reason"]


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
