# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import asyncio
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Inject mock package into sys.path so coreason_validator can be imported
MOCK_DIR = Path(__file__).parent / "mocks"
sys.path.insert(0, str(MOCK_DIR))

from coreason_veritas.server import app  # noqa: E402

client = TestClient(app)
TEST_CONTEXT = {"user_id": "test_user", "email": "test@coreason.ai", "groups": [], "scopes": [], "claims": {}}


def test_unicode_urn() -> None:
    """Test handling of URNs with unicode characters."""
    # Emojis and non-latin characters
    urn = "urn:job:🚀-project-Ω"
    artifact = {"enrichment_level": "TAGGED", "source_urn": urn}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "APPROVED"


def test_urn_whitespace_handling() -> None:
    """
    Test how the server handles whitespace.
    Note: Standard startswith logic does NOT strip whitespace.
    So ' urn:job:123' should fail check 2 if not stripped by Pydantic.
    """
    # Leading whitespace
    artifact = {"enrichment_level": "TAGGED", "source_urn": " urn:job:123"}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    # Expect 403 because " urn:job:..." does not start with "urn:job:"
    assert response.status_code == 403
    assert "start with 'urn:job:'" in response.json()["detail"]["reason"]

    # Trailing whitespace (should pass validation as it starts with urn:job:)
    artifact_trail = {"enrichment_level": "TAGGED", "source_urn": "urn:job:123 "}
    payload_trail = {"artifact": artifact_trail, "context": TEST_CONTEXT}
    response_trail = client.post("/audit/artifact", json=payload_trail)
    assert response_trail.status_code == 200


def test_enum_case_sensitivity() -> None:
    """Test that Enum values are case sensitive (Pydantic default behavior)."""
    # 'tagged' instead of 'TAGGED'
    artifact = {"enrichment_level": "tagged", "source_urn": "urn:job:123"}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    # Should be 422 Unprocessable Entity (Validation Error)
    assert response.status_code == 422


def test_statelessness_redundancy() -> None:
    """Verify that repeated requests yield identical results (Stateless)."""
    artifact = {"enrichment_level": "TAGGED", "source_urn": "urn:job:redundant"}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}

    # Send 50 identical requests
    for _ in range(50):
        response = client.post("/audit/artifact", json=payload)
        assert response.status_code == 200
        assert response.json()["status"] == "APPROVED"


@pytest.mark.asyncio  # type: ignore[misc]
async def test_concurrent_load() -> None:
    """
    Simulate concurrent requests using httpx AsyncClient.
    TestClient is synchronous, so we use AsyncClient for this test.
    """
    from httpx import ASGITransport, AsyncClient

    # Create 50 concurrent requests
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        tasks = []
        artifact = {"enrichment_level": "TAGGED", "source_urn": "urn:job:concurrent"}
        payload = {"artifact": artifact, "context": TEST_CONTEXT}

        for _ in range(50):
            tasks.append(ac.post("/audit/artifact", json=payload))

        responses = await asyncio.gather(*tasks)

        for response in responses:
            assert response.status_code == 200
            assert response.json()["status"] == "APPROVED"
