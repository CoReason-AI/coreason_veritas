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
import os
import sys
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Inject mock package into sys.path so coreason_validator can be imported
MOCK_DIR = Path(__file__).parent / "mocks"
sys.path.insert(0, str(MOCK_DIR))

from coreason_veritas.server import app  # noqa: E402

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
            mock_logger.log_event = MagicMock()

            async def async_log(*args: object, **kwargs: object) -> None:
                return None

            mock_logger.log_event.side_effect = async_log

            with TestClient(app) as test_client:
                yield test_client


def test_unicode_urn(client: TestClient) -> None:
    """Test handling of URNs with unicode characters."""
    # Emojis and non-latin characters
    urn = "urn:job:🚀-project-Ω"
    artifact = {"enrichment_level": "TAGGED", "source_urn": urn}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "APPROVED"


def test_urn_whitespace_handling(client: TestClient) -> None:
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


def test_enum_case_sensitivity(client: TestClient) -> None:
    """Test that Enum values are case sensitive (Pydantic default behavior)."""
    # 'tagged' instead of 'TAGGED'
    artifact = {"enrichment_level": "tagged", "source_urn": "urn:job:123"}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    # Should be 422 Unprocessable Entity (Validation Error)
    assert response.status_code == 422


def test_statelessness_redundancy(client: TestClient) -> None:
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

    # Mock dependencies manually for this async test
    with patch.dict(os.environ, {"COREASON_SRB_PUBLIC_KEY": "dummy_key"}):
        with (
            patch("coreason_veritas.server.SignatureValidator") as MockValidator,
            patch("coreason_veritas.server.IERLogger") as MockLogger,
        ):
            # Configure Mock Validator
            MockValidator.return_value = MagicMock()

            # Configure Mock Logger
            mock_logger = MockLogger.return_value
            mock_logger.log_event = MagicMock()

            async def async_log(*args: object, **kwargs: object) -> None:
                return None

            mock_logger.log_event.side_effect = async_log

            # Create 50 concurrent requests
            # We must use the app with lifespan triggered by AsyncClient (handled by ASGITransport?)
            # ASGITransport does NOT run lifespan by default unless you use LifespanManager?
            # Actually, newer httpx + fastapi might run it if client context manager is used.
            # But just in case, patching ensures it works or at least doesn't crash if it runs.
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
