import os
import sys
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Inject mock package into sys.path
MOCK_DIR = Path(__file__).parent / "mocks"
sys.path.insert(0, str(MOCK_DIR))

# Import app after sys.path hack
from coreason_veritas.server import app  # noqa: E402


@pytest.fixture  # type: ignore[misc]
def client() -> Generator[TestClient, None, None]:
    # Mock env var and SignatureValidator/IERLogger for lifespan.
    # We patch the names in coreason_veritas.server namespace because server.py imports them.

    with patch.dict(os.environ, {"COREASON_SRB_PUBLIC_KEY": "dummy_key"}):
        with (
            patch("coreason_veritas.server.SignatureValidator") as MockValidator,
            patch("coreason_veritas.server.IERLogger") as MockLogger,
        ):
            # Configure Mock Validator to not raise error on init
            MockValidator.return_value = MagicMock()

            # Configure Mock Logger
            mock_logger_instance = MockLogger.return_value
            # app.state.logger will be this instance.
            # We need to make sure calls to log_event don't fail.
            # log_event is async.
            mock_logger_instance.log_event = MagicMock()

            async def async_log(*args: object, **kwargs: object) -> None:
                return None

            mock_logger_instance.log_event.side_effect = async_log

            with TestClient(app) as test_client:
                yield test_client


def test_health_check(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "active", "mode": "governance_sidecar", "version": "0.9.0"}


def test_audit_artifact_pass(client: TestClient) -> None:
    artifact = {"enrichment_level": "TAGGED", "source_urn": "urn:job:123"}
    context = {"user_id": "test_user", "email": "test@coreason.ai"}
    response = client.post("/audit/artifact", json={"artifact": artifact, "context": context})
    assert response.status_code == 200
    assert response.json() == {"status": "APPROVED", "reason": "All checks passed."}


TEST_CONTEXT = {
    "user_id": "test_user",
    "email": "test@coreason.ai",
    "groups": [],
    "scopes": [],
    "claims": {},
}


def test_audit_artifact_fail_policy(client: TestClient) -> None:
    artifact = {"enrichment_level": "RAW", "source_urn": "urn:job:123"}
    response = client.post("/audit/artifact", json={"artifact": artifact, "context": TEST_CONTEXT})
    assert response.status_code == 403
    assert response.json()["detail"]["status"] == "REJECTED"


def test_verify_access_allowed(client: TestClient) -> None:
    # Default PolicyGuard allows everything if blocklist is empty
    response = client.post("/verify/access", json={"user_context": TEST_CONTEXT, "agent_id": "agent-007"})
    assert response.status_code == 200
    assert response.json() == {"status": "ALLOWED"}


def test_verify_access_denied(client: TestClient) -> None:
    # Mock the policy guard in app.state

    original_guard = app.state.policy_guard
    mock_guard = MagicMock()
    # Simulate denial by raising Exception
    mock_guard.verify_access.side_effect = Exception("Blocked by policy")
    app.state.policy_guard = mock_guard

    try:
        response = client.post("/verify/access", json={"user_context": TEST_CONTEXT, "agent_id": "agent-007"})
        assert response.status_code == 403
        assert response.json()["status"] == "DENIED"
    finally:
        app.state.policy_guard = original_guard
