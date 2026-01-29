# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import sys
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

# Inject mock package into sys.path so coreason_validator can be imported
# We do this before importing the server module
MOCK_DIR = Path(__file__).parent / "mocks"
sys.path.insert(0, str(MOCK_DIR))

from fastapi.testclient import TestClient  # noqa: E402

from coreason_veritas.server import app  # noqa: E402

TEST_CONTEXT = {"user_id": "test_user", "email": "test@coreason.ai", "groups": [], "scopes": [], "claims": {}}

@pytest.fixture
def client():
    # Mock env var and SignatureValidator/IERLogger for lifespan.
    with patch.dict(os.environ, {"COREASON_SRB_PUBLIC_KEY": "dummy_key"}):
        with patch("coreason_veritas.server.SignatureValidator") as MockValidator, \
             patch("coreason_veritas.server.IERLogger") as MockLogger:

            # Configure Mock Validator
            MockValidator.return_value = MagicMock()

            # Configure Mock Logger
            mock_logger = MockLogger.return_value
            async def async_log(*args, **kwargs):
                return None
            mock_logger.log_event.side_effect = async_log

            with TestClient(app) as test_client:
                yield test_client

def test_audit_valid_artifact_tagged(client) -> None:
    artifact = {"enrichment_level": "TAGGED", "source_urn": "urn:job:101-alpha"}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 200
    assert response.json() == {"status": "APPROVED", "reason": "All checks passed."}


def test_audit_valid_artifact_linked(client) -> None:
    artifact = {"enrichment_level": "LINKED", "source_urn": "urn:job:production-123"}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 200
    assert response.json() == {"status": "APPROVED", "reason": "All checks passed."}


def test_audit_fail_enrichment_raw(client) -> None:
    artifact = {"enrichment_level": "RAW", "source_urn": "urn:job:101-alpha"}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 403
    data = response.json()
    assert data["detail"]["status"] == "REJECTED"
    assert "RAW" in data["detail"]["reason"]


def test_audit_fail_provenance(client) -> None:
    artifact = {"enrichment_level": "LINKED", "source_urn": "urn:user:bob"}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 403
    data = response.json()
    assert data["detail"]["status"] == "REJECTED"
    assert "start with 'urn:job:'" in data["detail"]["reason"]


def test_audit_fail_both(client) -> None:
    # Provenance check is second, but Enrichment is first.
    # It should fail on enrichment first.
    artifact = {"enrichment_level": "RAW", "source_urn": "urn:user:bob"}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 403
    data = response.json()
    assert data["detail"]["status"] == "REJECTED"
    assert "RAW" in data["detail"]["reason"]


# --- Edge Cases ---


def test_validation_error_missing_fields(client) -> None:
    # Missing enrichment_level in artifact
    artifact = {"source_urn": "urn:job:123"}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 422  # FastAPI validation error


def test_validation_error_missing_context(client) -> None:
    artifact = {"enrichment_level": "TAGGED", "source_urn": "urn:job:101-alpha"}
    payload = {"artifact": artifact}  # Missing context
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 422


def test_validation_error_empty_payload(client) -> None:
    response = client.post("/audit/artifact", json={})
    assert response.status_code == 422


def test_extra_fields_ignored(client) -> None:
    # Pydantic defaults to ignoring extra fields unless configured otherwise
    # Extra field in artifact
    artifact = {"enrichment_level": "TAGGED", "source_urn": "urn:job:123", "extra_field": "malicious_payload"}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "APPROVED"


def test_malformed_urn_just_prefix(client) -> None:
    # urn:job: is allowed by startswith logic?
    # Logic is `startswith("urn:job:")`. So just "urn:job:" is allowed.
    # This might be an edge case behavior to verify.
    # The requirement says "starts with urn:job:". It doesn't imply it must have characters after.
    artifact = {"enrichment_level": "TAGGED", "source_urn": "urn:job:"}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 200


def test_malformed_urn_almost_prefix(client) -> None:
    artifact = {"enrichment_level": "TAGGED", "source_urn": "urn:job"}  # Missing colon
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 403


def test_injection_attempt_in_urn(client) -> None:
    # SQL-like injection string, should be treated as literal string
    artifact = {"enrichment_level": "TAGGED", "source_urn": "urn:job:123; DROP TABLE users;"}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 200  # It starts with urn:job:, so it passes policy.
    # This is correct behavior unless stricter URN validation is added.


def test_large_payload(client) -> None:
    # Very long URN
    long_urn = "urn:job:" + "a" * 10000
    artifact = {"enrichment_level": "TAGGED", "source_urn": long_urn}
    payload = {"artifact": artifact, "context": TEST_CONTEXT}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 200
