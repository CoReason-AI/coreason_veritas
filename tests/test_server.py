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
from pathlib import Path

# Inject mock package into sys.path so coreason_validator can be imported
# We do this before importing the server module
MOCK_DIR = Path(__file__).parent / "mocks"
sys.path.insert(0, str(MOCK_DIR))

from fastapi.testclient import TestClient  # noqa: E402

from coreason_veritas.server import app  # noqa: E402

client = TestClient(app)


def test_audit_valid_artifact_tagged() -> None:
    payload = {"enrichment_level": "TAGGED", "source_urn": "urn:job:101-alpha"}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 200
    assert response.json() == {"status": "APPROVED", "reason": "All checks passed."}


def test_audit_valid_artifact_linked() -> None:
    payload = {"enrichment_level": "LINKED", "source_urn": "urn:job:production-123"}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 200
    assert response.json() == {"status": "APPROVED", "reason": "All checks passed."}


def test_audit_fail_enrichment_raw() -> None:
    payload = {"enrichment_level": "RAW", "source_urn": "urn:job:101-alpha"}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 403
    data = response.json()
    assert data["detail"]["status"] == "REJECTED"
    assert "RAW" in data["detail"]["reason"]


def test_audit_fail_provenance() -> None:
    payload = {"enrichment_level": "LINKED", "source_urn": "urn:user:bob"}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 403
    data = response.json()
    assert data["detail"]["status"] == "REJECTED"
    assert "start with 'urn:job:'" in data["detail"]["reason"]


def test_audit_fail_both() -> None:
    # Provenance check is second, but Enrichment is first.
    # It should fail on enrichment first.
    payload = {"enrichment_level": "RAW", "source_urn": "urn:user:bob"}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 403
    data = response.json()
    assert data["detail"]["status"] == "REJECTED"
    assert "RAW" in data["detail"]["reason"]


# --- Edge Cases ---


def test_validation_error_missing_fields() -> None:
    payload = {"source_urn": "urn:job:123"}  # Missing enrichment_level
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 422  # FastAPI validation error


def test_validation_error_empty_payload() -> None:
    response = client.post("/audit/artifact", json={})
    assert response.status_code == 422


def test_extra_fields_ignored() -> None:
    # Pydantic defaults to ignoring extra fields unless configured otherwise
    payload = {"enrichment_level": "TAGGED", "source_urn": "urn:job:123", "extra_field": "malicious_payload"}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "APPROVED"


def test_malformed_urn_just_prefix() -> None:
    # urn:job: is allowed by startswith logic?
    # Logic is `startswith("urn:job:")`. So just "urn:job:" is allowed.
    # This might be an edge case behavior to verify.
    # The requirement says "starts with urn:job:". It doesn't imply it must have characters after.
    payload = {"enrichment_level": "TAGGED", "source_urn": "urn:job:"}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 200


def test_malformed_urn_almost_prefix() -> None:
    payload = {"enrichment_level": "TAGGED", "source_urn": "urn:job"}  # Missing colon
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 403


def test_injection_attempt_in_urn() -> None:
    # SQL-like injection string, should be treated as literal string
    payload = {"enrichment_level": "TAGGED", "source_urn": "urn:job:123; DROP TABLE users;"}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 200  # It starts with urn:job:, so it passes policy.
    # This is correct behavior unless stricter URN validation is added.


def test_large_payload() -> None:
    # Very long URN
    long_urn = "urn:job:" + "a" * 10000
    payload = {"enrichment_level": "TAGGED", "source_urn": long_urn}
    response = client.post("/audit/artifact", json=payload)
    assert response.status_code == 200
