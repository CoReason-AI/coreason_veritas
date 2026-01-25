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
