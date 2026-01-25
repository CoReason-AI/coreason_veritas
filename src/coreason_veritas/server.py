# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

from fastapi import FastAPI, HTTPException, status
from loguru import logger
from pydantic import BaseModel
from coreason_validator.schemas.knowledge import KnowledgeArtifact

app = FastAPI(title="CoReason Veritas Governance Microservice")

class AuditResponse(BaseModel):
    status: str
    reason: str

@app.post("/audit/artifact", response_model=AuditResponse)
async def audit_artifact(artifact: KnowledgeArtifact) -> AuditResponse:
    """
    Audits a KnowledgeArtifact against strict governance policies.
    Returns APPROVED or REJECTED.
    Fails closed with 403 Forbidden for any violations.
    """

    # Policy 1: Enrichment Level
    # Must be TAGGED or LINKED. Cannot be RAW.
    # We convert to string to handle both Enum and string inputs safely.
    level = str(artifact.enrichment_level)
    if level == "EnrichmentLevel.RAW" or level == "RAW":
        reason = "Artifact enrichment level is RAW. Must be TAGGED or LINKED."
        logger.bind(
            source_urn=artifact.source_urn,
            policy_id="104-MANDATORY-ENRICHMENT",
            decision="REJECTED"
        ).warning(reason)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"status": "REJECTED", "reason": reason}
        )

    # Policy 2: Provenance
    # source_urn must start with "urn:job:"
    if not artifact.source_urn.startswith("urn:job:"):
        reason = f"Artifact source_urn '{artifact.source_urn}' does not start with 'urn:job:'."
        logger.bind(
            source_urn=artifact.source_urn,
            policy_id="105-PROVENANCE-CHECK",
            decision="REJECTED"
        ).warning(reason)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"status": "REJECTED", "reason": reason}
        )

    # If all checks pass
    logger.bind(
        source_urn=artifact.source_urn,
        policy_id="ALL-PASSED",
        decision="APPROVED"
    ).info("Artifact passed all audit checks.")

    return AuditResponse(status="APPROVED", reason="All checks passed.")
