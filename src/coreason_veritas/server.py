# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import os
from contextlib import asynccontextmanager
from typing import AsyncIterator, Dict

from coreason_identity.models import UserContext
from coreason_validator.schemas.knowledge import KnowledgeArtifact
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from loguru import logger
from pydantic import BaseModel

from coreason_veritas import __version__
from coreason_veritas.auditor import IERLogger
from coreason_veritas.gatekeeper import PolicyGuard, SignatureValidator


class AuditResponse(BaseModel):  # type: ignore[misc]
    status: str
    reason: str


class VerifyAccessRequest(BaseModel):  # type: ignore[misc]
    user_context: UserContext
    agent_id: str


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Initialize Governance Singletons
    srb_public_key = os.environ.get("COREASON_SRB_PUBLIC_KEY")
    if not srb_public_key:
        logger.warning("COREASON_SRB_PUBLIC_KEY not set in environment.")
        # We allow it to proceed to let SignatureValidator handle it or fail.
        # SignatureValidator expects a string.
        srb_public_key = ""

    # SignatureValidator
    # This might raise if key is invalid, failing startup (Fail-Closed).
    try:
        app.state.validator = SignatureValidator(public_key_store=srb_public_key)
    except Exception as e:
        logger.error(f"Failed to initialize SignatureValidator: {e}")
        # If strict fail-closed at startup is required:
        # raise e
        # But for now, we will log error. However, if validator is critical, we should probably raise.
        # The prompt says "Store these instances...".
        # I'll let it raise if it fails, which is standard behavior (app won't start).
        raise e

    # IERLogger
    app.state.logger = IERLogger()

    # PolicyGuard
    app.state.policy_guard = PolicyGuard()

    yield


app = FastAPI(title="CoReason Veritas Governance Microservice", lifespan=lifespan)


@app.exception_handler(Exception)  # type: ignore[misc]
async def fail_closed_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Global exception handler to ensure Fail-Closed behavior.
    Catches any unhandled exception (crash) and returns 403 Forbidden
    instead of the default 500 Internal Server Error.
    """
    logger.exception("Unexpected server crash during audit. Failing closed.")
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": {"status": "REJECTED", "reason": "Internal System Error (Fail-Closed)"}},
    )


@app.get("/health")  # type: ignore[misc]
async def health_check() -> Dict[str, str]:
    return {"status": "active", "mode": "governance_sidecar", "version": __version__}


@app.post("/audit/artifact", response_model=AuditResponse)  # type: ignore[misc]
async def audit_artifact(artifact: KnowledgeArtifact, context: UserContext) -> AuditResponse:
    """
    Audits a KnowledgeArtifact against strict governance policies.
    Returns APPROVED or REJECTED.
    Fails closed with 403 Forbidden for any violations.
    """
    ier_logger: IERLogger = app.state.logger

    try:
        # Policy 1: Enrichment Level
        # Must be TAGGED or LINKED. Cannot be RAW.
        # We convert to string to handle both Enum and string inputs safely.
        level = str(artifact.enrichment_level)
        if level == "EnrichmentLevel.RAW" or level == "RAW":
            reason = "Artifact enrichment level is RAW. Must be TAGGED or LINKED."

            await ier_logger.log_event(
                "AUDIT_EVENT",
                {
                    "user_id": context.user_id,
                    "source_urn": artifact.source_urn,
                    "policy_id": "104-MANDATORY-ENRICHMENT",
                    "decision": "REJECTED",
                    "reason": reason,
                },
            )

            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"status": "REJECTED", "reason": reason})

        # Policy 2: Provenance
        # source_urn must start with "urn:job:"
        if not artifact.source_urn.startswith("urn:job:"):
            reason = f"Artifact source_urn '{artifact.source_urn}' does not start with 'urn:job:'."

            await ier_logger.log_event(
                "AUDIT_EVENT",
                {
                    "user_id": context.user_id,
                    "source_urn": artifact.source_urn,
                    "policy_id": "105-PROVENANCE-CHECK",
                    "decision": "REJECTED",
                    "reason": reason,
                },
            )

            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"status": "REJECTED", "reason": reason})

        # If all checks pass
        await ier_logger.log_event(
            "AUDIT_EVENT",
            {
                "user_id": context.user_id,
                "source_urn": artifact.source_urn,
                "policy_id": "ALL-PASSED",
                "decision": "APPROVED",
            },
        )

        return AuditResponse(status="APPROVED", reason="All checks passed.")

    except HTTPException:
        # Re-raise HTTPExceptions as they are intended responses
        raise
    except Exception as e:
        # Catch any other unexpected error here to ensure it hits the fail-closed logic
        # (Though the global handler catches it, explicit try-except in the endpoint is safer)
        logger.exception(f"Crash in audit logic: {e}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"status": "REJECTED", "reason": "Internal Audit Logic Crash"},
        ) from e


@app.post("/verify/access")  # type: ignore[misc]
async def verify_access(request: VerifyAccessRequest) -> JSONResponse:
    """
    Verifies if a user is authorized to execute a specific agent.
    """
    policy_guard: PolicyGuard = app.state.policy_guard
    try:
        # verify_access returns True if allowed, or raises exception.
        policy_guard.verify_access(request.agent_id, request.user_context)
        return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "ALLOWED"})
    except Exception as e:
        logger.warning(f"Access denied: {e}")
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"status": "DENIED", "reason": str(e)})
