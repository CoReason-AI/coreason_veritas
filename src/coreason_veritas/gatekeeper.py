# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

from datetime import datetime, timezone
from typing import Any, Dict, List

import jcs
from coreason_identity.models import UserContext
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from loguru import logger

from coreason_veritas.exceptions import AssetTamperedError, ComplianceViolationError


class PolicyGuard:
    """
    Enforces governance and access control policies for Agent Execution.
    """

    def __init__(self, blocklist: List[str] | None = None) -> None:
        """
        Initialize the PolicyGuard.

        Args:
            blocklist: A list of user IDs to block. Defaults to None.
        """
        # Future extensibility: Initialize connection to OPA, Database, or load policy files here.
        self.blocklist = blocklist or []

    def verify_access(self, agent_id: str, user_context: UserContext) -> bool:
        """
        Verifies if a user is authorized to execute a specific agent.

        Args:
            agent_id: The unique identifier of the agent.
            user_context: Context containing user details (e.g., 'user_id', 'role').

        Returns:
            bool: True if access is allowed.

        Raises:
            ComplianceViolationError: If access is denied.
            ValueError: If user_context is invalid.
        """
        user_id = user_context.user_id
        if not user_id:
            raise ValueError("Missing 'user_id' in user_context")

        # Basic Check Logic (Extensible)
        # TODO: Replace with OPA or Database lookup
        if user_id in self.blocklist:
            logger.warning(f"Access denied for user '{user_id}' on agent '{agent_id}'")
            raise ComplianceViolationError(f"Access denied: User '{user_id}' is restricted.")

        logger.info(f"Access allowed for user '{user_id}' on agent '{agent_id}'")
        return True


class SignatureValidator:
    """
    Validates the cryptographic chain of custody for Agent Specs and Charters.
    """

    def __init__(self, public_key_store: str):
        """
        Initialize the validator with the public key store.

        Args:
            public_key_store: The SRB Public Key (PEM format string).
        """
        self.key_store = public_key_store
        # Pre-load the public key to improve performance on repeated verification calls
        try:
            self._public_key = serialization.load_pem_public_key(self.key_store.encode())
        except Exception as e:
            # We log but allow initialization; verification will fail later if key is invalid,
            # or we could raise here. Raising here is safer to fail fast.
            logger.error(f"Failed to load public key: {e}")
            raise ValueError(f"Invalid public key provided: {e}") from e

    def verify_asset(self, asset_payload: Dict[str, Any], signature: str, check_timestamp: bool = True) -> bool:
        """
        Verifies the `x-coreason-sig` header against the payload hash.

        Args:
            asset_payload: The JSON payload to verify.
            signature: The hex-encoded signature string.
            check_timestamp: Whether to enforce timestamp/replay protection. Defaults to True.

        Returns:
            bool: True if verification succeeds.

        Raises:
            AssetTamperedError: If verification fails.
        """
        try:
            # 1. Replay Protection Check
            if check_timestamp:
                timestamp_str = asset_payload.get("timestamp")
                if not timestamp_str:
                    raise ValueError("Missing 'timestamp' in payload")

                try:
                    # ISO 8601 format expected
                    ts = datetime.fromisoformat(str(timestamp_str))
                    # Ensure timezone awareness (assuming UTC if not provided, or reject naive?)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                except ValueError as e:
                    raise ValueError(f"Invalid 'timestamp' format: {e}") from e

                now = datetime.now(timezone.utc)
                # Allow 5 minutes clock skew/latency
                if abs((now - ts).total_seconds()) > 300:
                    raise ValueError(f"Timestamp out of bounds (Replay Attack?): {ts} vs {now}")

            # 2. Cryptographic Verification
            # Use pre-loaded public key
            public_key = self._public_key

            # Canonicalize the asset_payload (JSON) to ensure consistent hashing
            canonical_payload = jcs.canonicalize(asset_payload)

            # Verify the signature
            # The spec example uses PSS padding with MGF1 and SHA256
            public_key.verify(
                bytes.fromhex(signature),
                canonical_payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            logger.info("Asset verification successful.")
            return True

        except (ValueError, TypeError, InvalidSignature) as e:
            logger.error(f"Asset verification failed: {e}")
            raise AssetTamperedError(f"Signature verification failed: {e}") from e

    def get_policy_instruction_for_llm(self) -> list[str]:
        """
        Returns a list of governance policies to be injected into the LLM prompt.

        Returns:
            list[str]: A list of policy strings.
        """
        return ["No use of 'eval'"]
