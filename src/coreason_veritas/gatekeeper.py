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
from datetime import datetime, timezone
from typing import Any, Dict

import jwt
from cryptography.hazmat.primitives import serialization
from loguru import logger

from coreason_veritas.exceptions import AssetTamperedError


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
        Verifies the JWS signature and ensures the payload matches.

        Args:
            asset_payload: The expected JSON payload.
            signature: The JWS string.
            check_timestamp: Whether to enforce timestamp/replay protection. Defaults to True.

        Returns:
            bool: True if verification succeeds.

        Raises:
            AssetTamperedError: If verification fails.
        """
        try:
            # 1. Decode and Verify JWS
            # We use the public key object loaded in __init__
            decoded_payload = jwt.decode(signature, self._public_key, algorithms=["RS256"])

            # 2. Payload Integrity Check
            # The payload inside the JWS must match the provided asset_payload
            if decoded_payload != asset_payload:
                raise ValueError("Payload mismatch: JWS content does not match provided asset.")

            # 3. Replay Protection Check
            if check_timestamp:
                timestamp_str = decoded_payload.get("timestamp")
                if not timestamp_str:
                    raise ValueError("Missing 'timestamp' in payload")

                try:
                    # ISO 8601 format expected
                    ts = datetime.fromisoformat(str(timestamp_str))
                    # Ensure timezone awareness
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                except ValueError as e:
                    raise ValueError(f"Invalid 'timestamp' format: {e}") from e

                now = datetime.now(timezone.utc)
                # Allow 5 minutes clock skew/latency
                if abs((now - ts).total_seconds()) > 300:
                    raise ValueError(f"Timestamp out of bounds (Replay Attack?): {ts} vs {now}")

            logger.info("Asset verification successful.")
            return True

        except (ValueError, TypeError, jwt.PyJWTError, json.JSONDecodeError) as e:
            logger.error(f"Asset verification failed: {e}")
            raise AssetTamperedError(f"Signature verification failed: {e}") from e
