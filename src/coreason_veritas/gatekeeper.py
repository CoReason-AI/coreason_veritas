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
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
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

    def verify_asset(self, asset_payload: Dict[str, Any], signature: str) -> bool:
        """
        Verifies the `x-coreason-sig` header against the payload hash.

        Args:
            asset_payload: The JSON payload to verify.
            signature: The hex-encoded signature string.

        Returns:
            bool: True if verification succeeds.

        Raises:
            AssetTamperedError: If verification fails.
        """
        try:
            # Load the public key
            public_key = serialization.load_pem_public_key(self.key_store.encode())

            # Canonicalize the asset_payload (JSON) to ensure consistent hashing
            canonical_payload = json.dumps(asset_payload, sort_keys=True).encode()

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

        except (ValueError, TypeError, InvalidSignature, Exception) as e:
            logger.error(f"Asset verification failed: {e}")
            raise AssetTamperedError(f"Signature verification failed: {e}") from e
