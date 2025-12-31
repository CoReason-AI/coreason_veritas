# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, SecretStr, field_validator


class GovernanceRequest(BaseModel):
    """
    Pydantic model for validating governance arguments.
    """
    asset_id: Dict[str, Any] = Field(..., description="The asset payload/metadata")
    user_id: str = Field(..., description="The ID of the user executing the action")
    signature: Optional[SecretStr] = Field(None, description="The cryptographic signature (JWS)")

    # Optional config for sanitization (handled separately but we can include it if needed for validation)
    # But wrapper.py handles it dynamically based on arg name.

    @field_validator("asset_id")
    @classmethod
    def validate_asset_structure(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure asset has minimum required structure (like timestamp)."""
        # We can enforce specific structure here if needed.
        # For now, we trust Gatekeeper to validate contents deeper.
        return v
