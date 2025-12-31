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
from unittest.mock import patch

from coreason_veritas.anchor import DeterminismInterceptor


def test_determinism_interceptor_invalid_seed_env() -> None:
    """Test that invalid VERITAS_SEED falls back to 42."""
    with patch.dict(os.environ, {"VERITAS_SEED": "invalid_int"}):
        config = {"model": "gpt-4", "temperature": 0.5, "seed": 999}
        sanitized = DeterminismInterceptor.enforce_config(config)
        assert sanitized["seed"] == 42
