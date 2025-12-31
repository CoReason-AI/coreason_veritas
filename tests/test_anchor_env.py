import os
from unittest.mock import patch

from coreason_veritas.anchor import DeterminismInterceptor


def test_determinism_interceptor_invalid_seed_env():
    """Test that invalid VERITAS_SEED falls back to 42."""
    with patch.dict(os.environ, {"VERITAS_SEED": "invalid_int"}):
        config = {"model": "gpt-4", "temperature": 0.5, "seed": 999}
        sanitized = DeterminismInterceptor.enforce_config(config)
        assert sanitized["seed"] == 42
