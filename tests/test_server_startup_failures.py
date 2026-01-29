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
import sys
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from loguru import logger

# Inject mock package into sys.path
MOCK_DIR = Path(__file__).parent / "mocks"
sys.path.insert(0, str(MOCK_DIR))

import coreason_veritas.server  # noqa: E402
from coreason_veritas.server import app  # noqa: E402


@pytest.fixture  # type: ignore[misc]
def capture_logs() -> Generator[list[str], None, None]:
    """Fixture to capture loguru logs."""
    logs: list[str] = []
    handler_id = logger.add(lambda msg: logs.append(str(msg)))
    yield logs
    logger.remove(handler_id)


def test_startup_missing_public_key_warning(capture_logs: list[str]) -> None:
    """Test that lifespan logs a warning if COREASON_SRB_PUBLIC_KEY is not set."""

    # We patch os.environ.get to return None for COREASON_SRB_PUBLIC_KEY
    # We also patch SignatureValidator and IERLogger to succeed so app startup completes.

    with patch.dict(os.environ, clear=True):
        if "COREASON_SRB_PUBLIC_KEY" in os.environ:
            del os.environ["COREASON_SRB_PUBLIC_KEY"]

        with (
            patch.object(coreason_veritas.server, "SignatureValidator") as MockValidator,
            patch.object(coreason_veritas.server, "IERLogger") as MockLogger,
        ):
            # Configure mocks to succeed
            MockValidator.return_value = MagicMock()
            MockLogger.return_value = MagicMock()

            # Trigger lifespan
            with TestClient(app) as _:
                pass

    # Check logs for the warning
    assert any("COREASON_SRB_PUBLIC_KEY not set in environment." in msg for msg in capture_logs)


def test_startup_signature_validator_failure(capture_logs: list[str]) -> None:
    """Test that lifespan fails closed (raises) if SignatureValidator initialization fails."""

    with patch.dict(os.environ, {"COREASON_SRB_PUBLIC_KEY": "invalid-key"}):
        with (
            patch.object(coreason_veritas.server, "SignatureValidator") as MockValidator,
            patch.object(coreason_veritas.server, "IERLogger"),
        ):
            # Configure Validator to raise Exception
            MockValidator.side_effect = Exception("Critical Crypto Failure")

            # Expect exception during startup
            with pytest.raises(Exception, match="Critical Crypto Failure"):
                with TestClient(app) as _:
                    pass

    # Check logs for the error
    assert any("Failed to initialize SignatureValidator: Critical Crypto Failure" in msg for msg in capture_logs)
