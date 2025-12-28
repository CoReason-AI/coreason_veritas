# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import logging
from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest
from opentelemetry.sdk._logs import LoggingHandler

from coreason_veritas.auditor import IERLogger


@pytest.fixture  # type: ignore[misc]
def clean_logger() -> Generator[logging.Logger, None, None]:
    """Fixture to ensure coreason.veritas logger is clean before and after test."""
    logger = logging.getLogger("coreason.veritas")
    # Clear handlers
    logger.handlers = []
    yield logger
    # Cleanup and restore
    logger.handlers = []


def test_idempotency_multiple_inits(clean_logger: logging.Logger) -> None:
    """
    Test that instantiating IERLogger multiple times does not duplicate LoggingHandler.
    """
    with (
        patch("coreason_veritas.auditor.trace.set_tracer_provider"),
        patch("coreason_veritas.auditor._logs.set_logger_provider"),
        patch("coreason_veritas.auditor.OTLPSpanExporter"),
        patch("coreason_veritas.auditor.OTLPLogExporter"),
    ):
        # First Init
        ier1 = IERLogger()
        assert len(ier1.otel_bridge_logger.handlers) == 1
        assert isinstance(ier1.otel_bridge_logger.handlers[0], LoggingHandler)

        # Second Init
        ier2 = IERLogger()
        assert len(ier2.otel_bridge_logger.handlers) == 1
        assert ier2.otel_bridge_logger.handlers[0] is ier1.otel_bridge_logger.handlers[0]


def test_idempotency_pre_existing_handler(clean_logger: logging.Logger) -> None:
    """
    Test that if a LoggingHandler is already attached (e.g. by another part of the app),
    IERLogger does not add a second one.
    """
    # Manually add a LoggingHandler
    existing_handler = LoggingHandler(level=logging.INFO, logger_provider=MagicMock())
    clean_logger.addHandler(existing_handler)

    with (
        patch("coreason_veritas.auditor.trace.set_tracer_provider"),
        patch("coreason_veritas.auditor._logs.set_logger_provider"),
        patch("coreason_veritas.auditor.OTLPSpanExporter"),
        patch("coreason_veritas.auditor.OTLPLogExporter"),
    ):
        ier = IERLogger()

        # Should still be 1
        assert len(ier.otel_bridge_logger.handlers) == 1
        assert ier.otel_bridge_logger.handlers[0] is existing_handler


def test_idempotency_mock_handler_conflict(clean_logger: logging.Logger) -> None:
    """
    Test the fix for the regression where a MagicMock handler caused issues.
    We verify that:
    1. A generic MagicMock (not named LoggingHandler) DOES NOT prevent adding a real handler.
    2. A MagicMock named 'LoggingHandler' DOES prevent adding a real handler (simulating a mocked environment).
    """
    # Case 1: Generic Mock
    generic_mock = MagicMock()
    clean_logger.addHandler(generic_mock)

    with (
        patch("coreason_veritas.auditor.trace.set_tracer_provider"),
        patch("coreason_veritas.auditor._logs.set_logger_provider"),
        patch("coreason_veritas.auditor.OTLPSpanExporter"),
        patch("coreason_veritas.auditor.OTLPLogExporter"),
    ):
        ier = IERLogger()
        # Should have added a real handler because generic_mock is not recognized as LoggingHandler
        assert len(ier.otel_bridge_logger.handlers) == 2
        assert isinstance(ier.otel_bridge_logger.handlers[1], LoggingHandler)

    # Cleanup for Case 2
    clean_logger.handlers = []

    # Case 2: Mock masquerading as LoggingHandler (what happens when we patch the class)
    masquerade_mock = MagicMock()
    masquerade_mock.__class__.__name__ = "LoggingHandler"
    clean_logger.addHandler(masquerade_mock)

    with (
        patch("coreason_veritas.auditor.trace.set_tracer_provider"),
        patch("coreason_veritas.auditor._logs.set_logger_provider"),
        patch("coreason_veritas.auditor.OTLPSpanExporter"),
        patch("coreason_veritas.auditor.OTLPLogExporter"),
    ):
        ier = IERLogger()
        # Should NOT add new handler because it thinks one exists
        assert len(ier.otel_bridge_logger.handlers) == 1
        assert ier.otel_bridge_logger.handlers[0] is masquerade_mock


def test_handshake_data_integrity(clean_logger: Any) -> None:
    """
    Verify that the handshake log contains the correct version and attributes.
    """
    with (
        patch("coreason_veritas.auditor.trace.set_tracer_provider"),
        patch("coreason_veritas.auditor._logs.set_logger_provider"),
        patch("coreason_veritas.auditor.OTLPSpanExporter"),
        patch("coreason_veritas.auditor.OTLPLogExporter"),
    ):
        ier = IERLogger()

        # Patch the logger to capture the log call
        with patch.object(ier.otel_bridge_logger, "info") as mock_info:
            version = "9.9.9-test"
            ier.emit_handshake(version)

            mock_info.assert_called_once_with(
                "Veritas Engine Initialized",
                extra={"co.veritas.version": version, "co.governance.status": "active"},
            )
