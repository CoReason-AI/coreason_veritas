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
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

from coreason_veritas.anchor import DeterminismInterceptor
from coreason_veritas.auditor import IERLogger


@pytest.fixture  # type: ignore[misc]
def mock_otlp_env() -> Generator[None, None, None]:
    """Ensure OTLP environment variables are handled correctly."""
    with patch.dict("os.environ", {"OTEL_SERVICE_NAME": "test-service", "DEPLOYMENT_ENV": "test-env"}):
        yield


@pytest.fixture  # type: ignore[misc]
def mock_tracer_provider() -> Generator[MagicMock, None, None]:
    with patch("coreason_veritas.auditor.TracerProvider") as mock_tp:
        yield mock_tp


@pytest.fixture  # type: ignore[misc]
def mock_logger_provider() -> Generator[MagicMock, None, None]:
    with patch("coreason_veritas.auditor.LoggerProvider") as mock_lp:
        yield mock_lp


@pytest.fixture  # type: ignore[misc]
def mock_tracer(mock_tracer_provider: MagicMock) -> Generator[MagicMock, None, None]:
    # Trace.get_tracer is called inside __init__ using the provider
    # But wait, implementation calls trace.set_tracer_provider(tp) then trace.get_tracer
    # We should mock trace.get_tracer directly or ensure logic flow works
    with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
        mock_tracer_instance = MagicMock()
        mock_get_tracer.return_value = mock_tracer_instance
        yield mock_tracer_instance


@pytest.fixture  # type: ignore[misc]
def mock_exporters() -> Generator[None, None, None]:
    with (
        patch("coreason_veritas.auditor.OTLPSpanExporter"),
        patch("coreason_veritas.auditor.OTLPLogExporter"),
        patch("coreason_veritas.auditor.BatchSpanProcessor"),
        patch("coreason_veritas.auditor.BatchLogRecordProcessor"),
        patch("coreason_veritas.auditor.LoggingHandler"),
    ):
        yield


def test_initialization(
    mock_otlp_env: None,
    mock_tracer_provider: MagicMock,
    mock_logger_provider: MagicMock,
    mock_exporters: None,
) -> None:
    """Test that IERLogger initializes providers and exporters."""
    with (
        patch("coreason_veritas.auditor.trace.set_tracer_provider") as mock_set_tp,
        patch("coreason_veritas.auditor._logs.set_logger_provider") as mock_set_lp,
    ):
        IERLogger()

        # Verify TracerProvider setup
        mock_tracer_provider.assert_called_once()
        mock_set_tp.assert_called_once()

        # Verify LoggerProvider setup
        mock_logger_provider.assert_called_once()
        mock_set_lp.assert_called_once()


def test_emit_handshake(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """Test emit_handshake logs correct message."""
    logger_instance = IERLogger("test-service")

    # Mock the internal logger
    logger_instance.logger = MagicMock()

    version = "1.0.0"
    logger_instance.emit_handshake(version)

    logger_instance.logger.info.assert_called_once_with(
        "Veritas Engine Initialized", extra={"co.veritas.version": version, "co.governance.status": "active"}
    )


def test_start_governed_span_attributes(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """Test that start_governed_span adds attributes and creates a span."""
    logger = IERLogger("test-service")

    attributes = {"co.user_id": "user-123", "co.asset_id": "asset-456", "co.srb_sig": "sig-789"}

    # Mock the context manager returned by start_as_current_span
    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    with logger.start_governed_span("test-span", attributes):
        pass

    # Verify start_as_current_span was called with correct args
    mock_tracer.start_as_current_span.assert_called_once()
    call_args = mock_tracer.start_as_current_span.call_args
    assert call_args[0][0] == "test-span"
    called_attributes = call_args[1]["attributes"]

    assert called_attributes["co.user_id"] == "user-123"
    assert called_attributes["co.asset_id"] == "asset-456"
    assert called_attributes["co.srb_sig"] == "sig-789"
    # Anchor is inactive by default
    assert called_attributes["co.determinism_verified"] == "False"


def test_start_governed_span_with_anchor(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """Test that co.determinism_verified is True when Anchor is active."""
    logger = IERLogger("test-service")
    anchor = DeterminismInterceptor()
    attributes = {"co.user_id": "u", "co.asset_id": "a", "co.srb_sig": "s"}

    with anchor.scope():
        with logger.start_governed_span("test-span-anchor", attributes):
            pass

    # Verify determinism flag
    mock_tracer.start_as_current_span.assert_called_once()
    called_attributes = mock_tracer.start_as_current_span.call_args[1]["attributes"]
    assert called_attributes["co.determinism_verified"] == "True"


def test_start_governed_span_missing_attributes(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """Test that missing mandatory attributes raise ValueError."""
    logger = IERLogger("test-service")

    # Missing all
    with pytest.raises(ValueError, match="Missing mandatory attributes"):
        with logger.start_governed_span("test-span", {}):
            pass

    # Missing one
    with pytest.raises(ValueError, match="Missing mandatory attributes"):
        with logger.start_governed_span("test-span", {"co.user_id": "u", "co.asset_id": "a"}):
            pass

    # Ensure no span was started
    mock_tracer.start_as_current_span.assert_not_called()


def test_start_governed_span_non_string_attributes(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """
    Test that start_governed_span handles non-string attribute values.
    """
    logger = IERLogger("test-service")

    # Pass int and bool
    attributes = {"co.user_id": 123, "co.asset_id": "asset-456", "co.srb_sig": "sig-789", "custom": True}

    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    with logger.start_governed_span("test-span", attributes):  # type: ignore
        pass

    mock_tracer.start_as_current_span.assert_called_once()
    called_attributes = mock_tracer.start_as_current_span.call_args[1]["attributes"]

    # Check that mandatory values are preserved (as provided)
    assert called_attributes["co.user_id"] == 123
    assert called_attributes["custom"] is True


def test_start_governed_span_none_attributes(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """Test behavior when attributes contain None."""
    logger = IERLogger("test-service")
    attributes = {"co.user_id": "u", "co.asset_id": "a", "co.srb_sig": "s", "nullable": None}

    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    with logger.start_governed_span("test-span", attributes):  # type: ignore
        pass

    called_attributes = mock_tracer.start_as_current_span.call_args[1]["attributes"]
    assert called_attributes["nullable"] is None


def test_start_governed_span_extra_attributes(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """Test that extra attributes are passed through."""
    logger = IERLogger("test-service")
    attributes = {
        "co.user_id": "u",
        "co.asset_id": "a",
        "co.srb_sig": "s",
        "extra_1": "value1",
        "extra_2": 123,
    }

    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    with logger.start_governed_span("test-span", attributes):
        pass

    called_attributes = mock_tracer.start_as_current_span.call_args[1]["attributes"]
    assert called_attributes["extra_1"] == "value1"
    assert called_attributes["extra_2"] == 123


def test_start_governed_span_empty_mandatory_values(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """
    Test that empty strings for mandatory attributes are accepted if keys exist.
    """
    logger = IERLogger("test-service")
    attributes = {"co.user_id": "", "co.asset_id": "", "co.srb_sig": ""}

    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    with logger.start_governed_span("test-span", attributes):
        pass

    mock_tracer.start_as_current_span.assert_called_once()


def test_initialization_env_var_precedence(
    mock_tracer_provider: MagicMock, mock_logger_provider: MagicMock, mock_exporters: None
) -> None:
    """Test that OTEL_SERVICE_NAME env var overrides constructor argument."""
    with (
        patch.dict("os.environ", {"OTEL_SERVICE_NAME": "env-service"}),
        patch("coreason_veritas.auditor.trace.set_tracer_provider"),
        patch("coreason_veritas.auditor._logs.set_logger_provider"),
        patch("coreason_veritas.auditor.Resource.create") as mock_resource_create,
    ):
        IERLogger("arg-service")

        # Verify resource creation used env var
        mock_resource_create.assert_called_once()
        args, _ = mock_resource_create.call_args
        # Resource.create takes a dictionary as first arg
        assert args[0]["service.name"] == "env-service"


def test_logging_handler_attached(mock_exporters: None, mock_logger_provider: MagicMock) -> None:
    """Test that the python logging handler is correctly attached."""
    with (
        patch("coreason_veritas.auditor.trace.set_tracer_provider"),
        patch("coreason_veritas.auditor._logs.set_logger_provider"),
    ):
        logger_instance = IERLogger("test-service")

        # Verify handler is attached to the internal logger
        assert len(logger_instance.logger.handlers) > 0
        assert isinstance(logger_instance.logger.handlers[0], logging.Handler)
