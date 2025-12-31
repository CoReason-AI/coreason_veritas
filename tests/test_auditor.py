# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

from typing import Any, Dict, Generator
from unittest.mock import MagicMock, patch

import pytest

from coreason_veritas.anchor import DeterminismInterceptor
from coreason_veritas.auditor import IERLogger, configure_telemetry


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
    with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
        mock_tracer_instance = MagicMock()
        mock_get_tracer.return_value = mock_tracer_instance
        yield mock_tracer_instance


@pytest.fixture  # type: ignore[misc]
def mock_exporters() -> Generator[None, None, None]:
    # Reset singleton and sinks before each test
    IERLogger._instance = None
    IERLogger._sinks = []

    with (
        patch("coreason_veritas.auditor.OTLPSpanExporter"),
        patch("coreason_veritas.auditor.OTLPLogExporter"),
        patch("coreason_veritas.auditor.BatchSpanProcessor"),
        patch("coreason_veritas.auditor.BatchLogRecordProcessor"),
        patch("coreason_veritas.auditor.configure_logging"),
    ):
        yield


def test_configure_telemetry(
    mock_otlp_env: None,
    mock_tracer_provider: MagicMock,
    mock_logger_provider: MagicMock,
    mock_exporters: None,
) -> None:
    """Test that configure_telemetry initializes providers and exporters."""
    with (
        patch("coreason_veritas.auditor.trace.set_tracer_provider") as mock_set_tp,
        patch("coreason_veritas.auditor._logs.set_logger_provider") as mock_set_lp,
    ):
        configure_telemetry()

        # Verify TracerProvider setup
        mock_tracer_provider.assert_called_once()
        mock_set_tp.assert_called_once()

        # Verify LoggerProvider setup
        mock_logger_provider.assert_called_once()
        mock_set_lp.assert_called_once()


def test_ier_logger_singleton() -> None:
    """Test that IERLogger is a singleton."""
    logger1 = IERLogger()
    logger2 = IERLogger()
    assert logger1 is logger2


def test_emit_handshake(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """Test emit_handshake logs correct message."""
    logger_instance = IERLogger()

    # Mock loguru logger
    with patch("coreason_veritas.auditor.logger") as mock_logger:
        version = "1.0.0"
        logger_instance.emit_handshake(version)

        # Verify bind called with structure
        mock_logger.bind.assert_called_once_with(co_veritas_version=version, co_governance_status="active")
        # Verify info called on the bound logger
        mock_logger.bind.return_value.info.assert_called_once_with("Veritas Engine Initialized")


def test_start_governed_span_attributes(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """Test that start_governed_span adds attributes and creates a span."""
    logger = IERLogger()

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
    logger = IERLogger()
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
    logger = IERLogger()

    with patch("coreason_veritas.auditor.logger"):
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
    logger = IERLogger()

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
    logger = IERLogger()
    attributes = {"co.user_id": "u", "co.asset_id": "a", "co.srb_sig": "s", "nullable": None}

    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    with logger.start_governed_span("test-span", attributes):  # type: ignore
        pass

    called_attributes = mock_tracer.start_as_current_span.call_args[1]["attributes"]
    assert called_attributes["nullable"] is None


def test_start_governed_span_extra_attributes(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """Test that extra attributes are passed through."""
    logger = IERLogger()
    attributes = {
        "co.user_id": "u",
        "co.asset_id": "a",
        "co.srb_sig": "s",
        "extra_1": "value1",
        "extra_2": 123,
    }

    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    # MyPy complains about mixed types in dict passed to start_governed_span
    with logger.start_governed_span("test-span", attributes):  # type: ignore[arg-type]
        pass

    called_attributes = mock_tracer.start_as_current_span.call_args[1]["attributes"]
    assert called_attributes["extra_1"] == "value1"
    assert called_attributes["extra_2"] == 123


def test_start_governed_span_empty_mandatory_values(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """
    Test that empty strings for mandatory attributes are accepted if keys exist.
    """
    logger = IERLogger()
    attributes = {"co.user_id": "", "co.asset_id": "", "co.srb_sig": ""}

    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    with logger.start_governed_span("test-span", attributes):
        pass

    mock_tracer.start_as_current_span.assert_called_once()


def test_configure_telemetry_env_var_precedence(
    mock_tracer_provider: MagicMock, mock_logger_provider: MagicMock, mock_exporters: None
) -> None:
    """Test that OTEL_SERVICE_NAME env var overrides default argument."""
    with (
        patch.dict("os.environ", {"OTEL_SERVICE_NAME": "env-service"}),
        patch("coreason_veritas.auditor.trace.set_tracer_provider"),
        patch("coreason_veritas.auditor._logs.set_logger_provider"),
        patch("coreason_veritas.auditor.Resource.create") as mock_resource_create,
    ):
        configure_telemetry("arg-service")

        # Verify resource creation used env var
        mock_resource_create.assert_called_once()
        args, _ = mock_resource_create.call_args
        # Resource.create takes a dictionary as first arg
        assert args[0]["service.name"] == "env-service"


def test_register_sink_and_execution(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """
    Test that registered sinks are called with the correct payload
    when start_governed_span is invoked.
    """
    logger = IERLogger()

    # Define a mock sink
    mock_sink = MagicMock()
    logger.register_sink(mock_sink)

    attributes = {"co.user_id": "u", "co.asset_id": "a", "co.srb_sig": "s"}
    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    with logger.start_governed_span("test-sink-execution", attributes):
        pass

    # Verify sink was called
    mock_sink.assert_called_once()
    payload = mock_sink.call_args[0][0]

    assert payload["span_name"] == "test-sink-execution"
    # Auditor adds 'co.determinism_verified', so we check subset or specific keys
    assert payload["attributes"]["co.user_id"] == attributes["co.user_id"]
    assert payload["attributes"]["co.asset_id"] == attributes["co.asset_id"]
    assert payload["attributes"]["co.srb_sig"] == attributes["co.srb_sig"]
    assert "co.determinism_verified" in payload["attributes"]

    assert "timestamp" in payload
    # Basic format check for ISO timestamp
    assert "T" in payload["timestamp"]


def test_sink_exception_suppression(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """
    Test that exceptions in sinks are caught and do not crash the application.
    """
    logger = IERLogger()

    # Define a sink that raises an exception
    def failing_sink(payload: Dict[str, Any]) -> None:
        raise RuntimeError("Sink exploded")

    logger.register_sink(failing_sink)

    attributes = {"co.user_id": "u", "co.asset_id": "a", "co.srb_sig": "s"}
    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    # Should raise exception (Fail Closed)
    with patch("coreason_veritas.auditor.logger"):
        with pytest.raises(RuntimeError, match="Sink exploded"):
            with logger.start_governed_span("test-sink-failure", attributes):
                pass

    # Loguru should have logged the error (we could mock loguru but ensuring no crash is main goal)


def test_configure_telemetry_production_mode(
    mock_tracer_provider: MagicMock, mock_logger_provider: MagicMock
) -> None:
    """
    Test that in production mode (TEST_MODE unset), real OTLP exporters are instantiated.
    """
    with patch.dict("os.environ", {"COREASON_VERITAS_TEST_MODE": ""}):
        with (
            patch("coreason_veritas.auditor.trace.set_tracer_provider"),
            patch("coreason_veritas.auditor._logs.set_logger_provider"),
            patch("coreason_veritas.auditor.OTLPSpanExporter") as mock_span_exporter,
            patch("coreason_veritas.auditor.OTLPLogExporter") as mock_log_exporter,
            patch("coreason_veritas.auditor.BatchSpanProcessor") as mock_bsp,
            patch("coreason_veritas.auditor.BatchLogRecordProcessor") as mock_blrp,
            patch("coreason_veritas.auditor.configure_logging"),
        ):
            configure_telemetry()

            # Verify real exporters were instantiated
            mock_span_exporter.assert_called_once()
            mock_log_exporter.assert_called_once()

            # Verify they were passed to processors
            mock_bsp.assert_called_with(mock_span_exporter.return_value)
            mock_blrp.assert_called_with(mock_log_exporter.return_value)


def test_start_governed_span_draft_mode(mock_exporters: None, mock_tracer: MagicMock) -> None:
    """
    Test that start_governed_span allows missing signature if co.compliance_mode is DRAFT.
    """
    logger = IERLogger()

    attributes = {
        "co.user_id": "u",
        "co.asset_id": "a",
        "co.compliance_mode": "DRAFT",
    }  # Missing co.srb_sig

    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    # Should not raise ValueError
    with logger.start_governed_span("test-draft-mode", attributes):
        pass

    mock_tracer.start_as_current_span.assert_called_once()
