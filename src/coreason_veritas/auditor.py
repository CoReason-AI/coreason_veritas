# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import contextlib
import os
import platform
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Generator, List, Optional

from loguru import logger
from opentelemetry import _logs, trace
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import (
    BatchLogRecordProcessor,
    ConsoleLogRecordExporter,
    SimpleLogRecordProcessor,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)

from coreason_veritas.anchor import is_anchor_active
from coreason_veritas.logging_utils import configure_logging


def configure_telemetry(service_name: str = "coreason-veritas") -> None:
    """
    Configures global OpenTelemetry providers (Tracer and Logger).
    Uses environment variables for endpoint configuration.
    """
    # 1. Resource Attributes: Generic metadata for client portability
    resource = Resource.create(
        {
            "service.name": os.environ.get("OTEL_SERVICE_NAME", service_name),
            "deployment.environment": os.environ.get("DEPLOYMENT_ENV", "local-vibe"),
            "host.name": platform.node(),
        }
    )

    # 2. Setup Tracing (for AI workflow logic)
    tp = TracerProvider(resource=resource)

    if os.environ.get("COREASON_VERITAS_TEST_MODE"):
        # Use Console Exporter in Test Mode to avoid connection errors
        # Use SimpleSpanProcessor to ensure synchronous export and avoid race conditions
        tp.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    else:
        tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))

    # Set global tracer provider
    trace.set_tracer_provider(tp)

    # 3. Setup Logging (for the Handshake and IER events)
    lp = LoggerProvider(resource=resource)
    _logs.set_logger_provider(lp)

    if os.environ.get("COREASON_VERITAS_TEST_MODE"):
        # Use Console Exporter in Test Mode
        # Use SimpleLogRecordProcessor to ensure synchronous export
        lp.add_log_record_processor(SimpleLogRecordProcessor(ConsoleLogRecordExporter()))
    else:
        lp.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))

    # Configure Loguru to use OTel Sink
    configure_logging()


class IERLogger:
    """
    Manages the connection to the OpenTelemetry collector and enforces strict
    metadata schema for the Immutable Execution Record (IER).
    Singleton pattern ensures global providers are initialized only once.
    """

    _instance: Optional["IERLogger"] = None
    _sinks: List[Callable[[Dict[str, Any]], None]] = []
    tracer: trace.Tracer

    def __new__(cls) -> "IERLogger":
        if cls._instance is None:
            cls._instance = super(IERLogger, cls).__new__(cls)
            cls._instance.tracer = trace.get_tracer("veritas.audit")
        return cls._instance

    def register_sink(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Register a new audit sink callback.

        Args:
            callback: A function that accepts a dictionary of audit events.
        """
        self._sinks.append(callback)

    def emit_handshake(self, version: str) -> None:
        """
        Standardized GxP audit trail for package initialization.

        Args:
            version: The version string of the package.
        """
        # Unified logging via Loguru
        logger.bind(co_veritas_version=version, co_governance_status="active").info("Veritas Engine Initialized")

    @contextlib.contextmanager
    def start_governed_span(self, name: str, attributes: Dict[str, str]) -> Generator[trace.Span, None, None]:
        """
        Starts an OTel span with mandatory GxP attributes.

        Mandatory Attributes (should be present in attributes or context):
        - `co.user_id`: Who initiated the action?
        - `co.asset_id`: What code is running?
        - `co.srb_sig`: Proof of validation.
        - `co.determinism_verified`: Boolean flag from the Anchor.

        Args:
            name: The name of the span.
            attributes: Dictionary of attributes to add to the span.

        Raises:
            ValueError: If any mandatory attribute is missing.
        """
        # Prepare attributes
        span_attributes = attributes.copy()

        # Automatically check anchor status
        span_attributes["co.determinism_verified"] = str(is_anchor_active())

        # Strict Enforcement of Mandatory Attributes
        mandatory_attributes = ["co.user_id", "co.asset_id"]

        # If strictly compliant (default), require signature.
        # If in DRAFT mode, signature is optional.
        if span_attributes.get("co.compliance_mode") != "DRAFT":
            mandatory_attributes.append("co.srb_sig")

        missing = [attr for attr in mandatory_attributes if attr not in span_attributes]

        if missing:
            error_msg = f"Audit Failure: Missing mandatory attributes: {missing}"
            logger.error(error_msg)
            raise ValueError(error_msg)

        with self.tracer.start_as_current_span(name, attributes=span_attributes) as span:
            # Broadcast to external sinks (Glass Box)
            timestamp = datetime.now(timezone.utc).isoformat()
            event_payload = {
                "span_name": name,
                "attributes": span_attributes,
                "timestamp": timestamp,
            }
            for sink in self._sinks:
                try:
                    sink(event_payload)
                except Exception as e:
                    # Fail Closed: If an audit sink fails, the entire operation must fail.
                    logger.exception(f"Audit Sink Failure: {e}")
                    raise e

            yield span
