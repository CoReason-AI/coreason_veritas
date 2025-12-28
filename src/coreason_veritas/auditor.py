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
import logging
import os
import platform
from typing import Any, Dict, Generator, Optional

from loguru import logger as loguru_logger
from opentelemetry import _logs, trace
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from coreason_veritas.anchor import is_anchor_active


class IERLogger:
    """
    Manages the connection to the OpenTelemetry collector and enforces strict
    metadata schema for the Immutable Execution Record (IER).
    Singleton pattern ensures global providers are initialized only once.
    """

    _instance: Optional["IERLogger"] = None
    _initialized: bool = False

    def __new__(cls, *args: Any, **kwargs: Any) -> "IERLogger":
        if cls._instance is None:
            cls._instance = super(IERLogger, cls).__new__(cls)
        return cls._instance

    def __init__(self, service_name: str = "coreason-veritas"):
        """
        Initialize the IERLogger.

        Args:
            service_name: The name of the service for the tracer.
                          Defaults to "coreason-veritas" if not provided.
        """
        if self._initialized:
            return

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
        # Endpoint is pulled automatically from OTEL_EXPORTER_OTLP_ENDPOINT
        tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))

        # Guard: Check if a tracer provider is already set to avoid warnings/errors
        # Note: trace.get_tracer_provider() returns a ProxyTracerProvider by default if not set.
        # But set_tracer_provider is the one that sets the global.
        # Since this is a singleton, we assume we control the initialization.
        trace.set_tracer_provider(tp)
        self.tracer = trace.get_tracer("veritas.audit")

        # 3. Setup Logging (for the Handshake and IER events)
        lp = LoggerProvider(resource=resource)
        _logs.set_logger_provider(lp)
        lp.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))

        # Attach to standard Python logging
        # We use a specific logger for the OTel bridge
        self.otel_bridge_logger = logging.getLogger("coreason.veritas")

        # Check if LoggingHandler is already attached to avoid duplicates/memory leaks
        has_logging_handler = any(h.__class__.__name__ == "LoggingHandler" for h in self.otel_bridge_logger.handlers)

        if not has_logging_handler:
            handler = LoggingHandler(level=logging.INFO, logger_provider=lp)
            self.otel_bridge_logger.addHandler(handler)
            self.otel_bridge_logger.setLevel(logging.INFO)

        self._initialized = True

    def emit_handshake(self, version: str) -> None:
        """
        Standardized GxP audit trail for package initialization.

        Args:
            version: The version string of the package.
        """
        # This goes to OTel via the bridge logger
        self.otel_bridge_logger.info(
            "Veritas Engine Initialized", extra={"co.veritas.version": version, "co.governance.status": "active"}
        )

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
        mandatory_attributes = ["co.user_id", "co.asset_id", "co.srb_sig"]
        missing = [attr for attr in mandatory_attributes if attr not in span_attributes]

        if missing:
            error_msg = f"Audit Failure: Missing mandatory attributes: {missing}"
            loguru_logger.error(error_msg)
            raise ValueError(error_msg)

        with self.tracer.start_as_current_span(name, attributes=span_attributes) as span:
            yield span
