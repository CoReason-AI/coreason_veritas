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
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Generator, List, Optional

from coreason_identity.models import UserContext
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
from opentelemetry.trace import ProxyTracerProvider

from coreason_veritas.anchor import is_anchor_active
from coreason_veritas.logging_utils import configure_logging


class IERLogger:
    """
    Manages the connection to the OpenTelemetry collector and enforces strict
    metadata schema for the Immutable Execution Record (IER).
    Singleton pattern ensures global providers are initialized only once.
    """

    _instance: Optional["IERLogger"] = None
    _lock: threading.Lock = threading.Lock()

    _service_name: str
    _sinks: List[Callable[[Dict[str, Any]], None]]
    tracer: trace.Tracer

    def __new__(cls, service_name: str = "coreason-veritas") -> "IERLogger":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    self = super(IERLogger, cls).__new__(cls)
                    self._service_name = service_name
                    self._initialize_providers()
                    self._sinks = []
                    cls._instance = self

        if cls._instance._service_name != service_name:
            logger.warning(
                f"IERLogger already initialized with service_name='{cls._instance._service_name}'. "
                f"Ignoring new service_name='{service_name}'."
            )

        return cls._instance

    def __init__(self, service_name: str = "coreason-veritas") -> None:
        """
        Initialize the IERLogger.
        Arguments are handled in __new__, but this is required to prevent
        TypeError: object.__init__() takes no arguments.
        """
        pass

    def _initialize_providers(self) -> None:
        """Initialize OpenTelemetry providers."""
        resource = Resource.create(
            {
                "service.name": os.environ.get("OTEL_SERVICE_NAME", self._service_name),
                "deployment.environment": os.environ.get("DEPLOYMENT_ENV", "local-vibe"),
                "host.name": platform.node(),
            }
        )

        # Tracing Setup
        # Only set global TracerProvider if it's not already set or is a Proxy
        if isinstance(trace.get_tracer_provider(), ProxyTracerProvider):
            tp = TracerProvider(resource=resource)
            if os.environ.get("COREASON_VERITAS_TEST_MODE"):
                tp.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
            else:
                tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))

            trace.set_tracer_provider(tp)

        # Always get the tracer (even if provider was already set externally)
        self.tracer = trace.get_tracer("veritas.audit")

        # Logging Setup
        # Only set global LoggerProvider if it's not already set.
        # We rely on OTel's internal check or catching the error.

        lp = LoggerProvider(resource=resource)
        if os.environ.get("COREASON_VERITAS_TEST_MODE"):
            lp.add_log_record_processor(SimpleLogRecordProcessor(ConsoleLogRecordExporter()))
        else:
            lp.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))

        try:
            _logs.set_logger_provider(lp)
        except Exception:
            # LoggerProvider already set, which is fine.
            pass

        configure_logging()

    @classmethod
    def reset(cls) -> None:
        """
        Reset the singleton instance. Useful for testing.
        Note: This does NOT reset the global OpenTelemetry TracerProvider.
        """
        cls._instance = None

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

    def _validate_and_prepare_span(self, name: str, attributes: Dict[str, str]) -> Dict[str, str]:
        """
        Validates attributes and returns the final attribute dictionary.
        Broadcasts to sinks.
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

        return span_attributes

    def create_governed_span(self, name: str, attributes: Dict[str, str]) -> trace.Span:
        """
        Creates and starts a span but does NOT activate it in the current context.
        Useful for async generators where context management needs to be manual.
        """
        span_attributes = self._validate_and_prepare_span(name, attributes)
        return self.tracer.start_span(name, attributes=span_attributes)

    @contextlib.contextmanager
    def start_governed_span(self, name: str, attributes: Dict[str, str]) -> Generator[trace.Span, None, None]:
        """
        Starts an OTel span with mandatory GxP attributes AND activates it in context.
        """
        span_attributes = self._validate_and_prepare_span(name, attributes)

        with self.tracer.start_as_current_span(name, attributes=span_attributes) as span:
            yield span

    def log_action(
        self,
        action: str,
        details: Dict[str, Any],
        user_context: Optional[UserContext] = None,
    ) -> None:
        """
        Logs an action with Identity-Aware context.
        Enforces clean-room logging by stripping downstream tokens and populating actor metadata.
        """
        safe_details = details.copy()

        # Explicitly remove dangerous keys if present
        safe_details.pop("downstream_token", None)

        if user_context:
            # Populate actor from email or user_id
            actor = getattr(user_context, "email", None) or getattr(user_context, "user_id", None) or "unknown"
            safe_details["actor"] = str(actor)

            # Populate metadata
            if hasattr(user_context, "groups") and user_context.groups:
                safe_details["groups"] = user_context.groups
            if hasattr(user_context, "claims") and user_context.claims:
                safe_details["claims"] = user_context.claims

        # Sync logging for wrapper compatibility
        logger.bind(event_type=action, **safe_details).info(f"Audit Event: {action}")

    async def log_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """
        Logs a generic audit event.

        Args:
            event_type: The type of the event (e.g., "EXECUTION_START").
            details: A dictionary containing event details.
        """
        logger.bind(event_type=event_type, **details).info(f"Audit Event: {event_type}")

    def log_llm_transaction(
        self,
        trace_id: str,
        context: UserContext,
        project_id: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        latency_ms: int,
    ) -> None:
        """
        Log an LLM transaction with standardized attributes for governance and auditing.

        Args:
            trace_id: The request trace ID.
            context: The UserContext of the user initiating the request.
            project_id: The ID of the project/asset.
            model: The name of the model used.
            input_tokens: Number of input tokens.
            output_tokens: Number of output tokens.
            cost_usd: Estimated cost in USD.
            latency_ms: Latency in milliseconds.
        """
        logger.bind(
            **{
                "gen_ai.system": "coreason-platform",
                "gen_ai.request.model": model,
                "gen_ai.usage.input_tokens": input_tokens,
                "gen_ai.usage.output_tokens": output_tokens,
                "gen_ai.usage.cost": cost_usd,
                "co.user_id": context.user_id,
                "co.asset_id": project_id,
                "trace_id": trace_id,
                "latency_ms": latency_ms,
            }
        ).info("LLM Transaction Recorded")
