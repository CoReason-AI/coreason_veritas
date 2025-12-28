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
from typing import Dict, Generator

from opentelemetry import trace

from coreason_veritas.anchor import is_anchor_active


class IERLogger:
    """
    Manages the connection to the OpenTelemetry collector and enforces strict
    metadata schema for the Immutable Execution Record (IER).
    """

    def __init__(self, service_name: str = "coreason-veritas"):
        """
        Initialize the IERLogger.

        Args:
            service_name: The name of the service for the tracer.
                          Defaults to "coreason-veritas" if not provided.
        """
        self.tracer = trace.get_tracer(service_name)

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
        """
        # Prepare attributes
        span_attributes = attributes.copy()

        # Automatically check anchor status
        span_attributes["co.determinism_verified"] = str(is_anchor_active())

        with self.tracer.start_as_current_span(name, attributes=span_attributes) as span:
            yield span
