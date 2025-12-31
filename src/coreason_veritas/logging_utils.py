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
import os
import sys
from types import FrameType
from typing import Any, Dict, Optional

from loguru import logger
from opentelemetry import trace
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler

# Sensitive keys to redact
SENSITIVE_KEYS = {
    "password",
    "token",
    "authorization",
    "secret",
    "key",
    "access_token",
    "refresh_token",
    "api_key",
    "client_secret",
    "jwt",
}

# Add any additional sensitive keys from environment configuration
_extra_keys = os.environ.get("VERITAS_SENSITIVE_KEYS", "")
if _extra_keys:
    SENSITIVE_KEYS.update(k.strip() for k in _extra_keys.split(",") if k.strip())


def scrub_sensitive_data(
    data: Any,
    depth: int = 0,
    max_depth: int = 20,
    seen: Optional[Dict[int, Any]] = None,
) -> Any:
    """
    Recursively scrubs sensitive keys from dictionaries and lists.
    Returns a new structure with redacted values.

    Features:
    - Recursion depth limit (defaults to 20)
    - Circular reference detection
    - Set conversion to list
    - Custom object handling (via string representation)
    """
    if seen is None:
        seen = {}

    # Check max depth
    if depth > max_depth:
        return "[TRUNCATED_DEPTH]"

    # Check circular reference
    obj_id = id(data)
    if obj_id in seen:
        return "[CIRCULAR_REF]"

    # We only track container types for circular reference
    if isinstance(data, (dict, list, tuple, set)):
        seen[obj_id] = data

    try:
        if isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                if isinstance(k, str) and k.lower() in SENSITIVE_KEYS:
                    new_dict[k] = "[REDACTED]"
                else:
                    new_dict[k] = scrub_sensitive_data(v, depth + 1, max_depth, seen)
            return new_dict
        elif isinstance(data, list):
            return [scrub_sensitive_data(item, depth + 1, max_depth, seen) for item in data]
        elif isinstance(data, tuple):
            return tuple(scrub_sensitive_data(item, depth + 1, max_depth, seen) for item in data)
        elif isinstance(data, set):
            # Convert set to sorted list if possible for deterministic logging, else just list
            try:
                return sorted([scrub_sensitive_data(item, depth + 1, max_depth, seen) for item in data])
            except TypeError:
                # Fallback if items are not comparable
                return [scrub_sensitive_data(item, depth + 1, max_depth, seen) for item in data]
        elif hasattr(data, "__dict__"):
            # Attempt to serialize object __dict__ if present
            # We treat this as a dict but need to be careful not to recurse infinitely if __dict__ is complex
            # We'll just convert to string representation for safety and simplicity as per "Enhance it"
            return str(data)
        else:
            return data
    finally:
        pass


def _trace_context_patcher(record: Dict[str, Any]) -> None:
    """
    Loguru patcher to inject trace_id and span_id into extra.
    """
    span = trace.get_current_span()
    if not span:
        return

    ctx = span.get_span_context()
    if ctx.is_valid:
        record["extra"]["trace_id"] = f"{ctx.trace_id:032x}"
        record["extra"]["span_id"] = f"{ctx.span_id:016x}"
    else:
        record["extra"]["trace_id"] = "0" * 32
        record["extra"]["span_id"] = "0" * 16


class InterceptHandler(logging.Handler):
    """
    Intercept standard logging messages and redirect them to Loguru.
    """

    def emit(self, record: logging.LogRecord) -> None:
        # Get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = str(record.levelno)

        # Find caller from where originated the logged message
        frame: Optional[FrameType] = logging.currentframe()
        depth = 2
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


def configure_logging(logger_provider: Optional[LoggerProvider] = None) -> None:
    """
    Configures Loguru with:
    1. Console sink (Text or JSON)
    2. File sink (JSON with Rotation)
    3. OpenTelemetry sink (Standard LoggingHandler)
    4. Context propagation patcher
    5. Standard library logging interception

    Args:
        logger_provider: Optional OTel LoggerProvider.
    """
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_format = os.environ.get("LOG_FORMAT", "TEXT").upper()

    # Remove default handler
    logger.remove()

    # 1. Console Sink (Human Readable or JSON)
    if log_format == "JSON":
        logger.add(sys.stderr, level=log_level, serialize=True)
    else:
        # Text format with trace_id
        fmt = (
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "trace_id={extra[trace_id]} span_id={extra[span_id]} | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        )
        logger.add(sys.stderr, level=log_level, format=fmt)

    # 2. File Sink (Machine Readable JSON)
    logger.add("logs/app.log", rotation="500 MB", retention="10 days", serialize=True, enqueue=True, level=log_level)

    # 3. OpenTelemetry Sink
    # Use standard LoggingHandler which bridges standard logging records to OTel
    if logger_provider:
        otel_handler = LoggingHandler(logger_provider=logger_provider, level=logging.NOTSET)
        # Add as a sink to Loguru
        logger.add(otel_handler, level=log_level)

    # 4. Patcher
    logger.configure(patcher=_trace_context_patcher)

    # 5. Intercept Standard Library Logging
    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)
