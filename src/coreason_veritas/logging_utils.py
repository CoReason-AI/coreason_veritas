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
from opentelemetry import _logs, trace

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


def scrub_sensitive_data(data: Any) -> Any:
    """
    Recursively scrubs sensitive keys from dictionaries and lists.
    Returns a new structure with redacted values.
    """
    if isinstance(data, dict):
        new_dict = {}
        for k, v in data.items():
            if isinstance(k, str) and k.lower() in SENSITIVE_KEYS:
                new_dict[k] = "[REDACTED]"
            else:
                new_dict[k] = scrub_sensitive_data(v)
        return new_dict
    elif isinstance(data, list):
        return [scrub_sensitive_data(item) for item in data]
    elif isinstance(data, tuple):
        return tuple(scrub_sensitive_data(item) for item in data)
    else:
        return data


class OTelLogSink:
    """
    A Loguru sink that forwards log records to OpenTelemetry.
    """

    def __init__(self, service_name: str = "coreason-veritas") -> None:
        self.service_name = service_name
        self._logger: Any = None

    @property
    def otel_logger(self) -> Any:
        if self._logger is None:
            provider = _logs.get_logger_provider()
            self._logger = provider.get_logger(self.service_name)
        return self._logger

    def __call__(self, message: Any) -> None:
        """
        Loguru sink callback.
        """
        record = message.record

        # Map Loguru levels to OTel SeverityNumber
        # Trace=1, Debug=5, Info=9, Warn=13, Error=17, Fatal=21
        level_no = record["level"].no
        if level_no < 20:  # Trace(5), Debug(10) -> DEBUG
            severity_number = 5  # DEBUG
        elif level_no < 30:  # Info (20) / Success (25)
            severity_number = 9  # INFO
        elif level_no < 40:  # Warning (30)
            severity_number = 13  # WARN
        elif level_no < 50:  # Error (40)
            severity_number = 17  # ERROR
        else:  # Critical (50)
            severity_number = 21  # FATAL

        # Construct attributes
        attributes = {
            "log.file.name": record["file"].name,
            "log.file.path": record["file"].path,
            "log.line": record["line"],
            "log.function": record["function"],
            "log.module": record["module"],
        }

        # Merge extra attributes
        extra = record["extra"]
        for k, v in extra.items():
            if k in ["trace_id", "span_id"]:
                # We skip manual trace_id/span_id injection into attributes if we rely on OTel context,
                # but sticking them in attributes doesn't hurt.
                continue
            if isinstance(v, (str, bool, int, float)):
                attributes[str(k)] = v
            else:
                attributes[str(k)] = str(v)

        timestamp_ns = int(record["time"].timestamp() * 1e9)

        # Emit the log record using kwargs
        self.otel_logger.emit(
            body=record["message"],
            severity_number=severity_number,
            severity_text=record["level"].name,
            timestamp=timestamp_ns,
            attributes=attributes,
        )


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


def configure_logging() -> None:
    """
    Configures Loguru with:
    1. Console sink (Text or JSON)
    2. File sink (JSON with Rotation)
    3. OpenTelemetry sink
    4. Context propagation patcher
    5. Standard library logging interception
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
    otel_sink = OTelLogSink()
    logger.add(otel_sink, level=log_level)

    # 4. Patcher
    logger.configure(patcher=_trace_context_patcher)

    # 5. Intercept Standard Library Logging
    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)
