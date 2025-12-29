# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import unittest
from unittest.mock import MagicMock, patch

from loguru import logger

from coreason_veritas.logging_utils import (
    OTelLogSink,
    configure_logging,
    scrub_sensitive_data,
)


class TestLoggingUtils(unittest.TestCase):
    def test_scrub_sensitive_data_dict(self) -> None:
        data = {
            "username": "alice",
            "password": "secret_password",
            "nested": {
                "token": "secret_token",
                "public": "visible",
            },
        }
        scrubbed = scrub_sensitive_data(data)
        self.assertEqual(scrubbed["username"], "alice")
        self.assertEqual(scrubbed["password"], "[REDACTED]")
        self.assertEqual(scrubbed["nested"]["token"], "[REDACTED]")
        self.assertEqual(scrubbed["nested"]["public"], "visible")

    def test_scrub_sensitive_data_list(self) -> None:
        data = [
            {"key": "secret_key", "id": 1},
            {"authorization": "Bearer xyz"},
        ]
        scrubbed = scrub_sensitive_data(data)
        self.assertEqual(scrubbed[0]["key"], "[REDACTED]")
        self.assertEqual(scrubbed[0]["id"], 1)
        self.assertEqual(scrubbed[1]["authorization"], "[REDACTED]")

    def test_scrub_sensitive_data_case_insensitive(self) -> None:
        data = {"PaSsWoRd": "secret"}
        scrubbed = scrub_sensitive_data(data)
        self.assertEqual(scrubbed["PaSsWoRd"], "[REDACTED]")

    def test_scrub_sensitive_data_tuple(self) -> None:
        data = ({"password": "secret"}, "public")
        scrubbed = scrub_sensitive_data(data)
        self.assertEqual(scrubbed[0]["password"], "[REDACTED]")
        self.assertEqual(scrubbed[1], "public")
        self.assertIsInstance(scrubbed, tuple)

    def test_otel_sink_emit(self) -> None:
        # Initialize Sink
        sink = OTelLogSink()

        # Inject Mock Logger directly (avoiding import patching issues)
        mock_otel_logger = MagicMock()
        sink._logger = mock_otel_logger  # type: ignore

        # Manually invoke call with a mock loguru message
        mock_message = MagicMock()

        mock_level = MagicMock()
        mock_level.no = 20
        mock_level.name = "INFO"

        mock_record = {
            "level": mock_level,
            "time": MagicMock(timestamp=lambda: 1000.0),
            "file": MagicMock(name="test_file.py", path="/path/test_file.py"),
            "line": 10,
            "function": "test_func",
            "module": "test_module",
            "extra": {"custom_key": "custom_value"},
            "message": "Test Message",
        }
        mock_message.record = mock_record

        # Call sink
        sink(mock_message)

        # Verification
        mock_otel_logger.emit.assert_called_once()
        kwargs = mock_otel_logger.emit.call_args[1]

        self.assertEqual(kwargs["body"], "Test Message")
        self.assertEqual(kwargs["severity_text"], "INFO")
        self.assertEqual(kwargs["attributes"]["custom_key"], "custom_value")
        self.assertEqual(kwargs["attributes"]["log.function"], "test_func")

    def test_otel_sink_severity_mapping(self) -> None:
        sink = OTelLogSink()
        sink._logger = MagicMock()  # type: ignore

        levels = [
            (5, 5),   # Trace
            (20, 9),  # Info
            (30, 13), # Warning
            (40, 17), # Error
            (50, 21), # Critical
        ]

        for loguru_no, otel_severity in levels:
            mock_message = MagicMock()
            mock_message.record = {
                "level": MagicMock(no=loguru_no, name="LEVEL"),
                "time": MagicMock(timestamp=lambda: 1000.0),
                "file": MagicMock(name="f"),
                "line": 1,
                "function": "f",
                "module": "m",
                "extra": {
                    "trace_id": "skip_me",
                    "complex": {"a": 1} # Should trigger str() conversion
                },
                "message": "m",
            }
            sink(mock_message)
            kwargs = sink._logger.emit.call_args[1]
            self.assertEqual(kwargs["severity_number"], otel_severity)
            # Verify extra attributes
            self.assertNotIn("trace_id", kwargs["attributes"])
            self.assertEqual(kwargs["attributes"]["complex"], "{'a': 1}")

    def test_otel_sink_lazy_init(self) -> None:
        # Patch the function in opentelemetry._logs
        with patch("opentelemetry._logs.get_logger_provider") as mock_get_provider:
            mock_provider = MagicMock()
            mock_get_provider.return_value = mock_provider

            sink = OTelLogSink()
            # Access property to trigger init
            _ = sink.otel_logger

            mock_get_provider.assert_called_once()
            mock_provider.get_logger.assert_called_with(sink.service_name)

    def test_trace_context_patcher(self) -> None:
        from coreason_veritas.logging_utils import _trace_context_patcher
        from unittest.mock import patch

        # Test with valid span
        with patch("coreason_veritas.logging_utils.trace.get_current_span") as mock_get_span:
            mock_ctx = MagicMock()
            mock_ctx.is_valid = True
            mock_ctx.trace_id = 0x123
            mock_ctx.span_id = 0x456
            mock_get_span.return_value.get_span_context.return_value = mock_ctx

            record = {"extra": {}}  # type: ignore
            _trace_context_patcher(record)  # type: ignore
            self.assertEqual(record["extra"]["trace_id"], f"{0x123:032x}")  # type: ignore

        # Test with invalid span
        with patch("coreason_veritas.logging_utils.trace.get_current_span") as mock_get_span:
            mock_ctx = MagicMock()
            mock_ctx.is_valid = False
            mock_get_span.return_value.get_span_context.return_value = mock_ctx

            record = {"extra": {}}  # type: ignore
            _trace_context_patcher(record)  # type: ignore
            self.assertEqual(record["extra"]["trace_id"], "0" * 32)  # type: ignore

        # Test with no span (None)
        with patch("coreason_veritas.logging_utils.trace.get_current_span") as mock_get_span:
            mock_get_span.return_value = None

            record = {"extra": {}}  # type: ignore
            _trace_context_patcher(record)  # type: ignore
            # Should return without modifying if we assume extra is empty?
            pass

    def test_configure_logging(self) -> None:
        # Patch the singleton logger methods directly
        with (
            patch.object(logger, "remove") as mock_remove,
            patch.object(logger, "add") as mock_add,
            patch.object(logger, "configure") as mock_configure,
        ):

            configure_logging()

            # Verify logger.remove was called
            mock_remove.assert_called()

            # Verify logger.add was called for console (stderr) and otel sink
            self.assertTrue(mock_add.call_count >= 2)

            # Verify logger.configure was called (for patcher)
            mock_configure.assert_called()

    def test_configure_logging_json(self) -> None:
        # Patch environment and logger
        with (
            patch.dict("os.environ", {"LOG_FORMAT": "JSON"}),
            patch.object(logger, "remove"),
            patch.object(logger, "add") as mock_add,
            patch.object(logger, "configure"),
        ):

            configure_logging()

            # Verify that add was called with serialize=True (for the console sink)
            # Since we add multiple sinks, we check if ANY call has serialize=True
            calls = mock_add.call_args_list
            json_sink_added = False
            for call in calls:
                if call.kwargs.get("serialize") is True:
                    json_sink_added = True
                    break

            self.assertTrue(json_sink_added, "Expected JSON console sink to be added")
