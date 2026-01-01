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
import unittest
from typing import Any, Dict
from unittest.mock import MagicMock, patch

from loguru import logger
from opentelemetry._logs.severity import SeverityNumber

from coreason_veritas.logging_utils import (
    InterceptHandler,
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

    def test_scrub_dag_no_circular_ref(self) -> None:
        """
        Test that scrub_sensitive_data correctly handles Directed Acyclic Graphs (DAGs)
        where an object is referenced multiple times but there is no cycle.
        """
        shared_obj = {"safe_key": "value"}
        # A list containing the same object twice. This is NOT a cycle.
        data = [shared_obj, shared_obj]

        result = scrub_sensitive_data(data)

        # Both elements should be the scrubbed version of shared_obj
        self.assertEqual(result[0], {"safe_key": "value"})
        self.assertEqual(result[1], {"safe_key": "value"})
        self.assertNotEqual(result[1], "[CIRCULAR_REF]")

    def test_scrub_actual_circular_ref(self) -> None:
        """
        Test that scrub_sensitive_data still detects actual circular references.
        """
        cycle: Dict[str, Any] = {}
        cycle["self"] = cycle

        result = scrub_sensitive_data(cycle)

        self.assertEqual(result["self"], "[CIRCULAR_REF]")

    def test_otel_sink_emit(self) -> None:
        # Initialize Sink
        sink = OTelLogSink()

        # Inject Mock Logger directly (avoiding import patching issues)
        mock_otel_logger = MagicMock()
        sink._logger = mock_otel_logger

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

    def test_otel_sink_severity_mapping_and_attributes(self) -> None:
        """
        Tests severity mapping AND attribute processing (extra fields).
        Covers lines 150-151 (skipping trace_id) and 156-157 (str conversion).
        """
        sink = OTelLogSink()
        sink._logger = MagicMock()

        levels = [
            (5, SeverityNumber.DEBUG),  # Trace
            (20, SeverityNumber.INFO),  # Info
            (30, SeverityNumber.WARN),  # Warning
            (40, SeverityNumber.ERROR),  # Error
            (50, SeverityNumber.FATAL),  # Critical
        ]

        for loguru_no, otel_severity in levels:
            mock_message = MagicMock()
            mock_message.record = {
                "level": MagicMock(no=loguru_no, name="LEVEL"),
                "time": MagicMock(timestamp=lambda: 1000.0),
                "file": MagicMock(name="f", path="p"),
                "line": 1,
                "function": "f",
                "module": "m",
                "extra": {
                    "trace_id": "should_be_skipped_in_attributes_loop",
                    "span_id": "should_be_skipped_in_attributes_loop",
                    "simple_str": "value",
                    "simple_int": 123,
                    "complex_obj": {"nested": "dict"},  # Should trigger str() conversion
                },
                "message": "m",
            }
            sink(mock_message)
            kwargs = sink._logger.emit.call_args[1]
            self.assertEqual(kwargs["severity_number"], otel_severity)

            # Verify extra attributes logic
            attrs = kwargs["attributes"]
            # trace_id/span_id should be skipped
            self.assertNotIn("trace_id", attrs)
            self.assertNotIn("span_id", attrs)
            # primitives should remain
            self.assertEqual(attrs["simple_str"], "value")
            self.assertEqual(attrs["simple_int"], 123)
            # complex objects should be stringified
            self.assertEqual(attrs["complex_obj"], "{'nested': 'dict'}")

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
        from unittest.mock import patch

        from coreason_veritas.logging_utils import _trace_context_patcher

        # Test with valid span
        with patch("coreason_veritas.logging_utils.trace.get_current_span") as mock_get_span:
            mock_ctx = MagicMock()
            mock_ctx.is_valid = True
            mock_ctx.trace_id = 0x123
            mock_ctx.span_id = 0x456
            mock_get_span.return_value.get_span_context.return_value = mock_ctx

            record: Dict[str, Any] = {"extra": {}}
            _trace_context_patcher(record)
            self.assertEqual(record["extra"]["trace_id"], f"{0x123:032x}")

        # Test with invalid span
        with patch("coreason_veritas.logging_utils.trace.get_current_span") as mock_get_span:
            mock_ctx = MagicMock()
            mock_ctx.is_valid = False
            mock_get_span.return_value.get_span_context.return_value = mock_ctx

            record = {"extra": {}}
            _trace_context_patcher(record)
            self.assertEqual(record["extra"]["trace_id"], "0" * 32)

        # Test with no span (None)
        with patch("coreason_veritas.logging_utils.trace.get_current_span") as mock_get_span:
            mock_get_span.return_value = None

            record = {"extra": {}}
            _trace_context_patcher(record)
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
            calls = mock_add.call_args_list
            count_serialized = 0
            for call in calls:
                if call.kwargs.get("serialize") is True:
                    count_serialized += 1

            # Expect at least 2 (Console + File)
            self.assertTrue(count_serialized >= 2, f"Expected 2 JSON sinks, found {count_serialized}")

    def test_intercept_handler(self) -> None:
        """
        Test InterceptHandler captures standard logging and forwards to Loguru.
        """
        handler = InterceptHandler()

        # Test 1: Standard Level
        mock_record_std = MagicMock(spec=logging.LogRecord)
        mock_record_std.levelname = "INFO"
        mock_record_std.levelno = 20
        mock_record_std.getMessage.return_value = "Standard Msg"
        mock_record_std.exc_info = None
        mock_record_std.name = "test.logger"

        with patch.object(logger, "opt") as mock_opt:
            # Make sure log() is called on the result of opt()
            mock_log_func = MagicMock()
            mock_opt.return_value.log = mock_log_func

            handler.emit(mock_record_std)

            # Verify Loguru was called with "INFO"
            mock_log_func.assert_called_with("INFO", "Standard Msg")

        # Test 2: Custom Level (ValueError path)
        mock_record_custom = MagicMock(spec=logging.LogRecord)
        mock_record_custom.levelname = "MY_CUSTOM_LEVEL"
        mock_record_custom.levelno = 99
        mock_record_custom.getMessage.return_value = "Custom Msg"
        mock_record_custom.exc_info = None

        with patch.object(logger, "opt") as mock_opt:
            mock_log_func = MagicMock()
            mock_opt.return_value.log = mock_log_func

            # Force logger.level to raise ValueError
            with patch.object(logger, "level", side_effect=ValueError):
                handler.emit(mock_record_custom)

            # Verify Loguru was called with string "99"
            mock_log_func.assert_called_with("99", "Custom Msg")

        # Test 3: Stack Depth Adjustment
        # Simulate stack inside logging module
        with patch("logging.currentframe") as mock_frame:
            # Create a mock frame chain: logging -> logging -> app
            frame_logging_1 = MagicMock()
            frame_logging_1.f_code.co_filename = logging.__file__

            frame_logging_2 = MagicMock()
            frame_logging_2.f_code.co_filename = logging.__file__

            frame_app = MagicMock()
            frame_app.f_code.co_filename = "app.py"

            # Link frames
            frame_logging_1.f_back = frame_logging_2
            frame_logging_2.f_back = frame_app
            frame_app.f_back = None  # End of stack

            mock_frame.return_value = frame_logging_1

            with patch.object(logger, "opt") as mock_opt:
                handler.emit(mock_record_std)

                # Default depth is 2.
                # Loop:
                # 1. frame=logging_1 (logging), depth=2 -> frame=logging_2, depth=3
                # 2. frame=logging_2 (logging), depth=3 -> frame=app, depth=4
                # 3. frame=app (app != logging), break.
                # Expected depth=4

                mock_opt.assert_called_with(depth=4, exception=None)

    def test_scrub_unsortable_set(self) -> None:
        """Test set with unsortable items (mixed types) returns as list."""
        data = {1, "a"}  # Mixed int and str is not sortable in Py3
        scrubbed = scrub_sensitive_data(data)
        self.assertIsInstance(scrubbed, list)
        self.assertEqual(len(scrubbed), 2)
        # Order is undefined, but elements should be present
        self.assertIn(1, scrubbed)
        self.assertIn("a", scrubbed)

    def test_scrub_custom_object(self) -> None:
        """Test custom object with __dict__ is converted to string."""

        class MyObj:
            def __init__(self) -> None:
                self.x = 1

            def __str__(self) -> str:
                return "MyObjString"

        obj = MyObj()
        scrubbed = scrub_sensitive_data(obj)
        self.assertEqual(scrubbed, "MyObjString")

    def test_extra_sensitive_keys_env(self) -> None:
        """Test environment variable loading for sensitive keys via module reload."""
        import importlib
        import os

        from coreason_veritas import logging_utils

        # Save original state
        original_env = os.environ.get("VERITAS_SENSITIVE_KEYS")

        try:
            # Set env var
            os.environ["VERITAS_SENSITIVE_KEYS"] = "env_secret_1, env_secret_2"

            # Reload module to trigger the top-level code
            importlib.reload(logging_utils)

            self.assertIn("env_secret_1", logging_utils.SENSITIVE_KEYS)
            self.assertIn("env_secret_2", logging_utils.SENSITIVE_KEYS)

        finally:
            # Restore env
            if original_env is None:
                del os.environ["VERITAS_SENSITIVE_KEYS"]
            else:
                os.environ["VERITAS_SENSITIVE_KEYS"] = original_env

            # Restore module state (reload again)
            importlib.reload(logging_utils)
            # Restore the exact set object if needed (reload creates a new one, which is fine)
            # But we want to ensure other tests aren't affected by "env_secret_1" if reload failed?
            # Reloading with original env should reset it.

    def test_max_depth_truncation(self) -> None:
        """Test that recursion stops at max_depth."""
        # Create a deep structure
        root: Dict[str, Any] = {}
        curr = root
        for _ in range(25):
            curr["next"] = {}
            curr = curr["next"]

        # Default max_depth is 20
        scrubbed = scrub_sensitive_data(root)

        # Traverse to check truncation
        curr = scrubbed
        depth = 0
        while isinstance(curr, dict) and "next" in curr:
            curr = curr["next"]
            depth += 1

        self.assertEqual(curr, "[TRUNCATED_DEPTH]")
