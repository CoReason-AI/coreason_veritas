# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import os
import sys
import types
from unittest.mock import MagicMock, patch

from loguru import logger


def _unload_coreason_veritas() -> None:
    """Unload all coreason_veritas modules to ensure clean import."""
    modules_to_remove = [m for m in sys.modules if m.startswith("coreason_veritas")]
    for m in modules_to_remove:
        del sys.modules[m]


def test_init_audit_handshake() -> None:
    """
    Test that calling initialize() triggers the audit handshake.
    """
    _unload_coreason_veritas()

    # Enable Handshake by unsetting TEST_MODE
    with patch.dict(os.environ):
        if "COREASON_VERITAS_TEST_MODE" in os.environ:
            del os.environ["COREASON_VERITAS_TEST_MODE"]

        # Create a mock module for auditor
        mock_auditor_module = types.ModuleType("coreason_veritas.auditor")
        mock_ier_logger_class = MagicMock()
        mock_configure = MagicMock()
        mock_auditor_module.IERLogger = mock_ier_logger_class  # type: ignore[attr-defined]
        mock_auditor_module.configure_telemetry = mock_configure  # type: ignore[attr-defined]

        sys.modules["coreason_veritas.auditor"] = mock_auditor_module

        try:
            import coreason_veritas

            # Should NOT be called on import anymore
            mock_ier_logger_class.assert_not_called()

            # Call initialize explicitly
            coreason_veritas.initialize()

            # Verify Telemetry Configured
            mock_configure.assert_called_once()
            # Verify IERLogger was instantiated
            mock_ier_logger_class.assert_called_once()
            mock_ier_logger_class.return_value.emit_handshake.assert_called_once_with(coreason_veritas.__version__)

        finally:
            if "coreason_veritas.auditor" in sys.modules:
                del sys.modules["coreason_veritas.auditor"]
            if "coreason_veritas" in sys.modules:
                del sys.modules["coreason_veritas"]


def test_init_audit_handshake_failure() -> None:
    """
    Test that failures in handshake are logged but don't crash.
    """
    _unload_coreason_veritas()

    # We need to capture the Loguru log.
    # We can use a simple sink list.
    captured_logs = []
    logger.add(lambda msg: captured_logs.append(msg))

    # Enable Handshake by unsetting TEST_MODE
    with patch.dict(os.environ):
        if "COREASON_VERITAS_TEST_MODE" in os.environ:
            del os.environ["COREASON_VERITAS_TEST_MODE"]

        # Create a mock module for auditor
        mock_auditor_module = types.ModuleType("coreason_veritas.auditor")
        mock_ier_logger_class = MagicMock()
        mock_configure = MagicMock()
        mock_ier_logger_class.side_effect = Exception("Simulated Failure")
        mock_auditor_module.IERLogger = mock_ier_logger_class  # type: ignore[attr-defined]
        mock_auditor_module.configure_telemetry = mock_configure  # type: ignore[attr-defined]

        sys.modules["coreason_veritas.auditor"] = mock_auditor_module

        try:
            import coreason_veritas

            coreason_veritas.initialize()

            # Verify error log in Loguru sink
            found = False
            for msg in captured_logs:
                if "MACO Audit Link Failed: Simulated Failure" in msg:
                    found = True
                    break
            assert found, f"Expected error message not found in logs: {captured_logs}"

        finally:
            if "coreason_veritas.auditor" in sys.modules:
                del sys.modules["coreason_veritas.auditor"]
            if "coreason_veritas" in sys.modules:
                del sys.modules["coreason_veritas"]
