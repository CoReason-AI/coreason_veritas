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
import types
from typing import Any
from unittest.mock import MagicMock, patch


def _unload_coreason_veritas() -> None:
    """Unload all coreason_veritas modules to ensure clean import."""
    modules_to_remove = [m for m in sys.modules if m.startswith("coreason_veritas")]
    for m in modules_to_remove:
        del sys.modules[m]


def test_init_audit_handshake(caplog: Any) -> None:
    """
    Test that importing coreason_veritas triggers the audit handshake.
    We manually inject a mock module for coreason_veritas.auditor to guarantee
    that the import uses our mock.
    """
    _unload_coreason_veritas()

    # Enable Handshake by unsetting TEST_MODE
    with patch.dict(os.environ):
        if "COREASON_VERITAS_TEST_MODE" in os.environ:
            del os.environ["COREASON_VERITAS_TEST_MODE"]

        # Create a mock module for auditor
        mock_auditor_module = types.ModuleType("coreason_veritas.auditor")
        mock_ier_logger_class = MagicMock()
        # Mypy complains about dynamic attribute assignment to ModuleType
        mock_auditor_module.IERLogger = mock_ier_logger_class  # type: ignore[attr-defined]

        # Inject it into sys.modules
        # We must also ensure coreason_veritas (parent) is not loaded,
        # but we need to let it load during import.
        sys.modules["coreason_veritas.auditor"] = mock_auditor_module

        try:
            # Import the package
            import coreason_veritas  # noqa: F401

            # Verify IERLogger was instantiated
            mock_ier_logger_class.assert_called_once()
            # Verify handshake was called
            mock_ier_logger_class.return_value.emit_handshake.assert_called_once_with(coreason_veritas.__version__)

        finally:
            # Cleanup: remove our manual mock so other tests are not affected
            if "coreason_veritas.auditor" in sys.modules:
                del sys.modules["coreason_veritas.auditor"]
            if "coreason_veritas" in sys.modules:
                del sys.modules["coreason_veritas"]


def test_init_audit_handshake_failure(caplog: Any) -> None:
    """
    Test that failures in handshake are logged but don't crash import.
    """
    _unload_coreason_veritas()

    # Enable Handshake by unsetting TEST_MODE
    with patch.dict(os.environ):
        if "COREASON_VERITAS_TEST_MODE" in os.environ:
            del os.environ["COREASON_VERITAS_TEST_MODE"]

        # Create a mock module for auditor
        mock_auditor_module = types.ModuleType("coreason_veritas.auditor")
        mock_ier_logger_class = MagicMock()
        # Simulate failure
        mock_ier_logger_class.side_effect = Exception("Simulated Failure")
        mock_auditor_module.IERLogger = mock_ier_logger_class  # type: ignore[attr-defined]

        sys.modules["coreason_veritas.auditor"] = mock_auditor_module

        try:
            with caplog.at_level(logging.ERROR, logger="coreason.veritas"):
                import coreason_veritas  # noqa: F401

                # Verify error log
                assert "MACO Audit Link Failed: Simulated Failure" in caplog.text

        finally:
            # Cleanup
            if "coreason_veritas.auditor" in sys.modules:
                del sys.modules["coreason_veritas.auditor"]
            if "coreason_veritas" in sys.modules:
                del sys.modules["coreason_veritas"]
