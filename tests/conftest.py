# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

from typing import Generator
from unittest.mock import patch

import pytest

from coreason_veritas.auditor import IERLogger

# Cache clearing is no longer needed as lru_cache was removed.


@pytest.fixture(autouse=True)  # type: ignore[misc]
def set_test_mode() -> Generator[None, None, None]:
    """
    Set COREASON_VERITAS_TEST_MODE to force IERLogger to use Console Exporters
    instead of connecting to a real OTLP collector.
    """
    with patch.dict("os.environ", {"COREASON_VERITAS_TEST_MODE": "true"}):
        yield


@pytest.fixture(autouse=True)  # type: ignore[misc]
def reset_singleton() -> Generator[None, None, None]:
    """
    Reset the IERLogger singleton instance before each test.
    This ensures that each test gets a fresh start and can inject its own mocks
    into the IERLogger initialization (e.g. for trace providers).
    """
    if hasattr(IERLogger, "reset"):
        IERLogger.reset()
    else:
        # Fallback if reset method not yet implemented
        IERLogger._instance = None
    yield
    if hasattr(IERLogger, "reset"):
        IERLogger.reset()
    else:
        IERLogger._instance = None
