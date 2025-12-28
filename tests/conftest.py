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


@pytest.fixture(autouse=True)  # type: ignore[misc]
def mock_global_exporters() -> Generator[None, None, None]:
    """
    Globally mock OTLP exporters and processors to prevent real network connections
    during tests. This ensures that IERLogger instantiation in any test does not
    trigger background connection attempts to localhost:4318.
    """
    with (
        patch("coreason_veritas.auditor.OTLPSpanExporter"),
        patch("coreason_veritas.auditor.OTLPLogExporter"),
        patch("coreason_veritas.auditor.BatchSpanProcessor"),
        patch("coreason_veritas.auditor.BatchLogRecordProcessor"),
    ):
        yield
