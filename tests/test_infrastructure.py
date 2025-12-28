# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import pytest
from cryptography.hazmat.primitives import hashes
from opentelemetry import trace
from pydantic import BaseModel

from coreason_veritas.exceptions import AssetTamperedError


def test_dependencies_installed() -> None:
    """Verify that all added dependencies are importable."""
    assert hashes.SHA256
    assert trace.get_tracer
    assert BaseModel


def test_exception_import() -> None:
    """Verify that the custom exception is importable and usable."""
    with pytest.raises(AssetTamperedError):
        raise AssetTamperedError("Test")
