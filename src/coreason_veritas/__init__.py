# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

"""
coreason_veritas is the non-negotiable governance layer of the CoReason platform
"""

import os

from loguru import logger

from .anchor import DeterminismInterceptor
from .auditor import IERLogger
from .gatekeeper import PolicyGuard, SignatureValidator
from .quota import QuotaGuard
from .resilience import AsyncCircuitBreaker
from .sanitizer import scrub_pii_payload, scrub_pii_recursive
from .wrapper import governed_execution

__version__ = "0.12.0"
__author__ = "Gowtham A Rao"
__email__ = "gowtham.rao@coreason.ai"

__all__ = [
    "governed_execution",
    "PolicyGuard",
    "SignatureValidator",
    "DeterminismInterceptor",
    "scrub_pii_payload",
    "scrub_pii_recursive",
    "AsyncCircuitBreaker",
    "QuotaGuard",
]


def initialize() -> None:
    """
    Explicitly initializes the Veritas Engine and emits the handshake audit log.
    This should be called by the application entry point, not implicitly on import.
    """
    if not os.environ.get("COREASON_VERITAS_TEST_MODE"):
        try:
            _auditor = IERLogger()
            _auditor.emit_handshake(__version__)
        except Exception as e:
            logger.error(f"MACO Audit Link Failed: {e}")
