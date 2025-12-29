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

import logging
import os

from .anchor import DeterminismInterceptor
from .auditor import IERLogger
from .gatekeeper import SignatureValidator
from .wrapper import governed_execution

__version__ = "0.2.0"
__author__ = "Gowtham A Rao"
__email__ = "gowtham.rao@coreason.ai"

__all__ = ["governed_execution", "SignatureValidator", "DeterminismInterceptor"]

if not os.environ.get("COREASON_VERITAS_TEST_MODE"):
    try:
        _auditor = IERLogger()
        _auditor.emit_handshake(__version__)
    except Exception as e:
        logging.getLogger("coreason.veritas").error(f"MACO Audit Link Failed: {e}")
