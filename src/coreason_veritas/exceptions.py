# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas


class VeritasError(Exception):
    """Base exception for all Veritas errors."""

    pass


class AssetTamperedError(VeritasError):
    """Raised when asset verification fails."""

    pass


class QuotaExceededError(VeritasError):
    """Raised when a user or entity exceeds their daily financial quota."""

    pass


class CircuitOpenError(VeritasError):
    """Raised when the circuit breaker is open and refusing execution."""

    pass
