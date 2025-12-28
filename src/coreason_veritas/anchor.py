# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import contextlib
from contextvars import ContextVar
from typing import Any, Dict, Generator

from loguru import logger

# Context variable to track if the Anchor is active
_ANCHOR_ACTIVE: ContextVar[bool] = ContextVar("anchor_active", default=False)


def is_anchor_active() -> bool:
    """Check if the Anchor determinism scope is currently active."""
    return _ANCHOR_ACTIVE.get()


class DeterminismInterceptor:
    """
    Acts as a proxy/hook into the LLM Client configuration.
    Enforces the 'Lobotomy' Protocol for epistemic integrity.
    """

    @staticmethod
    def enforce_config(raw_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        The 'Lobotomy' Protocol:
        1. Forcibly sets `temperature = 0.0`.
        2. Forcibly sets `top_p = 1.0`.
        3. Injects `seed = 42`.
        4. Logs a warning if the original config attempted to deviate.

        Args:
            raw_config: The original configuration dictionary.

        Returns:
            The sanitized, deterministic configuration dictionary.
        """
        sanitized = raw_config.copy()

        # Check for deviations to log warnings
        if sanitized.get("temperature") is not None and sanitized.get("temperature") != 0.0:
            logger.warning(f"DeterminismInterceptor: Overriding unsafe temperature {sanitized['temperature']} to 0.0")

        if sanitized.get("top_p") is not None and sanitized.get("top_p") != 1.0:
            logger.warning(f"DeterminismInterceptor: Overriding unsafe top_p {sanitized['top_p']} to 1.0")

        if sanitized.get("seed") is not None and sanitized.get("seed") != 42:
            logger.warning(f"DeterminismInterceptor: Overriding seed {sanitized['seed']} to 42")

        # Enforce values
        sanitized["temperature"] = 0.0
        sanitized["top_p"] = 1.0
        sanitized["seed"] = 42

        return sanitized

    @staticmethod
    @contextlib.contextmanager
    def scope() -> Generator[None, None, None]:
        """
        Context manager that sets the Anchor context variable.
        Use this to wrap execution blocks that must be deterministic.
        """
        token = _ANCHOR_ACTIVE.set(True)
        try:
            yield
        finally:
            _ANCHOR_ACTIVE.reset(token)
