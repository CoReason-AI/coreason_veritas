# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import time
from collections import deque
from typing import Any, Callable, Type

from loguru import logger

from coreason_veritas.exceptions import CircuitOpenError


class AsyncCircuitBreaker:
    """
    A simple asyncio-compatible Circuit Breaker.
    """

    def __init__(self, fail_max: int = 5, reset_timeout: float = 60, time_window: float = 10.0) -> None:
        """
        :param fail_max: Number of failures allowed within time_window before opening.
        :param reset_timeout: Seconds to wait before attempting Half-Open.
        :param time_window: Sliding window in seconds for counting failures.
        """
        self.fail_max = fail_max
        self.reset_timeout = reset_timeout
        self.time_window = time_window
        self.failure_history: deque[float] = deque()
        self.state = "closed"
        self.last_failure_time = 0.0

    def _check_state(self) -> None:
        """Checks and updates the circuit state based on time and history."""
        if self.state == "open":
            if time.monotonic() - self.last_failure_time > self.reset_timeout:
                self.state = "half-open"
            else:
                raise CircuitOpenError("Circuit is open")

    async def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """
        Calls the async function, managing circuit state.
        """
        self._check_state()

        try:
            result = await func(*args, **kwargs)
            self._handle_success()
            return result
        except CircuitOpenError:
            # Re-raise CircuitOpenError without counting it as a new failure
            raise
        except Exception as e:
            self._handle_failure()
            raise e

    def _prune_history(self, now: float) -> None:
        """Remove failures older than time_window."""
        while self.failure_history and self.failure_history[0] <= now - self.time_window:
            self.failure_history.popleft()

    def _handle_failure(self) -> None:
        now = time.monotonic()
        self.last_failure_time = now
        self.failure_history.append(now)
        self._prune_history(now)

        if len(self.failure_history) >= self.fail_max:
            self.state = "open"
            logger.warning(f"Circuit Breaker tripped. {len(self.failure_history)} failures in {self.time_window}s.")

    def _handle_success(self) -> None:
        if self.state == "half-open":
            self.state = "closed"
            logger.info("Circuit Breaker recovered to Closed state.")

        # Reset failure count on success to prevent accumulating intermittent errors.
        if self.failure_history:
            self.failure_history.clear()

    async def __aenter__(self) -> "AsyncCircuitBreaker":
        self._check_state()
        return self

    async def __aexit__(
        self,
        exc_type: Type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> bool:
        if exc_type:
            if exc_type is not CircuitOpenError:
                # We treat any exception (other than CircuitOpenError) as a failure
                self._handle_failure()
        else:
            self._handle_success()
        return False  # Propagate exception
