# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import inspect
import os
import time
from functools import lru_cache, wraps
from typing import Any, Callable, Dict, Optional, Tuple

from loguru import logger

from coreason_veritas.anchor import DeterminismInterceptor
from coreason_veritas.auditor import IERLogger
from coreason_veritas.gatekeeper import SignatureValidator
from coreason_veritas.logging_utils import scrub_sensitive_data


@lru_cache(maxsize=1)
def get_public_key_from_store() -> str:
    """
    Retrieves the SRB Public Key from the immutable Key Store.
    For this implementation, it reads from the COREASON_VERITAS_PUBLIC_KEY environment variable.
    """
    key = os.getenv("COREASON_VERITAS_PUBLIC_KEY")
    if not key:
        raise ValueError("COREASON_VERITAS_PUBLIC_KEY environment variable is not set.")
    return key


class GovernanceContext:
    """
    Context Manager that encapsulates the governance workflow (Gatekeeper, Auditor, Anchor).
    It replaces the redundant logic in the decorator branches.
    """

    def __init__(
        self,
        func: Callable[..., Any],
        args: Tuple[Any, ...],
        kwargs: Dict[str, Any],
        asset_id_arg: str,
        signature_arg: str,
        user_id_arg: str,
        config_arg: Optional[str],
        allow_unsigned: bool,
    ):
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.asset_id_arg = asset_id_arg
        self.signature_arg = signature_arg
        self.user_id_arg = user_id_arg
        self.config_arg = config_arg
        self.allow_unsigned = allow_unsigned

        self.start_time: float = 0.0
        self.attributes: Dict[str, str] = {}
        self.bound_args: Optional[inspect.BoundArguments] = None

        # internal state
        self._audit_span_ctx: Any = None
        self._anchor_ctx: Any = None

    def _prepare_governance(self) -> None:
        """
        Inspect arguments, perform Gatekeeper checks, and sanitize configuration.
        Populates self.attributes and self.bound_args.
        """
        sig = inspect.signature(self.func)
        try:
            bound = sig.bind(*self.args, **self.kwargs)
        except TypeError as e:
            raise TypeError(f"Arguments mapping failed: {e}") from e

        bound.apply_defaults()
        arguments = bound.arguments

        # 1. Gatekeeper Check
        asset = arguments.get(self.asset_id_arg)
        user_id = arguments.get(self.user_id_arg)
        signature = arguments.get(self.signature_arg)

        if asset is None:
            raise ValueError(f"Missing asset argument: {self.asset_id_arg}")
        if user_id is None:
            raise ValueError(f"Missing user ID argument: {self.user_id_arg}")

        self.attributes = {
            "asset": str(asset),
            "co.asset_id": str(asset),
            "co.user_id": str(user_id),
        }

        # Draft Mode Logic
        if self.allow_unsigned and signature is None:
            self.attributes["co.compliance_mode"] = "DRAFT"
        else:
            if signature is None:
                raise ValueError(f"Missing signature argument: {self.signature_arg}")

            public_key = get_public_key_from_store()
            SignatureValidator(public_key).verify_asset(asset, signature)

            self.attributes["co.srb_sig"] = str(signature)

        # 2. Config Sanitization
        if self.config_arg and self.config_arg in arguments:
            original_config = arguments[self.config_arg]
            if isinstance(original_config, dict):
                sanitized_config = DeterminismInterceptor.enforce_config(original_config)
                arguments[self.config_arg] = sanitized_config

        self.bound_args = bound

    def __enter__(self) -> inspect.BoundArguments:
        self.start_time = time.perf_counter()
        try:
            self._prepare_governance()
            assert self.bound_args is not None

            # Log Start
            safe_args = scrub_sensitive_data(self.bound_args.arguments)
            logger.bind(**self.attributes).info(
                "Governance Execution Started", safe_payload=safe_args, function=self.func.__name__
            )

            # Start Audit Span
            self._audit_span_ctx = IERLogger().start_governed_span(self.func.__name__, self.attributes)
            self._audit_span_ctx.__enter__()

            # Start Anchor Scope
            self._anchor_ctx = DeterminismInterceptor.scope()
            self._anchor_ctx.__enter__()

            return self.bound_args

        except Exception as e:
            self._handle_exception(e)
            raise e

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        # Exit Anchor Scope
        if self._anchor_ctx:
            self._anchor_ctx.__exit__(exc_type, exc_value, traceback)

        # Exit Audit Span
        if self._audit_span_ctx:
            self._audit_span_ctx.__exit__(exc_type, exc_value, traceback)

        if exc_type:
            self._handle_exception(exc_value)
        else:
            self._log_end(success=True)

    def _log_end(self, success: bool) -> None:
        duration_ms = (time.perf_counter() - self.start_time) * 1000
        verdict = "ALLOWED" if success else "BLOCKED"
        # If attributes were never set (e.g. failure in init), use fallback
        attrs = self.attributes if self.attributes else {"co.error": "PrepareGovernanceFailed"}

        if success:
            logger.bind(**attrs).info(
                "Governance Execution Completed",
                duration_ms=duration_ms,
                verdict=verdict,
                function=self.func.__name__,
            )
        else:
            # For failure, we log exception in handle_exception usually,
            # but log_end is for the audit trail "Completed" message if desired,
            # or we just rely on the exception log.
            # The original code logged "Governance Execution Completed" even on failure in the finally block logic?
            # Actually, original code had:
            # log_end(attributes, start_time, success=False) inside except block
            logger.bind(**attrs).info(
                "Governance Execution Completed",
                duration_ms=duration_ms,
                verdict=verdict,
                function=self.func.__name__,
            )

    def _handle_exception(self, e: Exception) -> None:
        attrs = self.attributes if self.attributes else {"co.error": "PrepareGovernanceFailed"}
        logger.bind(**attrs).exception(f"Governance Execution Failed: {e}")
        self._log_end(success=False)


def governed_execution(
    asset_id_arg: str,
    signature_arg: str,
    user_id_arg: str,
    config_arg: Optional[str] = None,
    allow_unsigned: bool = False,
) -> Callable[..., Any]:
    """
    Decorator that bundles Gatekeeper, Auditor, and Anchor into a single atomic wrapper.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.isasyncgenfunction(func):

            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                context = GovernanceContext(
                    func, args, kwargs, asset_id_arg, signature_arg, user_id_arg, config_arg, allow_unsigned
                )
                with context as bound:
                    async for item in func(*bound.args, **bound.kwargs):
                        yield item

            return wrapper

        elif inspect.isgeneratorfunction(func):

            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                context = GovernanceContext(
                    func, args, kwargs, asset_id_arg, signature_arg, user_id_arg, config_arg, allow_unsigned
                )
                with context as bound:
                    yield from func(*bound.args, **bound.kwargs)

            return wrapper

        elif inspect.iscoroutinefunction(func):

            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                context = GovernanceContext(
                    func, args, kwargs, asset_id_arg, signature_arg, user_id_arg, config_arg, allow_unsigned
                )
                with context as bound:
                    return await func(*bound.args, **bound.kwargs)

            return wrapper

        else:

            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                context = GovernanceContext(
                    func, args, kwargs, asset_id_arg, signature_arg, user_id_arg, config_arg, allow_unsigned
                )
                with context as bound:
                    return func(*bound.args, **bound.kwargs)

            return wrapper

    return decorator
