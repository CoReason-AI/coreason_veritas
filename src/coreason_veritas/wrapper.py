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
from opentelemetry import context, trace

import coreason_veritas.anchor
from coreason_veritas.anchor import DeterminismInterceptor
from coreason_veritas.auditor import IERLogger
from coreason_veritas.gatekeeper import SignatureValidator
from coreason_veritas.sanitizer import scrub_pii_recursive


def get_public_key_from_store() -> str:
    """
    Retrieves the SRB Public Key from the immutable Key Store.
    For this implementation, it reads from the COREASON_VERITAS_PUBLIC_KEY environment variable.
    """
    key = os.getenv("COREASON_VERITAS_PUBLIC_KEY")
    if not key:
        raise ValueError("COREASON_VERITAS_PUBLIC_KEY environment variable is not set.")
    return key


@lru_cache(maxsize=4)
def _get_validator(public_key: str) -> SignatureValidator:
    """
    Returns a SignatureValidator instance for the given public key.
    Cached to avoid expensive key parsing on every call.
    """
    return SignatureValidator(public_key)


def _prepare_governance(
    func: Callable[..., Any],
    args: Any,
    kwargs: Any,
    asset_id_arg: str,
    signature_arg: str,
    user_id_arg: str,
    config_arg: Optional[str],
    allow_unsigned: bool,
) -> Tuple[Dict[str, str], inspect.BoundArguments]:
    """
    Helper function to inspect arguments, perform Gatekeeper checks, and sanitize configuration.
    It returns the audit attributes and the bound arguments (which may be modified).
    """
    sig = inspect.signature(func)
    try:
        bound = sig.bind(*args, **kwargs)
    except TypeError as e:
        raise TypeError(f"Arguments mapping failed: {e}") from e

    bound.apply_defaults()
    arguments = bound.arguments

    # 1. Gatekeeper Check
    asset = arguments.get(asset_id_arg)
    user_id = arguments.get(user_id_arg)
    signature = arguments.get(signature_arg)

    if asset is None:
        raise ValueError(f"Missing asset argument: {asset_id_arg}")
    if user_id is None:
        raise ValueError(f"Missing user ID argument: {user_id_arg}")

    attributes = {
        "asset": str(asset),  # Legacy support from spec example
        "co.asset_id": str(asset),
        "co.user_id": str(user_id),
    }

    # Draft Mode Logic
    if allow_unsigned and signature is None:
        # Bypass signature check and inject Draft Mode tag
        attributes["co.compliance_mode"] = "DRAFT"
    else:
        # Strict Mode (Default)
        if signature is None:
            raise ValueError(f"Missing signature argument: {signature_arg}")

        # Retrieve key from store (Env Var)
        public_key = get_public_key_from_store()
        _get_validator(public_key).verify_asset(asset, signature)

        attributes["co.srb_sig"] = str(signature)

    # 2. Config Sanitization
    if config_arg and config_arg in arguments:
        original_config = arguments[config_arg]
        if isinstance(original_config, dict):
            sanitized_config = DeterminismInterceptor.enforce_config(original_config)
            arguments[config_arg] = sanitized_config

    return attributes, bound


class GovernanceContext:
    """
    Manages the lifecycle of a governed execution, handling:
    1. Preparation (Gatekeeper, Argument binding)
    2. Logging (Start/End)
    3. OTel Span Management
    4. Anchor Context Management
    """

    def __init__(
        self,
        func: Callable[..., Any],
        args: Any,
        kwargs: Any,
        asset_id_arg: str,
        signature_arg: str,
        user_id_arg: str,
        config_arg: Optional[str],
        allow_unsigned: bool,
        anchor_var: Any = None,
    ):
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.asset_id_arg = asset_id_arg
        self.signature_arg = signature_arg
        self.user_id_arg = user_id_arg
        self.config_arg = config_arg
        self.allow_unsigned = allow_unsigned
        self.anchor_var = anchor_var or coreason_veritas.anchor._ANCHOR_ACTIVE

        self.attributes: Dict[str, str] = {}
        self.bound: Optional[inspect.BoundArguments] = None
        self.start_time: float = 0.0
        self.span: Optional[trace.Span] = None
        self.token_otel: Any = None
        self.token_anchor: Any = None
        self.ier_logger = IERLogger()
        self.user_context_obj: Any = None

        self._prepare()

    def _prepare(self) -> None:
        self.start_time = time.perf_counter()
        try:
            self.attributes, self.bound = _prepare_governance(
                self.func,
                self.args,
                self.kwargs,
                self.asset_id_arg,
                self.signature_arg,
                self.user_id_arg,
                self.config_arg,
                self.allow_unsigned,
            )

            # Auto-capture Identity
            if "user_context" in self.bound.arguments:
                self.user_context_obj = self.bound.arguments["user_context"]

            self._log_start()
        except Exception as e:
            self._handle_error(e)
            raise e

    def _log_start(self) -> None:
        if self.bound:
            safe_args = scrub_pii_recursive(self.bound.arguments)
            details = {
                **self.attributes,
                "safe_payload": safe_args,
                "function": self.func.__name__,
            }
            self.ier_logger.log_action("Governance Execution Started", details, self.user_context_obj)

    def _log_end(self, success: bool = True) -> None:
        duration_ms = (time.perf_counter() - self.start_time) * 1000
        verdict = "ALLOWED" if success else "BLOCKED"
        attrs = self.attributes or {"co.error": "PrepareGovernanceFailed"}

        details = {
            **attrs,
            "duration_ms": duration_ms,
            "verdict": verdict,
            "function": self.func.__name__,
        }
        self.ier_logger.log_action("Governance Execution Completed", details, self.user_context_obj)

    def _handle_error(self, e: Exception) -> None:
        if not self.attributes:
            self.attributes = {"co.error": "PrepareGovernanceFailed"}

        logger.bind(**self.attributes).exception(f"Governance Execution Failed: {e}")
        self._log_end(success=False)

    def __enter__(self) -> "GovernanceContext":
        self.span = self.ier_logger.create_governed_span(self.func.__name__, self.attributes)

        # Activate OTel Context
        ctx = trace.set_span_in_context(self.span)
        self.token_otel = context.attach(ctx)

        # Activate Anchor
        self.token_anchor = self.anchor_var.set(True)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        # Reset ContextVars (Anchor and OTel)
        try:
            if self.token_anchor:
                self.anchor_var.reset(self.token_anchor)
        except ValueError:
            pass

        try:
            if self.token_otel:
                context.detach(self.token_otel)
        except BaseException:
            pass

        # End Span
        if self.span:
            if exc_type:
                self.span.record_exception(exc_val)
                self.span.set_status(trace.Status(trace.StatusCode.ERROR))
            self.span.end()

        # Log Execution Result
        if exc_type:
            self._handle_error(exc_val)
            # Do NOT return True; allow exception to propagate
        else:
            self._log_end(success=True)

    # For Async Context Manager support
    async def __aenter__(self) -> "GovernanceContext":
        return self.__enter__()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.__exit__(exc_type, exc_val, exc_tb)


def governed_execution(
    asset_id_arg: str,
    signature_arg: str,
    user_id_arg: str,
    config_arg: Optional[str] = None,
    allow_unsigned: bool = False,
) -> Callable[..., Any]:
    """
    Decorator that bundles Gatekeeper, Auditor, and Anchor into a single atomic wrapper.

    Args:
        asset_id_arg: The name of the keyword argument containing the asset/spec.
        signature_arg: The name of the keyword argument containing the signature.
        user_id_arg: The name of the keyword argument containing the user ID.
        config_arg: Optional name of the keyword argument containing the configuration dict to be sanitized.
        allow_unsigned: If True, allows execution without a valid signature (Draft Mode).
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.isasyncgenfunction(func):

            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = GovernanceContext(
                    func, args, kwargs, asset_id_arg, signature_arg, user_id_arg, config_arg, allow_unsigned
                )
                assert ctx.bound is not None
                async with ctx:
                    async for item in func(*ctx.bound.args, **ctx.bound.kwargs):
                        yield item

            return wrapper

        elif inspect.isgeneratorfunction(func):

            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = GovernanceContext(
                    func, args, kwargs, asset_id_arg, signature_arg, user_id_arg, config_arg, allow_unsigned
                )
                assert ctx.bound is not None
                with ctx:
                    yield from func(*ctx.bound.args, **ctx.bound.kwargs)

            return wrapper

        elif inspect.iscoroutinefunction(func):

            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = GovernanceContext(
                    func, args, kwargs, asset_id_arg, signature_arg, user_id_arg, config_arg, allow_unsigned
                )
                assert ctx.bound is not None
                async with ctx:
                    return await func(*ctx.bound.args, **ctx.bound.kwargs)

            return wrapper

        else:

            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = GovernanceContext(
                    func, args, kwargs, asset_id_arg, signature_arg, user_id_arg, config_arg, allow_unsigned
                )
                assert ctx.bound is not None
                with ctx:
                    return func(*ctx.bound.args, **ctx.bound.kwargs)

            return wrapper

    return decorator
