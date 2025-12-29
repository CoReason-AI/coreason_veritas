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
from functools import lru_cache, wraps
from typing import Any, Callable, Dict, Optional, Tuple

from coreason_veritas.anchor import DeterminismInterceptor
from coreason_veritas.auditor import IERLogger
from coreason_veritas.gatekeeper import SignatureValidator


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
        SignatureValidator(public_key).verify_asset(asset, signature)

        attributes["co.srb_sig"] = str(signature)

    # 2. Config Sanitization
    if config_arg and config_arg in arguments:
        original_config = arguments[config_arg]
        if isinstance(original_config, dict):
            sanitized_config = DeterminismInterceptor.enforce_config(original_config)
            arguments[config_arg] = sanitized_config

    return attributes, bound


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
                attributes, bound = _prepare_governance(
                    func,
                    args,
                    kwargs,
                    asset_id_arg,
                    signature_arg,
                    user_id_arg,
                    config_arg,
                    allow_unsigned,
                )
                with IERLogger().start_governed_span(func.__name__, attributes):
                    with DeterminismInterceptor.scope():
                        async for item in func(*bound.args, **bound.kwargs):
                            yield item

            return wrapper

        elif inspect.isgeneratorfunction(func):

            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                attributes, bound = _prepare_governance(
                    func,
                    args,
                    kwargs,
                    asset_id_arg,
                    signature_arg,
                    user_id_arg,
                    config_arg,
                    allow_unsigned,
                )
                with IERLogger().start_governed_span(func.__name__, attributes):
                    with DeterminismInterceptor.scope():
                        yield from func(*bound.args, **bound.kwargs)

            return wrapper

        elif inspect.iscoroutinefunction(func):

            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                attributes, bound = _prepare_governance(
                    func,
                    args,
                    kwargs,
                    asset_id_arg,
                    signature_arg,
                    user_id_arg,
                    config_arg,
                    allow_unsigned,
                )

                # 2. Start Audit Span
                with IERLogger().start_governed_span(func.__name__, attributes):
                    # 3. Anchor Context (Context Manager)
                    with DeterminismInterceptor.scope():
                        return await func(*bound.args, **bound.kwargs)

            return wrapper

        else:

            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                attributes, bound = _prepare_governance(
                    func,
                    args,
                    kwargs,
                    asset_id_arg,
                    signature_arg,
                    user_id_arg,
                    config_arg,
                    allow_unsigned,
                )

                # 2. Start Audit Span
                with IERLogger().start_governed_span(func.__name__, attributes):
                    # 3. Anchor Context (Context Manager)
                    with DeterminismInterceptor.scope():
                        return func(*bound.args, **bound.kwargs)

            return wrapper

    return decorator
