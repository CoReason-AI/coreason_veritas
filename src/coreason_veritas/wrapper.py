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
from functools import wraps
from typing import Any, Callable, Dict, Optional

from coreason_veritas.anchor import DeterminismInterceptor
from coreason_veritas.auditor import IERLogger
from coreason_veritas.gatekeeper import SignatureValidator


def get_public_key_from_store() -> str:
    """
    Retrieves the SRB Public Key from the immutable Key Store.
    For this implementation, it reads from the COREASON_VERITAS_PUBLIC_KEY environment variable.
    """
    key = os.getenv("COREASON_VERITAS_PUBLIC_KEY")
    if not key:
        raise ValueError("COREASON_VERITAS_PUBLIC_KEY environment variable is not set.")
    return key


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
        signature = inspect.signature(func)

        def _extract_arguments(args: Any, kwargs: Dict[str, Any]) -> inspect.BoundArguments:
            """
            Binds args and kwargs to the function signature.
            """
            bound_args = signature.bind(*args, **kwargs)
            bound_args.apply_defaults()
            return bound_args

        def _perform_gatekeeping(all_args: Dict[str, Any]) -> Dict[str, str]:
            # 1. Gatekeeper Check
            sig = all_args.get(signature_arg)
            asset = all_args.get(asset_id_arg)
            user_id = all_args.get(user_id_arg)

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
            if allow_unsigned and sig is None:
                # Bypass signature check and inject Draft Mode tag
                attributes["co.compliance_mode"] = "DRAFT"
            else:
                # Strict Mode (Default)
                if sig is None:
                    raise ValueError(f"Missing signature argument: {signature_arg}")

                # Retrieve key from store (Env Var)
                public_key = get_public_key_from_store()
                SignatureValidator(public_key).verify_asset(asset, sig)

                attributes["co.srb_sig"] = str(sig)

            # Prepare attributes for Auditor
            return attributes

        def _sanitize_kwargs(all_args: Dict[str, Any]) -> None:
            """
            If config_arg is specified, find it in all_args, sanitize it, and update it.
            Note: Since we are working with a copy of arguments or modifying kwargs in place,
            we need to ensure the changes propagate to the actual function call.
            However, for 'wrapper', we pass *args and **kwargs.
            Ideally, we should modify the mutable objects in place or reconstruct args/kwargs.
            """
            if config_arg and config_arg in all_args:
                original_config = all_args[config_arg]
                if isinstance(original_config, dict):
                    sanitized_config = DeterminismInterceptor.enforce_config(original_config)
                    # We modify the object in place if possible, but enforce_config returns a new dict.
                    # So we need to update the all_args dictionary.
                    all_args[config_arg] = sanitized_config

        if inspect.isasyncgenfunction(func):

            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound_args = _extract_arguments(args, kwargs)
                all_args = bound_args.arguments
                attributes = _perform_gatekeeping(all_args)
                _sanitize_kwargs(all_args)

                with IERLogger().start_governed_span(func.__name__, attributes):
                    with DeterminismInterceptor.scope():
                        async for item in func(*bound_args.args, **bound_args.kwargs):
                            yield item

            return wrapper

        elif inspect.isgeneratorfunction(func):

            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound_args = _extract_arguments(args, kwargs)
                all_args = bound_args.arguments
                attributes = _perform_gatekeeping(all_args)
                _sanitize_kwargs(all_args)
                with IERLogger().start_governed_span(func.__name__, attributes):
                    with DeterminismInterceptor.scope():
                        yield from func(*bound_args.args, **bound_args.kwargs)

            return wrapper

        elif inspect.iscoroutinefunction(func):

            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound_args = _extract_arguments(args, kwargs)
                all_args = bound_args.arguments
                attributes = _perform_gatekeeping(all_args)
                _sanitize_kwargs(all_args)

                # 2. Start Audit Span
                with IERLogger().start_governed_span(func.__name__, attributes):
                    # 3. Anchor Context (Context Manager)
                    with DeterminismInterceptor.scope():
                        return await func(*bound_args.args, **bound_args.kwargs)

            return wrapper

        else:

            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound_args = _extract_arguments(args, kwargs)
                all_args = bound_args.arguments
                attributes = _perform_gatekeeping(all_args)
                _sanitize_kwargs(all_args)

                # 2. Start Audit Span
                with IERLogger().start_governed_span(func.__name__, attributes):
                    # 3. Anchor Context (Context Manager)
                    with DeterminismInterceptor.scope():
                        return func(*bound_args.args, **bound_args.kwargs)

            return wrapper

    return decorator
