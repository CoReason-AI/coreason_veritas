# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import os
from functools import wraps
from typing import Any, Callable

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


def governed_execution(asset_id_arg: str, signature_arg: str) -> Callable[..., Any]:
    """
    Decorator that bundles Gatekeeper, Auditor, and Anchor into a single atomic wrapper.

    Args:
        asset_id_arg: The name of the keyword argument containing the asset/spec.
        signature_arg: The name of the keyword argument containing the signature.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # 1. Gatekeeper Check
            sig = kwargs.get(signature_arg)
            asset = kwargs.get(asset_id_arg)

            if sig is None:
                raise ValueError(f"Missing signature argument: {signature_arg}")
            if asset is None:
                raise ValueError(f"Missing asset argument: {asset_id_arg}")

            # Retrieve key from store (Env Var)
            public_key = get_public_key_from_store()
            SignatureValidator(public_key).verify_asset(asset, sig)

            # 2. Start Audit Span
            # Note: func.__name__ is used as span name
            # asset is passed as an attribute. The spec example passed {"asset": asset}
            # which maps to `co.asset_id` in our Auditor logic (though we pass it as 'asset' here,
            # IERLogger creates span with provided attributes.
            # To be strictly compliant with Auditor "Mandatory Attributes", we should map it.
            # However, the spec usage example was explicit: `{"asset": asset}`.
            # I'll pass it as is, but maybe I should map it to `co.asset_id`?
            # The Auditor spec says `co.asset_id` is mandatory.
            # I will pass `co.asset_id` as well.

            attributes = {
                "asset": str(asset),  # As per example
                "co.asset_id": str(asset),  # For strict compliance
            }

            with IERLogger().start_governed_span(func.__name__, attributes):
                # 3. Anchor Context (Context Manager)
                with DeterminismInterceptor().scope():
                    return await func(*args, **kwargs)

        return wrapper

    return decorator
