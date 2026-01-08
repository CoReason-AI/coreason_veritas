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
import copy
import os
from contextvars import ContextVar
from typing import Any, Dict, Generator, cast

import jcs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
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

    def __init__(self) -> None:
        """
        Initialize the DeterminismInterceptor.
        Loads the private key from the environment if available.
        """
        self._private_key: Any = None
        self._load_private_key()

    def _load_private_key(self) -> None:
        """Helper to load the private key from the environment variable."""
        private_key_pem = os.getenv("COREASON_VERITAS_PRIVATE_KEY")
        if private_key_pem:
            try:
                self._private_key = serialization.load_pem_private_key(
                    private_key_pem.encode(),
                    password=None,
                )
            except Exception as e:
                logger.error(f"Failed to load private key: {e}")
                # We don't raise here to allow instantiation even if key is bad/missing,
                # but seal() will fail.

    def seal(self, artifact: Dict[str, Any]) -> str:
        """
        Cryptographically signs the provided artifact and returns a signature string.
        The artifact is first canonicalized using JCS.
        The signature is generated using the private key from COREASON_VERITAS_PRIVATE_KEY.

        Args:
            artifact: The dictionary artifact to sign.

        Returns:
            The hex-encoded signature string.

        Raises:
            ValueError: If the private key environment variable is missing.
        """
        if self._private_key is None:
            # Try reloading in case env var was set after init (e.g. during tests or late config)
            self._load_private_key()
            if self._private_key is None:
                raise ValueError("COREASON_VERITAS_PRIVATE_KEY environment variable is not set or invalid.")

        canonical_payload = jcs.canonicalize(artifact)
        signature = self._private_key.sign(
            canonical_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

        return cast(str, signature.hex())

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
        sanitized = copy.deepcopy(raw_config)

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
        try:
            sanitized["seed"] = int(os.getenv("VERITAS_SEED", 42))
        except ValueError:
            logger.warning("VERITAS_SEED is not a valid integer. Falling back to default 42.")
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
            try:
                _ANCHOR_ACTIVE.reset(token)
            except ValueError:  # pragma: no cover
                # This can happen during async cancellation if the context has diverged.
                # Since we are exiting the scope anyway, it is safe to ignore.
                pass  # pragma: no cover
