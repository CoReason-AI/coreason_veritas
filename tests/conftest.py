# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

from typing import Any, Callable, Generator
from unittest.mock import patch

import jcs
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from coreason_veritas.auditor import IERLogger

# Cache clearing is no longer needed as lru_cache was removed.


@pytest.fixture(autouse=True)  # type: ignore[misc]
def set_test_mode() -> Generator[None, None, None]:
    """
    Set COREASON_VERITAS_TEST_MODE to force IERLogger to use Console Exporters
    instead of connecting to a real OTLP collector.
    """
    with patch.dict("os.environ", {"COREASON_VERITAS_TEST_MODE": "true"}):
        yield


@pytest.fixture(autouse=True)  # type: ignore[misc]
def reset_singleton() -> Generator[None, None, None]:
    """
    Reset the IERLogger singleton instance before each test.
    This ensures that each test gets a fresh start and can inject its own mocks
    into the IERLogger initialization (e.g. for trace providers).
    """
    if hasattr(IERLogger, "reset"):
        IERLogger.reset()
    else:
        # Fallback if reset method not yet implemented
        IERLogger._instance = None
    yield
    if hasattr(IERLogger, "reset"):
        IERLogger.reset()
    else:
        IERLogger._instance = None


# --- Shared Crypto Fixtures (Moved from edge_cases) ---


@pytest.fixture(scope="session")
def private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def public_key(private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
    return private_key.public_key()


@pytest.fixture(scope="session")
def pem_public(public_key: rsa.RSAPublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


@pytest.fixture
def sign_payload_func(private_key: rsa.RSAPrivateKey) -> Callable[..., str]:
    def _sign(payload: Any, p_key: Any = None) -> str:
        key_to_use = p_key or private_key
        canonical = jcs.canonicalize(payload)
        signature = key_to_use.sign(
            canonical,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return signature.hex()

    return _sign
