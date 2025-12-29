from typing import Dict

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from coreason_veritas.exceptions import AssetTamperedError
from coreason_veritas.gatekeeper import SignatureValidator

# Generate a valid key pair for testing initialization
# Done at module level to avoid re-generation
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key_pem = (
    private_key.public_key()
    .public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    .decode()
)


@pytest.fixture(scope="module")  # type: ignore[misc]
def validator_module() -> SignatureValidator:
    return SignatureValidator(public_key_store=public_key_pem)


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])  # type: ignore[misc]
@given(payload=st.dictionaries(keys=st.text(), values=st.text()), signature=st.text())  # type: ignore[misc]
def test_verify_asset_fuzz(validator_module: SignatureValidator, payload: Dict[str, str], signature: str) -> None:
    """
    Fuzz the Gatekeeper verify_asset method with random payloads and signatures.
    It should either return True (extremely unlikely) or raise AssetTamperedError.
    It should NEVER raise a ValueError, TypeError, or crash unexpectedly.
    """
    try:
        validator_module.verify_asset(payload, signature)
    except AssetTamperedError:
        # Expected outcome for garbage inputs
        pass
    except Exception as e:
        # Any other exception is a failure of robustness
        pytest.fail(f"Gatekeeper crashed with unexpected error: {type(e).__name__}: {e}")


@given(invalid_pem=st.text())  # type: ignore[misc]
def test_init_fuzz(invalid_pem: str) -> None:
    """
    Fuzz the initialization with garbage PEM strings.
    Should raise ValueError but not crash hard.
    """
    try:
        SignatureValidator(public_key_store=invalid_pem)
    except ValueError:
        pass
    except Exception as e:
        pytest.fail(f"Gatekeeper init crashed with unexpected error: {type(e).__name__}: {e}")
