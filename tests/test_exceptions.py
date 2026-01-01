from coreason_veritas.exceptions import (
    AssetTamperedError,
    CircuitOpenError,
    QuotaExceededError,
    VeritasError,
)


def test_exception_hierarchy():
    assert issubclass(VeritasError, Exception)
    assert issubclass(AssetTamperedError, VeritasError)
    assert issubclass(QuotaExceededError, VeritasError)
    assert issubclass(CircuitOpenError, VeritasError)


def test_exception_instantiation():
    e = AssetTamperedError("test")
    assert isinstance(e, VeritasError)
    assert str(e) == "test"
