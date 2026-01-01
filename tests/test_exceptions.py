from coreason_veritas.exceptions import (
    AssetTamperedError,
    AuthenticationError,
    BudgetExceededError,
    CircuitOpenError,
    ClientError,
    ComplianceViolationError,
    CoreasonError,
    QuotaExceededError,
    RateLimitError,
    ServerError,
    ServiceUnavailableError,
)


def test_exception_inheritance():
    """Verify the inheritance hierarchy of exceptions."""
    assert issubclass(ClientError, CoreasonError)
    assert issubclass(ServerError, CoreasonError)
    assert issubclass(AuthenticationError, ClientError)
    assert issubclass(BudgetExceededError, ClientError)
    assert issubclass(QuotaExceededError, BudgetExceededError)
    assert issubclass(ComplianceViolationError, ClientError)
    assert issubclass(RateLimitError, ClientError)
    assert issubclass(ServiceUnavailableError, ServerError)
    assert issubclass(CircuitOpenError, CoreasonError)
    assert issubclass(AssetTamperedError, Exception)


def test_exception_instantiation():
    """Verify that exceptions can be instantiated."""
    err = CoreasonError("test")
    assert str(err) == "test"
    assert err.response is None
    assert err.status_code is None

    err = QuotaExceededError("quota exceeded")
    assert isinstance(err, BudgetExceededError)
    assert isinstance(err, ClientError)
    assert isinstance(err, CoreasonError)

    err = CircuitOpenError("circuit open")
    assert isinstance(err, CoreasonError)

    err = AssetTamperedError("tampered")
    assert isinstance(err, Exception)
