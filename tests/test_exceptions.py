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


def test_exception_inheritance() -> None:
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


def test_exception_instantiation() -> None:
    """Verify that exceptions can be instantiated."""
    err: CoreasonError = CoreasonError("test")
    assert str(err) == "test"
    assert err.response is None
    assert err.status_code is None

    err_quota: QuotaExceededError = QuotaExceededError("quota exceeded")
    assert isinstance(err_quota, BudgetExceededError)
    assert isinstance(err_quota, ClientError)
    assert isinstance(err_quota, CoreasonError)

    err_circuit: CircuitOpenError = CircuitOpenError("circuit open")
    assert isinstance(err_circuit, CoreasonError)

    err_asset: AssetTamperedError = AssetTamperedError("tampered")
    assert isinstance(err_asset, Exception)
