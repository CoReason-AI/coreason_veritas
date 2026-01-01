from coreason_veritas import AsyncCircuitBreaker, QuotaGuard


def test_exports() -> None:
    """Verify that new modules are exported from top-level."""
    assert AsyncCircuitBreaker is not None
    assert QuotaGuard is not None
