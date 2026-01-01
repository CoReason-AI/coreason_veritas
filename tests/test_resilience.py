import asyncio

import pytest

from coreason_veritas.exceptions import CircuitOpenError
from coreason_veritas.resilience import AsyncCircuitBreaker


async def success_func():
    return "success"


async def fail_func():
    raise ValueError("fail")


@pytest.mark.asyncio
async def test_circuit_breaker_success():
    cb = AsyncCircuitBreaker(fail_max=2)
    res = await cb.call(success_func)
    assert res == "success"
    assert cb.state == "closed"


@pytest.mark.asyncio
async def test_circuit_breaker_trip():
    cb = AsyncCircuitBreaker(fail_max=2, time_window=10)

    # 1st failure
    with pytest.raises(ValueError):
        await cb.call(fail_func)
    assert cb.state == "closed"
    assert len(cb.failure_history) == 1

    # 2nd failure - should trip
    with pytest.raises(ValueError):
        await cb.call(fail_func)
    assert cb.state == "open"

    # 3rd call - should raise CircuitOpenError immediately
    with pytest.raises(CircuitOpenError):
        await cb.call(success_func)


@pytest.mark.asyncio
async def test_circuit_breaker_recovery():
    # Short reset timeout
    cb = AsyncCircuitBreaker(fail_max=1, reset_timeout=0.1)

    # Trip it
    with pytest.raises(ValueError):
        await cb.call(fail_func)
    assert cb.state == "open"

    # Wait for reset
    await asyncio.sleep(0.15)

    # Should be half-open internally when called
    # If successful, should go to closed
    res = await cb.call(success_func)
    assert res == "success"
    assert cb.state == "closed"
    assert len(cb.failure_history) == 0


@pytest.mark.asyncio
async def test_circuit_breaker_context_manager():
    cb = AsyncCircuitBreaker(fail_max=1)

    # Trip it via context manager
    with pytest.raises(ValueError):
        async with cb:
            await fail_func()

    assert cb.state == "open"

    # Verify open
    with pytest.raises(CircuitOpenError):
        async with cb:
            await success_func()


@pytest.mark.asyncio
async def test_circuit_breaker_time_window():
    cb = AsyncCircuitBreaker(fail_max=2, time_window=0.1)

    # 1st failure
    with pytest.raises(ValueError):
        await cb.call(fail_func)

    # Wait for window to pass
    await asyncio.sleep(0.15)

    # 2nd failure - should NOT trip because 1st one expired
    with pytest.raises(ValueError):
        await cb.call(fail_func)

    assert cb.state == "closed"
    assert len(cb.failure_history) == 1  # Only the recent one
