
import asyncio
import contextvars
from typing import Any, Dict, List
import pytest
from coreason_veritas.anchor import is_anchor_active, DeterminismInterceptor

@pytest.mark.asyncio
async def test_context_propagation_asyncio_gather() -> None:
    """
    Test that the Anchor context variable propagates correctly across asyncio.gather tasks.
    """
    async def worker(idx: int) -> bool:
        # Check if anchor is active inside the worker
        return is_anchor_active()

    # Without anchor
    results = await asyncio.gather(*[worker(i) for i in range(5)])
    assert not any(results), "Anchor should be inactive by default"

    # With anchor
    with DeterminismInterceptor.scope():
        results = await asyncio.gather(*[worker(i) for i in range(5)])
        assert all(results), "Anchor should be active in all gathered tasks"


@pytest.mark.asyncio
async def test_context_propagation_create_task() -> None:
    """
    Test that the Anchor context variable propagates to tasks created with create_task.
    """
    async def worker() -> bool:
        return is_anchor_active()

    # With anchor
    with DeterminismInterceptor.scope():
        task = asyncio.create_task(worker())
        result = await task
        assert result is True, "Anchor should propagate to created task"

    # Verify it doesn't leak out
    assert is_anchor_active() is False


@pytest.mark.asyncio
async def test_context_leak_prevention() -> None:
    """
    Test that the Anchor context does not leak to parallel tasks started outside the scope.
    """

    start_event = asyncio.Event()
    finish_event = asyncio.Event()

    async def long_running_ungoverned_task() -> bool:
        await start_event.wait() # Wait for governed task to start
        # At this point, the governed task is running with anchor active.
        # This task should NOT see it.
        status = is_anchor_active()
        finish_event.set()
        return status

    async def governed_task() -> None:
        with DeterminismInterceptor.scope():
            start_event.set() # Signal that we are in the scope
            await finish_event.wait() # Wait for ungoverned task to check

    # Start ungoverned task
    t1 = asyncio.create_task(long_running_ungoverned_task())

    # Start governed task
    t2 = asyncio.create_task(governed_task())

    await asyncio.gather(t1, t2)

    leak_detected = t1.result()
    assert leak_detected is False, "Anchor context leaked to a parallel task!"
