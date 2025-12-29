import concurrent.futures
from typing import Any, Dict

import pytest

from coreason_veritas.anchor import DeterminismInterceptor
from coreason_veritas.auditor import IERLogger


# A simple mock sink to verify callbacks are hit
def mock_sink(event: Dict[str, Any]) -> None:
    pass


@pytest.fixture  # type: ignore[misc]
def ier_logger() -> IERLogger:
    """Ensure we have a clean logger for the test."""
    # Since IERLogger is a singleton, we might need to reset it or just use it.
    # For this stress test, accessing the existing singleton is fine.
    logger = IERLogger()
    return logger


def test_concurrent_auditing_and_gatekeeping() -> None:
    """
    Stress test:
    - 20 threads simultaneously interacting with IERLogger and DeterminismInterceptor.
    - Ensures no race conditions, deadlocks, or crashes.
    """
    logger = IERLogger()
    interceptor = DeterminismInterceptor()

    # Register a sink to add work to the critical path
    logger.register_sink(mock_sink)

    errors: list[Exception] = []

    def worker(thread_id: int) -> None:
        try:
            # 1. Emit Handshake (logging)
            logger.emit_handshake(version=f"1.0.{thread_id}")

            # 2. Start a Governed Span (tracing)
            attributes = {
                "co.user_id": f"user_{thread_id}",
                "co.asset_id": f"asset_{thread_id}",
                "co.srb_sig": "dummy_sig",
                "co.compliance_mode": "DRAFT",  # Skip signature verification for speed/simplicity here
            }

            with logger.start_governed_span(f"span_{thread_id}", attributes) as span:
                # 3. Interceptor Logic (anchor) inside span
                config = {"temperature": 0.9, "seed": 100}
                safe_config = interceptor.enforce_config(config)
                assert safe_config["temperature"] == 0.0
                span.set_attribute("processed", True)

        except Exception as e:
            errors.append(e)

    # Hammer it with threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(worker, i) for i in range(100)]
        concurrent.futures.wait(futures)

    if errors:
        pytest.fail(f"Concurrent stress test failed with {len(errors)} errors: {errors[0]}")
