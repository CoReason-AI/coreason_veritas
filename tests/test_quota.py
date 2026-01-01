from unittest.mock import AsyncMock

import pytest

from coreason_veritas.exceptions import QuotaExceededError
from coreason_veritas.quota import QuotaGuard


@pytest.fixture  # type: ignore
def mock_redis() -> AsyncMock:
    redis = AsyncMock()
    # Mock return values for common operations
    redis.incrbyfloat.return_value = 5.0
    redis.get.return_value = b"5.0"
    return redis


@pytest.mark.asyncio  # type: ignore
async def test_quota_guard_init(mock_redis: AsyncMock) -> None:
    guard = QuotaGuard(mock_redis, daily_limit=100.0)
    assert guard.daily_limit == 100.0
    assert guard.redis == mock_redis


@pytest.mark.asyncio  # type: ignore
async def test_check_and_increment_success(mock_redis: AsyncMock) -> None:
    guard = QuotaGuard(mock_redis, daily_limit=10.0)

    # Mock incrbyfloat to return 5.0 (under limit)
    mock_redis.incrbyfloat.return_value = 5.0

    allowed = await guard.check_and_increment("user1", 5.0)

    assert allowed is True
    mock_redis.incrbyfloat.assert_called_once()
    mock_redis.expire.assert_called_once_with(guard._get_key("user1"), 172800)


@pytest.mark.asyncio  # type: ignore
async def test_check_and_increment_exceeded(mock_redis: AsyncMock) -> None:
    guard = QuotaGuard(mock_redis, daily_limit=10.0)

    # Mock incrbyfloat to return 11.0 (over limit)
    mock_redis.incrbyfloat.return_value = 11.0

    with pytest.raises(QuotaExceededError):
        await guard.check_and_increment("user1", 5.0)

    # Verify rollback
    # 2nd call to incrbyfloat with negative cost
    assert mock_redis.incrbyfloat.call_count == 2
    args, _ = mock_redis.incrbyfloat.call_args_list[1]
    assert args[1] == -5.0


@pytest.mark.asyncio  # type: ignore
async def test_check_status_under_limit(mock_redis: AsyncMock) -> None:
    guard = QuotaGuard(mock_redis, daily_limit=10.0)

    mock_redis.get.return_value = b"5.0"

    status = await guard.check_status("user1")
    assert status is True


@pytest.mark.asyncio  # type: ignore
async def test_check_status_over_limit(mock_redis: AsyncMock) -> None:
    guard = QuotaGuard(mock_redis, daily_limit=10.0)

    mock_redis.get.return_value = b"10.0"  # Equals limit (strict inequality < limit?)
    # Implementation: current < limit. If current == limit, it returns False (limit reached).

    status = await guard.check_status("user1")
    # 10.0 < 10.0 is False
    assert status is False


@pytest.mark.asyncio  # type: ignore
async def test_check_status_none(mock_redis: AsyncMock) -> None:
    guard = QuotaGuard(mock_redis, daily_limit=10.0)

    mock_redis.get.return_value = None

    status = await guard.check_status("user1")
    assert status is True
