# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import datetime

from redis.asyncio import Redis  # type: ignore[import-untyped, unused-ignore]

from coreason_veritas.exceptions import QuotaExceededError


class QuotaGuard:
    """
    Enforces daily financial limits using Redis.
    """

    def __init__(self, redis_client: Redis, daily_limit: float) -> None:
        """
        :param redis_client: Async Redis client instance.
        :param daily_limit: Daily budget limit in USD (or base currency).
        """
        self.redis = redis_client
        self.daily_limit = daily_limit

    def _get_key(self, user_id: str) -> str:
        today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        return f"budget:{today}:{user_id}"

    async def check_and_increment(self, user_id: str, cost: float) -> bool:
        """
        Increments the user's daily usage and checks against the limit.
        If limit is exceeded, rolls back the increment and raises QuotaExceededError.

        :param user_id: The unique identifier of the user.
        :param cost: The cost to add to the daily total.
        :return: True if allowed (within limit).
        :raises QuotaExceededError: If the daily limit is exceeded.
        """
        key = self._get_key(user_id)

        # Increment by cost
        new_value = await self.redis.incrbyfloat(key, cost)

        # Set expiry to 48 hours if it's a new key (or refresh it)
        # We can just set it every time or check ttl. Setting every time is safer/simpler.
        await self.redis.expire(key, 172800)  # 48 hours in seconds

        if new_value > self.daily_limit:
            # Rollback
            await self.redis.incrbyfloat(key, -cost)
            raise QuotaExceededError(
                f"Daily limit of {self.daily_limit} exceeded. Current: {new_value - cost}, Attempted: {cost}"
            )

        return True

    async def check_status(self, user_id: str) -> bool:
        """
        Checks if the user has reached their daily limit without incrementing.

        :param user_id: The unique identifier of the user.
        :return: False if limit reached or exceeded, True otherwise.
        """
        key = self._get_key(user_id)
        current_value_bytes = await self.redis.get(key)

        if current_value_bytes is None:
            current_value = 0.0
        else:
            current_value = float(current_value_bytes)

        return current_value < self.daily_limit
