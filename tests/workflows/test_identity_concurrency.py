import asyncio
from typing import Any
from unittest.mock import patch

import pytest

from coreason_veritas.auditor import IERLogger
from coreason_veritas.wrapper import governed_execution


# Define a picklable UserContext for testing
class MockUserContext:
    def __init__(self, email: str) -> None:
        self.email = email
        self.user_id = email.split("@")[0]
        self.groups: list[str] = []
        self.claims: dict[str, Any] = {}


@pytest.mark.asyncio  # type: ignore[misc]
async def test_identity_concurrency_isolation() -> None:
    """
    Verify that concurrent executions of a governed async function
    correctly attribute actions to the respective identities.
    """

    # Use the singleton instance directly
    real_logger = IERLogger()

    # Patch the log_action method on the singleton instance
    with patch.object(real_logger, "log_action", side_effect=real_logger.log_action) as mock_log_action:
        # We use side_effect=real_logger.log_action to invoke the real method?
        # No, we want to STOP the real method to avoid Loguru pickling errors and just verify calls.
        # So just MagicMock is fine.
        mock_log_action.return_value = None

        @governed_execution(asset_id_arg="asset", signature_arg="sig", user_id_arg="uid", allow_unsigned=True)
        async def slow_operation(asset: str, sig: str | None, uid: str, user_context: Any, delay: float) -> str:
            await asyncio.sleep(delay)
            return uid

        # Create 3 contexts using picklable class
        uc1 = MockUserContext("user1@example.com")
        uc2 = MockUserContext("user2@example.com")
        uc3 = MockUserContext("user3@example.com")

        # Run concurrently
        tasks = [
            slow_operation(asset="a1", sig=None, uid="u1", user_context=uc1, delay=0.2),
            slow_operation(asset="a2", sig=None, uid="u2", user_context=uc2, delay=0.1),
            slow_operation(asset="a3", sig=None, uid="u3", user_context=uc3, delay=0.3),
        ]

        results = await asyncio.gather(*tasks)
        assert results == ["u1", "u2", "u3"]

        # Verify Logs
        # Each execution logs Start and End. Total 6 logs.
        assert mock_log_action.call_count == 6

        calls = mock_log_action.call_args_list

        users_seen = []
        for call in calls:
            args, _ = call
            # action = args[0]  # Unused
            details = args[1]
            ctx = args[2]

            # Check consistency
            if ctx == uc1:
                assert details["co.user_id"] == "u1"
                users_seen.append("u1")
            elif ctx == uc2:
                assert details["co.user_id"] == "u2"
                users_seen.append("u2")
            elif ctx == uc3:
                assert details["co.user_id"] == "u3"
                users_seen.append("u3")
            else:
                pytest.fail(f"Unknown context seen: {ctx}")

        # Ensure we saw all users twice (Start/End)
        assert users_seen.count("u1") == 2
        assert users_seen.count("u2") == 2
        assert users_seen.count("u3") == 2
