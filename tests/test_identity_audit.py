from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

from coreason_veritas.auditor import IERLogger
from coreason_veritas.wrapper import governed_execution

try:
    from coreason_identity.models import UserContext
except ImportError:
    UserContext = MagicMock


@pytest.fixture  # type: ignore[misc]
def mock_logger() -> Generator[MagicMock, None, None]:
    with patch("coreason_veritas.auditor.logger") as mock:
        yield mock


@pytest.fixture  # type: ignore[misc]
def auditor() -> IERLogger:
    return IERLogger()


def test_log_action_identity(auditor: IERLogger, mock_logger: MagicMock) -> None:
    user_context = MagicMock()
    user_context.email = "alice@example.com"
    user_context.groups = ["admin"]
    user_context.claims = {"iss": "veritas"}

    details = {"action": "test"}
    auditor.log_action("TEST_ACTION", details, user_context)

    mock_logger.bind.assert_called()
    call_kwargs = mock_logger.bind.call_args[1]

    assert call_kwargs["event_type"] == "TEST_ACTION"
    assert call_kwargs["actor"] == "alice@example.com"
    assert call_kwargs["groups"] == ["admin"]
    assert call_kwargs["claims"] == {"iss": "veritas"}
    assert "downstream_token" not in call_kwargs


def test_log_action_no_identity(auditor: IERLogger, mock_logger: MagicMock) -> None:
    auditor.log_action("TEST_ACTION", {"foo": "bar"}, None)
    call_kwargs = mock_logger.bind.call_args[1]
    assert "actor" not in call_kwargs
    assert call_kwargs["foo"] == "bar"


def test_log_action_strips_token(auditor: IERLogger, mock_logger: MagicMock) -> None:
    details = {"downstream_token": "secret"}
    auditor.log_action("TEST_ACTION", details, None)
    call_kwargs = mock_logger.bind.call_args[1]
    assert "downstream_token" not in call_kwargs


def test_wrapper_identity_integration() -> None:
    with patch("coreason_veritas.wrapper.IERLogger") as MockLoggerClass:
        mock_instance = MockLoggerClass.return_value
        mock_instance.create_governed_span.return_value = MagicMock()
        mock_instance.log_action = MagicMock()

        user_context = MagicMock()

        @governed_execution(asset_id_arg="a", signature_arg="s", user_id_arg="u", allow_unsigned=True)
        def process(a: str, s: str | None, u: str, user_context: Any) -> None:
            pass

        process(a="1", s=None, u="u1", user_context=user_context)

        assert mock_instance.log_action.called
        args = mock_instance.log_action.call_args
        assert args[0][2] == user_context
