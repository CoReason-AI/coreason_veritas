from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

from coreason_veritas.auditor import IERLogger
from coreason_veritas.wrapper import governed_execution

# Mock UserContext
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


def test_auditor_user_context_partial(auditor: IERLogger, mock_logger: MagicMock) -> None:
    # Missing email, has user_id
    uc = MagicMock()
    del uc.email  # ensure attribute error if accessed, or mock getattr logic
    # MagicMock usually creates attributes on access. We need to be careful.
    # The code uses: getattr(user_context, "email", None)
    # So if we want it to return None, we don't set it.
    # Actually, MagicMock(spec=...) might be better, or just rely on getattr behavior.
    # If I just use MagicMock(), getattr(uc, "email", None) returns a Mock object (truthy).
    # I should explicitly set email to None.

    uc.email = None
    uc.user_id = "user123"

    auditor.log_action("TEST", {}, uc)

    call_kwargs = mock_logger.bind.call_args[1]
    assert call_kwargs["actor"] == "user123"


def test_auditor_user_context_empty(auditor: IERLogger, mock_logger: MagicMock) -> None:
    # Missing both
    uc = MagicMock()
    uc.email = None
    uc.user_id = None

    auditor.log_action("TEST", {}, uc)

    call_kwargs = mock_logger.bind.call_args[1]
    assert call_kwargs["actor"] == "unknown"


def test_auditor_context_none(auditor: IERLogger, mock_logger: MagicMock) -> None:
    auditor.log_action("TEST", {}, None)
    call_kwargs = mock_logger.bind.call_args[1]
    assert "actor" not in call_kwargs


def test_wrapper_user_context_none() -> None:
    with patch("coreason_veritas.wrapper.IERLogger") as MockLoggerClass:
        mock_instance = MockLoggerClass.return_value
        mock_instance.create_governed_span.return_value = MagicMock()
        mock_instance.log_action = MagicMock()

        @governed_execution(asset_id_arg="a", signature_arg="s", user_id_arg="u", allow_unsigned=True)
        def func(a: str, s: str | None, u: str, user_context: Any) -> None:
            pass

        func(a="1", s=None, u="1", user_context=None)

        assert mock_instance.log_action.called
        args = mock_instance.log_action.call_args
        # user_context_obj should be None
        assert args[0][2] is None


@pytest.mark.asyncio  # type: ignore[misc]
async def test_wrapper_async_identity() -> None:
    with patch("coreason_veritas.wrapper.IERLogger") as MockLoggerClass:
        mock_instance = MockLoggerClass.return_value
        mock_instance.create_governed_span.return_value = MagicMock()
        mock_instance.log_action = MagicMock()

        uc = MagicMock()

        @governed_execution(asset_id_arg="a", signature_arg="s", user_id_arg="u", allow_unsigned=True)
        async def async_func(a: str, s: str | None, u: str, user_context: Any) -> str:
            return "done"

        res = await async_func(a="1", s=None, u="1", user_context=uc)
        assert res == "done"

        # Verify log_action captured identity
        assert mock_instance.log_action.called
        args = mock_instance.log_action.call_args
        assert args[0][2] == uc


def test_wrapper_generator_identity() -> None:
    with patch("coreason_veritas.wrapper.IERLogger") as MockLoggerClass:
        mock_instance = MockLoggerClass.return_value
        mock_instance.create_governed_span.return_value = MagicMock()
        mock_instance.log_action = MagicMock()

        uc = MagicMock()

        @governed_execution(asset_id_arg="a", signature_arg="s", user_id_arg="u", allow_unsigned=True)
        def gen_func(a: str, s: str | None, u: str, user_context: Any) -> Generator[str, None, None]:
            yield "val"

        gen = gen_func(a="1", s=None, u="1", user_context=uc)
        assert next(gen) == "val"

        # Verify log_action captured identity (start should be called on enter)
        assert mock_instance.log_action.called
        # Check first call (Start)
        args_start = mock_instance.log_action.call_args_list[0]
        assert args_start[0][2] == uc


def test_wrapper_gatekeeper_failure() -> None:
    # If gatekeeper fails (e.g. strict mode, no signature), does it crash or log?
    # It logs failure via _handle_error -> _log_end.
    # Identity capture happens AFTER gatekeeper checks in _prepare.
    # So if gatekeeper fails, identity is NOT captured.

    with patch("coreason_veritas.wrapper.IERLogger") as MockLoggerClass:
        mock_instance = MockLoggerClass.return_value
        mock_instance.create_governed_span.return_value = MagicMock()
        mock_instance.log_action = MagicMock()

        uc = MagicMock()

        @governed_execution(asset_id_arg="a", signature_arg="s", user_id_arg="u", allow_unsigned=False)
        def func(a: str, s: str | None, u: str, user_context: Any) -> None:
            pass

        with pytest.raises(ValueError, match="Missing signature"):
            func(a="1", s=None, u="1", user_context=uc)

        # log_action should be called for FAILURE (End)
        # Start log might not be called if exception raised before _log_start?
        # wrapper.py:
        # try:
        #   attributes, bound = _prepare_governance(...)  <-- raises here
        #   ...
        #   _log_start()
        # except Exception:
        #   _handle_error(e)
        #
        # _handle_error calls _log_end(success=False).
        # _log_end calls log_action.

        assert mock_instance.log_action.called
        args = mock_instance.log_action.call_args
        assert args[0][0] == "Governance Execution Completed"
        assert args[0][1]["verdict"] == "BLOCKED"
        # Identity should be None because we failed before capture
        assert args[0][2] is None
