import logging
import os
from types import FrameType
from unittest.mock import MagicMock, patch

import pytest
from loguru import logger

from coreason_veritas.logging_utils import (
    InterceptHandler,
    _trace_context_patcher,
    configure_logging,
    scrub_sensitive_data,
)


def test_scrub_sensitive_data_set_uncomparable() -> None:
    """Test scrubbing a set with uncomparable items (triggers TypeError in sorted)."""
    # Use objects that definitely don't support comparison
    obj1 = object()
    obj2 = object()
    data = {obj1, obj2}

    # Verify sorted fails
    with pytest.raises(TypeError):
        sorted([obj1, obj2])

    scrubbed = scrub_sensitive_data(data)

    # Result should be a list (set converted to list)
    assert isinstance(scrubbed, list)
    assert len(scrubbed) == 2
    assert obj1 in scrubbed
    assert obj2 in scrubbed


class CustomObj:
    def __init__(self, x: int):
        self.x = x
    def __str__(self) -> str:
        return f"CustomObj({self.x})"

def test_scrub_sensitive_data_custom_object() -> None:
    """Test scrubbing a custom object (triggers hasattr(__dict__))."""
    obj = CustomObj(10)
    # Ensure it has __dict__
    assert hasattr(obj, "__dict__")

    scrubbed = scrub_sensitive_data(obj)
    assert scrubbed == "CustomObj(10)"


def test_scrub_sensitive_data_primitive() -> None:
    """Test scrubbing a primitive (hits final else block)."""
    assert scrub_sensitive_data(123) == 123
    assert scrub_sensitive_data("foo") == "foo"


def test_trace_context_patcher_no_span() -> None:
    """Test patcher when get_current_span returns None."""
    record: dict = {}
    with patch("coreason_veritas.logging_utils.trace.get_current_span", return_value=None):
        _trace_context_patcher(record)
    # Should return early
    assert "extra" not in record


def test_intercept_handler_unknown_level() -> None:
    """Test InterceptHandler with an unknown log level."""
    handler = InterceptHandler()
    record = logging.LogRecord(
        name="test",
        level=99,  # Unknown level
        pathname=__file__,
        lineno=10,
        msg="test message",
        args=(),
        exc_info=None,
    )

    with patch("coreason_veritas.logging_utils.logger.opt") as mock_opt:
        mock_log = MagicMock()
        mock_opt.return_value = mock_log

        handler.emit(record)

        mock_log.log.assert_called_with("99", "test message")


def test_configure_logging_json() -> None:
    """Test configure_logging with JSON format."""
    with patch.dict(os.environ, {"LOG_FORMAT": "JSON"}):
        with patch("coreason_veritas.logging_utils.logger.add") as mock_add:
            configure_logging()
            # Check if one of the calls was for sys.stderr with serialize=True
            calls = mock_add.call_args_list
            json_sink_call = False
            for args, kwargs in calls:
                if kwargs.get("serialize") is True:
                    json_sink_call = True
                    break
            assert json_sink_call


def test_intercept_handler_frame_walking_mock() -> None:
    """Test frame walking by mocking logging.currentframe."""
    handler = InterceptHandler()
    record = logging.LogRecord("test", 20, "path", 10, "msg", (), None)

    # Create mock frames
    # frame1 (top) -> frame2 (logging) -> frame3 (logging) -> frame4 (caller)

    frame4 = MagicMock(spec=FrameType)
    frame4.f_code.co_filename = "caller.py"
    frame4.f_back = None

    frame3 = MagicMock(spec=FrameType)
    frame3.f_code.co_filename = logging.__file__
    frame3.f_back = frame4

    frame2 = MagicMock(spec=FrameType)
    frame2.f_code.co_filename = logging.__file__
    frame2.f_back = frame3

    frame1 = MagicMock(spec=FrameType)
    # currentframe() returns this

    # We patch logging.currentframe to return frame2 (simulating we are inside logging module)
    # Wait, InterceptHandler calls logging.currentframe().
    # It returns the frame of InterceptHandler.emit usually.
    # The loop starts with that frame.

    # Let's say frame1 is InterceptHandler.emit. Its file is logging_utils.py.
    # But logic is:
    # frame = logging.currentframe()
    # while frame and frame.f_code.co_filename == logging.__file__: ...

    # logging.currentframe() returns the frame of the caller of currentframe().
    # So it returns the frame inside emit().
    # That frame's filename is `logging_utils.py` (where emit is defined).
    # `logging.__file__` is `.../logging/__init__.py`.
    # They are NOT equal.
    # So the loop condition `frame.f_code.co_filename == logging.__file__` is False initially!

    # Wait, why does `logging_utils.py` have this loop?
    # Because `InterceptHandler` is usually copy-pasted from Loguru docs.
    # The goal is to skip frames belonging to the `logging` module if the handler was called FROM the logging module (e.g. basicConfig defaults).
    # But `emit` is in `logging_utils.py`.

    # If the loop condition is False initially, then lines inside loop are never reached.
    # That explains why they are not covered.

    # BUT, if I mock `logging.currentframe` to return a frame that IS in `logging.__file__`, the loop will run.

    fake_frame = MagicMock(spec=FrameType)
    fake_frame.f_code.co_filename = logging.__file__
    fake_frame.f_back = frame4 # Breaks loop

    with patch("coreason_veritas.logging_utils.logging.currentframe", return_value=fake_frame):
         with patch("coreason_veritas.logging_utils.logger.opt") as mock_opt:
             handler.emit(record)
             # Loop should run once
             # depth starts at 2.
             # Loop runs. frame becomes frame4. depth becomes 3.
             # Loop checks frame4 (caller.py) != logging.__file__. Stops.

             assert mock_opt.called
             kwargs = mock_opt.call_args[1]
             assert kwargs["depth"] == 3
