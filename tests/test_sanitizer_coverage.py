
from unittest.mock import MagicMock
from typing import Any, Dict, List

import pytest

import coreason_veritas.sanitizer
from coreason_veritas.sanitizer import scrub_pii_recursive, scrub_pii_payload


def test_circular_reference_dict() -> None:
    """Test handling of circular references in dictionary."""
    # Use a safe string that won't be redacted by Presidio (which defaults to 'Alice' being a Person)
    # or accept the redaction.
    a: Dict[str, Any] = {"name": "NotAPerson"}
    b: Dict[str, Any] = {"parent": a}
    a["child"] = b

    # a -> b -> a

    scrubbed_a = scrub_pii_recursive(a)

    # Check structure logic, not PII logic here
    assert scrubbed_a["child"]["parent"] is scrubbed_a


def test_circular_reference_list() -> None:
    """Test handling of circular references in list."""
    a: List[Any] = []
    b: List[Any] = [a]
    a.append(b)

    # a -> b -> a

    scrubbed_a = scrub_pii_recursive(a)

    assert len(scrubbed_a) == 1
    assert len(scrubbed_a[0]) == 1
    assert scrubbed_a[0][0] is scrubbed_a


def test_shared_object_diamond() -> None:
    """Test handling of shared objects (diamond pattern)."""
    shared = {"info": "shared"}
    root = {"left": shared, "right": shared}

    scrubbed_root = scrub_pii_recursive(root)

    assert scrubbed_root["left"] == {"info": "shared"}
    assert scrubbed_root["right"] == {"info": "shared"}
    # Verify it's the SAME object instance in result
    assert scrubbed_root["left"] is scrubbed_root["right"]


def test_list_of_primitives() -> None:
    """Test list containing primitives."""
    data: List[Any] = [1, 2, 3, True, None]
    scrubbed = scrub_pii_recursive(data)
    assert scrubbed == [1, 2, 3, True, None]


def test_dict_primitives() -> None:
    """Test dict containing primitives."""
    data: Dict[str, Any] = {"a": 1, "b": True}
    scrubbed = scrub_pii_recursive(data)
    assert scrubbed == {"a": 1, "b": True}


def test_tuple_conversion() -> None:
    """Test tuple conversion and preservation."""
    data = (1, "sensitive")

    scrubbed = scrub_pii_recursive(data)
    assert isinstance(scrubbed, tuple)
    assert scrubbed == (1, "sensitive")


def test_nested_tuple_conversion() -> None:
    """Test nested tuples are converted/preserved (implementation converts to lists internally)."""
    data = {"key": (1, 2)}
    scrubbed = scrub_pii_recursive(data)

    # Implementation details: nested tuples are converted to lists in the iterative process
    # and NOT converted back (only root is converted back).
    # So we expect list here based on current implementation.
    assert isinstance(scrubbed["key"], list)
    assert scrubbed["key"] == [1, 2]


def test_scrub_pii_payload_value_error_too_large() -> None:
    """Test error handling for large payload raising ValueError."""
    # Manually replace PIIAnalyzer in the module
    original_cls = coreason_veritas.sanitizer.PIIAnalyzer

    MockPIIAnalyzer = MagicMock()
    coreason_veritas.sanitizer.PIIAnalyzer = MockPIIAnalyzer

    try:
        # Configure mock chain to raise ValueError
        mock_instance = MockPIIAnalyzer.return_value
        mock_engine = mock_instance.get_analyzer.return_value
        mock_engine.analyze.side_effect = ValueError("[E088] Text of length 2000000 exceeds maximum")

        result = scrub_pii_payload("A very large string")
        assert result == "<REDACTED: PAYLOAD TOO LARGE FOR PII ANALYSIS>"
    finally:
        coreason_veritas.sanitizer.PIIAnalyzer = original_cls


def test_scrub_pii_payload_unexpected_error() -> None:
    """Test error handling for unexpected exceptions."""
    original_cls = coreason_veritas.sanitizer.PIIAnalyzer

    MockPIIAnalyzer = MagicMock()
    coreason_veritas.sanitizer.PIIAnalyzer = MockPIIAnalyzer

    try:
        # Configure mock chain to raise generic Exception
        mock_instance = MockPIIAnalyzer.return_value
        mock_engine = mock_instance.get_analyzer.return_value
        mock_engine.analyze.side_effect = Exception("Boom")

        with pytest.raises(Exception, match="Boom"):
            scrub_pii_payload("test")
    finally:
        coreason_veritas.sanitizer.PIIAnalyzer = original_cls
