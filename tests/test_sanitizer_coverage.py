
import pytest
from coreason_veritas.sanitizer import scrub_pii_recursive, scrub_pii_payload, PIIAnalyzer
from unittest.mock import patch, MagicMock

def test_circular_reference_dict():
    """Test handling of circular references in dictionary."""
    # Use a safe string that won't be redacted by Presidio (which defaults to 'Alice' being a Person)
    # or accept the redaction.
    a = {"name": "NotAPerson"}
    b = {"parent": a}
    a["child"] = b

    # a -> b -> a

    scrubbed_a = scrub_pii_recursive(a)

    # Check structure logic, not PII logic here
    assert scrubbed_a["child"]["parent"] is scrubbed_a

def test_circular_reference_list():
    """Test handling of circular references in list."""
    a = []
    b = [a]
    a.append(b)

    # a -> b -> a

    scrubbed_a = scrub_pii_recursive(a)

    assert len(scrubbed_a) == 1
    assert len(scrubbed_a[0]) == 1
    assert scrubbed_a[0][0] is scrubbed_a

def test_shared_object_diamond():
    """Test handling of shared objects (diamond pattern)."""
    shared = {"info": "shared"}
    root = {"left": shared, "right": shared}

    scrubbed_root = scrub_pii_recursive(root)

    assert scrubbed_root["left"] == {"info": "shared"}
    assert scrubbed_root["right"] == {"info": "shared"}
    # Verify it's the SAME object instance in result
    assert scrubbed_root["left"] is scrubbed_root["right"]

def test_list_of_primitives():
    """Test list containing primitives."""
    data = [1, 2, 3, True, None]
    scrubbed = scrub_pii_recursive(data)
    assert scrubbed == [1, 2, 3, True, None]

def test_dict_primitives():
    """Test dict containing primitives."""
    data = {"a": 1, "b": True}
    scrubbed = scrub_pii_recursive(data)
    assert scrubbed == {"a": 1, "b": True}

def test_tuple_conversion():
    """Test tuple conversion and preservation."""
    data = (1, "sensitive")

    scrubbed = scrub_pii_recursive(data)
    assert isinstance(scrubbed, tuple)
    assert scrubbed == (1, "sensitive")

def test_nested_tuple_conversion():
    """Test nested tuples are converted/preserved (implementation converts to lists internally)."""
    data = {"key": (1, 2)}
    scrubbed = scrub_pii_recursive(data)

    # Implementation details: nested tuples are converted to lists in the iterative process
    # and NOT converted back (only root is converted back).
    # So we expect list here based on current implementation.
    assert isinstance(scrubbed["key"], list)
    assert scrubbed["key"] == [1, 2]

def test_scrub_pii_payload_value_error_too_large():
    """Test error handling for large payload raising ValueError."""
    # Ensure analyzer is initialized
    analyzer_instance = PIIAnalyzer().get_analyzer()
    assert analyzer_instance is not None

    # Patch the analyze method of the singleton instance's analyzer
    with patch.object(analyzer_instance, 'analyze', side_effect=ValueError("[E088] Text of length 2000000 exceeds maximum")):
        result = scrub_pii_payload("A very large string")
        assert result == "<REDACTED: PAYLOAD TOO LARGE FOR PII ANALYSIS>"

def test_scrub_pii_payload_unexpected_error():
    """Test error handling for unexpected exceptions."""
    # Ensure analyzer is initialized
    analyzer_instance = PIIAnalyzer().get_analyzer()

    # Patch the analyze method of the singleton instance's analyzer
    with patch.object(analyzer_instance, 'analyze', side_effect=Exception("Boom")):
        with pytest.raises(Exception, match="Boom"):
            scrub_pii_payload("test")
