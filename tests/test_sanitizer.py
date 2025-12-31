# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import importlib
import sys
from types import ModuleType
from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

# Sample text with PII
SAMPLE_TEXT_CLEAN = "This is a safe string."
SAMPLE_TEXT_PII = "My email is gowtham@coreason.ai and phone is 555-0199."


@pytest.fixture  # type: ignore[misc]
def reset_sanitizer_module() -> Generator[ModuleType, None, None]:
    """
    Fixture to reload the sanitizer module to ensure fresh state for globals/singletons.
    """
    if "coreason_veritas.sanitizer" in sys.modules:
        importlib.reload(sys.modules["coreason_veritas.sanitizer"])
    else:
        import coreason_veritas.sanitizer

    yield sys.modules["coreason_veritas.sanitizer"]


@pytest.fixture  # type: ignore[misc]
def mock_analyzer_engine() -> Generator[MagicMock, None, None]:
    with patch("coreason_veritas.sanitizer.AnalyzerEngine") as mock:
        engine_instance = mock.return_value

        # Mock analyze method
        def analyze_side_effect(text: str, entities: Any, language: str) -> list[MagicMock]:
            results = []
            if "gowtham@coreason.ai" in text:
                # Mock email result
                email_res = MagicMock()
                email_res.entity_type = "EMAIL_ADDRESS"
                email_res.start = text.find("gowtham@coreason.ai")
                email_res.end = email_res.start + len("gowtham@coreason.ai")
                results.append(email_res)
            if "555-0199" in text:
                # Mock phone result
                phone_res = MagicMock()
                phone_res.entity_type = "PHONE_NUMBER"
                phone_res.start = text.find("555-0199")
                phone_res.end = phone_res.start + len("555-0199")
                results.append(phone_res)
            return results

        engine_instance.analyze.side_effect = analyze_side_effect
        yield mock


@pytest.fixture  # type: ignore[misc]
def clear_singleton() -> Generator[None, None, None]:
    """Ensure PIIAnalyzer singleton is cleared before and after test."""
    from coreason_veritas.sanitizer import PIIAnalyzer

    PIIAnalyzer._instance = None
    PIIAnalyzer._analyzer = None
    yield
    PIIAnalyzer._instance = None
    PIIAnalyzer._analyzer = None


def test_pii_analyzer_singleton(
    reset_sanitizer_module: ModuleType, clear_singleton: None, mock_analyzer_engine: MagicMock
) -> None:
    sanitizer = reset_sanitizer_module
    PIIAnalyzer = sanitizer.PIIAnalyzer

    a1 = PIIAnalyzer()
    a2 = PIIAnalyzer()
    assert a1 is a2

    # Check that AnalyzerEngine was initialized
    assert a1.get_analyzer() is not None
    mock_analyzer_engine.assert_called()


def test_scrub_pii_payload_none(reset_sanitizer_module: ModuleType) -> None:
    assert reset_sanitizer_module.scrub_pii_payload(None) is None


def test_scrub_pii_payload_clean(
    reset_sanitizer_module: ModuleType, clear_singleton: None, mock_analyzer_engine: MagicMock
) -> None:
    assert reset_sanitizer_module.scrub_pii_payload(SAMPLE_TEXT_CLEAN) == SAMPLE_TEXT_CLEAN


def test_scrub_pii_payload_with_pii(
    reset_sanitizer_module: ModuleType, clear_singleton: None, mock_analyzer_engine: MagicMock
) -> None:
    sanitizer = reset_sanitizer_module

    result = sanitizer.scrub_pii_payload(SAMPLE_TEXT_PII)
    assert "<REDACTED EMAIL_ADDRESS>" in result
    assert "<REDACTED PHONE_NUMBER>" in result
    assert "gowtham@coreason.ai" not in result
    assert "555-0199" not in result


def test_scrub_pii_recursive_dict(
    reset_sanitizer_module: ModuleType, clear_singleton: None, mock_analyzer_engine: MagicMock
) -> None:
    sanitizer = reset_sanitizer_module
    data = {"safe": SAMPLE_TEXT_CLEAN, "sensitive": SAMPLE_TEXT_PII, "nested": {"deep_sensitive": SAMPLE_TEXT_PII}}
    result = sanitizer.scrub_pii_recursive(data)

    assert result["safe"] == SAMPLE_TEXT_CLEAN
    assert "<REDACTED EMAIL_ADDRESS>" in result["sensitive"]
    assert "<REDACTED EMAIL_ADDRESS>" in result["nested"]["deep_sensitive"]


def test_scrub_pii_recursive_list(
    reset_sanitizer_module: ModuleType, clear_singleton: None, mock_analyzer_engine: MagicMock
) -> None:
    sanitizer = reset_sanitizer_module
    data = [SAMPLE_TEXT_CLEAN, SAMPLE_TEXT_PII, [SAMPLE_TEXT_PII]]
    result = sanitizer.scrub_pii_recursive(data)

    assert result[0] == SAMPLE_TEXT_CLEAN
    assert "<REDACTED EMAIL_ADDRESS>" in result[1]
    assert "<REDACTED EMAIL_ADDRESS>" in result[2][0]


def test_scrub_pii_recursive_tuple(
    reset_sanitizer_module: ModuleType, clear_singleton: None, mock_analyzer_engine: MagicMock
) -> None:
    sanitizer = reset_sanitizer_module
    data = (SAMPLE_TEXT_CLEAN, SAMPLE_TEXT_PII, (SAMPLE_TEXT_PII,))
    result = sanitizer.scrub_pii_recursive(data)

    assert isinstance(result, tuple)
    assert result[0] == SAMPLE_TEXT_CLEAN
    assert "<REDACTED EMAIL_ADDRESS>" in result[1]
    # The iterative implementation currently converts nested tuples to lists
    # This matches the coreason-adlc-api behavior we are porting
    assert isinstance(result[2], list)
    assert "<REDACTED EMAIL_ADDRESS>" in result[2][0]


def test_scrub_pii_large_payload(reset_sanitizer_module: ModuleType, clear_singleton: None) -> None:
    sanitizer = reset_sanitizer_module
    PIIAnalyzer = sanitizer.PIIAnalyzer

    with patch.object(PIIAnalyzer, "get_analyzer") as mock_get:
        mock_engine = MagicMock()
        mock_engine.analyze.side_effect = ValueError("exceeds maximum length")
        mock_get.return_value = mock_engine

        result = sanitizer.scrub_pii_payload("Very long text...")
        assert result == "<REDACTED: PAYLOAD TOO LARGE FOR PII ANALYSIS>"


def test_scrub_pii_missing_dependency(reset_sanitizer_module: ModuleType, clear_singleton: None) -> None:
    # We need to simulate _HAS_PRESIDIO = False
    # Since we cannot easily unload presidio, we patch the module attribute
    sanitizer = reset_sanitizer_module

    with patch.object(sanitizer, "_HAS_PRESIDIO", False):
        # When _HAS_PRESIDIO is False, get_analyzer returns None
        # And scrub_pii_payload should return original text (warning mode)

        result = sanitizer.scrub_pii_payload(SAMPLE_TEXT_PII)
        assert result == SAMPLE_TEXT_PII


def test_scrub_pii_analyzer_init_failure(reset_sanitizer_module: ModuleType, clear_singleton: None) -> None:
    sanitizer = reset_sanitizer_module

    # We patch AnalyzerEngine to raise exception during init
    with patch("coreason_veritas.sanitizer.AnalyzerEngine", side_effect=Exception("Init failed")):
        # Ensure _HAS_PRESIDIO is True
        with patch.object(sanitizer, "_HAS_PRESIDIO", True):
            # scrub_pii_payload calls PIIAnalyzer().get_analyzer()
            # get_analyzer calls _initialize
            # _initialize fails, sets _analyzer to None
            # get_analyzer returns None
            # scrub_pii_payload sees None analyzer but _HAS_PRESIDIO is True -> returns error string

            result = sanitizer.scrub_pii_payload(SAMPLE_TEXT_PII)
            assert result == "<REDACTED: PII ANALYZER MISSING>"


def test_scrub_pii_unexpected_error(reset_sanitizer_module: ModuleType, clear_singleton: None) -> None:
    sanitizer = reset_sanitizer_module
    PIIAnalyzer = sanitizer.PIIAnalyzer

    with patch.object(PIIAnalyzer, "get_analyzer") as mock_get:
        # Return a valid analyzer
        mock_engine = MagicMock()
        # But analyze raises generic exception
        mock_engine.analyze.side_effect = Exception("Boom")
        mock_get.return_value = mock_engine

        with pytest.raises(Exception, match="Boom"):
            sanitizer.scrub_pii_payload("text")


def test_scrub_pii_recursive_mixed_types(
    reset_sanitizer_module: ModuleType, clear_singleton: None, mock_analyzer_engine: MagicMock
) -> None:
    sanitizer = reset_sanitizer_module
    # Test handling of non-container, non-string types
    data = {"int": 1, "float": 2.5, "bool": True, "none": None}
    result = sanitizer.scrub_pii_recursive(data)
    assert result == data


def test_initialize_fail_open_logging(reset_sanitizer_module: ModuleType, clear_singleton: None) -> None:
    """Test that if presidio is missing, we log a warning during init."""
    sanitizer = reset_sanitizer_module

    with patch.object(sanitizer, "_HAS_PRESIDIO", False):
        with patch("coreason_veritas.sanitizer.logger") as mock_logger:
            analyzer = sanitizer.PIIAnalyzer()
            analyzer._initialize()
            mock_logger.warning.assert_called_with("presidio-analyzer not installed. PII scrubbing will be disabled.")


def test_initialize_exception_logging(reset_sanitizer_module: ModuleType, clear_singleton: None) -> None:
    """Test that if init raises exception, we log a warning."""
    sanitizer = reset_sanitizer_module

    with patch.object(sanitizer, "_HAS_PRESIDIO", True):
        with patch("coreason_veritas.sanitizer.AnalyzerEngine", side_effect=Exception("Fail")):
            with patch("coreason_veritas.sanitizer.logger") as mock_logger:
                analyzer = sanitizer.PIIAnalyzer()
                analyzer._initialize()
                # Check for partial match string
                found = False
                for call in mock_logger.warning.call_args_list:
                    if "Failed to initialize Presidio Analyzer" in call[0][0]:
                        found = True
                assert found
