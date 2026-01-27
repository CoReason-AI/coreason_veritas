# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import threading
from typing import Any, Optional

from loguru import logger

try:
    from presidio_analyzer import AnalyzerEngine

    _HAS_PRESIDIO = True
except (ImportError, Exception) as e:  # pragma: no cover
    logger.warning(f"Failed to import presidio_analyzer: {e}")
    _HAS_PRESIDIO = False


class PIIAnalyzer:
    """
    Singleton class to handle PII analysis using Presidio.
    Ensures the model is loaded only once.
    """

    _instance: Optional["PIIAnalyzer"] = None
    _analyzer: Optional["AnalyzerEngine"] = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "PIIAnalyzer":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(PIIAnalyzer, cls).__new__(cls)
        return cls._instance

    def get_analyzer(self) -> Optional["AnalyzerEngine"]:
        """
        Lazy initialization of the analyzer.
        """
        if self._analyzer is None:
            with self._lock:
                if self._analyzer is None:
                    self._initialize()
        return self._analyzer

    def _initialize(self) -> None:
        if not _HAS_PRESIDIO:
            logger.warning("presidio-analyzer not installed. PII scrubbing will be disabled.")
            return

        try:
            logger.info("Initializing Presidio Analyzer Engine...")
            self._analyzer = AnalyzerEngine()
            logger.info("Presidio Analyzer Initialized.")
        except Exception as e:
            logger.warning(f"Failed to initialize Presidio Analyzer: {e}")
            self._analyzer = None


def scrub_pii_payload(text: str | None) -> str | None:
    """
    Scrub PII from a string.
    Scans for ["PHONE_NUMBER", "EMAIL_ADDRESS", "PERSON"] and replaces with <REDACTED {ENTITY_TYPE}>.
    """
    if text is None:
        return None

    analyzer = PIIAnalyzer().get_analyzer()
    if analyzer is None:
        if not _HAS_PRESIDIO:
            # If dependency is missing, we might return original text or error.
            # API behavior was fail-safe/warning.
            # Given prompt instructions: "Handle ImportError gracefully (log warning if missing...)"
            # If called and missing, we'll return text but log.
            return text
        return "<REDACTED: PII ANALYZER MISSING>"

    try:
        results = analyzer.analyze(text=text, entities=["PHONE_NUMBER", "EMAIL_ADDRESS", "PERSON"], language="en")

        # Sort results by start index in descending order to perform replacement correctly
        results.sort(key=lambda x: x.start, reverse=True)

        scrubbed_text = list(text)

        for result in results:
            start = result.start
            end = result.end
            entity_type = result.entity_type
            replacement = f"<REDACTED {entity_type}>"
            scrubbed_text[start:end] = replacement

        return "".join(scrubbed_text)

    except ValueError as e:  # pragma: no cover
        # Spacy raises ValueError for text > 1,000,000 chars
        if "exceeds maximum" in str(e):  # pragma: no cover
            logger.warning(f"PII Scrubbing skipped due to excessive length: {len(text)} chars.")
            return "<REDACTED: PAYLOAD TOO LARGE FOR PII ANALYSIS>"
        logger.error(f"Error during PII scrubbing: {e}")
        raise e  # pragma: no cover
    except Exception as e:  # pragma: no cover
        logger.error(f"Unexpected error during PII scrubbing: {e}")  # pragma: no cover
        raise e  # pragma: no cover


def scrub_pii_recursive(data: Any) -> Any:
    """
    Recursively scrub PII from data structures (dict, list) using an iterative stack-based approach.
    Tracks visited objects to handle circular references.
    """
    if isinstance(data, str):
        return scrub_pii_payload(data)

    if not isinstance(data, (dict, list, tuple)):
        return data

    # Memoization for cycle detection
    # Maps id(source_obj) -> new_obj
    memo = {}

    # Helper to create shallow copy
    def _shallow_copy(obj: Any) -> Any:
        if isinstance(obj, dict):
            return obj.copy()
        if isinstance(obj, tuple):
            return list(obj)
        return obj[:]

    root_is_tuple = isinstance(data, tuple)
    new_data = _shallow_copy(data)
    memo[id(data)] = new_data

    # Stack contains (target_container, source_container)
    stack = [(new_data, data)]

    while stack:
        target, source = stack.pop()

        iterator: Any
        if isinstance(source, dict):
            iterator = source.items()
        elif isinstance(source, (list, tuple)):
            iterator = enumerate(source)
        else:
            continue  # pragma: no cover

        for k, v in iterator:
            try:
                # 1. Zero-Copy Rules (Only for dict keys)
                if isinstance(source, dict):
                    key_str = str(k).lower()

                    # Masking Rule
                    if any(s in key_str for s in ["token", "auth", "secret", "key", "password"]):
                        target[k] = "***MASKED***"
                        continue

                    # Truncation Rule
                    if any(s in key_str for s in ["content", "body", "text", "payload", "data"]):
                        val_str = str(v)
                        if len(val_str) > 256:
                            target[k] = f"{val_str[:256]}... <TRUNCATED_ZERO_COPY>"
                            continue

                if isinstance(v, str):
                    target[k] = scrub_pii_payload(v)
                elif isinstance(v, (dict, list, tuple)):
                    # Check cycle
                    if id(v) in memo:
                        target[k] = memo[id(v)]
                    else:
                        new_sub = _shallow_copy(v)
                        memo[id(v)] = new_sub
                        target[k] = new_sub
                        stack.append((new_sub, v))
                else:
                    target[k] = v
            except Exception as e:
                logger.warning(f"Sanitizer Error on key {k}: {e}")
                target[k] = "<UNREADABLE_VALUE>"

    if root_is_tuple:
        return tuple(new_data)

    return new_data
