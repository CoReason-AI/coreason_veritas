from typing import Any

from coreason_veritas.sanitizer import scrub_pii_recursive


def test_sanitizer_deep_recursion() -> None:
    # Create a deeply nested dict
    depth = 50
    data: dict[str, Any] = {}
    current = data
    for _ in range(depth):
        current["nested"] = {}
        current = current["nested"]

    # Add a sensitive key at the bottom
    current["token"] = "secret"

    scrubbed = scrub_pii_recursive(data)

    check = scrubbed
    for _ in range(depth):
        check = check["nested"]

    assert check["token"] == "***MASKED***"


def test_sanitizer_complex_cycle() -> None:
    a: dict[str, Any] = {"name": "a"}
    b: dict[str, Any] = {"name": "b"}
    c: dict[str, Any] = {"name": "c"}

    a["next"] = b
    b["next"] = c
    c["next"] = a

    # Add sensitive info
    b["secret_key"] = "hidden"

    scrubbed = scrub_pii_recursive(a)

    # Check structure
    assert scrubbed["name"] == "a"
    assert scrubbed["next"]["name"] == "b"
    assert scrubbed["next"]["next"]["name"] == "c"

    # Check cycle resolution (should reference back to start object or similar structure)
    # The memoization handles this. The object identity might change, but structure matches.
    assert scrubbed["next"]["next"]["next"] is scrubbed

    # Check masking
    assert scrubbed["next"]["secret_key"] == "***MASKED***"


def test_sanitizer_non_string_keys() -> None:
    data = {123: "val", (1, 2): "val", None: "val", "token": "masked"}

    scrubbed = scrub_pii_recursive(data)
    assert scrubbed[123] == "val"
    assert scrubbed[(1, 2)] == "val"
    assert scrubbed[None] == "val"
    assert scrubbed["token"] == "***MASKED***"


def test_sanitizer_truncation_boundary() -> None:
    # Exactly 256
    s256 = "x" * 256
    # 257
    s257 = "x" * 257

    data = {"payload_exact": s256, "payload_over": s257}

    scrubbed = scrub_pii_recursive(data)

    assert scrubbed["payload_exact"] == s256
    assert len(scrubbed["payload_over"]) == 256 + len("... <TRUNCATED_ZERO_COPY>")
    assert scrubbed["payload_over"].startswith("x" * 256)


def test_sanitizer_case_insensitivity() -> None:
    data = {"ToKeN": "secret", "PASSword": "secret", "BoDy": "x" * 300}
    scrubbed = scrub_pii_recursive(data)

    assert scrubbed["ToKeN"] == "***MASKED***"
    assert scrubbed["PASSword"] == "***MASKED***"
    assert "TRUNCATED_ZERO_COPY" in scrubbed["BoDy"]


def test_sanitizer_unusual_types() -> None:
    class CustomObj:
        def __repr__(self) -> str:
            return "CustomObj"

    obj = CustomObj()
    s_set = {1, 2}

    data = {"obj": obj, "set": s_set, "token": "secret"}

    scrubbed = scrub_pii_recursive(data)

    assert scrubbed["obj"] is obj
    assert scrubbed["set"] is s_set
    assert scrubbed["token"] == "***MASKED***"
