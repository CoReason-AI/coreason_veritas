from typing import Any

from coreason_veritas.sanitizer import scrub_pii_recursive


def test_sanitizer_masking() -> None:
    data = {
        "user_token": "secret_token_123",
        "auth_header": "Bearer xyz",
        "api_key": "12345",
        "my_password": "supersecretpassword",
        "secret_stuff": "hidden",
    }
    scrubbed = scrub_pii_recursive(data)
    assert scrubbed["user_token"] == "***MASKED***"
    assert scrubbed["auth_header"] == "***MASKED***"
    assert scrubbed["api_key"] == "***MASKED***"
    assert scrubbed["my_password"] == "***MASKED***"
    assert scrubbed["secret_stuff"] == "***MASKED***"


def test_sanitizer_truncation() -> None:
    long_string = "a" * 300
    data = {"body": long_string, "payload_data": long_string, "text_content": long_string, "short_text": "short"}
    scrubbed = scrub_pii_recursive(data)
    assert len(scrubbed["body"]) == 256 + len("... <TRUNCATED_ZERO_COPY>")
    assert "TRUNCATED_ZERO_COPY" in scrubbed["body"]
    assert scrubbed["short_text"] == "short"


def test_sanitizer_mixed_recursion() -> None:
    long_string = "b" * 300
    data = {
        "meta": {"auth": "secret", "info": {"payload": long_string}},
        "list": [{"token": "123"}, {"body": long_string}],
    }
    scrubbed = scrub_pii_recursive(data)
    assert scrubbed["meta"]["auth"] == "***MASKED***"
    assert "TRUNCATED_ZERO_COPY" in scrubbed["meta"]["info"]["payload"]
    assert scrubbed["list"][0]["token"] == "***MASKED***"
    assert "TRUNCATED_ZERO_COPY" in scrubbed["list"][1]["body"]


def test_sanitizer_tuple() -> None:
    data = ({"token": "123"},)
    scrubbed = scrub_pii_recursive(data)
    assert isinstance(scrubbed, tuple)
    assert scrubbed[0]["token"] == "***MASKED***"


def test_sanitizer_error_handling(caplog: Any) -> None:
    class BrokenStr:
        def __str__(self) -> str:
            raise ValueError("I am broken")

    data = {"body": BrokenStr()}
    scrubbed = scrub_pii_recursive(data)
    assert scrubbed["body"] == "<UNREADABLE_VALUE>"
