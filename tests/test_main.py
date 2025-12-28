# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import os
from typing import Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from coreason_veritas.main import app

client = TestClient(app)


@pytest.fixture  # type: ignore[misc]
def mock_httpx_client() -> Generator[AsyncMock, None, None]:
    with patch("httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance
        yield mock_instance


def test_governed_inference_determinism_enforcement(mock_httpx_client: AsyncMock) -> None:
    """
    Test that the gateway proxy enforces determinism (temperature=0.0, seed=42)
    even when the user requests otherwise.
    """
    # Setup mock response from upstream
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "id": "chatcmpl-123",
        "choices": [{"message": {"content": "Hello world"}}],
    }
    mock_response.status_code = 200
    mock_httpx_client.post.return_value = mock_response

    # User payload with "unsafe" parameters
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello"}],
        "temperature": 0.9,
        "top_p": 0.95,
        "seed": 12345,
    }

    response = client.post("/v1/chat/completions", json=payload, headers={"Authorization": "Bearer test-key"})

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "Hello world"

    # Verify what was sent to upstream
    mock_httpx_client.post.assert_called_once()
    call_kwargs = mock_httpx_client.post.call_args.kwargs
    sent_json = call_kwargs["json"]
    sent_headers = call_kwargs["headers"]

    # Assert Determinism Enforcement
    assert sent_json["temperature"] == 0.0
    assert sent_json["top_p"] == 1.0
    assert sent_json["seed"] == 42
    assert sent_json["model"] == "gpt-4"

    # Assert Headers
    assert sent_headers["Authorization"] == "Bearer test-key"


def test_governed_inference_configurable_upstream(mock_httpx_client: AsyncMock) -> None:
    """
    Test that the upstream URL is configurable via environment variable.
    """
    # Mock environment variable
    custom_url = "https://custom-llm-provider.com/v1/chat"

    # We must patch the constant imported in main.py because it's already bound at import time.
    with patch("coreason_veritas.main.LLM_PROVIDER_URL", custom_url):
        mock_response = MagicMock()
        mock_response.json.return_value = {}
        mock_response.status_code = 200
        mock_httpx_client.post.return_value = mock_response

        client.post("/v1/chat/completions", json={"model": "test"})

        # Verify URL
        args, _ = mock_httpx_client.post.call_args
        assert args[0] == custom_url


def test_run_server_configuration() -> None:
    """Test that run_server uses environment variables."""
    with patch("uvicorn.run") as mock_run:
        with patch.dict(os.environ, {"VERITAS_HOST": "127.0.0.1", "VERITAS_PORT": "9000"}):
            from coreason_veritas.main import run_server

            run_server()

            mock_run.assert_called_once()
            kwargs = mock_run.call_args.kwargs
            assert kwargs["host"] == "127.0.0.1"
            assert kwargs["port"] == 9000
