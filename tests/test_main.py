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

import httpx
import pytest
from fastapi.testclient import TestClient

import coreason_veritas.main
from coreason_veritas.main import app, lifespan


@pytest.fixture  # type: ignore[misc]
def mock_httpx_client() -> Generator[AsyncMock, None, None]:
    """
    Mocks the httpx.AsyncClient that is instantiated during app startup (lifespan).
    This fixture must be active BEFORE the client fixture starts the app.
    """
    with patch("httpx.AsyncClient") as mock_cls:
        mock_instance = AsyncMock()
        mock_cls.return_value = mock_instance
        yield mock_instance


@pytest.fixture  # type: ignore[misc]
def client(mock_httpx_client: AsyncMock) -> Generator[TestClient, None, None]:
    """
    Fixture that returns a TestClient context manager to trigger lifespan events.
    Depends on mock_httpx_client to ensure the patch is active during startup.
    """
    with TestClient(app) as c:
        yield c


def test_governed_inference_determinism_enforcement(client: TestClient, mock_httpx_client: AsyncMock) -> None:
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


def test_governed_inference_configurable_upstream(client: TestClient, mock_httpx_client: AsyncMock) -> None:
    """
    Test that the upstream URL is configurable via environment variable.
    """
    # Mock environment variable
    custom_url = "https://custom-llm-provider.com/v1/chat"

    # We patch the attribute on the imported module object directly
    with patch.object(coreason_veritas.main, "LLM_PROVIDER_URL", custom_url):
        # Verify patch applied
        assert coreason_veritas.main.LLM_PROVIDER_URL == custom_url

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


def test_governed_inference_missing_auth_header(client: TestClient, mock_httpx_client: AsyncMock) -> None:
    """
    Test that the gateway works even if no Authorization header is present (public endpoint scenario).
    """
    mock_response = MagicMock()
    mock_response.json.return_value = {}
    mock_response.status_code = 200
    mock_httpx_client.post.return_value = mock_response

    client.post("/v1/chat/completions", json={"model": "test"})

    call_kwargs = mock_httpx_client.post.call_args.kwargs
    sent_headers = call_kwargs["headers"]
    assert "Authorization" not in sent_headers


def test_governed_inference_upstream_error(client: TestClient, mock_httpx_client: AsyncMock) -> None:
    """
    Test that the gateway propagates upstream errors (e.g. 500) correctly.
    """
    mock_response = MagicMock()
    mock_response.json.return_value = {"error": "Internal Server Error"}
    mock_response.status_code = 500
    mock_httpx_client.post.return_value = mock_response

    response = client.post("/v1/chat/completions", json={"model": "test"})

    # Check that we get the error body back
    assert response.json() == {"error": "Internal Server Error"}


def test_governed_inference_upstream_timeout(client: TestClient, mock_httpx_client: AsyncMock) -> None:
    """
    Test handling of upstream timeout.
    """
    mock_httpx_client.post.side_effect = httpx.ReadTimeout("Timeout")

    with pytest.raises(httpx.ReadTimeout):
        client.post("/v1/chat/completions", json={"model": "test"})


@pytest.mark.asyncio  # type: ignore[misc]
async def test_lifespan_initialization() -> None:
    """
    Verify that the lifespan context manager initializes and closes the http client.
    """
    with patch("httpx.AsyncClient") as mock_cls:
        mock_instance = AsyncMock()
        mock_cls.return_value = mock_instance

        async with lifespan(app):
            # Startup: Client created
            mock_cls.assert_called_once()
            assert app.state.http_client == mock_instance

        # Shutdown: Client closed
        mock_instance.aclose.assert_called_once()
