# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import Request
from coreason_veritas.proxy import ProxyService

@pytest.mark.asyncio
async def test_proxy_service_forward_request() -> None:
    """Test standard forwarding logic."""
    service = ProxyService()
    scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"host", b"example.com"), (b"custom", b"val")]
    }
    request = Request(scope)
    # Mock body
    request._body = b'{"a": 1}' # type: ignore

    client = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.aiter_bytes.return_value = AsyncMock()
    client.send.return_value = mock_response

    await service.forward_request(request, client, "http://target")

    # Verify build_request
    client.build_request.assert_called_once()
    kwargs = client.build_request.call_args.kwargs
    assert kwargs["method"] == "POST"
    assert kwargs["url"] == "http://target"
    assert kwargs["content"] == b'{"a": 1}'
    assert "host" not in kwargs["headers"]
    assert "custom" in kwargs["headers"]


@pytest.mark.asyncio
async def test_proxy_service_json_override() -> None:
    """Test forwarding with JSON body override (coverage for line 78)."""
    service = ProxyService()

    scope = {
        "type": "http",
        "method": "POST",
        "headers": [
            (b"content-type", b"application/json"),
            (b"host", b"example.com"),
            (b"custom", b"val")
        ]
    }
    request = Request(scope)

    client = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.aiter_bytes.return_value = AsyncMock()
    client.send.return_value = mock_response

    # Call with json_body
    await service.forward_request(request, client, "http://target", json_body={"overridden": True})

    # Check that headers passed to build_request do NOT have content-type
    # because json parameter in httpx sets it, and we shouldn't duplicate/conflict
    call_kwargs = client.build_request.call_args.kwargs
    headers = call_kwargs["headers"]
    assert "content-type" not in headers
    assert "custom" in headers
    assert call_kwargs["json"] == {"overridden": True}
    assert call_kwargs["content"] is None
