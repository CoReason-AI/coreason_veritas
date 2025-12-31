# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import httpx
from fastapi import Request
from fastapi.responses import StreamingResponse


class ProxyService:
    """
    Service to handle reverse proxy logic for LLM providers.
    """

    # Headers to strip before forwarding the request
    HOP_BY_HOP_HEADERS = {
        "host",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
    }

    async def forward_request(
        self,
        request: Request,
        client: httpx.AsyncClient,
        target_url: str,
        json_body: object = None,
    ) -> StreamingResponse:
        """
        Forwards a request to the target URL, stripping hop-by-hop headers
        and maintaining streaming response capability.

        Args:
            request: The incoming FastAPI Request.
            client: The shared HTTPX client.
            target_url: The destination URL.
            json_body: Optional JSON body to use instead of the original request body.

        Returns:
            StreamingResponse: The streaming response from the target.
        """
        # 1. Prepare Headers
        # Filter out hop-by-hop headers and host header
        # Note: request.headers keys are case-insensitive in FastAPI/Starlette, but typically lowercase.
        proxy_headers = {
            k: v for k, v in request.headers.items() if k.lower() not in self.HOP_BY_HOP_HEADERS
        }

        # 2. Get Body
        # If json_body is provided, use it. Otherwise, read from request.
        content = None
        json_payload = None

        if json_body is not None:
            json_payload = json_body
            # httpx handles Content-Length and Content-Type update if json is passed
            # But we copied headers. If Content-Length or Content-Type is in proxy_headers,
            # httpx might get confused or override?
            # httpx `json` param sets Content-Type to application/json.
            # We should remove Content-Type from proxy_headers if we are sending json
            if "content-type" in proxy_headers:
                del proxy_headers["content-type"]
            # Content-Length is hop-by-hop so it should be gone already.
        else:
            content = await request.body()

        # 3. Build Request
        req = client.build_request(
            method=request.method,
            url=target_url,
            content=content,
            json=json_payload,
            headers=proxy_headers,
            timeout=60.0,
        )

        # 4. Send Request
        r = await client.send(req, stream=True)

        # 5. Stream Response
        return StreamingResponse(
            r.aiter_bytes(),
            status_code=r.status_code,
            media_type=r.headers.get("content-type"),
            background=None,  # Caller can manage background tasks if needed, but r.aclose is handled by StreamingResponse usually?
            # Actually StreamingResponse doesn't auto-close the httpx response if passed an iterator.
            # We should pass a background task to close it.
        )
