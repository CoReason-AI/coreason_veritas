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
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from loguru import logger
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from starlette.background import BackgroundTask

import coreason_veritas
from coreason_veritas.anchor import DeterminismInterceptor
from coreason_veritas.proxy import ProxyService


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manage the lifecycle of the FastAPI application.
    Initializes a shared HTTP client on startup and closes it on shutdown.
    """
    # Initialize the Veritas Engine (Auditor Handshake)
    coreason_veritas.initialize()

    app.state.http_client = httpx.AsyncClient()
    yield
    await app.state.http_client.aclose()


app = FastAPI(title="CoReason Veritas Gateway", lifespan=lifespan)

# Configuration from Environment Variables
LLM_PROVIDER_URL = os.environ.get("LLM_PROVIDER_URL", "https://api.openai.com/v1/chat/completions")


@app.post("/v1/chat/completions")  # type: ignore[misc]
async def governed_inference(request: Request) -> StreamingResponse:
    """
    Gateway Proxy endpoint that enforces determinism and forwards requests to the LLM provider.
    Supports streaming responses.
    """
    # 1. Parse Request (Non-destructive read for body inspection)
    # Note: request.json() consumes the stream. To proxy the modified body, we need to rebuild the request?
    # ProxyService.forward_request takes the original request body.
    # But we want to send the *governed* body.

    # We need to construct a new request with the governed body, or pass the governed body to the proxy service.
    # The current ProxyService implementation reads `request.body()`.
    # But we modified the body via DeterminismInterceptor.

    raw_body = await request.json()

    # 2. Anchor Check: Enforce Determinism
    governed_body = DeterminismInterceptor.enforce_config(raw_body)

    # 3. Proxy: Forward to LLM Provider
    client: httpx.AsyncClient = request.app.state.http_client
    proxy_service = ProxyService()

    return await proxy_service.forward_request(
        request=request,
        client=client,
        target_url=LLM_PROVIDER_URL,
        json_body=governed_body,
    )


# Instrument the app
FastAPIInstrumentor.instrument_app(app)


@logger.catch  # type: ignore[misc]
def run_server() -> None:
    """Entry point for the veritas-proxy command. Configured via ENV."""
    host = os.environ.get("VERITAS_HOST", "0.0.0.0")
    port = int(os.environ.get("VERITAS_PORT", "8080"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()  # pragma: no cover
