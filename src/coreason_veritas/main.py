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
from coreason_identity.models import UserContext
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from loguru import logger
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from starlette.background import BackgroundTask

import coreason_veritas
from coreason_veritas.anchor import DeterminismInterceptor


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
    # 1. Parse Request
    raw_body = await request.json()
    headers = dict(request.headers)

    # 2. Anchor Check: Enforce Determinism
    governed_body = DeterminismInterceptor.enforce_config(raw_body)

    # 3. Instantiate Gateway Context
    gateway_context = UserContext(
        user_id="veritas-gateway",
        email="gateway@coreason.ai",
        roles=["gateway"],
        metadata={"source": "api"},
    )
    logger.bind(gateway_user=gateway_context.user_id).debug("Gateway context active")

    # 4. Proxy: Forward to LLM Provider
    # We only forward essential headers like Authorization
    proxy_headers = {}
    if "authorization" in headers:
        proxy_headers["Authorization"] = headers["authorization"]

    client: httpx.AsyncClient = request.app.state.http_client

    req = client.build_request("POST", LLM_PROVIDER_URL, json=governed_body, headers=proxy_headers, timeout=60.0)
    r = await client.send(req, stream=True)

    return StreamingResponse(
        r.aiter_bytes(),
        status_code=r.status_code,
        media_type=r.headers.get("content-type"),
        background=BackgroundTask(r.aclose),
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
