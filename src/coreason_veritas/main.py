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
from typing import Any, AsyncGenerator, Dict

import httpx
import uvicorn
from fastapi import FastAPI, Request
from loguru import logger
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from coreason_veritas.anchor import DeterminismInterceptor


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manage the lifecycle of the FastAPI application.
    Initializes a shared HTTP client on startup and closes it on shutdown.
    """
    app.state.http_client = httpx.AsyncClient()
    yield
    await app.state.http_client.aclose()


app = FastAPI(title="CoReason Veritas Gateway", lifespan=lifespan)

# Configuration from Environment Variables
LLM_PROVIDER_URL = os.environ.get("LLM_PROVIDER_URL", "https://api.openai.com/v1/chat/completions")


@app.post("/v1/chat/completions")  # type: ignore[misc]
async def governed_inference(request: Request) -> Dict[str, Any]:
    """
    Gateway Proxy endpoint that enforces determinism and forwards requests to the LLM provider.
    """
    # 1. Parse Request
    raw_body = await request.json()
    headers = dict(request.headers)

    # 2. Anchor Check: Enforce Determinism
    governed_body = DeterminismInterceptor.enforce_config(raw_body)

    # 3. Proxy: Forward to LLM Provider
    # Define Allowlist for headers
    # We normalize to lowercase for checking
    allowed_headers = {
        "authorization",
        "x-api-key",
        "traceparent",
        "tracestate",
        "content-type",
        "accept",
        "user-agent",
    }

    proxy_headers = {}
    for key, value in headers.items():
        if key.lower() in allowed_headers:
            proxy_headers[key] = value

    client: httpx.AsyncClient = request.app.state.http_client

    async def _forward_request(payload: Dict[str, Any]) -> httpx.Response:
        return await client.post(
            LLM_PROVIDER_URL,
            json=payload,
            headers=proxy_headers,
            timeout=60.0,
        )

    try:
        # Attempt 1: Strict Mode (with seed=42 injected by enforce_config)
        resp = await _forward_request(governed_body)

        # If the provider rejects the seed parameter (e.g. 400 Bad Request), retry without it
        # Note: We assume 400 is the likely code for "Unknown parameter: seed"
        if resp.status_code == 400 and "seed" in governed_body:
            error_content = resp.text.lower()
            if "seed" in error_content or "parameter" in error_content:
                logger.warning("Provider rejected strict configuration. Retrying without 'seed' parameter.")

                # Retry without seed
                fallback_body = governed_body.copy()
                fallback_body.pop("seed", None)
                resp = await _forward_request(fallback_body)

    except httpx.RequestError as exc:
        # Network errors, etc.
        logger.error(f"Proxy request failed: {exc}")
        raise

    # We return the JSON response from the provider
    return resp.json()  # type: ignore[no-any-return]


# Instrument the app
FastAPIInstrumentor.instrument_app(app)


def run_server() -> None:
    """Entry point for the veritas-proxy command. Configured via ENV."""
    host = os.environ.get("VERITAS_HOST", "0.0.0.0")
    port = int(os.environ.get("VERITAS_PORT", "8080"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()  # pragma: no cover
