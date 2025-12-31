# **Package Specification: coreason-veritas**

**Role:** Governance Middleware (The "Safety Anchor")
**Context:** GxP Enforcement & Immutable Audit
**Runtime:** Python 3.11+
**Dependencies:** `opentelemetry-api`, `opentelemetry-sdk`, `opentelemetry-exporter-otlp`, `fastapi`, `uvicorn`, `httpx`, `pydantic`, `cryptography`

## **1. Design Philosophy**

**coreason_veritas** is the non-negotiable governance layer of the CoReason platform. While the maco-api orchestrates *what* happens, veritas enforces *how* it happens.

It operates on the principle of **"Trust through Constraint"**:

1. **The Gatekeeper:** No code executes without a valid SRB (Scientific Review Board) signature.
2. **The Anchor:** No inference runs with stochastic parameters (Temperature is forced to 0.0).
3. **The Auditor:** No action occurs without a corresponding Immutable Execution Record (IER) span.

This package is designed to be injected as **Middleware** (for API routes) or **Decorators** (for service methods), acting as a "clean room" wrapper around execution logic.

## **2. Architecture & Modules**

The package is structured into three primary enforcement modules corresponding to its core responsibilities.

| Module | Component | Responsibility | Failure Mode |
| --- | --- | --- | --- |
| **gatekeeper** | **Asset Verifier** | Validates the cryptographic chain of custody for Agent Specs and Charters. | **Block (403):** "Untrusted Asset" |
| **anchor** | **Determinism Enforcer** | Intercepts LLM calls to override configuration (Temp=0, Seeds). | **Override (Warn):** Forces Config |
| **auditor** | **IER Logger** | Emits OpenTelemetry spans to WORM storage. | **Halt (500):** "Audit Failure" |

## **3. Module Specifications**

### **3.1 coreason_veritas.gatekeeper**

**Responsibility:** Supply Chain Security. Ensures that the "Recipe" or "Agent" being loaded has not been tampered with since the SRB signed it.

**Technical Requirements:**

* **Library:** `cryptography`
* **Algorithm:** SHA256 hashing with RSA-PSS padding (MGF1).
* **Canonicalization:** Uses **JCS (JSON Canonicalization Scheme - RFC 8785)** to ensure strict, byte-level consistency across platforms.
* **Replay Protection:** Enforces a mandatory `timestamp` field in the payload with a maximum skew of 5 minutes.
* **Interface:** Accepts payload (dict) and signature (hex string).
* **Failure:** Returns `False` on verification failure (Caller raises 403).

**Key Class:** `SignatureValidator`

```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import jcs

class SignatureValidator:
    def __init__(self, public_key_store: str = None):
        self.public_key_store = public_key_store

    def verify_asset(self, asset_payload: dict, signature: str, check_timestamp: bool = True) -> bool:
        """
        1. Checks 'timestamp' for replay protection (max 5m skew).
        2. Loads PEM public key.
        3. Canonicalizes asset_payload using jcs.canonicalize().
        4. Verifies signature against payload hash using padding.PSS.
        """
        pass

```

### **3.2 coreason_veritas.anchor**

**Responsibility:** Epistemic Integrity. Prevents "temperature creep" where developers might accidentally or intentionally enable stochastic behavior in GxP workflows.

**Technical Requirements:**

* **The Lobotomy Protocol:**
* `temperature` must be overwritten to `0.0`.
* `top_p` must be overwritten to `1.0`.
* `seed` must be injected as `42` (configurable via `VERITAS_SEED` environment variable).


* **Implementation:** Static method that returns a sanitized *copy* of the configuration dictionary.

**Key Class:** `DeterminismInterceptor`

```python
import os

class DeterminismInterceptor:
    @staticmethod
    def enforce_config(payload: dict) -> dict:
        """
        Forcibly sets: temp=0.0, top_p=1.0, seed=int(os.getenv("VERITAS_SEED", 42)).
        Returns sanitized copy of the payload.
        """
        pass

```

### **3.3 coreason_veritas.auditor**

**Responsibility:** Forensic Traceability. Manages the connection to the OpenTelemetry collector and enforces strict metadata schema for the Immutable Execution Record (IER).

**Technical Requirements:**

* **Protocol:** Must use `OTLPSpanExporter` and `OTLPLogExporter` (Proto over HTTP).
* **Logging:** Uses `loguru` configured with an OTel sink for unified logging.
* **Initialization:** Must emit a structured Log Record ("Handshake") on startup confirming `co.veritas.version`.
* **Span Attributes:** The `start_governed_span` method must enforce the following GxP attributes:
* `co.user_id`: Who initiated the action?
* `co.asset_id`: What code is running?
* `co.srb_sig`: Proof of validation.
* `co.determinism_verified`: Boolean flag from the Anchor.



**Key Class:** `IERLogger`

```python
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from loguru import logger

class IERLogger:
    def __init__(self):
        # Configure TracerProvider and LoggerProvider with OTLP exporters
        # Configure Loguru to use OTel Sink
        pass

    def emit_handshake(self, version: str):
        # Emits INFO log "Veritas Engine Initialized" via loguru
        logger.bind(co_veritas_version=version).info("Veritas Engine Initialized")

    def start_governed_span(self, name: str, attributes: dict):
        # Wraps tracer.start_as_current_span
        # Injects mandatory co.* attributes
        pass

```

## **4. The Veritas Wrapper (Usage Pattern)**

The primary interface for developers is the `@governed_execution` decorator, which bundles all three pillars into a single atomic wrapper.

**Implementation Logic:**

1. **Gatekeeper Check:** Validates `signature` and `asset_id`. If `SignatureValidator` returns False, execution halts (exception raised).
2. **Audit Start:** `IERLogger` starts a span with the verified asset ID.
3. **Anchor Enforcement:** The payload/config is sanitized via `DeterminismInterceptor` before logic execution.

**Usage Example:**

```python
from coreason_veritas import governed_execution

@governed_execution(
    asset_id_arg="spec_id",
    signature_arg="signature",
    user_id_arg="user_id",
    config_arg="config",  # Optional
    allow_unsigned=False  # Set to True for Draft Mode (bypasses signature check)
)
async def execute_agent_logic(spec_id: str, signature: str, user_id: str, config: dict):
    # 1. Gatekeeper runs first. If signature fails (and not draft mode), this code is UNREACHABLE.
    # 2. Auditor starts the Span.
    # 3. Anchor ensures determinism (sanitizing 'config').
    ...

```

## **5. Integration & Deployment**

### **Deployment Mode A: Library Injection**

* **Integration:** Used in `services.project_lock` and `integrations.asset_registry`.
* **Lifecycle:** Requires explicit initialization via `coreason_veritas.initialize()` to ensure the audit handshake is recorded on process start.

### **Deployment Mode B: Gateway Proxy**

* **Module:** `src/coreason_veritas/main.py`
* **Framework:** FastAPI + Uvicorn.
* **Behavior:**
* Exposes `POST /v1/chat/completions`.
* **Anchor:** Intercepts request -> Sanitizes config (Temp=0).
* **Proxy:** Forwards to LLM Provider -> Returns streaming response.


* **Configuration:** Reads `VERITAS_HOST` and `VERITAS_PORT` from environment variables.

Example scripts:
1. src/coreason_veritas/anchor.py
This module acts as the "Determinism Enforcer".

class DeterminismInterceptor:
    """ANCHOR: Forces Epistemic Integrity by ensuring deterministic LLM calls."""

    @staticmethod
    def enforce_config(payload: dict) -> dict:
        """The 'Lobotomy Protocol': Forcibly sets temp=0.0 and seed=42 (or ENV)."""
        sanitized = payload.copy()
        sanitized["temperature"] = 0.0
        sanitized["seed"] = int(os.getenv("VERITAS_SEED", 42))
        sanitized["top_p"] = 1.0
        return sanitized

2. src/coreason_veritas/gatekeeper.py
This module acts as the "Supply Chain Security" layer.
import json
import jcs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timezone

class SignatureValidator:
    """GATEKEEPER: Validates cryptographic signatures for Agent Specs."""

    def __init__(self, public_key_pem: str = None):
        self.public_key_pem = public_key_pem

    def verify_asset(self, payload: dict, signature_hex: str, check_timestamp: bool = True) -> bool:
        """Verifies if the asset payload matches the provided SRB signature with replay protection."""
        if not signature_hex or not self.public_key_pem:
            return False

        # Replay Protection (Example simplified)
        if check_timestamp:
            ts_str = payload.get("timestamp")
            # ... logic to check ts_str against datetime.now() with 5m skew ...

        try:
            public_key = serialization.load_pem_public_key(self.public_key_pem.encode())
            # Use JCS for canonicalization
            canonical_payload = jcs.canonicalize(payload)
            public_key.verify(
                bytes.fromhex(signature_hex),
                canonical_payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


3. src/coreason_veritas/main.py
The IP and Port are now pulled from environment variables. If they aren't set, it defaults to standard localhost, keeping the code clean.


import os
from contextlib import asynccontextmanager
import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from .anchor import DeterminismInterceptor
import coreason_veritas

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize Veritas Engine Handshake
    coreason_veritas.initialize()

    app.state.http_client = httpx.AsyncClient()
    yield
    await app.state.http_client.aclose()

app = FastAPI(title="CoReason Veritas Gateway", lifespan=lifespan)
LLM_PROVIDER_URL = os.environ.get("LLM_PROVIDER_URL", "https://api.openai.com/v1/chat/completions")

@app.post("/v1/chat/completions")
async def governed_inference(request: Request):
    # Logic uses the internal package modules
    raw_body = await request.json()
    headers = dict(request.headers)

    # Anchor Check
    governed_body = DeterminismInterceptor.enforce_config(raw_body)

    client = request.app.state.http_client
    # Forward essential headers
    proxy_headers = {}
    if "authorization" in headers:
        proxy_headers["Authorization"] = headers["authorization"]

    req = client.build_request("POST", LLM_PROVIDER_URL, json=governed_body, headers=proxy_headers)
    r = await client.send(req, stream=True)

    return StreamingResponse(
        r.aiter_bytes(),
        status_code=r.status_code,
        media_type=r.headers.get("content-type")
    )

FastAPIInstrumentor.instrument_app(app)

def run_server():
    """Entry point for the veritas-proxy command. Configured via ENV."""
    # Pull config from environment, NOT hardcoded
    host = os.environ.get("VERITAS_HOST", "0.0.0.0")
    port = int(os.environ.get("VERITAS_PORT", "8080"))
    uvicorn.run(app, host=host, port=port)


4. src/coreason_veritas/__init__.py
Standardized entry point that initializes the auditor handshake.
from loguru import logger
from .auditor import IERLogger
from .gatekeeper import SignatureValidator
from .anchor import DeterminismInterceptor
from .wrapper import governed_execution

__version__ = "0.4.0"

def initialize():
    """Explicitly initializes the Veritas Engine and emits the handshake."""
    try:
        _auditor = IERLogger()
        _auditor.emit_handshake(__version__)
    except Exception as e:
        logger.error(f"MACO Audit Link Failed: {e}")

5.) src/coreason_veritas/auditor.py
This module handles the heavy lifting of connecting to the VM Vault. It is designed to be generic and environment-aware.

import os
import platform
from loguru import logger
from opentelemetry import trace, _logs
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter

class IERLogger:
    """Handles GxP-compliant Immutable Execution Records (IER) via OTel."""

    def __init__(self):
        # 1. Resource Attributes: Generic metadata for client portability
        resource = Resource.create({
            "service.name": os.environ.get("OTEL_SERVICE_NAME", "coreason-veritas"),
            "deployment.environment": os.environ.get("DEPLOYMENT_ENV", "local-vibe"),
            "host.name": platform.node()
        })

        # 2. Setup Tracing (for AI workflow logic)
        tp = TracerProvider(resource=resource)
        # Endpoint is pulled automatically from OTEL_EXPORTER_OTLP_ENDPOINT
        tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(tp)
        self.tracer = trace.get_tracer("veritas.audit")

        # 3. Setup Logging (for the Handshake and IER events)
        lp = LoggerProvider(resource=resource)
        _logs.set_logger_provider(lp)
        lp.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))

        # Configure Loguru to use OTel Sink (conceptual)
        # configure_logging()

    def emit_handshake(self, version: str):
        """Standardized GxP audit trail for package initialization."""
        logger.bind(
            co_veritas_version=version,
            co_governance_status="active"
        ).info("Veritas Engine Initialized")
