# **Package Specification: coreason-veritas**

**Role:** Governance Middleware (The "Safety Anchor")
**Context:** GxP Enforcement & Immutable Audit
**Runtime:** Python 3.11+
**Dependencies:** `opentelemetry-api`, `opentelemetry-sdk`, `opentelemetry-exporter-otlp`, `fastapi`, `uvicorn`, `httpx`, `pydantic`, `cryptography`, `jcs`, `presidio-analyzer`

## **1. Design Philosophy**

**coreason_veritas** is the non-negotiable governance layer of the CoReason platform. While the maco-api orchestrates *what* happens, veritas enforces *how* it happens.

It operates on the principle of **"Trust through Constraint"**:

1. **The Gatekeeper:** No code executes without a valid SRB (Scientific Review Board) signature.
2. **The Anchor:** No inference runs with stochastic parameters (Temperature is forced to 0.0).
3. **The Auditor:** No action occurs without a corresponding Immutable Execution Record (IER) span.
4. **The Sanitizer:** No sensitive data (PII) leaks into logs or external providers.

This package is designed to be injected as **Middleware** (for API routes) or **Decorators** (for service methods), acting as a "clean room" wrapper around execution logic.

## **2. Architecture & Modules**

The package is structured into four primary enforcement modules corresponding to its core responsibilities.

| Module | Component | Responsibility | Failure Mode |
| --- | --- | --- | --- |
| **gatekeeper** | **Asset Verifier** | Validates the cryptographic chain of custody for Agent Specs and Charters. | **Block (403):** "Untrusted Asset" |
| **anchor** | **Determinism Enforcer** | Intercepts LLM calls to override configuration (Temp=0, Seeds). | **Override (Warn):** Forces Config |
| **auditor** | **IER Logger** | Emits OpenTelemetry spans to WORM storage. | **Halt (500):** "Audit Failure" |
| **sanitizer** | **PII Redactor** | Scans and redacts sensitive information. | **Fail Open (Warn):** Returns original text if analyzer fails |

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
    def __init__(self, public_key_store: str):
        self.key_store = public_key_store

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

### **3.4 coreason_veritas.sanitizer**

**Responsibility:** Data Privacy. Scans and redacts Personally Identifiable Information (PII) from data structures and strings before they are logged or processed.

**Technical Requirements:**

* **Library:** `presidio-analyzer`
* **Entities:** Scans for `PHONE_NUMBER`, `EMAIL_ADDRESS`, `PERSON`.
* **Behavior:**
* Uses a Singleton `PIIAnalyzer` to manage the heavy NLP model.
* Provides `scrub_pii_payload` for strings.
* Provides `scrub_pii_recursive` for deep cleaning of JSON-like structures (dicts/lists), handling circular references.
* **Failure Mode:** Fail Open. If the analyzer fails or is missing, it logs a warning but returns the original data (to avoid breaking the application).


**Key Functions:** `scrub_pii_payload`, `scrub_pii_recursive`

```python
from presidio_analyzer import AnalyzerEngine

def scrub_pii_payload(text: str | None) -> str | None:
    """
    Scans text for PII entities and replaces them with <REDACTED {ENTITY_TYPE}>.
    """
    pass

def scrub_pii_recursive(data: Any) -> Any:
    """
    Recursively traverses dictionaries and lists to scrub PII from all string values.
    Handles circular references.
    """
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
    """
    Acts as a proxy/hook into the LLM Client configuration.
    Enforces the 'Lobotomy Protocol' for epistemic integrity.
    """

    @staticmethod
    def enforce_config(raw_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        The 'Lobotomy Protocol':
        1. Forcibly sets `temperature = 0.0`.
        2. Forcibly sets `top_p = 1.0`.
        3. Injects `seed = 42`.
        4. Logs a warning if the original config attempted to deviate.
        """
        sanitized = copy.deepcopy(raw_config)

        # Check for deviations to log warnings
        if sanitized.get("temperature") is not None and sanitized.get("temperature") != 0.0:
            logger.warning(f"DeterminismInterceptor: Overriding unsafe temperature {sanitized['temperature']} to 0.0")

        if sanitized.get("top_p") is not None and sanitized.get("top_p") != 1.0:
            logger.warning(f"DeterminismInterceptor: Overriding unsafe top_p {sanitized['top_p']} to 1.0")

        if sanitized.get("seed") is not None and sanitized.get("seed") != 42:
            logger.warning(f"DeterminismInterceptor: Overriding seed {sanitized['seed']} to 42")

        # Enforce values
        sanitized["temperature"] = 0.0
        sanitized["top_p"] = 1.0
        try:
            sanitized["seed"] = int(os.getenv("VERITAS_SEED", 42))
        except ValueError:
            logger.warning("VERITAS_SEED is not a valid integer. Falling back to default 42.")
            sanitized["seed"] = 42

        return sanitized

2. src/coreason_veritas/gatekeeper.py
This module acts as the "Supply Chain Security" layer.

class SignatureValidator:
    """
    Validates the cryptographic chain of custody for Agent Specs and Charters.
    """

    def __init__(self, public_key_store: str):
        """
        Initialize the validator with the public key store.

        Args:
            public_key_store: The SRB Public Key (PEM format string).
        """
        self.key_store = public_key_store
        # Pre-load the public key to improve performance on repeated verification calls
        try:
            self._public_key = serialization.load_pem_public_key(self.key_store.encode())
        except Exception as e:
            # We log but allow initialization; verification will fail later if key is invalid,
            # or we could raise here. Raising here is safer to fail fast.
            logger.error(f"Failed to load public key: {e}")
            raise ValueError(f"Invalid public key provided: {e}") from e

    def verify_asset(self, asset_payload: Dict[str, Any], signature: str, check_timestamp: bool = True) -> bool:
        """
        Verifies the `x-coreason-sig` header against the payload hash.
        """
        try:
            # 1. Replay Protection Check
            if check_timestamp:
                timestamp_str = asset_payload.get("timestamp")
                if not timestamp_str:
                    raise ValueError("Missing 'timestamp' in payload")

                try:
                    # ISO 8601 format expected
                    ts = datetime.fromisoformat(str(timestamp_str))
                    # Ensure timezone awareness (assuming UTC if not provided, or reject naive?)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                except ValueError as e:
                    raise ValueError(f"Invalid 'timestamp' format: {e}") from e

                now = datetime.now(timezone.utc)
                # Allow 5 minutes clock skew/latency
                if abs((now - ts).total_seconds()) > 300:
                    raise ValueError(f"Timestamp out of bounds (Replay Attack?): {ts} vs {now}")

            # 2. Cryptographic Verification
            # Use pre-loaded public key
            public_key = self._public_key

            # Canonicalize the asset_payload (JSON) to ensure consistent hashing
            canonical_payload = jcs.canonicalize(asset_payload)

            # Verify the signature
            # The spec example uses PSS padding with MGF1 and SHA256
            public_key.verify(
                bytes.fromhex(signature),
                canonical_payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            logger.info("Asset verification successful.")
            return True

        except (ValueError, TypeError, InvalidSignature) as e:
            logger.error(f"Asset verification failed: {e}")
            raise AssetTamperedError(f"Signature verification failed: {e}") from e


3. src/coreason_veritas/main.py
The IP and Port are now pulled from environment variables. If they aren't set, it defaults to standard localhost, keeping the code clean.


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

    # 3. Proxy: Forward to LLM Provider
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


4. src/coreason_veritas/__init__.py
Standardized entry point that initializes the auditor handshake.

def initialize() -> None:
    """
    Explicitly initializes the Veritas Engine and emits the handshake audit log.
    This should be called by the application entry point, not implicitly on import.
    """
    if not os.environ.get("COREASON_VERITAS_TEST_MODE"):
        try:
            _auditor = IERLogger()
            _auditor.emit_handshake(__version__)
        except Exception as e:
            logger.error(f"MACO Audit Link Failed: {e}")

5.) src/coreason_veritas/auditor.py
This module handles the heavy lifting of connecting to the VM Vault. It is designed to be generic and environment-aware.

class IERLogger:
    """
    Manages the connection to the OpenTelemetry collector and enforces strict
    metadata schema for the Immutable Execution Record (IER).
    Singleton pattern ensures global providers are initialized only once.
    """

    _instance: Optional["IERLogger"] = None

    _service_name: str
    _sinks: List[Callable[[Dict[str, Any]], None]]
    tracer: trace.Tracer

    def __new__(cls, service_name: str = "coreason-veritas") -> "IERLogger":
        if cls._instance is not None:
            if cls._instance._service_name != service_name:
                logger.warning(
                    f"IERLogger already initialized with service_name='{cls._instance._service_name}'. "
                    f"Ignoring new service_name='{service_name}'."
                )
            return cls._instance

        self = super(IERLogger, cls).__new__(cls)
        self._service_name = service_name
        self._initialize_providers()
        self._sinks = []

        cls._instance = self
        return self

    def _initialize_providers(self) -> None:
        """Initialize OpenTelemetry providers."""
        resource = Resource.create(
            {
                "service.name": os.environ.get("OTEL_SERVICE_NAME", self._service_name),
                "deployment.environment": os.environ.get("DEPLOYMENT_ENV", "local-vibe"),
                "host.name": platform.node(),
            }
        )
        # ... (Provider setup) ...
        configure_logging()

    def emit_handshake(self, version: str) -> None:
        """
        Standardized GxP audit trail for package initialization.

        Args:
            version: The version string of the package.
        """
        # Unified logging via Loguru
        logger.bind(co_veritas_version=version, co_governance_status="active").info("Veritas Engine Initialized")
