# coreason_veritas

coreason_veritas is the non-negotiable governance layer of the CoReason platform.

[![CI](https://github.com/CoReason-AI/coreason_veritas/actions/workflows/ci.yml/badge.svg)](https://github.com/CoReason-AI/coreason_veritas/actions/workflows/ci.yml)

# **The Architecture and Utility of coreason_veritas**

### **1. The Philosophy (The Why)**

In the high-stakes world of biopharmaceuticals and GxP regulated environments, the probabilistic nature of standard Large Language Models represents a massive liability. `coreason_veritas` was architected to solve this specific friction point: it is the non-negotiable governance layer designed to impose **"Glass Box"** principles onto AI agents.

Our intent is to replace the inherent randomness of generative AI with **"Deterministic Equivalence"** and **"Radical Auditability"**. This package acts as a middleware "Safety Anchor," enforcing a "Lobotomy Protocol" that restricts an LLM’s creativity in favor of epistemic integrity. By cryptographically verifying the chain of custody for code and forcibly overriding stochastic parameters, we turn AI from a creative writer into a verifiable reasoning engine backed by an **Immutable Execution Record (IER)**.

### **2. Under the Hood (The Dependencies & Logic)**

The stack defined in our `pyproject.toml` is focused and lightweight, designed for integration rather than heavy computation:

*   **opentelemetry-api**: We depend on OTel to treat AI reasoning traces as critical infrastructure telemetry, enabling cloud-native, enterprise-grade observability.
*   **cryptography**: This powers our **Gatekeeper** function. We use asymmetric cryptographic verification to ensure that "Agent Specs" have not been tampered with since they were signed by a Scientific Review Board.
*   **loguru**: Used for developer ergonomics and structured logging output.
*   **fastapi/uvicorn/httpx**: Powers the **Gateway Proxy** mode, allowing `coreason_veritas` to act as a standalone governance sidecar.
*   **jcs (JSON Canonicalization Scheme)**: Ensures consistent hashing of JSON payloads across platforms.
*   **presidio-analyzer**: (Optional) Powered by Microsoft Presidio, this drives the **Sanitizer** to detect and redaction PII.

The internal logic is structured around four atomic units:

1.  **The Gatekeeper:** Verifies the cryptographic signature of the input asset before any code runs. If the signature is invalid, execution halts immediately.
2.  **The Auditor:** Initializes an OpenTelemetry span with mandatory attributes (User ID, Asset ID, Signature) to create the IER.
3.  **The Anchor:** Uses Python's `contextvars` to set a thread-safe flag (`_ANCHOR_ACTIVE`). It creates a scope where any LLM configuration is sanitized—forcing `temperature=0.0` and `seed=42` (configurable via `VERITAS_SEED`)—effectively "lobotomizing" the model to ensure it produces the exact same output for the same input every time.
4.  **The Sanitizer:** An optional utility that scans payloads for Personally Identifiable Information (PII) like phone numbers or email addresses and redacts them before logging or processing.

### **3. In Practice (The How)**

The most powerful way to use `coreason_veritas` is via our high-level wrapper, which bundles the Gatekeeper, Auditor, and Anchor into a single line of code.

**Example 1: The Atomic Wrapper**

This example demonstrates the "Happy Path" for protecting an asynchronous agent function. The `@governed_execution` decorator ensures that the function cannot run unless the inputs are signed, the execution is traced, and the environment is deterministic.

```python
from typing import Any, Dict
from coreason_veritas import governed_execution
from coreason_veritas.anchor import is_anchor_active

# The decorator handles the heavy lifting of verification and tracing
@governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
async def run_clinical_analysis(spec: Dict[str, Any], sig: str, user: str) -> str:
    """
    A critical analysis function that must be auditable.
    """
    # Verify we are in a deterministic scope (The Anchor is holding)
    if is_anchor_active():
        print("System is anchored: Temperature forced to 0.0")

    # ... perform business logic ...
    return "Analysis Complete: Risk Low"

# Execution
# If 'sig' is invalid, this raises AssetTamperedError before the function body ever runs.
await run_clinical_analysis(
    spec={"trial_id": "NCT123456"},
    sig="deadbeef...",
    user="dr_who"
)
```

**Example 2: The "Lobotomy" Protocol**

For developers integrating directly with LLM clients (like OpenAI or Anthropic), the `DeterminismInterceptor` can be used explicitly to sanitize configuration payloads, ensuring no "creative" parameters slip through.

```python
from coreason_veritas.anchor import DeterminismInterceptor

# An unsafe config that might produce hallucinations (high temp, random seed)
risky_config = {
    "model": "gpt-4",
    "temperature": 0.9,
    "top_p": 0.95,
    "seed": 999
}

# The interceptor forcibly overrides stochastic params
safe_config = DeterminismInterceptor.enforce_config(risky_config)

print(safe_config)
# Output:
# {
#   "model": "gpt-4",
#   "temperature": 0.0,  <-- Sanitized
#   "top_p": 1.0,        <-- Sanitized
#   "seed": 42           <-- Injected (Configurable via VERITAS_SEED)
# }
```

### **4. The Governance Microservice**

For environments where Python library injection is not feasible (e.g., Sidecar deployment), `coreason_veritas` provides a standalone FastAPI server that exposes governance logic via REST.

**Features:**
*   **Fail-Closed Architecture:** Any unhandled exception results in a 403 Forbidden.
*   **Singleton Management:** Cryptographic keys and OTel exporters are initialized once at startup.
*   **Endpoints:**
    *   `GET /health`: Liveness probe.
    *   `POST /audit/artifact`: Validates `KnowledgeArtifact` against enrichment and provenance policies.
    *   `POST /verify/access`: Checks user authorization via `PolicyGuard`.

**Running with Docker:**

```sh
docker run -p 8000:8000 \
  -e COREASON_SRB_PUBLIC_KEY="<your_pem_key>" \
  -e OTEL_EXPORTER_OTLP_ENDPOINT="http://otel-collector:4317" \
  coreason-veritas:latest
```

## Getting Started

### Prerequisites

- Python 3.12+
- Poetry

### Installation

You can install `coreason_veritas` directly from PyPI:

```sh
pip install coreason-veritas
```

Or using Poetry:

```sh
poetry add coreason-veritas
```

Alternatively, to install from source:

1.  Clone the repository:
    ```sh
    git clone https://github.com/CoReason-AI/coreason_veritas.git
    cd coreason_veritas
    ```
2.  Install dependencies:
    ```sh
    poetry install
    ```

### Development

-   Run the linter:
    ```sh
    poetry run pre-commit run --all-files
    ```
-   Run the tests:
    ```sh
    poetry run pytest
    ```

## License

This project is licensed under the Prosperity Public License 3.0.0. See the [LICENSE](LICENSE) file for details.
