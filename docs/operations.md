# Operations Manual

This guide is for System Operators, Auditors, and Compliance Officers responsible for monitoring the `coreason_veritas` runtime.

## Deployment & Configuration

### Deployment Mode A: Library Injection

*   **Integration:** Used in `services.project_lock` and `integrations.asset_registry`.
*   **Lifecycle:** Auto-initializes `IERLogger` in `__init__.py`.

### Deployment Mode B: Gateway Proxy

For environments where Python library injection is not feasible, `coreason_veritas` operates as a standalone Gateway Proxy.

*   **Module:** `src/coreason_veritas/main.py`
*   **Framework:** FastAPI + Uvicorn.
*   **Endpoints:** Exposes `POST /v1/chat/completions`.
*   **Behavior:**
    1.  **Anchor:** Intercepts request -> Sanitizes config (Temp=0, Seed=42).
    2.  **Proxy:** Forwards to LLM Provider -> Returns response.
*   **Configuration:**
    *   `VERITAS_HOST`: Host to bind (default: `0.0.0.0`).
    *   `VERITAS_PORT`: Port to bind (default: `8080`).
    *   `LLM_PROVIDER_URL`: Upstream LLM provider URL.

## The Immutable Execution Record (IER)

The IER is a structured log entry (OpenTelemetry Span) that serves as the legal proof of execution.

### Telemetry Schema

Every "Governed" span will contain the following attributes. These attributes are **mandatory** and enforced by the `IERLogger`.

| Attribute | Description | Example |
| :--- | :--- | :--- |
| `co.user_id` | The identity of the human or system invoking the agent. | `user_1234` |
| `co.asset_id` | A unique identifier for the logic being executed. | `spec_clinical_v2` |
| `co.srb_sig` | The cryptographic signature proving authorization. | `a1b2c3d4...` |
| `co.determinism_verified` | Boolean confirming "Lobotomy Protocol" status. | `true` |

### Reading the Traces

When auditing traces in your observability backend (e.g., Jaeger, Honeycomb, Datadog):

1.  **Filter by Service:** Look for `service.name = coreason-veritas`.
2.  **Verify Integrity:** Check that `co.determinism_verified` is `true`. If it is `false`, the execution was **NOT** anchored and should be flagged for review.
3.  **Check Status:**
    *   `OK`: The function executed successfully.
    *   `ERROR`: The function failed. Check the `exception.message` event.

## Alerting Rules

Operators should configure alerts for the following conditions:

1.  **`AssetTamperedError`**: Indicates a potential security breach or deployment of unverified code.
2.  **`co.determinism_verified = false`**: Indicates a configuration error where the Anchor failed to engage.
3.  **Missing Attributes**: If spans appear without `co.srb_sig`, the governance wrapper is being bypassed.

## Troubleshooting

### "Public Key Missing" Error
*   **Cause:** The `COREASON_VERITAS_PUBLIC_KEY` environment variable is not set.
*   **Fix:** Ensure the SRB Public Key PEM string is loaded into the environment.

### "Asset Tampered" Error
*   **Cause:** The input arguments passed to the function do not match the signature.
*   **Fix:**
    *   Verify the `asset` dictionary is exactly what was signed.
    *   Ensure no types were changed (e.g., `int` to `float`) during transit.
    *   Check if the `signature` string was truncated.
