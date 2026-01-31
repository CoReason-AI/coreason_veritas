# Operations Manual

This guide is for System Operators, Auditors, and Compliance Officers responsible for monitoring the `coreason_veritas` runtime.

## Deployment & Configuration

### Deployment Mode A: Library Injection

*   **Integration:** Used in `services.project_lock` and `integrations.asset_registry`.
*   **Lifecycle:** Requires explicit initialization via `coreason_veritas.initialize()`.

### Deployment Mode B: Governance Microservice

For environments where Python library injection is not feasible, `coreason_veritas` operates as a standalone Governance Microservice (Sidecar).

*   **Module:** `src/coreason_veritas/server.py`
*   **Framework:** FastAPI + Uvicorn.
*   **Endpoints:**
    *   `POST /audit/artifact`: Validates artifact provenance and enrichment.
    *   `POST /verify/access`: Checks user authorization.
    *   `GET /health`: Liveness probe.
*   **Behavior:**
    1.  **Fail-Closed:** Any unhandled exception halts the request with 403 Forbidden.
    2.  **Singleton State:** Keys and Loggers are initialized once via `lifespan`.
*   **Configuration:**
    *   `COREASON_SRB_PUBLIC_KEY`: The PEM-encoded public key for signature verification.
    *   `OTEL_SERVICE_NAME`: Service name for traces (default: `coreason-veritas-svc`).

## The Immutable Execution Record (IER)

The IER is a structured log entry (OpenTelemetry Span) that serves as the legal proof of execution.

### Telemetry Schema

Every "Governed" span will contain the following attributes. These attributes are **mandatory** and enforced by the `IERLogger`.

| Attribute | Description | Example |
| :--- | :--- | :--- |
| `co.user_id` | The identity of the human or system invoking the agent. | `user_1234` |
| `co.asset_id` | A unique identifier for the logic being executed. | `spec_clinical_v2` |
| `co.srb_sig` | The cryptographic signature proving authorization. (Optional in **Draft Mode**) | `a1b2c3d4...` |
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
