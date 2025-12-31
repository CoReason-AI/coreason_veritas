# The Architecture and Utility of coreason-veritas

### 1. The Philosophy (The Why)

In the high-stakes, regulated environments of biopharmaceuticals and GxP compliance, the inherent probabilistic nature of Large Language Models (LLMs) represents a massive liability. A model that "hallucinates" or varies its output for the same input is not just annoying—it is non-compliant. `coreason-veritas` was architected to solve this specific friction point: it is the non-negotiable governance layer designed to impose **"Glass Box"** principles onto AI agents.

The author’s intent is clear: to replace the "magic" of generative AI with **"Deterministic Equivalence"** and **"Radical Auditability"**. This package acts as a middleware "Safety Anchor," enforcing a "Lobotomy Protocol" that intentionally restricts an LLM’s creativity in favor of epistemic integrity. By cryptographically verifying the chain of custody for code and forcibly overriding stochastic parameters, `coreason-veritas` transforms AI from a creative writer into a verifiable reasoning engine backed by an **Immutable Execution Record (IER)**.

### 2. Under the Hood (The Dependencies & logic)

The stack defined in `pyproject.toml` is precise, selecting dependencies that enable enterprise-grade trust without unnecessary bloat:

*   **`opentelemetry-api`**: This is the backbone of the **Auditor**. It treats AI reasoning traces as critical infrastructure telemetry, enabling the creation of an Immutable Execution Record (IER) that persists beyond the lifespan of the request.
*   **`cryptography`**: Powers the **Gatekeeper**. It provides the asymmetric cryptographic primitives necessary to verify that "Agent Specs" have not been tampered with since they were signed by a Scientific Review Board.
*   **`jcs` (JSON Canonicalization Scheme)**: A subtle but critical engineering nuance. To ensure signatures are robust and reproducible across different systems (e.g., Python vs. Node.js), `veritas` uses `jcs` to create a canonical, mathematically consistent representation of the JSON payload before hashing. This prevents "fragile signature" failures caused by insignificant whitespace or key-ordering differences.
*   **`pydantic`**: Enforces strict data validation and type safety, ensuring that governance metadata adheres to a rigorous schema.

The internal logic operates as a three-stage pipeline:
1.  **The Gatekeeper:** First, the `SignatureValidator` uses `jcs` to canonicalize the input asset and verifies its cryptographic signature. If the signature is invalid, execution is strictly blocked.
2.  **The Auditor:** Once verified, the `IERLogger` initializes an OpenTelemetry span, tagging it with mandatory governance attributes (User ID, Asset ID, Signature).
3.  **The Anchor:** Finally, the `DeterminismInterceptor` uses Python's `contextvars` to activate a thread-safe scope. Inside this scope, the "Lobotomy Protocol" is active: any LLM configuration is intercepted and sanitized—forcing `temperature=0.0` and `seed=42`—ensuring the model behaves deterministically.

### 3. In Practice (The How)

The `coreason-veritas` package provides a high-level wrapper that bundles these three pillars into a single, developer-friendly interface, with a strong emphasis on asynchronous workloads common in modern AI gateways.

**Example 1: The Happy Path (Async Governance)**

This example demonstrates protecting a critical asynchronous analysis function. The `@governed_execution` decorator handles the heavy lifting, ensuring the function is unreachable unless the inputs are signed and the environment is locked down.

```python
from typing import Any, Dict, AsyncGenerator
from coreason_veritas import governed_execution

# The decorator acts as a firewall.
# If 'sig' doesn't match the signature of 'spec', this function never runs.
@governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
async def run_clinical_analysis(spec: Dict[str, Any], sig: str, user: str) -> Dict[str, str]:
    """
    A critical, GxP-regulated analysis function.
    At this point, we are guaranteed:
    1. 'spec' is authentic (Gatekeeper).
    2. We are being traced (Auditor).
    3. Any LLM calls will be deterministic (Anchor).
    """
    # ... perform business logic or call LLM ...
    return {"status": "Complete", "risk_score": "Low"}

# Execution
await run_clinical_analysis(
    spec={"trial_id": "NCT123456", "phase": 3},
    sig="deadbeef...",
    user="dr_who"
)
```

**Example 2: The "Lobotomy" Protocol**

For deeper integration, the `DeterminismInterceptor` can be used to manually sanitize configuration payloads before sending them to an LLM provider. This prevents "temperature creep" where experimental settings might leak into production.

```python
from coreason_veritas.anchor import DeterminismInterceptor

interceptor = DeterminismInterceptor()

# An unsafe config that might produce hallucinations
risky_config = {
    "model": "gpt-4",
    "temperature": 0.9, # Too creative
    "seed": 999
}

# The interceptor forcibly overrides stochastic params
safe_config = interceptor.enforce_config(risky_config)

# Result: {'model': 'gpt-4', 'temperature': 0.0, 'seed': 42, ...}
```

**Example 3: Developer Pragmatism (Draft Mode)**

Recognizing that cryptographic signing can slow down the iterative "dev loop," `veritas` includes a "Draft Mode." By setting `allow_unsigned=True`, developers can bypass the strict signature checks during local testing while still benefiting from the tracing and determinism enforcement.

```python
@governed_execution(
    asset_id_arg="spec",
    signature_arg="sig",
    user_id_arg="user",
    allow_unsigned=True  # <--- Enables Draft Mode
)
async def prototype_agent(spec: Dict[str, Any], sig: str, user: str):
    # This runs even if 'sig' is None, but logs "co.compliance_mode": "DRAFT"
    pass
```
