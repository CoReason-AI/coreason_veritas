# Welcome to coreason_veritas

**coreason_veritas** is the non-negotiable governance layer of the CoReason platform. It replaces the probabilistic nature of LLMs with **Deterministic Equivalence** and **Radical Auditability**.

## Documentation Sections

*   **[Architecture](architecture.md)**: Understand the "Sandwich Execution" model, the three pillars (Gatekeeper, Auditor, Anchor), and the Blast Radius pattern.
*   **[Security Model](security.md)**: Learn about the Threat Model, SRB Keys, and how we prevent "Asset Tampered" events.
*   **[Operations Manual](operations.md)**: A guide for Auditors and Operators on reading the Immutable Execution Record (IER) and OpenTelemetry traces.
*   **[Cookbook](cookbook.md)**: Code examples and integration patterns (FastAPI, Nested Calls, etc.).
*   **[API Reference](api.md)**: Detailed technical documentation for the Python API.
*   **[Package Specification](specification.md)**: The complete technical specification and design document.
*   **[Contributing](contributing.md)**: Guidelines for developers who want to contribute to the codebase.

## Quick Start

The fastest way to get started is to wrap your critical agent functions with our decorator:

```python
from coreason_veritas import governed_execution

@governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
async def my_agent(spec, sig, user):
    # Your logic here is now:
    # 1. Cryptographically Verified (Gatekeeper)
    # 2. Audited via OpenTelemetry (Auditor)
    # 3. Deterministically Anchored (Anchor)
    ...
```

See the **[Cookbook](cookbook.md)** for more examples.
