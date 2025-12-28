# Security Model

`coreason_veritas` implements a **"Glass Box"** security model. The goal is not just to secure the code execution, but to make the execution properties transparent, verifiable, and immutable.

## Threat Model

The system is designed to defend against the following threats in a GxP (Good Practice) environment:

1.  **Unauthorized Code execution:** Developers or malicious actors modifying the behavior of an AI agent without approval.
2.  **Stochastic Drift:** An AI agent returning different answers for the same input due to non-deterministic LLM parameters.
3.  **Repudiation:** A user denying they initiated an action, or an organization losing the "chain of custody" for an AI decision.

## Chain of Custody (The SRB)

The root of trust in `coreason_veritas` is the **Scientific Review Board (SRB)**.

1.  **Asset Definition:** An "Asset" (e.g., an Agent Specification, Prompt Template, or Configuration) is defined.
2.  **Review:** The SRB reviews the Asset.
3.  **Signing:** If approved, the SRB signs the canonicalized JSON representation of the Asset using their **Private Key**.
4.  **Distribution:** The Asset and its **Signature** are deployed to the environment.

## Key Management

*   **Format:** The system expects keys in **PEM (Privacy Enhanced Mail)** format.
*   **Algorithm:** Standard asymmetric cryptography (implementation details handled by the `cryptography` library).
*   **Public Key:** The **SRB Public Key** must be available to the application environment, typically via the `COREASON_VERITAS_PUBLIC_KEY` environment variable.

## Canonicalization

To ensure consistent verification, JSON payloads are canonicalized before signing/verifying.
*   **Sorting:** Keys are sorted alphabetically (`sort_keys=True`).
*   **Separators:** Minimal whitespace is used (`,`, `:`).

**Example Canonical Form:**
```json
{"model":"gpt-4","temperature":0.0}
```

## "Asset Tampered" Event

If `verify_asset` fails, it raises an `AssetTamperedError`. This is a critical security event indicating:
*   The code/config on disk differs from what the SRB signed.
*   The signature itself is malformed or from the wrong key.
*   The payload has been corrupted in transit.

In this event, **execution is hard-stopped**. This is a "Fail Closed" design.
