# Package Specification: coreason-veritas

Role: Governance Middleware (The "Safety Anchor")
Context: GxP Enforcement & Immutable Audit
Runtime: Python 3.11+
Dependencies: opentelemetry-api, pydantic, cryptography

## 1. Design Philosophy

**coreason_veritas** is the non-negotiable governance layer of the CoReason platform. While the maco-api orchestrates *what* happens, veritas enforces *how* it happens.

It operates on the principle of **"Trust through Constraint"**:

1. **The Gatekeeper:** No code executes without a valid SRB (Scientific Review Board) signature.
2. **The Anchor:** No inference runs with stochastic parameters (Temperature is forced to 0.0).
3. **The Auditor:** No action occurs without a corresponding Immutable Execution Record (IER) span.

This package is designed to be injected as **Middleware** (for API routes) or **Decorators** (for service methods), acting as a "clean room" wrapper around execution logic.

## 2. Architecture & Modules

The package is structured into three primary enforcement modules corresponding to its core responsibilities.

| Module | Component | Responsibility | Failure Mode |
| :---- | :---- | :---- | :---- |
| **gatekeeper** | **Asset Verifier** | Validates the cryptographic chain of custody for Agent Specs and Charters. | **Block (403):** "Untrusted Asset" |
| **anchor** | **Determinism Enforcer** | Intercepts LLM calls to override configuration (Temp=0, Seeds). | **Override (Warn):** Forces Config |
| **auditor** | **IER Logger** | Emits OpenTelemetry spans to WORM storage. | **Halt (500):** "Audit Failure" |

## 3. Module Specifications

### 3.1 coreason_veritas.gatekeeper

**Responsibility:** Supply Chain Security. Ensures that the "Recipe" or "Agent" being loaded has not been tampered with since the SRB signed it.

**Key Class:** SignatureValidator

```python
from typing import Dict, Any
from coreason_veritas.exceptions import AssetTamperedError

class SignatureValidator:
    def __init__(self, public_key_store: str):
        self.key_store = public_key_store

    def verify_asset(self, asset_payload: Dict[str, Any], signature: str, check_timestamp: bool = True) -> bool:
        """
        1. Canonicalizes the `asset_payload` (JSON) to ensure consistent hashing.
        2. Retrieves the SRB Public Key from the immutable Key Store.
        3. Verifies the `x-coreason-sig` header against the payload hash.

        Raises:
            AssetTamperedError: If verification fails.
        """
        pass
```

### 3.2 coreason_veritas.anchor

**Responsibility:** Epistemic Integrity. Prevents "temperature creep" where developers might accidentally or intentionally enable stochastic behavior in GxP workflows.

**Key Class:** DeterminismInterceptor

```python
from typing import Optional

class DeterminismInterceptor:
    """
    Acts as a proxy/hook into the LLM Client configuration.
    """

    @staticmethod
    def enforce_config(raw_config: dict) -> dict:
        """
        The 'Lobotomy' Protocol:
        1. Forcibly sets `temperature = 0.0`.
        2. Forcibly sets `top_p = 1.0`.
        3. Injects `seed = 42` (or project-specific fixed seed).
        4. Logs a warning if the original config attempted to deviate.

        Returns:
            The sanitized, deterministic configuration dictionary.
        """
        sanitized = raw_config.copy()
        sanitized['temperature'] = 0.0
        sanitized['seed'] = 42
        return sanitized
```

### 3.3 coreason_veritas.auditor

**Responsibility:** Forensic Traceability. Manages the connection to the OpenTelemetry collector and enforces strict metadata schema for the Immutable Execution Record (IER).

**Key Class:** IERLogger

```python
from opentelemetry import trace

class IERLogger:
    def __init__(self, service_name: str):
        self.tracer = trace.get_tracer(service_name)

    def start_governed_span(self, name: str, attributes: Dict[str, str]):
        """
        Starts an OTel span with mandatory GxP attributes.

        Mandatory Attributes:
        - `co.user_id`: Who initiated the action?
        - `co.asset_id`: What code is running?
        - `co.srb_sig`: Proof of validation.
        - `co.determinism_verified`: Boolean flag from the Anchor.
        """
        pass
```

## 4. The Veritas Wrapper (Usage Pattern)

The primary interface for developers is the @governed_execution decorator, which bundles all three pillars into a single atomic wrapper.

**Usage Example:**

```python
from coreason_veritas import governed_execution

@governed_execution(
    asset_id_arg="spec_id",
    signature_arg="signature",
    user_id_arg="user_id"
)
async def execute_agent_logic(spec_id: str, signature: str, user_id: str, input_data: dict):
    # 1. Gatekeeper runs first. If signature fails, this code is UNREACHABLE.
    # 2. Auditor starts the Span.
    # 3. Anchor context var is set.
    ...
```

**Implementation Spec:**

```python
from functools import wraps

def governed_execution(
    asset_id_arg: str,
    signature_arg: str,
    user_id_arg: str,
    config_arg: Optional[str] = None,
    allow_unsigned: bool = False,
) -> Callable[..., Any]:
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # 1. Gatekeeper Check
            sig = kwargs.get(signature_arg)
            asset = kwargs.get(asset_id_arg)
            SignatureValidator().verify_asset(asset, sig)

            # 2. Start Audit Span
            with IERLogger().start_governed_span(func.__name__, {"asset": asset}):

                # 3. Anchor Context (Context Manager)
                with DeterminismInterceptor().scope():
                    return await func(*args, **kwargs)
        return wrapper
    return decorator
```

## 5. Integration with MACO API

This section defines how coreason-veritas integrates into the coreason-maco-api.

* **In services.project_lock:**
  * Veritas validates the user_signature against the IDP before allowing the lock.
  * It ensures the charter payload has not been modified since the last AI generation.
* **In integrations.ai_gateway:**
  * Veritas is injected as a dependency to sanitize the LLM configuration payload before it is sent to the provider.
* **In integrations.asset_registry:**
  * Veritas performs the SHA256 and signature checks on the retrieved JSON spec before passing it to the AgentFactory.

Example scripts:

1. governance.py

```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import json

class VeritasGovernance:
    @staticmethod
    def lobotomy_protocol(payload: dict) -> dict:
        """Forces Determinism: temp=0.0, seed=42"""
        sanitized = payload.copy()
        sanitized["temperature"] = 0.0
        sanitized["seed"] = 42
        sanitized["top_p"] = 1.0  # Optional but recommended for GxP
        print(f"Sanitizing config: {sanitized}")
        return sanitized

    @staticmethod
    def verify_signature(payload: dict, signature_hex: str, public_key_pem: str) -> bool:
        """Verifies if the Agent Code is SRB-Approved"""
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            # Canonicalize JSON to ensure consistent hashing
            canonical_payload = json.dumps(payload, sort_keys=True).encode()

            public_key.verify(
                bytes.fromhex(signature_hex),
                canonical_payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
```
