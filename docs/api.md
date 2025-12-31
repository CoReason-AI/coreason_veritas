# API Reference

This document provides a detailed reference for the public API of `coreason_veritas`.

## Wrapper

### `governed_execution`

The primary entry point for the library. This decorator bundles the Gatekeeper, Auditor, and Anchor into a single atomic wrapper to ensure governed execution of functions.

```python
def governed_execution(
    asset_id_arg: str,
    signature_arg: str,
    user_id_arg: str,
    config_arg: Optional[str] = None,
    allow_unsigned: bool = False
) -> Callable[..., Any]
```

**Parameters:**

*   `asset_id_arg` (*str*): The name of the keyword argument in the decorated function that contains the asset or specification.
*   `signature_arg` (*str*): The name of the keyword argument in the decorated function that contains the cryptographic signature.
*   `user_id_arg` (*str*): The name of the keyword argument in the decorated function that contains the user ID.
*   `config_arg` (*Optional[str]*): The name of the keyword argument in the decorated function that contains the configuration dictionary. If provided, the configuration will be sanitized by the Anchor.
*   `allow_unsigned` (*bool*): If set to `True`, enables **Draft Mode**, which bypasses the cryptographic signature verification. Defaults to `False`.

**Returns:**

*   (*Callable[..., Any]*): A decorated function that performs verification, tracing, and determinism enforcement before executing the original function. Supports asynchronous functions, synchronous functions, generators, and asynchronous generators.

**Raises:**

*   `ValueError`: If any of the required arguments (`signature_arg`, `asset_id_arg`, `user_id_arg`) are missing from the function call or if the environment variable `COREASON_VERITAS_PUBLIC_KEY` is not set.
*   `AssetTamperedError`: If the signature verification fails.

---

## Gatekeeper

### `SignatureValidator`

Validates the cryptographic chain of custody for Agent Specs and Charters.

**Technical Specifications:**
*   **Algorithm:** SHA256 hashing with RSA-PSS padding (MGF1).
*   **Canonicalization:** Uses **JCS (JSON Canonicalization Scheme - RFC 8785)** for strict, platform-independent consistency.
*   **Replay Protection:** Enforces a mandatory `timestamp` field in the payload to prevent replay attacks (max 5-minute skew).

#### `__init__`

```python
def __init__(self, public_key_store: str)
```

**Parameters:**

*   `public_key_store` (*str*): The Scientific Review Board (SRB) Public Key in PEM format string.

#### `verify_asset`

Verifies the cryptographic signature of an asset payload.

```python
def verify_asset(self, asset_payload: Dict[str, Any], signature: str) -> bool
```

**Parameters:**

*   `asset_payload` (*Dict[str, Any]*): The JSON payload (asset/spec) to verify.
*   `signature` (*str*): The hex-encoded signature string.

**Returns:**

*   (*bool*): `True` if the verification succeeds.

**Raises:**

*   `AssetTamperedError`: If the signature verification fails.

---

## Anchor

### `DeterminismInterceptor`

Acts as a proxy/hook into LLM Client configurations to enforce the "Lobotomy Protocol" for epistemic integrity.

#### `enforce_config`

Sanitizes a configuration dictionary to enforce deterministic parameters (The "Lobotomy Protocol").

```python
def enforce_config(self, raw_config: Dict[str, Any]) -> Dict[str, Any]
```

**Parameters:**

*   `raw_config` (*Dict[str, Any]*): The original configuration dictionary.

**Returns:**

*   (*Dict[str, Any]*): The sanitized configuration dictionary with:
    *   `temperature` set to `0.0`
    *   `top_p` set to `1.0`
    *   `seed` set to `42` (configurable via `VERITAS_SEED` environment variable)

**Behavior:**

*   Logs a warning if the original configuration attempts to set unsafe values for `temperature`, `top_p`, or `seed`.

#### `scope`

A context manager that sets the Anchor context variable, marking the execution scope as deterministic.

```python
@contextlib.contextmanager
def scope(self) -> Generator[None, None, None]
```

**Usage:**

```python
with DeterminismInterceptor().scope():
    # Code executed here is marked as anchored/deterministic
    ...
```

### `is_anchor_active`

Checks if the Anchor determinism scope is currently active.

```python
def is_anchor_active() -> bool
```

**Returns:**

*   (*bool*): `True` if the code is running within a `DeterminismInterceptor.scope()`, `False` otherwise.

---

## Auditor

### `IERLogger`

Manages the connection to the OpenTelemetry collector and enforces strict metadata schema for the Immutable Execution Record (IER). This class implements the Singleton pattern.

#### `__init__`

```python
def __init__(self, service_name: str = "coreason-veritas")
```

**Parameters:**

*   `service_name` (*str*): The name of the service for the tracer. Defaults to `"coreason-veritas"`.

#### `emit_handshake`

Emits a structured Log Record ("Handshake") confirming the engine version.

```python
def emit_handshake(self, version: str)
```

**Parameters:**

*   `version` (*str*): The version of the `coreason_veritas` package.

#### `start_governed_span`

Starts an OpenTelemetry span with mandatory GxP attributes.

```python
@contextlib.contextmanager
def start_governed_span(
    self,
    name: str,
    attributes: Dict[str, str]
) -> Generator[trace.Span, None, None]
```

**Parameters:**

*   `name` (*str*): The name of the span.
*   `attributes` (*Dict[str, str]*): A dictionary of attributes to add to the span.

**Mandatory Attributes:**

The `attributes` dictionary (or the resulting span attributes) **must** contain:

*   `co.user_id`: The ID of the user initiating the action.
*   `co.asset_id`: The ID of the asset/code being executed.
*   `co.srb_sig`: The cryptographic signature.

**Automatically Added Attributes:**

*   `co.determinism_verified`: Set to `True` or `False` based on `is_anchor_active()`.

**Raises:**

*   `ValueError`: If any mandatory attribute is missing.
