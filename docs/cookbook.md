# Cookbook

This cookbook provides patterns and examples for integrating `coreason_veritas` into various application architectures.

## Pattern 1: The Standard Wrapper (Async)

This is the most common usage pattern.

```python
import asyncio
from typing import Dict, Any
from coreason_veritas import governed_execution

# Your payload and signature (normally loaded from DB/API)
SPEC = {"task": "summarize", "version": 1}
SIG = "eyJhbGciOiJSUzI1NiIs... (JWS Token)"
USER = "alice@example.com"

@governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
async def run_agent(spec: Dict[str, Any], sig: str, user: str):
    print("Agent running in safe mode.")
    return "Result"

async def main():
    await run_agent(spec=SPEC, sig=SIG, user=USER)

if __name__ == "__main__":
    asyncio.run(main())
```

## Pattern 2: Manual Interceptor Usage

If you cannot use the decorator (e.g., inside a library you don't control), you can use the `DeterminismInterceptor` directly.

```python
from coreason_veritas.anchor import DeterminismInterceptor

# 1. Sanitize Config
unsafe_config = {"temperature": 0.7, "model": "gpt-4"}
interceptor = DeterminismInterceptor()
safe_config = interceptor.enforce_config(unsafe_config)
# safe_config is now {"temperature": 0.0, "seed": 42, ...}

# 2. Run in Scope
with interceptor.scope():
    # External calls here will detect the anchor
    print("I am anchored.")
```

## Pattern 3: FastAPI Integration

Integrating with a web framework requires extracting the signature from headers or the body.

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from coreason_veritas import governed_execution

app = FastAPI()

class RequestBody(BaseModel):
    spec: dict
    signature: str
    user_id: str

@governed_execution(asset_id_arg="spec", signature_arg="signature", user_id_arg="user_id")
async def _execute_logic(spec, signature, user_id):
    # Actual business logic
    return {"status": "success"}

@app.post("/run")
async def endpoint(body: RequestBody):
    # We create a wrapper helper or call the decorated function directly
    # Note: The arguments must match the decorator's expectation
    return await _execute_logic(
        spec=body.spec,
        signature=body.signature,
        user_id=body.user_id
    )
```

## Pattern 4: Nested Governance

When one governed function calls another, the "Sandwich" model applies.

```python
@governed_execution(asset_id_arg="config", signature_arg="sig", user_id_arg="user")
async def inner_tool(config, sig, user):
    # This creates a child span
    return "Tool Result"

@governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
async def outer_agent(spec, sig, user):
    # Parent span active
    # Calling inner governed function
    # Note: Inner function needs its own valid signature!
    result = await inner_tool(config=spec["tool_config"], sig=spec["tool_sig"], user=user)
    return result
```
