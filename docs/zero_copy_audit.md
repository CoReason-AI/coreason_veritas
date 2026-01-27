# Zero-Copy Logging & Identity-Aware Auditing

## Overview

Version 0.10.0 introduces strict "Zero-Copy" logging and Identity-Aware auditing to Veritas. This ensures that sensitive data is aggressively redacted or truncated before being logged, and that every action is attributed to a specific identity (User/Service).

## Zero-Copy Logging Rules

The sanitizer now enforces the following rules for dictionary keys:

### 1. Masking
If a key contains any of the following substrings (case-insensitive):
* `token`
* `auth`
* `secret`
* `key`
* `password`

The value is replaced with `***MASKED***`.

### 2. Truncation
If a key contains any of the following substrings (case-insensitive):
* `content`
* `body`
* `text`
* `payload`
* `data`

And the string representation of the value exceeds **256 characters**, it is truncated:
`{value[:256]}... <TRUNCATED_ZERO_COPY>`

This prevents accidental logging of large documents (e.g., PDF content, clinical trial data).

## Identity-Aware Auditing

The `governed_execution` decorator now automatically captures `UserContext` if passed as an argument.

### Behavior
* **Actor Attribution**: The audit log now includes an `actor` field populated from `user_context.email` (or `user_id`).
* **Group Metadata**: User groups and claims are included in the audit log.
* **Token Stripping**: The `downstream_token` is explicitly removed from audit logs to prevent leakage.

### Usage

```python
from coreason_veritas import governed_execution
from coreason_identity.models import UserContext

@governed_execution(
    asset_id_arg="asset_id",
    signature_arg="signature",
    user_id_arg="user_id"
)
def sensitive_operation(asset_id, signature, user_id, user_context: UserContext):
    # ... operation ...
    pass
```

The auditor will automatically extract identity from `user_context`.
