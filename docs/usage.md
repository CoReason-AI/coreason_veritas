# Usage Guide

## Governance Microservice (Server Mode)

The `coreason_veritas` server mode allows you to deploy governance logic as a microservice.

### Deployment

The server is distributed as a Docker image.

```bash
docker run -d \
  --name veritas-governance \
  -p 8000:8000 \
  -e COREASON_SRB_PUBLIC_KEY="$(cat srb_public_key.pem)" \
  -e OTEL_SERVICE_NAME="coreason-veritas-svc" \
  coreason/veritas:0.12.0
```

### API Reference

#### 1. Audit Artifact

Validates a Knowledge Artifact against governance policies.

**Request:** `POST /audit/artifact`

```json
{
  "artifact": {
    "enrichment_level": "TAGGED",
    "source_urn": "urn:job:12345"
  },
  "context": {
    "user_id": "user_123",
    "email": "user@coreason.ai"
  }
}
```

**Response:**

```json
{
  "status": "APPROVED",
  "reason": "All checks passed."
}
```

#### 2. Verify Access

Checks if a user is authorized to access a specific agent.

**Request:** `POST /verify/access`

```json
{
  "user_context": {
    "user_id": "user_123",
    "groups": ["researchers"]
  },
  "agent_id": "agent-clinical-analysis"
}
```

**Response:**

```json
{
  "status": "ALLOWED"
}
```

#### 3. Health Check

**Request:** `GET /health`

**Response:**

```json
{
  "status": "active",
  "mode": "governance_sidecar",
  "version": "0.12.0"
}
```
