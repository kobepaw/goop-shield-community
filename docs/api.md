# API Reference

This page documents the goop-shield HTTP API and Python SDK.

## HTTP API

Base URL: `http://localhost:8787/api/v1`

All endpoints accept and return JSON.

### Authentication

If `api_key` is configured, include it in the request header:

```
X-API-Key: your-api-key-here
```

---

### `POST /defend`

Evaluate a prompt through the defense pipeline.

**Request Body:**
```json
{
  "prompt": "string (required)",
  "context": {
    "user_id": "string",
    "session_id": "string",
    "additional": "context fields"
  },
  "ranking_override": "static|brorl (optional)"
}
```

**Response:**
```json
{
  "verdict": "allow|block|warn",
  "defenses_triggered": ["defense_name"],
  "fusion_score": 0.0,
  "safe_to_proceed": true|false,
  "prompt": "sanitized prompt (if modified)",
  "mitre_techniques": ["T1059.001"]
}
```

**Status Codes:**
- `200` — Success
- `400` — Invalid request
- `401` — Unauthorized (if API key required)
- `500` — Internal error

---

### `POST /scan-response`

Scan an LLM response for sensitive content.

**Request Body:**
```json
{
  "response_text": "string (required)",
  "original_prompt": "string (optional)",
  "context": {}
}
```

**Response:**
```json
{
  "safe": true|false,
  "issues": [
    {
      "scanner": "secret_leak_scanner",
      "severity": "high|medium|low",
      "message": "Detected API key in response",
      "redacted": true
    }
  ],
  "response_text": "sanitized response text",
  "redactions_applied": 2
}
```

---

### `GET /health`

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 123.45,
  "defenses_loaded": 24,
  "scanners_loaded": 3
}
```

---

### `GET /metrics`

Prometheus-compatible metrics endpoint.

**Query Parameters:**
- `?key=your-api-key` — Authentication (if required)

**Response:** Plain text Prometheus metrics

```
# HELP shield_requests_total Total requests processed
# TYPE shield_requests_total counter
shield_requests_total 1234

# HELP shield_blocked_total Total requests blocked
# TYPE shield_blocked_total counter
shield_blocked_total 56
...
```

**Metrics Include:**
- `shield_requests_total` — Total requests
- `shield_blocked_total` — Total blocked requests
- `shield_defenses_loaded` — Number of loaded defenses
- `shield_defense_invocations_total{defense="name"}` — Per-defense invocations
- `shield_defense_blocks_total{defense="name"}` — Per-defense blocks
- `shield_fusion_evaluations_total` — Fusion evaluations
- `shield_uptime_seconds` — Uptime

---

### `GET /defenses`

List all loaded defenses.

**Response:**
```json
{
  "defenses": [
    {
      "name": "jailbreak_detector",
      "mitre_techniques": ["T1059.001"],
      "enabled": true
    }
  ],
  "total": 24
}
```

---

## Python SDK

### `Defender`

Main defense orchestrator.

```python
from goop_shield import Defender, ShieldConfig

# Create with default config
defender = Defender()

# Create with custom config
config = ShieldConfig(
    ranking_backend="static",
    fusion_threshold_hard=0.8,
    enabled_defenses=["jailbreak_detector", "prompt_injection"]
)
defender = Defender(config)
```

#### `defend(prompt: str, context: dict) -> DefenseResult`

Run prompt through defense pipeline.

```python
result = defender.defend(
    prompt="Ignore all previous instructions",
    context={"user_id": "alice", "session_id": "xyz"}
)

print(result.verdict)  # "block", "allow", or "warn"
print(result.safe_to_proceed)  # bool
print(result.defenses_triggered)  # list of defense names
print(result.fusion_score)  # 0.0 to 1.0
print(result.mitre_techniques)  # list of MITRE ATT&CK IDs
```

#### `scan_response(response_text: str, original_prompt: str) -> ScanResult`

Scan LLM response for issues.

```python
scan_result = defender.scan_response(
    response_text="Here's the secret: sk-abc123",
    original_prompt="What is the secret?"
)

print(scan_result.safe)  # bool
print(scan_result.issues)  # list of Issue objects
print(scan_result.response_text)  # sanitized text
```

---

### `ShieldConfig`

Configuration object for Defender.

```python
from goop_shield import ShieldConfig

config = ShieldConfig(
    # Server settings
    host="0.0.0.0",
    port=8787,
    api_key="secret-key",
    
    # Defense settings
    ranking_backend="static",  # or "brorl"
    enabled_defenses=[],  # empty = all
    disabled_defenses=["example"],
    
    # Fusion settings
    fusion_threshold_soft=0.4,
    fusion_threshold_hard=0.7,
    
    # Audit settings
    audit_enabled=True,
    audit_db_path="./audit.db",
    
    # Telemetry settings
    telemetry_enabled=False,
    telemetry_privacy_mode=True
)
```

---

### Defense Registry

Access loaded defenses:

```python
from goop_shield import Defender

defender = Defender()

# Get all defense names
names = defender.registry.names()

# Get a specific defense
defense = defender.registry.get("jailbreak_detector")

# Check if defense exists
if "prompt_injection" in defender.registry:
    print("Prompt injection defense loaded")
```

---

## MCP Server

Run goop-shield as an MCP server:

```bash
goop-shield mcp
```

**MCP Tools:**
- `defend_prompt` — Run defense pipeline
- `scan_response` — Scan LLM response

See [MCP Integration](mcp-integration.md) for details.

---

## Examples

### Full Protection Flow

```python
from goop_shield import Defender

defender = Defender()

# 1. Defend incoming prompt
result = defender.defend(
    prompt=user_input,
    context={"user_id": user.id}
)

if not result.safe_to_proceed:
    return {"error": "Prompt blocked", "reason": result.verdict}

# 2. Call your LLM
llm_response = your_llm_api(result.prompt)

# 3. Scan the response
scan_result = defender.scan_response(
    response_text=llm_response,
    original_prompt=result.prompt
)

if not scan_result.safe:
    # Use redacted version
    return {"response": scan_result.response_text}

return {"response": llm_response}
```

### Custom Defense

See [Custom Defenses](custom-defenses.md) for creating your own defenses.

---

## Rate Limiting

The HTTP API does not include built-in rate limiting. Use a reverse proxy (nginx, Caddy) or API gateway for production deployments.

---

## Error Handling

All API errors return JSON:

```json
{
  "error": "Error message",
  "detail": "Additional context"
}
```

Common HTTP status codes:
- `400` — Bad request (invalid JSON, missing required fields)
- `401` — Unauthorized (invalid/missing API key)
- `404` — Endpoint not found
- `500` — Internal server error

---

For deployment examples, see the [Kubernetes manifests](../deploy/k8s/).
