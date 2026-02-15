# API Reference

goop-shield exposes a FastAPI REST API with OpenAPI docs at `/api/docs`.

## Authentication

Set `SHIELD_API_KEY` env var to enable bearer token auth. Include `Authorization: Bearer <key>` on all requests. Health and metrics endpoints are exempt.

---

## Core Endpoints

### POST /api/v1/defend

Classify and defend a prompt. Returns a minimal response (no defense names or per-verdict details) to prevent pipeline fingerprinting.

**Request:**

```json
{
  "prompt": "string (required, min 1 char)",
  "context": {}
}
```

**Response:**

```json
{
  "allow": true,
  "filtered_prompt": "string",
  "confidence": 0.0,
  "latency_ms": 1.2,
  "reason": "Request blocked by security policy"
}
```

The `reason` field is only present when `allow` is `false`.

### POST /debug/defend

Full-telemetry defend endpoint. Returns complete `DefendResponse` with all defense names, verdicts, and confidence scores. Requires API key authentication.

**Response:**

```json
{
  "allow": true,
  "filtered_prompt": "string",
  "defenses_applied": ["prompt_normalizer", "safety_filter", ...],
  "verdicts": [
    {
      "defense_name": "injection_blocker",
      "action": "allow",
      "confidence": 0.1,
      "details": "",
      "latency_ms": 0.5
    }
  ],
  "confidence": 0.0,
  "latency_ms": 3.2
}
```

### POST /api/v1/scan-response

Scan an LLM response for leaked secrets, canary tokens, and harmful content.

**Request:**

```json
{
  "response_text": "string (required, min 1 char)",
  "original_prompt": "string (optional)",
  "context": {}
}
```

**Response:**

```json
{
  "safe": true,
  "filtered_response": "string",
  "scanners_applied": ["secret_leak_scanner"],
  "verdicts": [...],
  "confidence": 0.0,
  "latency_ms": 2.1
}
```

### GET /api/v1/health

Health check. Always accessible without authentication.

**Response:**

```json
{
  "status": "healthy",
  "defenses_loaded": 21,
  "scanners_loaded": 3,
  "brorl_ready": true,
  "version": "0.1.0",
  "uptime_seconds": 42.5,
  "total_requests": 150,
  "total_blocked": 12,
  "active_defenses": ["prompt_normalizer", "safety_filter", ...],
  "active_scanners": ["secret_leak_scanner", "canary_leak_scanner", "harmful_content_scanner"],
  "audit_events_total": 150
}
```

### GET /api/v1/metrics

Prometheus-format metrics. Always accessible without authentication.

**Response** (text/plain):

```
shield_requests_total 150
shield_blocked_total 12
shield_defenses_loaded 21
shield_scanners_loaded 3
shield_uptime_seconds 42.5
shield_defense_invocations_total{defense="injection_blocker"} 150
shield_defense_blocks_total{defense="injection_blocker"} 8
shield_brorl_alpha{technique="injection_blocker"} 9.0
shield_brorl_beta{technique="injection_blocker"} 2.0
shield_brorl_success_rate{technique="injection_blocker"} 0.8182
```

---

## Telemetry

### POST /api/v1/telemetry/events

Report an external telemetry event.

**Request:**

```json
{
  "attack_type": "prompt_injection",
  "defense_action": "injection_blocker",
  "outcome": "block"
}
```

**Response:**

```json
{"received": true}
```

---

## Audit

### GET /api/v1/audit/events

Paginated audit event history with filters.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `since` | float | None | Unix timestamp lower bound |
| `until` | float | None | Unix timestamp upper bound |
| `source_ip` | str | None | Filter by source IP |
| `action` | str | None | Filter by action (allow/block/sanitize) |
| `classification` | str | None | Filter by attack classification |
| `limit` | int | 100 | Results per page (1-1000) |
| `offset` | int | 0 | Pagination offset |

**Response:**

```json
{
  "events": [...],
  "count": 50,
  "limit": 100,
  "offset": 0
}
```

### GET /api/v1/audit/events/{request_id}

Single audit event by request ID.

### GET /api/v1/audit/summary

Aggregate audit statistics.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `since` | float | None | Unix timestamp lower bound |

### GET /api/v1/audit/attackers

Unique source IPs with block counts.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 50 | Max results (1-500) |

---

## WebSocket Streams

### WS /api/v1/shield/events/stream

Real-time audit event stream.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `severity` | str | `"all"` | `"all"` or `"blocks"` (only block events) |
| `token` | str | `""` | Bearer token (alternative to Authorization header) |

Events are JSON objects matching the audit event schema.

### WS /api/v1/behavior/stream

Real-time behavioral monitoring stream. Send `BehaviorEvent` JSON, receive `BehaviorVerdict` JSON.

**Send:**

```json
{
  "event_type": "tool_call",
  "tool": "execute_code",
  "args": {"code": "import os"},
  "session_id": "sess-123"
}
```

**Receive:**

```json
{
  "decision": "allow",
  "severity": "low",
  "reason": "",
  "matched_rules": []
}
```

---

## BroRL / Ranking

### GET /api/v1/brorl/state

Export ranking backend weights (alpha/beta posteriors for BroRL).

### POST /api/v1/brorl/load

Load ranking backend weights.

**Request:** Dict of technique weights.

### GET /api/v1/defender/stats

Aggregated defender stats including per-defense invocation/block counts and BroRL weights.

---

## Red Team

### POST /api/v1/redteam/probe

Trigger an immediate red-team probe run.

**Request:**

```json
{
  "probe_names": ["injection", "exfil"]
}
```

**Response:**

```json
{
  "total_probes": 20,
  "defenses_bypassed": 1,
  "bypass_rate": 0.05,
  "results": [...],
  "alignment_results": [...],
  "timestamp": 1707750000.0,
  "latency_ms": 150.0
}
```

### GET /api/v1/redteam/results

Get the latest red-team probe results (same schema as above).

### GET /api/v1/redteam/report

Generate a vulnerability report from the latest probe results.

### GET /api/v1/redteam/alignment

Get alignment-specific probe results.

---

## Behavioral Monitoring

### POST /api/v1/behavior/event

Evaluate a single behavioral event.

**Request:**

```json
{
  "event_type": "tool_call",
  "tool": "execute_code",
  "args": {"code": "rm -rf /"},
  "session_id": "sess-123"
}
```

**Response:**

```json
{
  "decision": "block",
  "severity": "critical",
  "reason": "Destructive file system operation detected",
  "matched_rules": ["destructive_command"]
}
```

---

## Policy Management

### POST /api/v1/policy/load

Load a versioned policy bundle.

### GET /api/v1/policy/export

Export current policy as a versioned bundle.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `version` | str | `"latest"` | Policy version to export |

---

## Deception

### GET /api/v1/deception/canaries

List active canary tokens and their status.

---

## Alignment Canaries

### GET /api/v1/alignment/pending-canary

Check if a canary is due for injection (used by client SDK).

### POST /api/v1/alignment/canary-result

Record an alignment canary check result.

### GET /api/v1/alignment/canary-stats

Get alignment canary pass/fail statistics per category.

### GET /api/v1/alignment/canary-alerts

Get alignment canary alerts for categories exceeding failure threshold.

---

## Intelligence

### GET /api/v1/intel/actors

List threat actor profiles.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 50 | Max results (1-500) |
| `sort` | str | `"risk_level"` | Sort field |

### GET /api/v1/intel/actors/{actor_id}

Get full threat actor profile.

### GET /api/v1/intel/campaigns

List detected attack campaigns.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 20 | Max results (1-100) |
| `window_hours` | int | 24 | Detection window (1-168) |

### GET /api/v1/intel/campaigns/{campaign_id}

Get campaign detail with event timeline.

### GET /api/v1/intel/geo/{ip}

GeoIP/ASN lookup for an IP address.

### GET /api/v1/intel/mitre

MITRE ATT&CK technique coverage from audit data.

### GET /api/v1/intel/summary

Intelligence summary: top actors, active campaigns, geo distribution.

---

## Advanced Endpoints

These endpoints require advanced features to be enabled in config.

### POST /api/v1/sabotage/task-outcome

Record a task outcome for sandbagging detection. Requires `sandbag_detection_enabled=True`.

### POST /api/v1/training/validate

Validate a single training data item. Requires `training_gate_enabled=True`.

### POST /api/v1/training/validate-batch

Validate a batch of training data items.

### GET /api/v1/training/quarantine

List quarantined training data items.

### POST /api/v1/training/quarantine/{item_id}/release

Release a quarantined item for use.

### POST /api/v1/training/quarantine/{item_id}/reject

Permanently reject a quarantined item.

### POST /api/v1/consistency/check

Manually trigger a consistency check. Requires `consistency_check_enabled=True`.

### GET /api/v1/consistency/stats

Get consistency check statistics.

---

## Experiment Dashboard

### GET /api/v1/experiments/attack-log

Paginated list of recent attack attempts with Shield verdicts.

### GET /api/v1/experiments/defense-heatmap

Matrix of defense_name x attack_classification with block counts.

### GET /api/v1/experiments/brorl-drift

Current BroRL weights with success rates for drift monitoring.

---

## Aggregation

### POST /api/v1/aggregation/ingest

Ingest batched telemetry from Shield instances.

### GET /api/v1/aggregation/stats

Get aggregate statistics across all Shield instances.

---

## OpenAPI

Interactive API documentation is available at `/api/docs` when the server is running.
