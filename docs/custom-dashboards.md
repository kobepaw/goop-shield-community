# Custom Dashboards

goop-shield does not ship a built-in dashboard UI. Instead, it provides a comprehensive API surface that you can use to build custom dashboards with your preferred tools (Grafana, Retool, custom React/Vue apps, etc.).

This document catalogs every API endpoint relevant for dashboarding, organized by panel type.

## Overview Panel

### Health Status

**Endpoint:** `GET /api/v1/health`

**Polling interval:** 10-30 seconds

**Response schema:**

```json
{
  "status": "healthy",
  "defenses_loaded": 21,
  "scanners_loaded": 3,
  "brorl_ready": true,
  "version": "0.1.0",
  "uptime_seconds": 86400.0,
  "total_requests": 15230,
  "total_blocked": 842,
  "active_defenses": ["prompt_normalizer", "safety_filter", ...],
  "active_scanners": ["secret_leak_scanner", "canary_leak_scanner", "harmful_content_scanner"],
  "audit_events_total": 15230
}
```

**Suggested panels:**
- Status badge (healthy/unhealthy)
- Uptime counter
- Block rate gauge: `total_blocked / total_requests`
- Defense/scanner count badges

### Defender Stats

**Endpoint:** `GET /api/v1/defender/stats`

**Polling interval:** 30-60 seconds

Returns per-defense invocation counts, block counts, and BroRL weights. Use for:
- Per-defense bar chart (invocations vs. blocks)
- Defense effectiveness ranking

---

## Attack Log Panel

### Recent Attacks

**Endpoint:** `GET /api/v1/experiments/attack-log`

**Query params:** `limit`, `offset`, `classification`

**Polling interval:** 5-15 seconds

**Response schema:**

```json
{
  "entries": [
    {
      "request_id": "uuid",
      "timestamp": 1707750000.0,
      "source_ip": "192.168.1.100",
      "prompt_preview": "Ignore all previous...",
      "shield_action": "block",
      "confidence": 0.92,
      "latency_ms": 3.2,
      "attack_classification": "prompt_injection",
      "blocking_defense": "injection_blocker",
      "defenses_applied": ["prompt_normalizer", "injection_blocker"]
    }
  ],
  "count": 50,
  "limit": 50,
  "offset": 0
}
```

**Suggested panels:**
- Scrolling attack log table
- Attack classification pie chart
- Block vs. allow timeline

---

## Defense Heatmap Panel

### Defense vs. Attack Matrix

**Endpoint:** `GET /api/v1/experiments/defense-heatmap`

**Query params:** `since` (unix timestamp)

**Polling interval:** 60 seconds

**Response schema:**

```json
{
  "matrix": {
    "injection_blocker": {
      "prompt_injection": 45,
      "command_injection": 12
    },
    "exfil_detector": {
      "data_exfiltration": 8
    }
  },
  "defense_names": ["exfil_detector", "injection_blocker"],
  "attack_types": ["command_injection", "data_exfiltration", "prompt_injection"]
}
```

**Suggested panels:**
- Heatmap grid (defense rows x attack columns)
- Color intensity = block count

---

## BroRL Drift Panel

### Defense Ranking Over Time

**Endpoint:** `GET /api/v1/experiments/brorl-drift`

**Polling interval:** 30-60 seconds (store history client-side)

**Response schema:**

```json
{
  "timestamp": 1707750000.0,
  "techniques": {
    "injection_blocker": {
      "alpha": 45.2,
      "beta": 5.8,
      "success_rate": 0.886275,
      "total_samples": 49.0
    },
    "exfil_detector": {
      "alpha": 12.1,
      "beta": 3.9,
      "success_rate": 0.756250,
      "total_samples": 14.0
    }
  },
  "total_techniques": 21
}
```

**Suggested panels:**
- Success rate line chart per defense (track over time)
- Alpha/beta posterior distribution plots
- Top-ranked defenses leaderboard

---

## Audit Summary Panel

### Aggregate Statistics

**Endpoint:** `GET /api/v1/audit/summary`

**Query params:** `since` (unix timestamp)

**Polling interval:** 30-60 seconds

Returns aggregate counts by action, classification, and time bucket. Use for:
- Time-series area chart (requests over time)
- Action breakdown (allow/block/sanitize)
- Classification distribution

### Top Attackers

**Endpoint:** `GET /api/v1/audit/attackers`

**Query params:** `limit`

**Polling interval:** 60 seconds

Returns unique source IPs ranked by block count. Use for:
- Top attackers table
- Geographic distribution (combine with GeoIP)

---

## Threat Intelligence Panel

### Actor Profiles

**Endpoint:** `GET /api/v1/intel/actors`

**Query params:** `limit`, `sort`

**Polling interval:** 60-300 seconds

### Active Campaigns

**Endpoint:** `GET /api/v1/intel/campaigns`

**Query params:** `limit`, `window_hours`

**Polling interval:** 60-300 seconds

### GeoIP Lookup

**Endpoint:** `GET /api/v1/intel/geo/{ip}`

Use to enrich source IPs with country, city, ASN.

### MITRE ATT&CK Coverage

**Endpoint:** `GET /api/v1/intel/mitre`

Returns technique coverage matrix. Use for:
- MITRE ATT&CK navigator heatmap
- Coverage gap analysis

### Intelligence Summary

**Endpoint:** `GET /api/v1/intel/summary`

**Polling interval:** 60-300 seconds

```json
{
  "top_actors": [...],
  "active_campaigns": [...],
  "geo_distribution": {"US": 45, "CN": 12, "RU": 8}
}
```

---

## Real-Time Event Stream

### WebSocket: Audit Events

**Endpoint:** `WS /api/v1/shield/events/stream`

**Query params:** `severity` (`all` or `blocks`), `token`

Connect via WebSocket for real-time event push. Each event is a JSON object:

```json
{
  "request_id": "uuid",
  "timestamp": 1707750000.0,
  "source_ip": "192.168.1.100",
  "shield_action": "block",
  "confidence": 0.92,
  "attack_classification": "prompt_injection",
  "blocking_defense": "injection_blocker",
  "defenses_applied": [...],
  "geo": {"country": "US", "city": "San Francisco", "asn": 13335}
}
```

**Suggested panels:**
- Live event ticker
- Real-time block rate sparkline

### WebSocket: Behavioral Events

**Endpoint:** `WS /api/v1/behavior/stream`

Bidirectional stream. Send `BehaviorEvent`, receive `BehaviorVerdict`.

---

## Prometheus / Grafana Integration

### Prometheus Metrics

**Endpoint:** `GET /api/v1/metrics`

Returns Prometheus-format text metrics. Configure Prometheus to scrape:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'goop-shield'
    scrape_interval: 15s
    static_configs:
      - targets: ['shield:8787']
    metrics_path: '/api/v1/metrics'
```

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `shield_requests_total` | counter | Total requests processed |
| `shield_blocked_total` | counter | Total requests blocked |
| `shield_defenses_loaded` | gauge | Number of active defenses |
| `shield_scanners_loaded` | gauge | Number of active scanners |
| `shield_uptime_seconds` | gauge | Server uptime |
| `shield_defense_invocations_total{defense="..."}` | counter | Per-defense invocation count |
| `shield_defense_blocks_total{defense="..."}` | counter | Per-defense block count |
| `shield_brorl_alpha{technique="..."}` | gauge | BroRL alpha posterior |
| `shield_brorl_beta{technique="..."}` | gauge | BroRL beta posterior |
| `shield_brorl_success_rate{technique="..."}` | gauge | Derived success rate |
| `shield_redteam_probes_total` | counter | Total red team probes run |
| `shield_redteam_bypasses_total` | counter | Total defense bypasses |
| `shield_redteam_bypass_rate{probe="..."}` | gauge | Per-probe bypass rate |

### Grafana Dashboard

Import the Prometheus data source and create panels:

1. **Request Rate**: `rate(shield_requests_total[5m])`
2. **Block Rate**: `rate(shield_blocked_total[5m]) / rate(shield_requests_total[5m])`
3. **Defense Effectiveness**: `shield_brorl_success_rate` per technique
4. **Red Team Bypass Rate**: `shield_redteam_bypass_rate` per probe

---

## Authentication for Dashboard APIs

All endpoints except `/api/v1/health` require authentication when `SHIELD_API_KEY` is set.

For WebSocket connections, pass the token via the `Authorization` header (recommended):

```
Authorization: Bearer your-api-key
```

Alternatively, pass as a query parameter (not recommended -- query strings are logged by proxies and access logs):

```
ws://localhost:8787/api/v1/shield/events/stream?token=your-api-key
```

---

## Suggested Polling Intervals

| Panel Type | Endpoint | Interval |
|------------|----------|----------|
| Health badge | `/api/v1/health` | 10-30s |
| Live attack log | `/api/v1/experiments/attack-log` | 5-15s |
| Defense heatmap | `/api/v1/experiments/defense-heatmap` | 60s |
| BroRL drift | `/api/v1/experiments/brorl-drift` | 30-60s |
| Audit summary | `/api/v1/audit/summary` | 30-60s |
| Top attackers | `/api/v1/audit/attackers` | 60s |
| Intel actors | `/api/v1/intel/actors` | 60-300s |
| Campaigns | `/api/v1/intel/campaigns` | 60-300s |
| Real-time events | WebSocket | Push (no polling) |
| Prometheus | `/api/v1/metrics` | 15s (Prometheus scrape) |

For real-time use cases, prefer the WebSocket stream over polling.
