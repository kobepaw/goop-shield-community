# Configuration

goop-shield uses Pydantic v2 for configuration with YAML file loading, environment variable substitution, and config inheritance.

## Loading Config

### Environment Variable

```bash
SHIELD_CONFIG=config/shield_balanced.yaml goop-shield serve
```

### Python

```python
from goop_shield.config import ShieldConfig

# Defaults
config = ShieldConfig()

# From YAML
from goop_shield.config_loader import ConfigLoader
loader = ConfigLoader()
config = loader.load(ShieldConfig, "config/shield_balanced.yaml")

# With overrides
config = loader.load(ShieldConfig, "config/shield_balanced.yaml", port=9000)
```

## Config Inheritance

Use `extends` to inherit from a base config:

```yaml
# config/strict.yaml
extends: config/base.yaml
failure_policy: closed
injection_confidence_threshold: 0.5
max_prompt_length: 1000
```

## Environment Variable Substitution

```yaml
host: ${SHIELD_HOST:-0.0.0.0}
port: ${SHIELD_PORT:-8787}
audit_db_path: ${SHIELD_AUDIT_DB:-data/shield_audit.db}
```

## Full Config Reference

### Server

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | str | `"127.0.0.1"` | Bind address |
| `port` | int | `8787` | Port (1-65535) |
| `workers` | int | `1` | Uvicorn worker count (1-16) |

### Defense Pipeline

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_prompt_length` | int | `2000` | Max prompt characters (100-100000) |
| `max_prompt_tokens` | int | `1024` | Max prompt tokens (64-16384) |
| `max_context_tokens` | int | `2048` | Max context tokens (128-32768) |
| `injection_confidence_threshold` | float | `0.7` | Injection detection threshold (0.0-1.0) |

### Defense Filtering

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled_defenses` | list[str] \| None | `None` | Whitelist of defense names (None = all) |
| `disabled_defenses` | list[str] | `[]` | Blacklist of defense names |
| `enabled_scanners` | list[str] \| None | `None` | Whitelist of scanner names (None = all) |
| `disabled_scanners` | list[str] | `[]` | Blacklist of scanner names |

### Failure Policy

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `failure_policy` | str | `"closed"` | `"open"` (allow on error) or `"closed"` (block on error) |

### Ranking Backend

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ranking_backend` | str | `"auto"` | `"auto"`, `"static"`, or `"brorl"` |
| `static_defense_priorities` | dict[str, float] | `{}` | Priority weights for static ranking |

### BroRL

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `brorl_learning_rate` | float | `0.1` | Learning rate for posterior updates |
| `brorl_exploration_bonus` | float | `0.1` | Exploration bonus (0-1) |
| `brorl_epsilon` | float | `0.05` | Epsilon-greedy exploration rate (0-1) |
| `brorl_temperature` | float | `1.0` | Temperature for sampling |

### Telemetry

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `telemetry_enabled` | bool | `True` | Enable telemetry collection |
| `telemetry_buffer_size` | int | `1000` | Ring buffer size (10-100000) |
| `telemetry_flush_interval_seconds` | float | `30.0` | Flush interval |
| `telemetry_privacy_mode` | bool | `True` | Hash prompt content before storage |

### Audit

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `audit_enabled` | bool | `True` | Enable audit logging |
| `audit_db_path` | str | `"data/shield_audit.db"` | SQLite database path |
| `audit_max_prompt_chars` | int | `200` | Max chars stored per prompt (0-10000) |
| `audit_websocket_enabled` | bool | `True` | Enable real-time WebSocket audit stream |

### Red Team

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `use_redteam` | bool | `False` | Enable built-in red team probing |
| `redteam_probe_interval_seconds` | int | `900` | Auto-probe interval (60-86400) |
| `redteam_probe_categories` | list[str] \| None | `None` | Probe categories to run |
| `redteam_alert_success_threshold` | float | `0.3` | Alert when bypass rate exceeds this |

### Defense Profile

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `profile` | str | `"balanced"` | Defense profile preset name |

### IOC Feed

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ioc_file` | str | `""` | Path to IOC feed file |

### Deception

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `deception_enabled` | bool | `False` | Enable deception engine |
| `deception_canary_count` | int | `5` | Number of canary tokens (0-50) |
| `deception_honeypot_count` | int | `3` | Number of honeypot entries (0-20) |

### Alignment Probes

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `alignment_probes_enabled` | bool | `False` | Enable alignment probing |

### Alignment Canaries

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `alignment_canaries_enabled` | bool | `False` | Enable alignment canaries |
| `canary_injection_rate` | int | `50` | One canary per N requests (5-1000) |
| `canary_alert_threshold` | float | `0.3` | Alert threshold for canary failures |
| `canary_categories` | list[str] \| None | `None` | Canary categories to use |

### Threat Intelligence

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `intel_enabled` | bool | `True` | Enable threat intelligence enrichment |
| `geoip_db_dir` | str | `"data/geoip"` | GeoIP database directory |
| `threat_actor_db_path` | str | `"data/threat_actors.db"` | Threat actor SQLite DB path |

### ExfilDetector

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `exfil_single_axis` | bool | `True` | Single-axis mode for faster exfil detection |

### Session Tracking

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_tracking_enabled` | bool | `False` | Enable cross-request session tracking |
| `session_window_size` | int | `10` | Sliding window size (2-100) |

### Advanced Features

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `alignment_scanner_enabled` | bool | `False` | Enable alignment output scanner |
| `sandbag_detection_enabled` | bool | `False` | Enable sandbagging detection |
| `sandbag_sigma_threshold` | float | `2.0` | Z-score threshold for alerts (1.0-5.0) |
| `training_gate_enabled` | bool | `False` | Enable training data gate |
| `training_trust_threshold` | float | `0.7` | Trust score threshold (0.0-1.0) |
| `consistency_check_enabled` | bool | `False` | Enable cross-model consistency checks |
| `consistency_divergence_threshold` | float | `0.3` | Divergence threshold (0.0-1.0) |
| `validation_bridge_enabled` | bool | `False` | Enable validation bridge |
| `aggregator_enabled` | bool | `False` | Enable telemetry aggregation |

## Example Configurations

### Minimal (Development)

```yaml
host: "127.0.0.1"
port: 8787
telemetry_enabled: false
audit_enabled: false
intel_enabled: false
```

### Production

```yaml
host: "0.0.0.0"
port: 8787
workers: 4
failure_policy: closed
max_prompt_length: 4000
injection_confidence_threshold: 0.6
telemetry_enabled: true
telemetry_privacy_mode: true
audit_enabled: true
audit_websocket_enabled: true
intel_enabled: true
use_redteam: true
redteam_probe_interval_seconds: 3600
```

### Strict (High Security)

```yaml
extends: config/production.yaml
failure_policy: closed
max_prompt_length: 1000
max_prompt_tokens: 512
injection_confidence_threshold: 0.5
deception_enabled: true
deception_canary_count: 10
session_tracking_enabled: true
session_window_size: 20
```

## Authentication

Set `SHIELD_API_KEY` environment variable to enable bearer token authentication:

```bash
SHIELD_API_KEY=your-secret-key goop-shield serve
```

Exempt endpoints (no auth required):
- `GET /api/v1/health`
- `GET /api/v1/metrics`
