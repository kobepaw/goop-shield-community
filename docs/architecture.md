# Architecture

goop-shield processes prompts and responses through a layered defense pipeline, with adaptive ranking and full audit visibility.

## High-Level Flow

```
                    +---------+
                    | Client  |  (HTTP, MCP, SDK, Adapter)
                    +----+----+
                         |
                         v
                +--------+--------+
                | Auth Middleware  |  SHIELD_API_KEY env var
                +--------+--------+
                         |
            +------------+------------+
            |                         |
            v                         v
    +-------+--------+      +--------+--------+
    | /api/v1/defend |      | /api/v1/scan    |
    +-------+--------+      +--------+--------+
            |                         |
            v                         v
    +-------+--------+      +--------+--------+
    |   Defender      |      | Output Scanner  |
    |   Orchestrator  |      | Pipeline        |
    +-------+--------+      +--------+--------+
            |                         |
            v                         v
    +-------+--------+      +--------+--------+
    | Telemetry &    |      | Telemetry &     |
    | Audit DB       |      | Audit DB        |
    +----------------+      +-----------------+
```

## Three-Layer Defense

### Layer 1: Mandatory Defenses

Three defenses always execute first, in fixed order, regardless of ranking:

1. **PromptNormalizer** -- normalizes Unicode, detects confusable characters (homoglyphs), decodes leetspeak. This neutralizes evasion techniques before other defenses see the prompt.
2. **SafetyFilter** -- keyword and regex pattern matching for known-bad content.
3. **AgentConfigGuard** -- detects attempts to modify AI agent configuration files (`.claude/`, `.cursor/`, `.mcp.json`, etc.) across 9 vendor agents.

Mandatory defenses set `mandatory = True` on the `InlineDefense` base class. The Defender always runs them before consulting the ranking backend.

### Layer 2: Ranked Defenses

The remaining 18 defenses are ordered by a pluggable ranking backend:

- **Static ranking** (default in open-source): fixed priority order based on `static_defense_priorities` config.
- **BroRL ranking**: Thompson sampling with Beta(alpha, beta) distributions. Each defense has a posterior that updates from observed block/allow outcomes. Defenses that catch more attacks rise in priority.

The Defender executes ranked defenses sequentially. If any defense blocks, execution short-circuits immediately. If a defense sanitizes the prompt (e.g., removes encoded payloads), the sanitized version is passed to downstream defenses.

### Layer 3: Output Scanners

After the LLM generates a response, output scanners check for:

1. **SecretLeakScanner** -- API keys, passwords, tokens, connection strings
2. **CanaryLeakScanner** -- canary tokens planted by the deception engine
3. **HarmfulContentScanner** -- harmful, toxic, or policy-violating content

Output scanners run on the `/api/v1/scan-response` endpoint.

## Core Components

### Defender (Orchestrator)

`goop_shield.defender.Defender` is the central orchestrator. It:

1. Builds a `DefenseContext` from the incoming `DefendRequest`
2. Runs mandatory defenses first
3. Consults the `RankingBackend` to order remaining defenses
4. Executes defenses sequentially, chaining sanitized prompts
5. Records per-defense statistics for BroRL learning
6. Returns a `DefendResponse` with allow/block decision

### DefenseRegistry

Manages registration and lookup of inline defenses and output scanners. Defenses are registered by name:

```python
from goop_shield.defenses import DefenseRegistry, register_defaults

registry = DefenseRegistry()
register_defaults(registry)
print(registry.names())  # ['prompt_normalizer', 'safety_filter', ...]
```

### RankingBackend

Abstract interface for defense ordering. Two implementations:

- `StaticRanking` -- uses configured priority weights
- `BroRLRanking` -- adaptive Thompson sampling

### ShieldConfig

Pydantic v2 configuration model with YAML loading, env var substitution, and `extends` inheritance:

```yaml
extends: defaults/base.yaml
port: 9000
max_prompt_length: 4000
injection_confidence_threshold: 0.8
```

### TelemetryBuffer

Async ring buffer that batches telemetry events and flushes them periodically. Supports privacy mode (hashes prompt content before storage).

### ShieldAuditDB

SQLite-backed audit trail. Records every defend/scan request with:
- Source IP, user agent, headers hash
- Shield action (allow/block/sanitize)
- Attack classification
- Per-defense verdicts
- Latency

Supports paginated queries, time-range filtering, and summary aggregation.

## Request Lifecycle

A typical `/api/v1/defend` request:

1. **Auth check** -- `ShieldAuthMiddleware` validates bearer token (if `SHIELD_API_KEY` set)
2. **Build context** -- `DefenseContext(original_prompt=..., current_prompt=...)`
3. **Mandatory defenses** -- PromptNormalizer, SafetyFilter, AgentConfigGuard execute in order
4. **Ranking** -- backend returns ordered list of remaining defenses
5. **Execute pipeline** -- each defense gets `context`, may block or sanitize
6. **Short-circuit** -- on first block, pipeline stops immediately
7. **Build response** -- `DefendResponse(allow=..., filtered_prompt=..., verdicts=...)`
8. **Telemetry** -- events queued to `TelemetryBuffer`
9. **Audit** -- event recorded to `ShieldAuditDB` with threat intel enrichment
10. **Return** -- minimal response (public endpoint) or full telemetry (debug endpoint)

## Deployment Modes

### Standalone Server

```bash
goop-shield serve --port 8787
```

### Docker Sidecar

Run Shield alongside your application:

```yaml
services:
  app:
    image: my-app:latest
    environment:
      SHIELD_URL: http://shield:8787
  shield:
    image: goop-shield:latest
    ports:
      - "8787:8787"
```

### MCP Server

Embed Shield directly into AI agent workflows via Model Context Protocol:

```bash
goop-shield mcp --port 8787
```

### Python Embedding

Use the Defender directly without HTTP:

```python
from goop_shield.config import ShieldConfig
from goop_shield.defender import Defender
from goop_shield.models import DefendRequest

config = ShieldConfig(max_prompt_length=4000)
defender = Defender(config)

request = DefendRequest(prompt="Some user input")
response = defender.defend(request)
print(response.allow, response.filtered_prompt)
```

## Security Model

- **Auth**: Bearer token via `SHIELD_API_KEY` env var. Health/metrics endpoints are auth-exempt.
- **Failure policy**: configurable `open` (allow on error) or `closed` (block on error).
- **Minimal public API**: The `/api/v1/defend` endpoint returns no defense names or per-verdict details to prevent adaptive attackers from fingerprinting the pipeline. Full telemetry is available at `/debug/defend` (requires auth).
- **Session tracking**: optional sliding-window tracker for multi-turn attack detection across requests.
