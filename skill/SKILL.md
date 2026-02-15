---
name: shield
description: >-
  AI agent guardrails — defends prompts against injection attacks, jailbreaks,
  and evasion; scans LLM responses for leaked secrets and harmful content.
  24 inline defenses, 3 output scanners, BroRL-ranked pipeline.
  Keywords: shield, guardrails, prompt injection, defense, security, scan.
license: Apache-2.0
compatibility: Requires Python 3.11+ and pip/pipx/uvx for installation
argument-hint: "[setup|config|status] [strict|balanced|permissive]"
metadata:
  author: brianwtaylor
  version: "0.1.0"
---

# Shield

Runtime defense pipeline for AI agents. Intercepts prompts before they reach an LLM and scans responses before they reach the user. 24 inline defenses and 3 output scanners, ranked by a BroRL (Thompson sampling) backend that learns which defenses are most effective.

## Quick Start

```
Run: pip install goop-shield[mcp]
Run: scripts/setup.sh balanced
Run: python scripts/check.py
```

The setup script configures your MCP server entry and creates a default `shield.yaml`. The check script verifies the server starts and all defenses load.

## Core Workflow: Defending Prompts

**ALWAYS defend user prompts before sending them to an LLM.**

Use the `shield_defend` tool:

```json
{
  "prompt": "the user's prompt text",
  "session_id": "conversation-123",
  "context": {}
}
```

- `prompt` (required): The raw prompt to defend.
- `session_id` (optional): Ties requests to a conversation for multi-turn attack detection. Use the same session ID for all turns in a conversation.
- `context` (optional): Arbitrary metadata passed to defenses.

### Interpreting Results

```json
{
  "allowed": true,
  "filtered_prompt": "cleaned prompt text",
  "defenses_applied": ["prompt_normalizer", "safety_filter", "..."],
  "confidence": 0.12,
  "latency_ms": 8.3
}
```

| Field | Meaning |
|-------|---------|
| `allowed` | `true` = safe to send to LLM. `false` = blocked. |
| `filtered_prompt` | The sanitized prompt. Use this instead of the original when `allowed=true`. |
| `confidence` | Threat confidence score (0-1). |
| `latency_ms` | Pipeline execution time. |

### Decision Logic

- `allowed=true` -- Use `filtered_prompt` as the LLM input.
- `allowed=false` -- Do NOT send to LLM. Inform the user: *"Your request was blocked by security policy."* Never reveal which defense triggered or how to bypass it.

### Confidence Thresholds

| Range | Interpretation |
|-------|---------------|
| > 0.8 | Definite attack. Prompt will almost certainly be blocked. |
| 0.5 - 0.8 | Suspicious. May be blocked depending on active defenses and preset. |
| < 0.5 | Likely benign. Prompt will usually be allowed (possibly sanitized). |

## Core Workflow: Scanning Responses

**Scan LLM responses before returning them to the user.**

Use the `shield_scan` tool:

```json
{
  "response_text": "the LLM response",
  "original_prompt": "the prompt that produced this response"
}
```

- `response_text` (required): The LLM output to scan.
- `original_prompt` (optional but recommended): Enables cross-reference detection (e.g., canary token leaks).

### Interpreting Results

```json
{
  "safe": true,
  "filtered_response": "cleaned response text",
  "scanners_applied": ["secret_leak", "canary_leak", "harmful_content"],
  "confidence": 0.05,
  "latency_ms": 3.1
}
```

- `safe=true` -- Return `filtered_response` to the user.
- `safe=false` -- The response contains leaked secrets, canary tokens, or harmful content. Do NOT return it. Either redact the flagged content or inform the user the response was filtered.

The three output scanners:
- **secret_leak** -- Detects API keys, passwords, tokens in output.
- **canary_leak** -- Detects leaked canary/honeypot tokens.
- **harmful_content** -- Detects harmful, toxic, or policy-violating content.

## Health and Status

### Check Health

Use `shield_health` (no arguments):

```json
{
  "status": "healthy",
  "defenses_loaded": 21,
  "scanners_loaded": 3,
  "uptime_seconds": 3600.0,
  "total_requests": 142,
  "total_blocked": 7
}
```

Use this to verify Shield is running and to monitor block rates.

### Inspect Configuration

Use `shield_config` (no arguments):

```json
{
  "active_defenses": ["prompt_normalizer", "safety_filter", "..."],
  "active_scanners": ["secret_leak", "canary_leak", "harmful_content"],
  "failure_policy": "closed",
  "ranking_backend": "auto",
  "total_defenses": 21,
  "total_scanners": 3
}
```

## Configuration

### Presets

| Preset | Behavior |
|--------|----------|
| `strict` | Fail-closed. Low confidence thresholds. Blocks aggressively. Best for high-security environments. |
| `balanced` | Default. Reasonable thresholds. Good balance of security and usability. |
| `permissive` | Logging-only mode. High thresholds. Rarely blocks. Use for monitoring without enforcement. |

Set via setup script:
```
Run: scripts/setup.sh strict
```

### Custom Configuration

Create a `shield.yaml` in your project root:

```yaml
failure_policy: closed
injection_confidence_threshold: 0.5
max_prompt_length: 4000
disabled_defenses:
  - output_watermark
session_tracking_enabled: true
```

Point the MCP server at it:
```json
{
  "command": "goop-shield",
  "args": ["mcp", "--config", "shield.yaml"]
}
```

### Per-Request Overrides

Pass metadata in the `context` dict of `shield_defend`. Keys like `signing_key`, `canary_tokens`, and `allowed_intents` are consumed by specific defenses:

```json
{
  "prompt": "...",
  "session_id": "abc-123",
  "context": {
    "signing_key": "my-hmac-key"
  }
}
```

See [references/configuration.md](references/configuration.md) for the full field reference.

## Setup for Different Agents

All agents use the same MCP server command: `goop-shield mcp [--config path]`

| Agent | Config File |
|-------|-------------|
| Claude Code | `.mcp.json` |
| Cursor | `.cursor/mcp.json` |
| Windsurf | `.windsurf/mcp.json` |
| GitHub Copilot | `.github/copilot-mcp.json` |
| Continue.dev | `.continue/config.yaml` |

Example `.mcp.json` entry:

```json
{
  "mcpServers": {
    "goop-shield": {
      "command": "goop-shield",
      "args": ["mcp", "--config", "shield.yaml"]
    }
  }
}
```

## References

- [Defense catalog](references/defenses.md) -- All 24 inline defenses and 3 output scanners
- [Configuration reference](references/configuration.md) -- Every config field with types and defaults
- [API reference](references/api-reference.md) -- MCP tool schemas and response formats
