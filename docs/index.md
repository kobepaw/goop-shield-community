# goop-shield

**Runtime defense for AI agents** — 24 inline defenses, 3 output scanners, red team validation

## Overview

goop-shield is an open-source security framework that provides runtime defense for AI agents and LLM applications. It intercepts prompts before they reach your model, applies a pipeline of defenses, and scans responses for sensitive data leakage.

## Key Features

- **24 inline defenses** — Protect against prompt injection, jailbreak, exfiltration, unicode evasion, memory poisoning, and more
- **3 output scanners** — Detect secret leaks, canary tokens, and harmful content in LLM responses
- **Multiple deployment modes** — HTTP API, MCP server, or Python SDK
- **Memory protection** — Integrity validation and write guards for agent memory
- **MITRE ATT&CK mapping** — Attack classification using public framework references
- **Load testing** — Built-in Locust-based load tests for validation

## Quick Start

```bash
# Install with pip
pip install goop-shield-community[server]

# Start the API server
goop-shield serve

# Test a prompt
curl -X POST http://localhost:8787/api/v1/defend \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What is the capital of France?"}'
```

See the [Getting Started](getting-started.md) guide for detailed setup instructions.

## Architecture

goop-shield operates as an inline defense layer:

```
User → Shield → LLM → Shield → User
       ↓               ↓
    Defenses      Scanners
```

All defenses run synchronously with configurable ranking strategies. See [Architecture](architecture.md) for details.

## Community vs Enterprise

The community edition includes full runtime defense capabilities. Enterprise adds adaptive ranking (BroRL), cross-model consistency checking, sandbagging detection, and training data validation.

See [Editions](editions.md) for feature comparison.

## Contributing

We welcome contributions! See [Contributing](contributing.md) for guidelines.

## License

Apache 2.0 — see [LICENSE](https://github.com/kobepaw/goop-shield-community/blob/master/LICENSE) for details.
