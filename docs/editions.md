# Community vs Enterprise Editions

goop-shield ships as two editions. The community edition is fully functional for
runtime defense; enterprise features are stubbed and raise `ImportError` with a
clear message when instantiated.

## Community Edition (this repo)

Everything you need to defend prompts and scan responses:

- **24 inline defenses** — prompt injection, jailbreak, exfiltration, unicode
  evasion, memory poisoning, and more
- **3 output scanners** — secret leak, canary leak, harmful content
- **Static ranking** — deterministic defense ordering
- **Memory protection** — MemoryWriteGuard defense + MemoryIntegrity hash store
- **HTTP API, MCP server, Python SDK** deployment options
- **Deception defense** — honeypot token detection (purely defensive)
- **MITRE ATT&CK mapping** — public framework reference for attack classification

## Enterprise Edition (goop-ai Enterprise)

Adds adaptive and cross-model capabilities on top of community:

| Module | Purpose |
|--------|---------|
| `BroRLRankingBackend` | Thompson sampling adaptive defense prioritization |
| `ConsistencyChecker` | Cross-model response divergence detection |
| `SandbagDetector` | Cross-category performance divergence (Z-score) |
| `TrainingDataGate` | Trust scoring for training data pipelines |
| `QuarantineStore` | Directory-based quarantine for flagged training data |
| `TaskCategorizer` | Keyword-based task classification for sandbagging |
| `ShieldedProvider` | In-process LLM middleware (defend + scan) |
| `ValidationBridge` | Shield blocks to discovery DB records |
| `GoopRangeBridge` | Red probes to GoopRange real-world validation |
| `TelemetryPipeline` | Shield audit to trainer integration |
| `RedTeamRunner` | Adversarial probe execution engine |
| `ProbeScheduler` | Automated probe scheduling |
| `IPEnricher` | GeoIP enrichment (MaxMind + fallback) |
| `ThreatActorDB` | SQLite-backed threat actor and campaign tracking |

### How stubs work

Enterprise modules live in `goop_shield/enterprise/`, `goop_shield/red/`, and
`goop_shield/intel/`. In the community edition, classes import successfully
(preserving type signatures for IDE support) but raise `ImportError` on
instantiation:

```python
from goop_shield.enterprise import ConsistencyChecker

try:
    checker = ConsistencyChecker(providers=[...])
except ImportError as e:
    print(e)  # "ConsistencyChecker requires goop-ai Enterprise..."
```

The main application (`app.py`) wraps all enterprise initialization in
`try/except (ImportError, NotImplementedError)` blocks, so enabling enterprise
features in config on the community edition logs a warning instead of crashing.

### Experimental modules

The `goop_shield/_experimental/` directory contains functional modules not yet
wired into the main pipeline:

- `drift_detector` — defense behavior drift detection over time
- `supply_chain` — artifact and dependency integrity validation
- `memory_integrity` — file hash store for tamper detection

These are included to show the roadmap for future community integration.
