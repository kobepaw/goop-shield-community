# goop-shield-community v0.3.0 Release Runbook

## Current Status
- Branch: `feat/v0.3-new-defenses` checked out at `~/code/goop-shield-community`
- All 1,476 tests passing on both DGX Spark (Linux) and Kobe (macOS)
- 11 new modules ported, IP audit clean

---

## Stage 4: Final Review (Kobe)

### 4.1 Audit — verify no private IP leaked
```bash
cd ~/code/goop-shield-community

# Private repo / personal references
grep -rn 'goop_net\|goop_overwatch\|brianwtaylor\|FederatedRanking' src/ tests/
grep -rn 'brorl_hub\|ZKAS\|zkas\|psro\|purple_discovery' src/ tests/
grep -rn 'changeme\|node_key\.pem\|192\.168\.\|spark-c231' src/ tests/
grep -rn 'github\.com/brianwtaylor' src/ tests/ docs/ pyproject.toml

# Expected: zero matches (ClawHavoc in supply_chain_guard.py is OK — public tool)
```

### 4.2 Lint + type check
```bash
source .venv/bin/activate
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/
```

### 4.3 Security scan
```bash
bandit -r src/goop_shield/ --severity-level medium
pip-audit --desc --skip-editable
```

### 4.4 License headers — verify all new files
```bash
for f in src/goop_shield/defenses/mcp_guard.py \
         src/goop_shield/defenses/circuit_breaker.py \
         src/goop_shield/defenses/context_window_guard.py \
         src/goop_shield/defenses/plugin_hook_guard.py \
         src/goop_shield/defenses/supply_chain_guard.py \
         src/goop_shield/defenses/application_guard.py \
         src/goop_shield/defenses/operational_guard.py \
         src/goop_shield/ranking/bayesian.py \
         src/goop_shield/composition.py \
         src/goop_shield/red/advanced_probes.py \
         src/goop_shield/red/multi_turn_probes.py; do
    head -2 "$f" | grep -q 'Apache-2.0' && echo "OK: $f" || echo "MISSING: $f"
done
```

### 4.5 Docker build test
```bash
colima start
docker build -f docker/Dockerfile -t goop-shield:v0.3.0-test .
docker run --rm goop-shield:v0.3.0-test goop-shield --help
```

### 4.6 MCP + CLI smoke test
```bash
source .venv/bin/activate
pip install -e ".[server,mcp]"
goop-shield --help
goop-shield serve --help
```

---

## Stage 5: Documentation Updates

### Files to update — search and replace defense counts

```bash
# Find all references to old counts
grep -rn '24.*defenses\|24.*inline\|3.*scanner' \
  README.md docs/ skill/ llms.txt agents.txt
```

### 5.1 README.md
- "24 inline defenses and 3 output scanners" → "36 inline defenses and 4 output scanners"
- "**24 Inline Defenses**" → "**36 Inline Defenses**"
- "**3 Output Scanners**" → "**4 Output Scanners**"
- Add all 12 new defenses to the defense table
- Add AlignmentOutputScanner to output scanner table
- Update architecture diagram counts

### 5.2 docs/index.md
- Update counts

### 5.3 docs/defense-pipeline.md
- Update "24 inline defenses" → 36
- Add sections for each new defense category:
  - Context Window Guard (Structural)
  - Application Guards (ConfigMutationGuard, CredentialPathGuard, AlignmentInlineDefense)
  - Operational Guards (ToolCallFirewall, ApprovalFlowMonitor, ChannelImpersonationGuard)
  - Supply Chain / Plugin / MCP (PluginSupplyChainGuard, PluginHookGuard, MCPGuard)
  - Circuit Breaker

### 5.4 docs/quickstart.md
- `"defenses_loaded": 21` → update to new default count
- `"version": "0.1.0"` → `"0.3.0"`

### 5.5 docs/mcp-integration.md
- Update defenses_loaded count

### 5.6 docs/editions.md
- Update "24 inline defenses"

### 5.7 llms.txt and agents.txt
- Update defense/scanner counts

### 5.8 skill/SKILL.md
- Line 7: update description counts
- Line 13: `version: "0.3.0"`
- Line 18: update counts

### 5.9 SECURITY.md
- Add `0.3.x` to supported versions table

### 5.10 CHANGELOG.md

Add before `[0.1.0]`:

```markdown
## [0.3.0] - 2026-03-05

### Added

#### New Inline Defenses (12)
- **ContextWindowGuard** — deep context injection scanning with boundary/middle sampling
- **ConfigMutationGuard** — configuration file mutation attempt detection
- **CredentialPathGuard** — credential file path access detection
- **AlignmentInlineDefense** — inline alignment violation pattern detection
- **ToolCallFirewall** — tool call argument inspection and filtering
- **ApprovalFlowMonitor** — approval flow bypass attempt detection
- **ChannelImpersonationGuard** — channel/identity impersonation detection
- **PluginSupplyChainGuard** — plugin dependency integrity verification
- **PluginHookGuard** — plugin hook injection detection (TOCTOU defense)
- **MCPGuard** — MCP protocol tool schema validation (first OSS MCP guard)
- **CircuitBreaker** — per-session tool-call loop detection

#### New Ranking Backend
- **BayesianRankingBackend** — Thompson sampling adaptive defense ranking

#### New Red Team Probes
- **MultiTurnProbe** — ABC + 4 multi-turn attack probes (crescendo, DAN, role-play, authority)
- **5 encoding/obfuscation probes** — multilingual, emoji, split-blob, char-split, HTML comment

#### New Composition Engine
- **DefenseCompositionEngine** — cross-defense signal correlation with time-windowed rules

#### Infrastructure
- **PatternBasedDefense** base class for weighted regex-based defenses
- **DEFENSE_NAMES** frozenset — canonical set of all defense/scanner names

### Changed
- Total inline defenses: 24 → 36 (24 default + 12 opt-in)
- Total output scanners: 3 (unchanged)
- Defense registration supports PatternBasedDefense for pattern-matching defenses
```

---

## Stage 6: Release

### 6.0 CRITICAL PREREQUISITE — PyPI Trusted Publisher

Before pushing any tag, set up trusted publishing on PyPI:

1. Go to https://pypi.org/manage/account/publishing/
2. Add pending publisher:
   - PyPI project name: `goop-shield-community`
   - Owner: `kobepaw`
   - Repository: `goop-shield-community`
   - Workflow name: `release.yml`
   - Environment name: `pypi`

Without this, the automated PyPI publish will fail with 403.

### 6.1 Create RELEASE_NOTES_v0.3.0.md

```markdown
# goop-shield-community v0.3.0 Release Notes

## Summary

v0.3.0 adds 12 new inline defenses and a Bayesian ranking backend,
bringing the total to 36 inline defenses and 4 output scanners.

## Highlights — Industry Firsts

- **First OSS MCP protocol guard** — MCPGuard validates tool schemas
  for dangerous parameters before agents can use them
- **First context window defense** — ContextWindowGuard scans 1M+
  token prompts via head/tail/middle sampling
- **First plugin supply chain guard** — PluginSupplyChainGuard detects
  hook injection, OAuth hijack, trojanized dependencies
- **First adaptive defense ranking** — BayesianRankingBackend learns
  from block/bypass outcomes via Thompson sampling

## Breaking Changes

None. All new defenses are opt-in (config-gated) except
CredentialPathGuard and ToolCallFirewall (enabled by default).

## Migration from v0.1.0

Direct upgrade. No config changes required. To enable new defenses:

    shield_config = ShieldConfig(
        mcp_guard_enabled=True,
        circuit_breaker_enabled=True,
        plugin_supply_chain_guard_enabled=True,
        # ... etc
    )

Or use the agent preset to enable all agent-specific defenses:

    shield_config = ShieldConfig(agent_preset=True)
```

### 6.2 Version bump

Edit two files:
```bash
# pyproject.toml line 7
version = "0.3.0"

# src/goop_shield/_version.py line 5
__version__ = "0.3.0"
```

These MUST match or release.yml will fail (lines 48-55 verify tag == version).

### 6.3 Commit, tag, push

```bash
cd ~/code/goop-shield-community
git add -A
git commit -m "chore(release): prepare v0.3.0

Add 12 new inline defenses (36 total), Bayesian ranking backend,
multi-turn probes, composition engine. Update docs and changelog.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"

# Merge to master
git checkout master
git merge feat/v0.3-new-defenses

# Tag and push
git tag -a v0.3.0 -m "Release v0.3.0: 36 inline defenses, 4 output scanners"
git push origin master
git push origin v0.3.0
```

### 6.4 Monitor release workflow

```bash
gh run list --workflow=release.yml
gh run view <RUN_ID> --log
```

The release.yml will:
1. Run test suite (gate)
2. Build + publish to PyPI (trusted publisher)
3. Generate SBOM (cyclonedx-bom)
4. Create GitHub Release with artifacts
5. Build multi-arch Docker image → GHCR
6. Sign container with cosign

### 6.5 Verify

```bash
# PyPI
pip install goop-shield-community==0.3.0
python3 -c "from goop_shield import __version__; print(__version__)"

# Docker
docker pull ghcr.io/kobepaw/goop-shield-community:v0.3.0
docker run --rm ghcr.io/kobepaw/goop-shield-community:v0.3.0 goop-shield --help

# GitHub Release
gh release view v0.3.0 --repo=kobepaw/goop-shield-community

# Docs
curl -s https://kobepaw.github.io/goop-shield-community/ | grep -o '[0-9]* inline defenses'
```

---

## Stage 7: Skill Marketplace Publishing

### 7.1 PyPI — handled automatically by release.yml

### 7.2 Smithery (MCP Marketplace)

```bash
npm install -g @smithery/cli
smithery login
```

Add `smithery.yaml` to repo root:
```yaml
runtime: container
startCommand:
  type: stdio
  configSchema:
    type: object
    properties:
      port:
        type: number
        default: 8787
    required: []
  exampleConfig:
    port: 8787
```

```bash
smithery mcp publish "https://github.com/kobepaw/goop-shield-community" \
  -n kobepaw/goop-shield
```

### 7.3 Official MCP Registry

```bash
brew install mcp-publisher
mcp-publisher login github
mcp-publisher init  # generates servers.json
```

Configure servers.json:
```json
{
  "name": "io.github.kobepaw/goop-shield-community",
  "description": "Runtime defense for AI agents — 36 inline defenses, 4 output scanners",
  "version": "0.3.0",
  "packages": [{
    "registry_type": "pypi",
    "identifier": "goop-shield-community",
    "transport": "stdio"
  }]
}
```

```bash
mcp-publisher publish
```

### 7.4 awesome-mcp-servers

Submit PR to `modelcontextprotocol/servers`:
```bash
gh repo fork modelcontextprotocol/servers
# Add entry to README.md under Security section
gh pr create --title "Add goop-shield-community MCP server" \
  --body "Runtime defense for AI agents with 36 inline defenses, Bayesian ranking, and MCP-native security."
```

### 7.5 Auto-indexed directories (no action needed)

- **PulseMCP** (pulsemcp.com) — auto-crawls PyPI + GitHub
- **mcp.so** — repo already has `mcp` and `mcp-server` topics
- **Glama.ai** — submit manually at glama.ai/mcp if not auto-indexed

---

## New Module Summary (for review reference)

| Module | Type | Default | Lines | Purpose |
|--------|------|---------|-------|---------|
| MCPGuard | InlineDefense | opt-in | 144 | MCP tool schema validation |
| CircuitBreaker | InlineDefense | opt-in | 104 | Tool-call loop detection |
| ContextWindowGuard | InlineDefense | **enabled** | 283 | Deep context injection scanning |
| ToolCallFirewall | PatternBased | **enabled** | — | Tool argument filtering |
| ApprovalFlowMonitor | PatternBased | opt-in | — | Approval bypass detection |
| ChannelImpersonationGuard | PatternBased | opt-in | — | Channel impersonation |
| ConfigMutationGuard | PatternBased | opt-in | — | Config file mutation |
| CredentialPathGuard | PatternBased | **enabled** | — | Credential path access |
| AlignmentInlineDefense | PatternBased | opt-in | — | Alignment violation |
| PluginSupplyChainGuard | PatternBased | opt-in | 282 | Supply chain integrity |
| PluginHookGuard | PatternBased | opt-in | 223 | Hook injection (TOCTOU) |
| BayesianRankingBackend | RankingBackend | — | 191 | Thompson sampling ranking |
| MultiTurnProbe (4) | Probe | — | 241 | Multi-turn attack simulation |
| Advanced Probes (5) | Probe | — | ~170 | Encoding/obfuscation bypass |
| CompositionEngine | Engine | opt-in | ~375 | Cross-defense correlation |

## What Was Intentionally NOT Published

| Component | Reason |
|-----------|--------|
| network/ (ranking.py, peers.py, fingerprint.py) | Reveals federated ZK architecture |
| BroRL enterprise wiring | RL feedback loop — core differentiator |
| ConsistencyChecker | Cross-model consistency — novel |
| SandbagDetector | Performance divergence — unique |
| Alignment canaries | Continuous verification — novel |
| Red team feedback loop | Closed-loop BroRL integration |
| Tier 1 bypass probes (8) | Document specific defense gaps |
| Composition rules 4-7 | Full attack chain taxonomy |
| Context window MD5 seeding | Deterministic sampling strategy |

