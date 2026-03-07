# Defense Pipeline

goop-shield ships with 24 inline defenses and 3 output scanners. This document describes each one.

## Pipeline Execution Order

1. **Mandatory defenses** run first, in fixed order (not reorderable)
2. **Ranked defenses** run in order determined by the ranking backend
3. **Output scanners** run on the `/api/v1/scan-response` endpoint

If any defense blocks, the pipeline short-circuits immediately. If a defense sanitizes the prompt, the sanitized version is passed to downstream defenses.

---

## Mandatory Defenses

These three defenses always run first. They set `mandatory = True` and cannot be reordered by BroRL or static ranking.

### 1. PromptNormalizer

**Category**: Heuristic | **Mandatory**: Yes

Neutralizes Unicode and encoding evasion techniques:

- **Unicode normalization** (NFC) to collapse equivalent character representations
- **Confusable character detection** -- maps 62+ homoglyphs (Cyrillic, Greek, Armenian) back to Latin equivalents
- **Leetspeak decoding** -- `0->o, 1->i, 3->e, 4->a, 5->s, 7->t, @->a, $->s`
- **Whitespace normalization** -- collapses zero-width characters, invisible separators
- **Encoding detection** -- recursively decodes base64, hex, URL encoding, HTML entities (depth 2)

Runs first so all downstream defenses see a normalized prompt.

### 2. SafetyFilter

**Category**: Heuristic | **Mandatory**: Yes

Pattern-based safety filtering with keyword lists and regex rules. Catches explicit harmful content, policy violations, and known-bad prompt patterns.

### 3. AgentConfigGuard

**Category**: Behavioral | **Mandatory**: Yes

Detects attempts to modify AI agent configuration files. Vendor-neutral across 9 AI agents:

- Claude Code (`.claude/`, `CLAUDE.md`, `.mcp.json`)
- Cursor (`.cursor/`, `.cursorrc`)
- Windsurf (`.windsurf/`, `.windsurfrc`)
- Cline (`.cline/`, `cline_mcp_settings.json`)
- Roo Code (`.roo/`, `.roomcp`)
- GitHub Copilot (`.github/copilot/`)
- Aider (`.aider*`)
- Continue.dev (`.continue/`)
- OpenAI Codex (`.codex/`)

Matches 47 config file patterns against 19+ modification verbs (write, edit, overwrite, append, etc.) including non-English verbs (Spanish, French, German, Russian). Supports negation awareness ("don't modify" is not flagged) and cross-turn detection via session tracking.

---

## Ranked Defenses

These 18 defenses are ordered by the ranking backend. Listed here by category.

### Heuristic

#### 4. InputValidator

Validates prompt length and format. Blocks prompts exceeding `max_prompt_length` (default 2000 chars) or `max_prompt_tokens` (default 1024).

#### 5. InjectionBlocker

Detects SQL injection, OS command injection, and prompt injection patterns. Uses regex-based detection with configurable confidence threshold (`injection_confidence_threshold`, default 0.7).

#### 6. ContextLimiter

Prevents context window abuse where an attacker tries to fill the context window with padding to push instructions out of scope. Enforces `max_context_tokens` (default 2048).

#### 7. OutputFilter

Filters response content for policy violations. Applied during the defense pipeline for prompt-side content patterns.

### Crypto

#### 8. PromptSigning

Computes a cryptographic signature for the prompt to verify integrity. Detects if the prompt has been tampered with between signing and execution.

#### 9. OutputWatermark

Watermarks LLM responses for provenance tracking. Embeds invisible markers that survive copy/paste and light editing.

### Content

#### 10. RAGVerifier

Detects injection attacks targeting RAG (Retrieval-Augmented Generation) pipelines. Catches attempts to poison retrieved documents with adversarial instructions.

#### 11. CanaryTokenDetector

Detects attempts to extract canary tokens planted by the deception engine. Checks both the current (normalized) prompt and the original prompt to avoid false negatives from normalizer transformations.

#### 12. SemanticFilter

Semantic similarity-based filtering. Compares prompt embeddings against known-bad patterns using vector similarity rather than exact string matching.

#### 13. ObfuscationDetector

Detects encoded, obfuscated, or multi-layer-encoded payloads. Catches base64-wrapped instructions, hex-encoded commands, and nested encoding schemes.

### Behavioral

#### 14. AgentSandbox

Enforces sandboxing rules for agent execution. Restricts file system access, network calls, and subprocess execution based on configured policies.

#### 15. RateLimiter

Token-bucket rate limiting per source IP or session. Prevents brute-force probing and resource exhaustion attacks.

#### 16. PromptMonitor

Monitors prompt patterns over time. Detects anomalous prompt sequences, repeated probing patterns, and gradual escalation attempts.

#### 17. ModelGuardrails

Enforces model-specific guardrails. Applies different rules depending on the target LLM model (e.g., stricter rules for instruction-tuned models).

#### 18. IntentValidator

Classifies prompt intent and validates it against allowed intent categories. Blocks prompts with mismatched or suspicious intent signals.

#### 19. ExfilDetector

Detects data exfiltration attempts. Analyzes prompts for patterns that would cause the LLM to leak sensitive data. Supports single-axis mode (`exfil_single_axis=True`) for faster detection with reduced precision.

### IOC-Based

#### 20. DomainReputationDefense

Checks URLs and domains referenced in prompts against reputation databases. Blocks known-malicious domains, phishing URLs, and C2 infrastructure.

#### 21. IOCMatcherDefense

Matches Indicators of Compromise (hashes, IPs, domains, URLs) found in prompts against a threat intelligence feed. Configurable via the `ioc_file` config field.

---

## Output Scanners

Output scanners run on the `/api/v1/scan-response` endpoint to check LLM responses before they reach the user.

### SecretLeakScanner

Detects leaked secrets in LLM responses:
- API keys (AWS, GCP, Azure, GitHub, Stripe, etc.)
- Passwords and connection strings
- Private keys and certificates
- Bearer tokens and JWTs

### CanaryLeakScanner

Detects canary tokens that were planted by the deception engine. If an LLM response contains a canary, it indicates the model has been tricked into revealing planted traps.

### HarmfulContentScanner

Detects harmful, toxic, or policy-violating content in LLM responses. Catches content that passed the prompt-side defenses but resulted in a harmful output.

---

## Enabling and Disabling Defenses

### Via Configuration

```yaml
# Enable only specific defenses
enabled_defenses:
  - prompt_normalizer
  - safety_filter
  - injection_blocker
  - exfil_detector

# Or disable specific defenses (all others remain active)
disabled_defenses:
  - rate_limiter
  - output_watermark

# Same for scanners
disabled_scanners:
  - harmful_content_scanner
```

### Via Python

```python
from goop_shield.defenses import DefenseRegistry, register_defaults

registry = DefenseRegistry()
register_defaults(registry)

# Remove a defense
registry.remove("rate_limiter")

# Add a custom defense
registry.register(MyCustomDefense())
```

## Defense Verdicts

Each defense returns an `InlineVerdict` with:

| Field | Type | Description |
|-------|------|-------------|
| `defense_name` | str | Name of the defense |
| `blocked` | bool | Whether the prompt was blocked |
| `sanitized` | bool | Whether the prompt was modified |
| `filtered_prompt` | str | The (potentially modified) prompt |
| `confidence` | float | Confidence in the decision (0-1) |
| `threat_confidence` | float | Confidence that this is an attack (0-1) |
| `details` | str | Human-readable explanation |
| `metadata` | dict | Additional structured data |
