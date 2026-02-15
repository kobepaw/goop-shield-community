# Changelog

All notable changes to goop-shield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-02-12

Initial public release of goop-shield.

### Added

#### Core Defense Pipeline
- 24 inline defenses with 3 mandatory (PromptNormalizer, SafetyFilter, AgentConfigGuard)
- 3 output scanners: SecretLeakScanner, CanaryLeakScanner, HarmfulContentScanner
- BroRL adaptive defense ranking via Thompson Sampling with static fallback
- Configuration profiles: balanced, strict, permissive

#### Inline Defenses
- **PromptNormalizer** — Unicode normalization, confusable detection, bidi/tag stripping
- **SafetyFilter** — core injection pattern matching
- **InjectionBlocker** — configurable-threshold injection detection
- **AgentConfigGuard** — cross-vendor protection for AI agent config files (.claude, .cursor, .mcp.json, etc.)
- **IndirectInjectionDefense** — detection of malicious instructions in tool/RAG outputs
- **ExfilDetector** — data exfiltration pattern detection
- **ObfuscationDetector** — base64, hex, ROT13, URL-encoded payload detection
- **RAGVerifier** — injection delimiter detection in RAG content
- **AgentSandbox** — multi-signal scoring for agent abuse patterns
- **RateLimiter** — global RPM/TPM enforcement
- **SessionTracker** — sliding-window multi-turn attack detection with optional blocking
- **DeceptionEngine** — canary token injection and honeypot generation
- **IOCMatcher** — indicator of compromise matching (domains, IPs, hashes)
- **DomainReputation** — domain reputation scoring
- **PromptSigner** — prompt integrity verification

#### Output Scanners
- **SecretLeakScanner** — 17 patterns covering AWS keys, GitHub tokens, JWTs, database URLs, Slack/Stripe/Twilio/SendGrid tokens, and more
- **CanaryLeakScanner** — detects leaked canary tokens in LLM responses
- **HarmfulContentScanner** — 17 patterns covering shell injection, subprocess calls, eval/exec, SQL injection, dangerous permissions

#### Red Team & Alignment
- RedTeamRunner with 22 probes across 10 attack categories
- 7 alignment probes: sandbagging, deception, power-seeking, sycophancy, instruction leaking, goal drift, selective compliance
- Alignment canary system for continuous alignment monitoring

#### Integrations
- MCP server integration (`goop-shield mcp`)
- FastAPI standalone application with REST API
- Framework adapters: LangChain, CrewAI, OpenClaw, Generic HTTP
- Vendor-neutral agent skill for AI-assisted onboarding

#### Observability
- Audit logging with SQLite backend and WebSocket streaming
- Threat intelligence integration (opt-in, disabled by default)
- Advanced modules: SandbagDetector, ConsistencyChecker, TrainingGate, Aggregator

### Security
- Default `failure_policy` set to `"closed"` (fail-safe — defenses that error will block, not pass through)
- Advanced configuration fields clearly documented
- External API calls and threat intel disabled by default for privacy

### Fixed
- MCP command documentation corrected from `goop-shield-mcp` to `goop-shield mcp`
- Default server port set to 8787
- Internal codename references replaced with "Shield" throughout
