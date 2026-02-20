# Changelog

All notable changes to goop-shield-community are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [0.2.0] — 2026-02-19

### Added

#### OpenClaw Adapter — Sub-agent hardening and P1 security hooks

- **Sub-agent context propagation**: `OpenClawAdapter` now extracts `session_id`, `parent_agent_id`, `agent_depth`, and `task_content` from OpenClaw event envelopes and propagates them into the defense context. `SubAgentGuard` uses this to apply tighter thresholds at depth > 0. Without this, spawned child agents ran with the same permissive context as the root session.

- **Gateway origin validation (CVE-2026-25253)**: New `allowed_origins` config parameter on `OpenClawAdapter`. Incoming JSON-RPC WebSocket messages are validated against the allowlist before processing. Rejects connections from unexpected origins to prevent SSRF-style gateway hijacking via malicious web pages or injected iframes.

- **`llm_input` hook — `from_llm_input_event()`**: Intercepts the fully-assembled prompt (system + user + context) before it reaches the LLM. Catches injection patterns that span system/user message boundaries and wouldn't be visible in per-message scanning. Emits a `ShieldResult`.

- **`llm_output` hook — `from_llm_output_event()`**: Scans LLM responses on egress before delivery to the caller. Runs all output scanners (secret leak, canary, harmful content). Emits a `ScanResult`.

- **Sub-agent spawn interception — `intercept_subagent_spawn()`**: Scans `sessions_spawn` task delegation payloads as independent inputs. Task content is a separate attack surface from the main prompt — an injection string embedded in a delegation task bypasses all upstream scanning that only watches the system+user context window. Also enforces `max_agent_depth` at the adapter level as defense-in-depth.

- **External content trust levels**: `scan_tool_output()` and `from_tool_result()` now detect OpenClaw's `<<<EXTERNAL_UNTRUSTED_CONTENT>>>` markers and automatically set `trust_level=untrusted` and `has_external_content=True` in the defense context. Downstream defenses that gate on trust level (e.g. `openclaw_xss_event_handler`) activate automatically — no configuration required.

- **JSON-RPC `subagent_spawn` event routing**: `from_jsonrpc_message()` now routes `subagent_spawn` method calls through `intercept_subagent_spawn()`.

- **New `OpenClawAdapter` config options**:
  - `allowed_origins: list[str]` — WebSocket origin allowlist (CVE-2026-25253)
  - `max_agent_depth: int` — Maximum allowed agent recursion depth (default: `5`)
  - `llm_hooks_enabled: bool` — Enable `llm_input`/`llm_output` hooks (default: `True`)
  - `spawn_interception_enabled: bool` — Enable `intercept_subagent_spawn()` (default: `True`)

#### SubAgentGuard — New attack pattern coverage

- **Task delegation attacks** (new pattern group):
  - `task_instruction_override` — Instruction override embedded in spawned task content
  - `privilege_laundering` — Spawning a child agent with elevated scope to bypass parent controls
  - `task_exfiltration` — Exfiltration request disguised as legitimate task delegation

- **OpenClaw-specific threats** (new pattern group):
  - `openclaw_cwd_injection` — Working directory manipulation via tool args
  - `openclaw_cross_session_targeting` — References to other agent sessions in tool calls
  - `openclaw_gateway_url_override` — Gateway endpoint redirection in config payloads
  - `openclaw_bind_mount_escape` — Container breakout via bind mount manipulation

- **Task content scanning**: Task payloads passed to `sessions_spawn` are now scanned as a separate field in addition to the main prompt. Previously only the top-level prompt was scanned.

#### CI Pipeline hardening

- **`workflow-sanity.yml`**: New workflow runs on every PR.
  - `actionlint` validates all GitHub Actions workflow files against the schema, catching injection vectors and undefined context references before merge.
  - Composite action input interpolation check blocks direct `inputs.*` expression usage inside `run:` blocks — a documented GitHub Actions injection class.

- **`stale.yml`**: Automated stale issue/PR management.
  - Issues: stale at 14 days, close at 7.
  - PRs: stale at 10 days, close at 5.
  - `security` and `no-stale` labels exempt all issues from auto-close.
  - Active updates reset stale timers automatically.

- **`.secrets.baseline` + detect-secrets CI job**: Committed baseline documents all intentional secret-shaped strings in the codebase (test fixtures, doc examples). New secrets introduced in PRs fail CI with a clear remediation message. Complements the existing gitleaks scan with lifecycle management for known-safe patterns.

- **mypy enforced**: Removed `continue-on-error: true` from the mypy step. Fixed 72 type errors across 10 source files. Per-module override for `goop_shield.app` scopes the suppression narrowly — FastAPI route handlers idiomatically return both `dict` and `JSONResponse` (runtime-transparent, not expressible in the type system without the override).

- **`.gitleaks.toml`**: Added path allowlist for `tests/`, `docs/`, `examples/`, `README.md`, and `.secrets.baseline`. Prevents false positives on test fixture credentials used to validate goop-shield's own detection patterns.

### Changed

#### XSS defense — False positive reduction

- **`openclaw_xss_in_response` split into two patterns**:

  | Pattern | Label | Always active |
  |---|---|---|
  | `<script[\s>]\|javascript\s*:` | `openclaw_xss_script_tag` | Yes |
  | `on(?:error\|load\|click\|mouseover)\s*=` | `openclaw_xss_event_handler` | Only when `has_external_content=True` or `trust_level=untrusted` |

  **Before**: The event handler pattern fired on all content, including internal coding discussions with legitimate JavaScript event handler syntax. False positive rate: **79%** on internal coding prompts.

  **After**: The event handler pattern only activates on external/untrusted content — which OpenClaw marks with `<<<EXTERNAL_UNTRUSTED_CONTENT>>>`. Real XSS payloads targeting the canvas always arrive via external sources. Internal coding conversations are not affected.

  Attack detection rate: **unchanged at 100%**. False positive rate: **0%** on internal content.

  > A defense with a 79% false positive rate gets disabled. A disabled defense is worse than no defense — it creates the illusion of coverage. Calibrating on context preserves detection while eliminating noise.

### Fixed

- **`scan_tool_output` trust level propagation**: `trust_level = "untrusted"` was assigned to a local variable but never stored back into `ctx`. External content markers were detected correctly but the trust level was not visible to downstream defenses. Fixed: `ctx["trust_level"] = "untrusted"`.

- **Type safety across 10 source files**: 72 mypy errors resolved including `Callable` type annotation in `consistency_checker.py`, `maketrans` dict type in `heuristic.py`, `session_id` cast from `context.get()`, `float` casts in `_compute_overall_confidence()`, enterprise module attribute suppression in `gooprange_bridge.py`, and yaml stub types.

---

## [0.1.0] — 2026-02-14

### Added

- Initial public release of goop-shield-community
- 24 inline defense layers across Mandatory, Ranked, and IOC-based categories
- 3 output scanners: SecretLeakScanner, CanaryLeakScanner, HarmfulContentScanner
- BroRL adaptive defense ranking (Bayesian multi-armed bandit)
- Signal fusion (noisy-OR across weak threat signals)
- SubAgentGuard base patterns (agent impersonation, prompt hijacking, scope escalation)
- OpenClaw adapter with WebSocket event interception and JSON-RPC message filtering
- LangChain, CrewAI, and generic HTTP adapters
- MCP server for Claude Desktop and tool-calling LLM integration
- FastAPI application server with audit, telemetry, and red-team endpoints
- Docker support
- Python 3.11–3.13 compatibility

[0.2.0]: https://github.com/kobepaw/goop-shield-community/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kobepaw/goop-shield-community/releases/tag/v0.1.0
