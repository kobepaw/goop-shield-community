# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield Configuration

Pydantic v2 configuration for the Shield service.
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _ShieldBaseConfig(BaseModel):
    """Base configuration for Shield (inlined from goop.config.base.BaseConfig)."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        str_strip_whitespace=True,
    )
    extends: str | None = Field(
        default=None,
        description="Path to base config to inherit from",
        exclude=True,
    )


class ShieldConfig(_ShieldBaseConfig):
    """
    Configuration for the Shield runtime defense service.

    Inherits from BaseConfig: frozen=True, extra="forbid", env var substitution.
    """

    # Mandatory defenses that cannot be disabled
    MANDATORY_DEFENSES: ClassVar[frozenset[str]] = frozenset(
        {
            "prompt_normalizer",
            "safety_filter",
            "input_validator",
            "injection_blocker",
        }
    )

    # Server
    host: str = "127.0.0.1"
    port: int = Field(default=8787, ge=1, le=65535)
    workers: int = Field(default=1, ge=1, le=16)

    # Authentication
    api_key: str = Field(
        default="",
        repr=False,
        description="Pre-configured API key (overrides SHIELD_API_KEY env var)",
    )

    # CORS
    cors_origins: list[str] = Field(
        default_factory=list, description="Allowed CORS origins (empty = no CORS)"
    )

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    # Ranking backend
    ranking_backend: Literal["auto", "static", "brorl"] = "auto"
    static_defense_priorities: dict[str, float] = Field(default_factory=dict)

    # Defense pipeline
    max_prompt_length: int = Field(default=2000, ge=100, le=100000)
    max_prompt_tokens: int = Field(default=1024, ge=64, le=16384)
    max_context_tokens: int = Field(default=2048, ge=128, le=32768)
    injection_confidence_threshold: float = Field(default=0.7, ge=0.01, le=1.0)

    # BroRL — local Bayesian and Enterprise backends
    brorl_learning_rate: float = Field(
        default=0.1,
        gt=0,
        le=1.0,
        description="Used by local Bayesian and Enterprise backends",
    )
    brorl_exploration_bonus: float = Field(default=0.1, ge=0, le=1.0, description="Enterprise only")
    brorl_epsilon: float = Field(default=0.05, ge=0, le=1.0, description="Enterprise only")
    brorl_temperature: float = Field(default=1.0, gt=0, description="Enterprise only")
    brorl_state_path: str = Field(
        default="data/brorl_state.json",
        description="Path for persisting BroRL posteriors across restarts",
    )

    # Telemetry
    telemetry_enabled: bool = True
    telemetry_buffer_size: int = Field(default=1000, ge=10, le=100000)
    telemetry_flush_interval_seconds: float = Field(default=30.0, gt=0)
    telemetry_privacy_mode: bool = True

    # Defense filtering
    enabled_defenses: list[str] | None = None
    disabled_defenses: list[str] = Field(default_factory=list)
    enabled_scanners: list[str] | None = None
    disabled_scanners: list[str] = Field(default_factory=list)

    # Failure policy
    failure_policy: Literal["open", "closed"] = "closed"

    # Audit
    audit_enabled: bool = True
    audit_db_path: str = "data/shield_audit.db"
    audit_max_prompt_chars: int = Field(default=200, ge=0, le=10000)
    audit_websocket_enabled: bool = True
    audit_retention_days: int = Field(default=90, ge=1, le=3650)
    audit_hash_source_ip: bool = False

    # Validation bridge
    validation_bridge_enabled: bool = False
    validation_bridge_min_confidence: float = Field(default=0.8, ge=0.0, le=1.0)

    # Red team
    use_redteam: bool = False
    redteam_probe_interval_seconds: int = Field(default=900, ge=60, le=86400)
    redteam_probe_categories: list[str] | None = None
    redteam_alert_success_threshold: float = Field(default=0.3, ge=0.0, le=1.0)

    # Defense profile
    profile: str = "balanced"

    # Agent preset — when True, enables agent-critical defenses
    agent_preset: bool = True

    # IOC feed
    ioc_file: str = ""

    # Rate limiter
    rate_limiter_rpm: int = Field(default=10, ge=1, le=10000)
    rate_limiter_tpm: int = Field(default=5000, ge=100, le=10000000)
    rate_limiter_cooldown_seconds: float = Field(default=60.0, ge=0, le=3600)
    rate_limiter_global_rpm: int = Field(default=100, ge=1, le=100000)
    rate_limiter_global_tpm: int = Field(default=50000, ge=100, le=100000000)
    rate_limiter_max_sessions: int = Field(default=1000, ge=1, le=1000000)
    rate_limiter_authenticated_multiplier: float = Field(
        default=5.0,
        ge=1.0,
        le=100.0,
        description="Rate limit multiplier for authenticated requests (H-3)",
    )
    rate_limiter_ip_rpm: int = Field(
        default=60,
        ge=1,
        le=100000,
        description="Per-IP requests per minute (H-3)",
    )
    rate_limiter_ip_tpm: int = Field(
        default=30000,
        ge=100,
        le=100000000,
        description="Per-IP tokens per minute (H-3)",
    )
    rate_limiter_ip_cooldown_seconds: float = Field(
        default=120.0,
        ge=0,
        le=3600,
        description="Per-IP cooldown period in seconds (H-3)",
    )

    # Deception
    deception_enabled: bool = False
    deception_canary_count: int = Field(default=5, ge=0, le=50)
    deception_honeypot_count: int = Field(default=3, ge=0, le=20)

    # Alignment probes
    alignment_probes_enabled: bool = False

    # CMDI probes (command injection probes for defenses with zero coverage)
    cmdi_probes_enabled: bool = False

    # Advanced SOTA probes (stress-test probes targeting confirmed Shield gaps)
    advanced_probes_enabled: bool = False

    # Alignment canaries
    alignment_canaries_enabled: bool = False
    canary_injection_rate: int = Field(default=50, ge=5, le=1000)
    canary_alert_threshold: float = Field(default=0.3, ge=0.0, le=1.0)
    canary_categories: list[str] | None = None

    # Threat Intelligence (admin opt-in — enables GeoIP lookups and threat actor tracking)
    intel_enabled: bool = False
    geoip_db_dir: str = "data/geoip"
    threat_actor_db_path: str = "data/threat_actors.db"

    # Alignment scanner (output pipeline) — Enterprise only
    alignment_scanner_enabled: bool = False

    # Sandbagging detection — Enterprise only
    sandbag_detection_enabled: bool = False
    sandbag_sigma_threshold: float = Field(default=2.0, ge=1.0, le=5.0)
    sandbag_min_samples: int = Field(default=30, ge=5, le=1000)
    sandbag_decay_rate: float = Field(default=0.99, ge=0.9, le=1.0)
    sandbag_decay_interval_seconds: int = Field(default=3600, ge=300, le=86400)

    # Training data gate — Enterprise only
    training_gate_enabled: bool = False
    training_trust_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    training_trust_thresholds: dict[str, float] = Field(default_factory=dict)
    training_quarantine_path: str = "data/quarantine"
    training_scan_skip_defenses: list[str] = Field(
        default_factory=lambda: ["rate_limiter", "session_tracker", "prompt_signing"]
    )

    # Cross-model consistency — Enterprise only
    consistency_check_enabled: bool = False
    consistency_providers: list[dict] = Field(default_factory=list)
    consistency_check_rate: float = Field(default=0.05, ge=0.0, le=1.0)
    consistency_divergence_threshold: float = Field(default=0.3, ge=0.0, le=1.0)
    consistency_timeout_seconds: float = Field(default=30.0, ge=5.0, le=120.0)

    # ExfilDetector single-axis mode
    exfil_single_axis: bool = True

    # Indirect injection defense
    indirect_injection_enabled: bool = True
    indirect_injection_confidence_threshold: float = Field(default=0.4, ge=0.0, le=1.0)

    # Session tracking
    session_tracking_enabled: bool = False
    session_window_size: int = Field(default=10, ge=2, le=100)
    session_tracker_blocking_enabled: bool = False

    # Signal fusion (cross-defense correlation)
    signal_fusion_enabled: bool = False
    signal_fusion_threshold: float = Field(default=0.45, ge=0.0, le=1.0)
    signal_fusion_min_signal: float = Field(default=0.05, ge=0.0, le=1.0)
    signal_fusion_blocking_enabled: bool = False
    signal_fusion_session_aware: bool = False
    signal_fusion_escalation_multiplier: float = Field(default=0.7, ge=0.1, le=1.0)

    # Tool output scanning
    tool_output_scanning_enabled: bool = True
    tool_risk_levels: dict[str, str] = Field(
        default_factory=lambda: {
            "web_fetch": "high",
            "web_search": "high",
            "browser": "high",
            "message": "high",
            "exec": "medium",
            "read": "medium",
            "sub_agent": "medium",
            "mcp": "medium",
        }
    )

    # Memory protection
    memory_protection_enabled: bool = False
    memory_critical_files: list[str] = Field(
        default_factory=lambda: [
            "SOUL.md",
            "AGENTS.md",
            "USER.md",
            "TOOLS.md",
            "HEARTBEAT.md",
        ]
    )
    memory_hash_store_path: str = "data/integrity.json"
    memory_scan_on_read: bool = True
    memory_scan_on_write: bool = True
    memory_write_guard_threshold: float = Field(default=0.4, ge=0.0, le=1.0)

    # Social engineering defense
    social_engineering_enabled: bool = True
    social_engineering_threshold: float = Field(default=0.4, ge=0.0, le=1.0)

    # Sub-agent guard
    sub_agent_guard_enabled: bool = True
    sub_agent_guard_threshold: float = Field(default=0.4, ge=0.0, le=1.0)
    max_agent_depth: int = Field(default=5, ge=1, le=20)

    # Drift detection
    drift_detection_enabled: bool = False
    drift_baseline_path: str = "data/drift_baselines.json"
    drift_window_size: int = Field(default=100, ge=10, le=10000)
    drift_alert_threshold: float = Field(default=2.0, ge=1.0, le=5.0)

    # Supply chain validation
    supply_chain_validation_enabled: bool = False
    supply_chain_manifest_path: str = "data/supply_chain_manifest.json"

    # Config mutation guard
    config_mutation_guard_enabled: bool = False
    config_mutation_guard_threshold: float = Field(default=0.4, ge=0.0, le=1.0)

    # Credential path guard
    credential_path_guard_enabled: bool = False
    credential_path_guard_threshold: float = Field(default=0.4, ge=0.0, le=1.0)

    # Alignment guard
    alignment_guard_enabled: bool = False
    alignment_guard_threshold: float = Field(default=0.4, ge=0.0, le=1.0)

    # Tool call firewall
    tool_call_firewall_enabled: bool = False
    tool_call_firewall_threshold: float = Field(default=0.4, ge=0.0, le=1.0)

    # MCP guard
    mcp_guard_enabled: bool = False

    # Circuit breaker
    circuit_breaker_enabled: bool = False

    # Approval flow monitor
    approval_flow_monitor_enabled: bool = False
    approval_flow_monitor_threshold: float = Field(default=0.4, ge=0.0, le=1.0)

    # Channel impersonation guard
    channel_impersonation_guard_enabled: bool = False
    channel_impersonation_guard_threshold: float = Field(default=0.4, ge=0.0, le=1.0)

    # Plugin supply chain guard
    plugin_supply_chain_guard_enabled: bool = False
    plugin_supply_chain_guard_threshold: float = Field(default=0.4, ge=0.0, le=1.0)

    # Context window guard (deep-context injection for 1M+ prompts)
    context_window_guard_enabled: bool = True
    context_window_scan_threshold: int = Field(default=10000, ge=1000, le=1000000)
    context_window_window_size: int = Field(default=2000, ge=500, le=10000)
    context_window_middle_count: int = Field(default=5, ge=1, le=20)
    context_window_threshold: float = Field(default=0.4, ge=0.0, le=1.0)

    # Plugin hook guard (TOCTOU gap protection for llm_input/llm_output hooks)
    plugin_hook_guard_enabled: bool = False
    plugin_hook_guard_threshold: float = Field(default=0.4, ge=0.0, le=1.0)

    # Defense composition engine
    composition_engine_enabled: bool = False
    composition_engine_max_history: int = Field(default=1000, ge=100, le=100000)

    # Aggregation — Enterprise only
    aggregator_enabled: bool = False
    aggregator_url: str = ""

    @model_validator(mode="after")
    def _validate_wallet_encryption(self) -> ShieldConfig:
        """Placeholder for wallet encryption validation (requires goop-net)."""
        return self

    def model_post_init(self, __context: Any) -> None:
        """When agent_preset is True, enable agent-critical defenses not explicitly set."""
        super().model_post_init(__context)
        if not self.agent_preset:
            return
        agent_flags = (
            "tool_call_firewall_enabled",
            "credential_path_guard_enabled",
            "plugin_supply_chain_guard_enabled",
            "memory_protection_enabled",
            "config_mutation_guard_enabled",
            "approval_flow_monitor_enabled",
            "channel_impersonation_guard_enabled",
            "sub_agent_guard_enabled",
            "mcp_guard_enabled",
            "circuit_breaker_enabled",
            "plugin_hook_guard_enabled",
        )
        for flag in agent_flags:
            if flag not in self.model_fields_set:
                object.__setattr__(self, flag, True)
