# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield Defense Registry

Manages registration and lookup of inline defenses and output scanners.
"""

from __future__ import annotations

from goop_shield.defenses.base import (
    DefenseContext,
    InlineDefense,
    InlineVerdict,
    OutputContext,
    OutputScanner,
    PatternBasedDefense,
)


class DefenseRegistry:
    """Registry of available inline defenses and output scanners."""

    def __init__(self) -> None:
        self._defenses: dict[str, InlineDefense] = {}
        self._scanners: dict[str, OutputScanner] = {}

    # -- Defenses --

    def register(self, defense: InlineDefense) -> None:
        """Register a defense by its name."""
        self._defenses[defense.name] = defense

    def get(self, name: str) -> InlineDefense | None:
        """Get a defense by name."""
        return self._defenses.get(name)

    def get_all(self) -> list[InlineDefense]:
        """Get all registered defenses."""
        return list(self._defenses.values())

    def names(self) -> list[str]:
        """Get names of all registered defenses."""
        return list(self._defenses.keys())

    def remove(self, name: str) -> None:
        """Remove a defense by name (no-op if not found)."""
        self._defenses.pop(name, None)

    def __len__(self) -> int:
        return len(self._defenses)

    # -- Scanners --

    def register_scanner(self, scanner: OutputScanner) -> None:
        """Register an output scanner by its name."""
        self._scanners[scanner.name] = scanner

    def get_scanner(self, name: str) -> OutputScanner | None:
        """Get an output scanner by name."""
        return self._scanners.get(name)

    def get_all_scanners(self) -> list[OutputScanner]:
        """Get all registered output scanners."""
        return list(self._scanners.values())

    def scanner_names(self) -> list[str]:
        """Get names of all registered output scanners."""
        return list(self._scanners.keys())

    def remove_scanner(self, name: str) -> None:
        """Remove an output scanner by name (no-op if not found)."""
        self._scanners.pop(name, None)


def register_defaults(registry: DefenseRegistry, *, config: object | None = None) -> None:
    """Register all inline defenses (up to 36) and 3 output scanners.

    Args:
        registry: The defense registry to populate.
        config: Optional ShieldConfig (or duck-typed object) for config-driven
                defense initialization.
    """
    from goop_shield.defenses.behavioral import (
        AgentConfigGuard,
        AgentSandbox,
        ExfilDetector,
        IntentValidator,
        ModelGuardrails,
        PromptMonitor,
        RateLimiter,
    )
    from goop_shield.defenses.content import (
        CanaryTokenDetector,
        ObfuscationDetector,
        RAGVerifier,
        SemanticFilter,
    )
    from goop_shield.defenses.crypto import OutputWatermark, PromptSigning
    from goop_shield.defenses.heuristic import (
        ContextLimiter,
        InjectionBlocker,
        InputValidator,
        OutputFilter,
        PromptNormalizer,
        SafetyFilter,
    )

    # Normalizer (1) — MUST run first to neutralise Unicode/whitespace evasion
    registry.register(PromptNormalizer())

    # Context window guard (1) — mandatory, sees normalized text
    context_window_guard_enabled = getattr(config, "context_window_guard_enabled", True)
    if context_window_guard_enabled:
        from goop_shield.defenses.context_window_guard import ContextWindowGuard

        cwg_threshold = getattr(config, "context_window_scan_threshold", 10000)
        cwg_window_size = getattr(config, "context_window_window_size", 2000)
        cwg_middle_count = getattr(config, "context_window_middle_count", 5)
        cwg_confidence = getattr(config, "context_window_threshold", 0.4)
        registry.register(
            ContextWindowGuard(
                scan_threshold=cwg_threshold,
                window_size=cwg_window_size,
                middle_count=cwg_middle_count,
                confidence_threshold=cwg_confidence,
            )
        )

    # Heuristic (5)
    registry.register(SafetyFilter())
    registry.register(InputValidator())
    registry.register(InjectionBlocker())
    registry.register(ContextLimiter())
    registry.register(OutputFilter())
    # Crypto (2)
    registry.register(PromptSigning())
    registry.register(OutputWatermark())
    # Content (4) — canary tokens are generated once and shared with output scanner
    import secrets

    canary_tokens = [f"CANARY_{secrets.token_hex(8).upper()}" for _ in range(3)]
    registry.register(RAGVerifier())
    registry.register(CanaryTokenDetector(tokens=canary_tokens))
    registry.register(SemanticFilter())
    registry.register(ObfuscationDetector())
    # Behavioral (7)
    registry.register(AgentConfigGuard())
    registry.register(AgentSandbox())
    rate_rpm = getattr(config, "rate_limiter_rpm", 10)
    rate_tpm = getattr(config, "rate_limiter_tpm", 5000)
    registry.register(RateLimiter(rpm=rate_rpm, tpm=rate_tpm))
    registry.register(PromptMonitor())
    registry.register(ModelGuardrails())
    registry.register(IntentValidator())
    exfil_single_axis = getattr(config, "exfil_single_axis", True)
    registry.register(ExfilDetector(single_axis=exfil_single_axis))

    # Indirect injection (1) — config-gated
    indirect_injection_enabled = getattr(config, "indirect_injection_enabled", True)
    if indirect_injection_enabled:
        from goop_shield.defenses.indirect_injection import IndirectInjectionDefense

        indirect_threshold = getattr(config, "indirect_injection_confidence_threshold", 0.4)
        registry.register(IndirectInjectionDefense(confidence_threshold=indirect_threshold))

    # Memory protection (1) — config-gated
    memory_protection_enabled = getattr(config, "memory_protection_enabled", False)
    if memory_protection_enabled:
        from goop_shield.defenses.memory import MemoryWriteGuard

        memory_threshold = getattr(config, "memory_write_guard_threshold", 0.4)
        registry.register(MemoryWriteGuard(confidence_threshold=memory_threshold))

    # Social engineering defense (1) — config-gated
    social_engineering_enabled = getattr(config, "social_engineering_enabled", True)
    if social_engineering_enabled:
        from goop_shield.defenses.social_engineering import SocialEngineeringDefense

        se_threshold = getattr(config, "social_engineering_threshold", 0.4)
        registry.register(SocialEngineeringDefense(confidence_threshold=se_threshold))

    # Sub-agent guard (1) — config-gated
    sub_agent_guard_enabled = getattr(config, "sub_agent_guard_enabled", True)
    if sub_agent_guard_enabled:
        from goop_shield.defenses.sub_agent import SubAgentGuard

        sa_threshold = getattr(config, "sub_agent_guard_threshold", 0.4)
        sa_max_depth = getattr(config, "max_agent_depth", 5)
        registry.register(
            SubAgentGuard(confidence_threshold=sa_threshold, max_agent_depth=sa_max_depth)
        )

    # Application guard (3) — config-gated (opt-in, default disabled)
    config_mutation_guard_enabled = getattr(config, "config_mutation_guard_enabled", False)
    if config_mutation_guard_enabled:
        from goop_shield.defenses.application_guard import ConfigMutationGuard

        cmg_threshold = getattr(config, "config_mutation_guard_threshold", 0.4)
        registry.register(ConfigMutationGuard(confidence_threshold=cmg_threshold))

    credential_path_guard_enabled = getattr(config, "credential_path_guard_enabled", True)
    if credential_path_guard_enabled:
        from goop_shield.defenses.application_guard import CredentialPathGuard

        cpg_threshold = getattr(config, "credential_path_guard_threshold", 0.4)
        registry.register(CredentialPathGuard(confidence_threshold=cpg_threshold))

    alignment_guard_enabled = getattr(config, "alignment_guard_enabled", False)
    if alignment_guard_enabled:
        from goop_shield.defenses.application_guard import AlignmentInlineDefense

        ag_threshold = getattr(config, "alignment_guard_threshold", 0.4)
        registry.register(AlignmentInlineDefense(confidence_threshold=ag_threshold))

    # Operational guard (3) — config-gated (opt-in, default disabled)
    tool_call_firewall_enabled = getattr(config, "tool_call_firewall_enabled", True)
    if tool_call_firewall_enabled:
        from goop_shield.defenses.operational_guard import ToolCallFirewall

        tcf_threshold = getattr(config, "tool_call_firewall_threshold", 0.4)
        registry.register(ToolCallFirewall(confidence_threshold=tcf_threshold))

    approval_flow_monitor_enabled = getattr(config, "approval_flow_monitor_enabled", False)
    if approval_flow_monitor_enabled:
        from goop_shield.defenses.operational_guard import ApprovalFlowMonitor

        afm_threshold = getattr(config, "approval_flow_monitor_threshold", 0.4)
        registry.register(ApprovalFlowMonitor(confidence_threshold=afm_threshold))

    channel_impersonation_guard_enabled = getattr(
        config, "channel_impersonation_guard_enabled", False
    )
    if channel_impersonation_guard_enabled:
        from goop_shield.defenses.operational_guard import ChannelImpersonationGuard

        cig_threshold = getattr(config, "channel_impersonation_guard_threshold", 0.4)
        registry.register(ChannelImpersonationGuard(confidence_threshold=cig_threshold))

    # Supply chain guard (1) — config-gated (opt-in, default disabled)
    plugin_supply_chain_guard_enabled = getattr(config, "plugin_supply_chain_guard_enabled", False)
    if plugin_supply_chain_guard_enabled:
        from goop_shield.defenses.supply_chain_guard import PluginSupplyChainGuard

        scg_threshold = getattr(config, "plugin_supply_chain_guard_threshold", 0.4)
        registry.register(PluginSupplyChainGuard(confidence_threshold=scg_threshold))

    # Plugin hook guard (1) — config-gated (agent_preset)
    plugin_hook_guard_enabled = getattr(config, "plugin_hook_guard_enabled", False)
    if plugin_hook_guard_enabled:
        from goop_shield.defenses.plugin_hook_guard import PluginHookGuard

        phg_threshold = getattr(config, "plugin_hook_guard_threshold", 0.4)
        registry.register(PluginHookGuard(confidence_threshold=phg_threshold))

    # MCP guard (1) — config-gated (agent_preset)
    mcp_guard_enabled = getattr(config, "mcp_guard_enabled", False)
    if mcp_guard_enabled:
        from goop_shield.defenses.mcp_guard import MCPGuard

        mcg_threshold = getattr(config, "tool_call_firewall_threshold", 0.4)
        registry.register(MCPGuard(confidence_threshold=mcg_threshold))

    # Circuit breaker (1) — config-gated (agent_preset)
    circuit_breaker_enabled = getattr(config, "circuit_breaker_enabled", False)
    if circuit_breaker_enabled:
        from goop_shield.defenses.circuit_breaker import CircuitBreaker

        registry.register(CircuitBreaker())

    # IOC-based (2) — with optional IOC feed loading
    from goop_shield.defenses.domain_reputation import DomainReputationDefense
    from goop_shield.defenses.ioc_matcher import IOCMatcherDefense

    domain_defense = DomainReputationDefense()
    ioc_defense = IOCMatcherDefense()
    ioc_file = getattr(config, "ioc_file", "")
    if ioc_file:
        ioc_defense.load_iocs(ioc_file)
        domain_defense.load_ioc_feed(ioc_file)
    registry.register(domain_defense)
    registry.register(ioc_defense)

    # Output scanners (3) — pass shared canary tokens to leak scanner
    register_default_scanners(registry, canary_tokens=canary_tokens)


def register_default_scanners(
    registry: DefenseRegistry, *, canary_tokens: list[str] | None = None
) -> None:
    """Register the 3 default output scanners."""
    from goop_shield.defenses.output import (
        CanaryLeakScanner,
        HarmfulContentScanner,
        SecretLeakScanner,
    )

    registry.register_scanner(SecretLeakScanner())
    registry.register_scanner(CanaryLeakScanner(tokens=canary_tokens))
    registry.register_scanner(HarmfulContentScanner())


# Canonical set of all defense and scanner names — single source of truth.
DEFENSE_NAMES: frozenset[str] = frozenset(
    {
        # Heuristic (6)
        "prompt_normalizer",
        "safety_filter",
        "input_validator",
        "injection_blocker",
        "context_limiter",
        "output_filter",
        # Crypto (2)
        "prompt_signing",
        "output_watermark",
        # Content (4)
        "rag_verifier",
        "canary_token_detector",
        "semantic_filter",
        "obfuscation_detector",
        # Behavioral (7)
        "agent_config_guard",
        "agent_sandbox",
        "rate_limiter",
        "prompt_monitor",
        "model_guardrails",
        "intent_validator",
        "exfil_detector",
        # Structural (3)
        "indirect_injection",
        "context_window_guard",
        "memory_write_guard",
        # Social / Sub-agent (2)
        "social_engineering",
        "sub_agent_guard",
        # Application guard (3)
        "config_mutation_guard",
        "credential_path_guard",
        "alignment_guard",
        # Operational guard (3)
        "tool_call_firewall",
        "approval_flow_monitor",
        "channel_impersonation_guard",
        # Supply chain / Plugin / MCP (3)
        "plugin_supply_chain_guard",
        "plugin_hook_guard",
        "mcp_guard",
        # Circuit breaker (1)
        "circuit_breaker",
        # IOC-based (2)
        "domain_reputation",
        "ioc_matcher",
        # Output scanners (3)
        "secret_leak",
        "canary_leak",
        "harmful_content",
    }
)

__all__ = [
    "DEFENSE_NAMES",
    "DefenseContext",
    "DefenseRegistry",
    "InlineDefense",
    "InlineVerdict",
    "OutputContext",
    "OutputScanner",
    "PatternBasedDefense",
    "register_default_scanners",
    "register_defaults",
]
