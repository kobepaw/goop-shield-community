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
    """Register all inline defenses (up to 24) and 3 output scanners.

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

    # IOC-based (2) — load feed if configured
    from goop_shield.defenses.domain_reputation import DomainReputationDefense
    from goop_shield.defenses.ioc_matcher import IOCMatcherDefense

    domain_defense = DomainReputationDefense()
    ioc_defense = IOCMatcherDefense()
    ioc_file = getattr(config, 'ioc_file', '')
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


__all__ = [
    "DefenseContext",
    "DefenseRegistry",
    "InlineDefense",
    "InlineVerdict",
    "OutputContext",
    "OutputScanner",
    "register_default_scanners",
    "register_defaults",
]
