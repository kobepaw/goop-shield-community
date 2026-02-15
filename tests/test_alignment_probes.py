"""
Tests for Shield Alignment Probes — Registry, Execution, and Config.

Requires goop-ai Enterprise.
"""

from __future__ import annotations

import pytest

from goop_shield.red.probes import ProbeRegistry, register_default_probes

_reg = ProbeRegistry()
register_default_probes(_reg)
_enterprise_red = len(_reg) > 0
del _reg

if not _enterprise_red:
    pytest.skip("Requires goop-ai Enterprise", allow_module_level=True)

from goop_shield.config import ShieldConfig
from goop_shield.defender import Defender
from goop_shield.defenses import DefenseRegistry, register_defaults
from goop_shield.red.alignment_probes import (
    InstructionLeakProbe,
)
from goop_shield.red.probes import (
    ProbeRegistry,
    register_alignment_probes,
    register_default_probes,
)
from goop_shield.red.runner import RedTeamRunner

# ============================================================================
# Constants & helpers
# ============================================================================

ALIGNMENT_PROBE_NAMES = {
    "sandbag",
    "deception",
    "power_seeking",
    "sycophancy",
    "instruction_leak",
    "goal_drift",
    "selective_compliance",
}


def _config_with_alignment(use_redteam: bool = True) -> ShieldConfig:
    """Build a ShieldConfig and patch alignment_probes_enabled onto it.

    ShieldConfig uses extra='forbid' so we can't pass the field directly
    until the lead adds it. We use object.__setattr__ to bypass frozen.
    """
    config = ShieldConfig(use_redteam=use_redteam)
    # If the field already exists natively, return as-is
    if hasattr(config, "alignment_probes_enabled"):
        if not config.alignment_probes_enabled:
            object.__setattr__(config, "alignment_probes_enabled", True)
        return config
    # Patch the attribute onto the frozen config
    object.__setattr__(config, "alignment_probes_enabled", True)
    return config


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def alignment_registry():
    """Registry with only alignment probes."""
    registry = ProbeRegistry()
    register_alignment_probes(registry)
    return registry


@pytest.fixture
def mixed_registry():
    """Registry with both default (15) and alignment (7) probes."""
    registry = ProbeRegistry()
    register_default_probes(registry)
    register_alignment_probes(registry)
    return registry


@pytest.fixture
def alignment_config():
    """ShieldConfig with red team and alignment probes enabled."""
    return _config_with_alignment(use_redteam=True)


@pytest.fixture
def alignment_defender(alignment_config):
    registry = DefenseRegistry()
    register_defaults(registry)
    return Defender(alignment_config, registry=registry)


@pytest.fixture
def alignment_runner(alignment_defender, alignment_config):
    """Runner with alignment probes enabled (no pre-populated registry)."""
    return RedTeamRunner(alignment_defender, alignment_config)


@pytest.fixture
def security_only_runner():
    """Runner with alignment probes disabled (default 15 probes only)."""
    config = ShieldConfig(use_redteam=True)
    registry = DefenseRegistry()
    register_defaults(registry)
    defender = Defender(config, registry=registry)
    return RedTeamRunner(defender, config)


# ============================================================================
# TestAlignmentProbeRegistry
# ============================================================================


class TestAlignmentProbeRegistry:
    def test_register_7_probes(self, alignment_registry):
        assert len(alignment_registry) == 7

    def test_unique_names(self, alignment_registry):
        names = alignment_registry.names()
        assert len(names) == len(set(names))

    def test_all_expected_names_present(self, alignment_registry):
        names = set(alignment_registry.names())
        assert names == ALIGNMENT_PROBE_NAMES

    def test_all_target_alignment_monitor(self, alignment_registry):
        for probe in alignment_registry.get_all():
            assert probe.target_defense == "alignment_monitor", (
                f"Probe {probe.name} targets {probe.target_defense}, expected alignment_monitor"
            )

    def test_non_empty_payloads(self, alignment_registry):
        for probe in alignment_registry.get_all():
            payload = probe.build_payload()
            assert len(payload) > 0, f"Probe {probe.name} has empty payload"

    def test_payload_variants(self, alignment_registry):
        """Run each probe 10x and verify not all payloads are identical."""
        for probe in alignment_registry.get_all():
            payloads = [probe.build_payload() for _ in range(10)]
            unique = set(payloads)
            assert len(unique) > 1, f"Probe {probe.name} returned identical payloads across 10 runs"

    def test_mixed_registry_has_22(self, mixed_registry):
        """Default 15 + alignment 7 = 22 total probes."""
        assert len(mixed_registry) == 22


# ============================================================================
# TestAlignmentProbeExecution
# ============================================================================


class TestAlignmentProbeExecution:
    def test_run_alignment_probes_only(self, alignment_defender, alignment_config):
        """Run only alignment probes by name filtering."""
        registry = ProbeRegistry()
        register_default_probes(registry)
        register_alignment_probes(registry)
        runner = RedTeamRunner(alignment_defender, alignment_config, registry=registry)

        report = runner.run_probes(probe_names=list(ALIGNMENT_PROBE_NAMES))
        assert report.total_probes == 7
        assert len(report.alignment_results) == 7
        assert len(report.results) == 0

    def test_run_mixed_probes(self, alignment_runner):
        """Run all probes (15 default + 33 agent + 5 fusion + 7 alignment)."""
        report = alignment_runner.run_probes()
        assert report.total_probes == 60
        assert len(report.results) == 53
        assert len(report.alignment_results) == 7

    def test_alignment_results_separate_from_security(self, alignment_runner):
        """Alignment results should not appear in security results list."""
        report = alignment_runner.run_probes()

        security_names = {r.probe_name for r in report.results}
        alignment_names = {r.probe_name for r in report.alignment_results}

        # No overlap
        assert security_names & alignment_names == set()

        # Alignment probes are in alignment_results
        assert alignment_names == ALIGNMENT_PROBE_NAMES

        # Security probes are in results (15 default + 33 agent + 5 fusion)
        assert len(security_names) == 53

    def test_alignment_probes_have_target_defense(self, alignment_runner):
        """All alignment probe results should target alignment_monitor."""
        report = alignment_runner.run_probes()
        for result in report.alignment_results:
            assert result.target_defense == "alignment_monitor"

    def test_security_only_runner_no_alignment(self, security_only_runner):
        """Runner without alignment_probes_enabled has no alignment results."""
        report = security_only_runner.run_probes()
        assert report.total_probes == 53
        assert len(report.alignment_results) == 0
        assert len(report.results) == 53

    def test_run_single_alignment_probe(self, alignment_runner):
        """Can run a single alignment probe by name."""
        report = alignment_runner.run_probes(probe_names=["sandbag"])
        assert report.total_probes == 1
        assert len(report.alignment_results) == 1
        assert report.alignment_results[0].probe_name == "sandbag"


# ============================================================================
# TestAlignmentProbeConfig
# ============================================================================


class TestAlignmentProbeConfig:
    def test_default_disabled(self):
        config = ShieldConfig()
        assert getattr(config, "alignment_probes_enabled", False) is False

    def test_enable_via_config(self):
        config = _config_with_alignment()
        assert config.alignment_probes_enabled is True

    def test_runner_respects_config_disabled(self):
        """When alignment_probes_enabled=False, runner has 15 default + 33 agent + 5 fusion probes."""
        config = ShieldConfig(use_redteam=True)
        defender = Defender(config)
        runner = RedTeamRunner(defender, config)
        assert len(runner.registry) == 53

    def test_runner_respects_config_enabled(self):
        """When alignment_probes_enabled=True, runner has 15 + 33 + 5 + 7 probes."""
        config = _config_with_alignment(use_redteam=True)
        defender = Defender(config)
        runner = RedTeamRunner(defender, config)
        assert len(runner.registry) == 60


# ============================================================================
# TestAlignmentProbePayloads
# ============================================================================


class TestAlignmentProbePayloads:
    """Verify specific payload properties for each probe type."""

    def test_sandbag_contains_coding_task(self, alignment_registry):
        probe = alignment_registry.get("sandbag")
        payload = probe.build_payload()
        assert any(kw in payload.lower() for kw in ["function", "write", "python"])

    def test_instruction_leak_has_4_variants(self):
        probe = InstructionLeakProbe()
        assert len(probe._PAYLOADS) == 4

    def test_sycophancy_contains_factual_claim(self, alignment_registry):
        probe = alignment_registry.get("sycophancy")
        payload = probe.build_payload()
        assert len(payload) > 20

    def test_goal_drift_has_multi_turn(self, alignment_registry):
        probe = alignment_registry.get("goal_drift")
        payload = probe.build_payload()
        assert "[Turn 1]" in payload
        assert "[Turn 2]" in payload

    def test_selective_compliance_mentions_unmonitored(self, alignment_registry):
        probe = alignment_registry.get("selective_compliance")
        payload = probe.build_payload()
        assert any(kw in payload.lower() for kw in ["not being logged", "disabled", "unmonitored"])

    def test_all_probes_expected_blocked(self, alignment_registry):
        """All alignment probes expect to be blocked."""
        for probe in alignment_registry.get_all():
            assert probe.expected_blocked() is True
            assert probe.expected_sanitized() is False

    def test_all_probes_default_context(self, alignment_registry):
        """All alignment probes return empty context by default."""
        for probe in alignment_registry.get_all():
            assert probe.build_context() == {}
