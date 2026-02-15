"""
Tests for GoopRange bridge and vulnerability report generation.

Requires goop-ai Enterprise.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from goop_shield.red.probes import ProbeRegistry, register_default_probes

_reg = ProbeRegistry()
register_default_probes(_reg)
_enterprise_red = len(_reg) > 0
del _reg

if not _enterprise_red:
    pytest.skip("Requires goop-ai Enterprise", allow_module_level=True)

from goop_shield.models import ProbeResult
from goop_shield.red.gooprange_bridge import (
    _PROBE_TO_GOOPRANGE,
    GoopRangeBridge,
)
from goop_shield.red.report import _PROBE_TO_MITRE, VulnerabilityReport

_ENTERPRISE_GOOPRANGE = len(_PROBE_TO_GOOPRANGE) > 0

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_probe_result(
    probe_name: str = "jailbreak",
    target_defense: str = "safety_filter",
    payload_blocked: bool = False,
    defense_bypassed: bool = True,
    caught_by: str | None = None,
    confidence: float = 0.8,
) -> ProbeResult:
    return ProbeResult(
        probe_name=probe_name,
        target_defense=target_defense,
        payload_blocked=payload_blocked,
        expected_blocked=True,
        defense_bypassed=defense_bypassed,
        caught_by=caught_by,
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# GoopRange Bridge Tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _ENTERPRISE_GOOPRANGE,
    reason="GoopRange probe mapping requires the enterprise edition",
)
class TestProbeToGoopRangeMapping:
    """Verify known mappings exist and are correct."""

    def test_jailbreak_maps_to_jailbreak_attempt(self):
        assert _PROBE_TO_GOOPRANGE["jailbreak"] == "jailbreak_attempt"

    def test_system_override_maps_to_prompt_inject(self):
        assert _PROBE_TO_GOOPRANGE["system_override"] == "prompt_inject"

    def test_rag_injection_maps_to_rag_poison(self):
        assert _PROBE_TO_GOOPRANGE["rag_injection"] == "rag_poison"

    def test_sandbox_escape_maps_to_agent_hijack(self):
        assert _PROBE_TO_GOOPRANGE["sandbox_escape"] == "agent_hijack"

    def test_all_mapped_probes_have_known_gooprange_attacks(self):
        """Every mapping target should be a known GoopRange attack."""
        known_attacks = {
            "jailbreak_attempt",
            "prompt_inject",
            "indirect_inject",
            "rag_poison",
            "extract_system_prompt",
            "agent_hijack",
            "adversarial_example",
            "prompt_leaking",
            "context_overflow",
        }
        for probe_name, attack_name in _PROBE_TO_GOOPRANGE.items():
            assert attack_name in known_attacks, (
                f"Probe {probe_name} maps to unknown attack {attack_name}"
            )

    def test_mapping_has_at_least_10_entries(self):
        assert len(_PROBE_TO_GOOPRANGE) >= 10


@pytest.mark.skipif(
    not _ENTERPRISE_GOOPRANGE,
    reason="GoopRange bridge tests require the enterprise edition",
)
class TestGoopRangeBridgeWithoutDocker:
    """Tests that gracefully fall back when GoopRange/Docker is unavailable."""

    def test_validate_bypass_unmapped_probe(self):
        bridge = GoopRangeBridge()
        result = bridge.validate_bypass(_make_probe_result(probe_name="totally_unknown_probe"))
        assert result.gooprange_attack == "unknown"
        assert result.error is not None
        assert "No GoopRange mapping" in result.error

    def test_validate_bypass_import_failure(self):
        bridge = GoopRangeBridge()
        with patch(
            "goop_shield.red.gooprange_bridge.GoopRangeBridge._get_validator",
            return_value=None,
        ):
            result = bridge.validate_bypass(_make_probe_result())
        assert result.real_world_success is False
        assert result.error == "GoopRange validator not available"

    def test_validate_bypass_validator_exception(self):
        bridge = GoopRangeBridge()
        mock_validator = MagicMock()
        mock_validator.validate.side_effect = RuntimeError("Docker not running")
        bridge._validator = mock_validator

        result = bridge.validate_bypass(_make_probe_result())
        assert result.real_world_success is False
        assert "Docker not running" in result.error

    def test_validate_bypass_success(self):
        bridge = GoopRangeBridge()
        mock_result = MagicMock()
        mock_result.is_valid = True
        mock_result.attack_success_rate = 0.85

        mock_validator = MagicMock()
        mock_validator.validate.return_value = mock_result
        bridge._validator = mock_validator

        result = bridge.validate_bypass(_make_probe_result())
        assert result.real_world_success is True
        assert result.real_world_success_rate == 0.85
        assert result.gooprange_attack == "jailbreak_attempt"

    def test_validate_bypass_failure(self):
        bridge = GoopRangeBridge()
        mock_result = MagicMock()
        mock_result.is_valid = False
        mock_result.attack_success_rate = 0.1

        mock_validator = MagicMock()
        mock_validator.validate.return_value = mock_result
        bridge._validator = mock_validator

        result = bridge.validate_bypass(_make_probe_result())
        assert result.real_world_success is False
        assert result.real_world_success_rate == 0.1


@pytest.mark.skipif(
    not _ENTERPRISE_GOOPRANGE,
    reason="GoopRange validation tests require the enterprise edition",
)
class TestValidateAllBypasses:
    """Test bulk validation filters correctly."""

    def test_filters_only_bypassed_probes(self):
        bridge = GoopRangeBridge()
        # Mock validator to avoid real GoopRange calls
        bridge._validator = MagicMock()
        mock_vr = MagicMock()
        mock_vr.is_valid = False
        mock_vr.attack_success_rate = 0.0
        bridge._validator.validate.return_value = mock_vr

        results = [
            _make_probe_result(probe_name="jailbreak", defense_bypassed=True),
            _make_probe_result(
                probe_name="system_override", defense_bypassed=False, payload_blocked=True
            ),
            _make_probe_result(probe_name="rag_injection", defense_bypassed=True),
        ]
        validations = bridge.validate_all_bypasses(results)
        # Only 2 bypassed probes should be validated
        assert len(validations) == 2

    def test_empty_results_returns_empty(self):
        bridge = GoopRangeBridge()
        assert bridge.validate_all_bypasses([]) == []

    def test_no_bypasses_returns_empty(self):
        bridge = GoopRangeBridge()
        results = [
            _make_probe_result(defense_bypassed=False, payload_blocked=True),
            _make_probe_result(
                probe_name="system_override", defense_bypassed=False, payload_blocked=True
            ),
        ]
        assert bridge.validate_all_bypasses(results) == []


# ---------------------------------------------------------------------------
# Vulnerability Report Tests
# ---------------------------------------------------------------------------


class TestVulnerabilityReportFromResults:
    """Test VulnerabilityReport.from_probe_results()."""

    def test_basic_report_generation(self):
        results = [
            _make_probe_result(probe_name="jailbreak", defense_bypassed=True),
            _make_probe_result(
                probe_name="system_override", defense_bypassed=False, payload_blocked=True
            ),
            _make_probe_result(
                probe_name="rag_injection", target_defense="rag_verifier", defense_bypassed=True
            ),
        ]
        report = VulnerabilityReport.from_probe_results(results)
        assert report.total_probes == 3
        assert report.total_bypasses == 2
        assert abs(report.bypass_rate - 2 / 3) < 0.01

    def test_zero_probes(self):
        report = VulnerabilityReport.from_probe_results([])
        assert report.total_probes == 0
        assert report.total_bypasses == 0
        assert report.bypass_rate == 0.0

    def test_all_blocked(self):
        results = [
            _make_probe_result(defense_bypassed=False, payload_blocked=True),
            _make_probe_result(
                probe_name="system_override", defense_bypassed=False, payload_blocked=True
            ),
        ]
        report = VulnerabilityReport.from_probe_results(results)
        assert report.total_bypasses == 0
        assert report.bypass_rate == 0.0

    def test_defense_breakdown(self):
        results = [
            _make_probe_result(target_defense="safety_filter", defense_bypassed=True),
            _make_probe_result(
                probe_name="system_override",
                target_defense="safety_filter",
                defense_bypassed=False,
                payload_blocked=True,
            ),
            _make_probe_result(
                probe_name="rag_injection", target_defense="rag_verifier", defense_bypassed=True
            ),
        ]
        report = VulnerabilityReport.from_probe_results(results)
        assert "safety_filter" in report.defense_breakdown
        assert report.defense_breakdown["safety_filter"]["probes"] == 2
        assert report.defense_breakdown["safety_filter"]["bypassed"] == 1
        assert report.defense_breakdown["safety_filter"]["blocked"] == 1
        assert "rag_verifier" in report.defense_breakdown
        assert report.defense_breakdown["rag_verifier"]["bypassed"] == 1

    def test_mitre_mapping_in_probe_results(self):
        results = [
            _make_probe_result(probe_name="jailbreak", defense_bypassed=True),
        ]
        report = VulnerabilityReport.from_probe_results(results)
        assert report.probe_results[0]["mitre"] == ["T1548"]

    def test_gooprange_results_included(self):
        results = [_make_probe_result()]
        gr_results = [
            {
                "probe_name": "jailbreak",
                "gooprange_attack": "jailbreak_attempt",
                "real_world_success": True,
                "real_world_success_rate": 0.8,
            }
        ]
        report = VulnerabilityReport.from_probe_results(results, gooprange_results=gr_results)
        assert len(report.gooprange_validations) == 1
        assert report.gooprange_validations[0]["real_world_success"] is True


class TestReportRecommendations:
    """Test that recommendations are generated correctly."""

    def test_all_blocked_recommendation(self):
        results = [
            _make_probe_result(defense_bypassed=False, payload_blocked=True),
        ]
        report = VulnerabilityReport.from_probe_results(results)
        assert any("All probes blocked" in r for r in report.recommendations)

    def test_high_bypass_rate_recommendation(self):
        results = [
            _make_probe_result(defense_bypassed=True),
            _make_probe_result(probe_name="system_override", defense_bypassed=True),
            _make_probe_result(
                probe_name="rag_injection", target_defense="rag_verifier", defense_bypassed=True
            ),
        ]
        report = VulnerabilityReport.from_probe_results(results)
        assert any("High bypass rate" in r for r in report.recommendations)

    def test_per_defense_recommendation(self):
        results = [
            _make_probe_result(target_defense="safety_filter", defense_bypassed=True),
        ]
        report = VulnerabilityReport.from_probe_results(results)
        assert any("Review safety_filter" in r for r in report.recommendations)


class TestReportMarkdown:
    """Test markdown output format."""

    def test_markdown_contains_header(self):
        report = VulnerabilityReport.from_probe_results([_make_probe_result()])
        md = report.to_markdown()
        assert "# Shield" in md
        assert "Vulnerability Assessment Report" in md

    def test_markdown_contains_executive_summary(self):
        report = VulnerabilityReport.from_probe_results([_make_probe_result()])
        md = report.to_markdown()
        assert "## Executive Summary" in md
        assert "Total Probes" in md
        assert "Bypass Rate" in md

    def test_markdown_contains_defense_breakdown_table(self):
        results = [
            _make_probe_result(target_defense="safety_filter", defense_bypassed=True),
            _make_probe_result(
                probe_name="system_override",
                target_defense="safety_filter",
                defense_bypassed=False,
                payload_blocked=True,
            ),
        ]
        report = VulnerabilityReport.from_probe_results(results)
        md = report.to_markdown()
        assert "## Defense Breakdown" in md
        assert "safety_filter" in md
        assert "| Defense |" in md

    def test_markdown_contains_probe_details_table(self):
        report = VulnerabilityReport.from_probe_results([_make_probe_result()])
        md = report.to_markdown()
        assert "## Probe Details" in md
        assert "| Probe |" in md

    def test_markdown_gooprange_section_when_present(self):
        gr = [
            {
                "probe_name": "jailbreak",
                "gooprange_attack": "jailbreak_attempt",
                "real_world_success": True,
                "real_world_success_rate": 0.8,
            }
        ]
        report = VulnerabilityReport.from_probe_results(
            [_make_probe_result()], gooprange_results=gr
        )
        md = report.to_markdown()
        assert "## GoopRange Real-World Validation" in md

    def test_markdown_no_gooprange_section_when_absent(self):
        report = VulnerabilityReport.from_probe_results([_make_probe_result()])
        md = report.to_markdown()
        assert "GoopRange Real-World Validation" not in md

    def test_markdown_contains_recommendations(self):
        report = VulnerabilityReport.from_probe_results([_make_probe_result()])
        md = report.to_markdown()
        assert "## Recommendations" in md


class TestReportJson:
    """Test JSON serialization."""

    def test_to_json_is_valid_json(self):
        report = VulnerabilityReport.from_probe_results([_make_probe_result()])
        parsed = json.loads(report.to_json())
        assert isinstance(parsed, dict)

    def test_to_json_roundtrip(self):
        results = [
            _make_probe_result(defense_bypassed=True),
            _make_probe_result(
                probe_name="system_override", defense_bypassed=False, payload_blocked=True
            ),
        ]
        report = VulnerabilityReport.from_probe_results(results)
        parsed = json.loads(report.to_json())
        assert parsed["total_probes"] == 2
        assert parsed["total_bypasses"] == 1
        assert len(parsed["probe_results"]) == 2

    def test_to_dict_matches_to_json(self):
        report = VulnerabilityReport.from_probe_results([_make_probe_result()])
        d = report.to_dict()
        parsed = json.loads(report.to_json())
        assert d == parsed


class TestMitreMapping:
    """Verify MITRE ATT&CK mapping coverage."""

    def test_all_15_probes_have_mitre_mapping(self):
        expected_probes = {
            "jailbreak",
            "system_override",
            "injection_marker",
            "separator_injection",
            "rag_injection",
            "prompt_extraction",
            "sandbox_escape",
            "guardrail_bypass",
            "entropy_attack",
            "canary_exfil",
            "secret_exfil",
            "context_overflow",
            "overlength",
            "prompt_forgery",
            "watermark_bypass",
        }
        for probe in expected_probes:
            assert probe in _PROBE_TO_MITRE, f"Missing MITRE mapping for {probe}"

    def test_mitre_ids_are_strings(self):
        for probe_name, mitre_ids in _PROBE_TO_MITRE.items():
            assert isinstance(mitre_ids, list)
            for mid in mitre_ids:
                assert isinstance(mid, str)
                assert mid.startswith("T"), f"MITRE ID {mid} should start with T"
