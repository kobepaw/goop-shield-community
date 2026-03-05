# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Tests for Advanced SOTA Probes and Multi-Turn Probes.
"""

from __future__ import annotations

import pytest

from goop_shield.red.advanced_probes import register_advanced_probes
from goop_shield.red.multi_turn_probes import (
    MultiTurnProbe,
    register_multi_turn_probes,
)
from goop_shield.red.probes import (
    ProbeRegistry,
    register_agent_probes,
    register_default_probes,
    register_fusion_probes,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def advanced_registry():
    """Registry with only advanced probes."""
    registry = ProbeRegistry()
    register_advanced_probes(registry)
    return registry


@pytest.fixture
def multi_turn_registry():
    """Registry with only multi-turn probes."""
    registry = ProbeRegistry()
    register_multi_turn_probes(registry)
    return registry


@pytest.fixture
def full_registry():
    """Registry with all probe types including advanced."""
    registry = ProbeRegistry()
    register_default_probes(registry)
    register_agent_probes(registry)
    register_fusion_probes(registry)
    register_advanced_probes(registry)
    register_multi_turn_probes(registry)
    return registry


# ============================================================================
# Registration Counts
# ============================================================================


class TestRegistrationCounts:
    def test_advanced_probe_count(self, advanced_registry):
        assert len(advanced_registry) == 5

    def test_multi_turn_probe_count(self, multi_turn_registry):
        assert len(multi_turn_registry) == 4

    def test_combined_count(self, full_registry):
        # Community: 0 default + 0 agent + 0 fusion + 5 advanced + 4 multi-turn = 9
        assert len(full_registry) >= 9


# ============================================================================
# Payload Non-Emptiness
# ============================================================================


class TestPayloadNonEmpty:
    def test_advanced_payloads_non_empty(self, advanced_registry):
        for probe in advanced_registry.get_all():
            payload = probe.build_payload()
            assert payload and len(payload) > 0, f"{probe.name} has empty payload"

    def test_multi_turn_payloads_non_empty(self, multi_turn_registry):
        for probe in multi_turn_registry.get_all():
            payload = probe.build_payload()
            assert payload and len(payload) > 0, f"{probe.name} has empty payload"

    def test_all_probes_have_target_defense(self, full_registry):
        for probe in full_registry.get_all():
            assert probe.target_defense, f"{probe.name} has no target_defense"

    def test_all_probes_have_unique_names(self, full_registry):
        names = [p.name for p in full_registry.get_all()]
        assert len(names) == len(set(names)), (
            f"Duplicate probe names: {[n for n in names if names.count(n) > 1]}"
        )


# ============================================================================
# Multi-Turn Backward Compatibility
# ============================================================================


class TestMultiTurnCompat:
    def test_build_payload_returns_first_turn(self, multi_turn_registry):
        for probe in multi_turn_registry.get_all():
            assert isinstance(probe, MultiTurnProbe)
            turns = probe.build_turns()
            assert probe.build_payload() == turns[0][0], (
                f"{probe.name}: build_payload() != first turn payload"
            )

    def test_build_context_returns_first_turn(self, multi_turn_registry):
        for probe in multi_turn_registry.get_all():
            turns = probe.build_turns()
            assert probe.build_context() == turns[0][1], (
                f"{probe.name}: build_context() != first turn context"
            )

    def test_num_turns_matches_build_turns(self, multi_turn_registry):
        for probe in multi_turn_registry.get_all():
            assert probe.num_turns == len(probe.build_turns()), (
                f"{probe.name}: num_turns mismatch"
            )

    def test_multi_turn_is_probe_subclass(self, multi_turn_registry):
        from goop_shield.red.probes import Probe

        for probe in multi_turn_registry.get_all():
            assert isinstance(probe, Probe), f"{probe.name} is not a Probe"


# ============================================================================
# Multi-Turn Turn Count Validation
# ============================================================================


class TestMultiTurnTurnCounts:
    def test_crescendo_has_5_turns(self, multi_turn_registry):
        probe = multi_turn_registry.get("crescendo_tool_injection")
        assert probe is not None
        assert probe.num_turns == 5

    def test_dan_has_3_turns(self, multi_turn_registry):
        probe = multi_turn_registry.get("dan_persona_reinforcement")
        assert probe is not None
        assert probe.num_turns == 3

    def test_roleplay_has_4_turns(self, multi_turn_registry):
        probe = multi_turn_registry.get("role_play_escalation")
        assert probe is not None
        assert probe.num_turns == 4

    def test_authority_has_4_turns(self, multi_turn_registry):
        probe = multi_turn_registry.get("authority_escalation")
        assert probe is not None
        assert probe.num_turns == 4

    def test_all_multi_turn_have_multiple_turns(self, multi_turn_registry):
        for probe in multi_turn_registry.get_all():
            assert probe.num_turns >= 2, f"{probe.name} has only {probe.num_turns} turn(s)"


# ============================================================================
# Integration: Runner with advanced_probes_enabled
# ============================================================================


class TestAdvancedProbeIntegration:
    def test_runner_not_available_in_community(self):
        """RedTeamRunner is an enterprise feature — stub raises ImportError."""
        with pytest.raises(ImportError):
            from goop_shield.red.runner import RedTeamRunner

            RedTeamRunner(None, None)


# ============================================================================
# Specific Probe Payload Validation (Tier 3 encoding probes)
# ============================================================================


class TestEncodingProbePayloads:
    def test_emoji_uses_regional_indicators(self, advanced_registry):
        probe = advanced_registry.get("emoji_substitution")
        payload = probe.build_payload()
        # Regional indicator symbols are in U+1F1E6-1F1FF range
        assert any(0x1F1E6 <= ord(c) <= 0x1F1FF for c in payload)

    def test_interpunct_probe_uses_hyphenation_point(self, advanced_registry):
        probe = advanced_registry.get("non_ws_char_split")
        payload = probe.build_payload()
        assert "\u2027" in payload

    def test_html_comment_has_no_keywords(self, advanced_registry):
        probe = advanced_registry.get("html_comment_nokey")
        ctx = probe.build_context()
        output = ctx["tool_output"]
        # Should NOT contain SYSTEM, ADMIN, ROOT, OVERRIDE in the HTML comment
        import re

        comment_match = re.search(r"<!--(.*?)-->", output, re.DOTALL)
        assert comment_match is not None
        comment_text = comment_match.group(1).upper()
        for keyword in ("SYSTEM", "ADMIN", "ROOT", "OVERRIDE"):
            assert keyword not in comment_text, f"HTML comment contains keyword: {keyword}"

    def test_split_blob_has_base64(self, advanced_registry):
        probe = advanced_registry.get("split_blob_encoding")
        payload = probe.build_payload()
        assert "Blob A:" in payload
        assert "Blob B:" in payload

    def test_crescendo_final_turn_has_exfil(self, multi_turn_registry):
        probe = multi_turn_registry.get("crescendo_tool_injection")
        turns = probe.build_turns()
        final_payload = turns[-1][0]
        assert "curl" in final_payload.lower()
