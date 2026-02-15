"""Tests for Signal Fusion — cross-defense noisy-OR correlation.

RFC Section 10.3: 17 test cases covering fusion math, edge cases,
feature flag, and integration with session tracking.
"""

from __future__ import annotations

import pytest

from goop_shield.config import ShieldConfig
from goop_shield.defender import Defender
from goop_shield.defenses import DefenseRegistry
from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict
from goop_shield.models import DefendRequest, DefenseAction

# ---------------------------------------------------------------------------
# Test helper defenses
# ---------------------------------------------------------------------------


class WeakSignalDefense(InlineDefense):
    """Defense that always passes but emits a weak threat_confidence."""

    def __init__(self, defense_name: str, threat_confidence: float) -> None:
        self._name = defense_name
        self._tc = threat_confidence

    @property
    def name(self) -> str:
        return self._name

    def execute(self, context: DefenseContext) -> InlineVerdict:
        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=context.current_prompt,
            confidence=0.5,
            threat_confidence=self._tc,
        )


class BlockingDefense(InlineDefense):
    """Defense that always blocks."""

    @property
    def name(self) -> str:
        return "blocker"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        return InlineVerdict(
            defense_name=self.name,
            blocked=True,
            filtered_prompt=context.current_prompt,
            confidence=0.9,
            threat_confidence=0.9,
        )


class SanitizingDefense(InlineDefense):
    """Defense that sanitizes and emits a threat_confidence."""

    def __init__(self, defense_name: str, threat_confidence: float) -> None:
        self._name = defense_name
        self._tc = threat_confidence

    @property
    def name(self) -> str:
        return self._name

    def execute(self, context: DefenseContext) -> InlineVerdict:
        return InlineVerdict(
            defense_name=self.name,
            sanitized=True,
            filtered_prompt=context.current_prompt.upper(),
            confidence=0.6,
            threat_confidence=self._tc,
        )


class BinaryPassDefense(InlineDefense):
    """Defense with high confidence but zero threat_confidence (binary pass)."""

    @property
    def name(self) -> str:
        return "binary_pass"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=context.current_prompt,
            confidence=0.95,
            threat_confidence=0.0,
        )


class ErrorDefense(InlineDefense):
    """Defense that always raises."""

    @property
    def name(self) -> str:
        return "error_defense"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        raise RuntimeError("Intentional error for testing")


# ---------------------------------------------------------------------------
# Helper factory
# ---------------------------------------------------------------------------


def _make_defender(
    defenses: list[InlineDefense],
    *,
    fusion_enabled: bool = True,
    blocking_enabled: bool = True,
    threshold: float = 0.45,
    min_signal: float = 0.05,
    failure_policy: str = "closed",
    session_tracking: bool = False,
    session_blocking: bool = False,
) -> Defender:
    """Build a Defender with only the given defenses and fusion config."""
    registry = DefenseRegistry()
    for d in defenses:
        registry.register(d)

    config = ShieldConfig(
        signal_fusion_enabled=fusion_enabled,
        signal_fusion_blocking_enabled=blocking_enabled,
        signal_fusion_threshold=threshold,
        signal_fusion_min_signal=min_signal,
        failure_policy=failure_policy,
        session_tracking_enabled=session_tracking,
        session_tracker_blocking_enabled=session_blocking,
        # Disable defaults that interfere with isolated tests
        telemetry_enabled=False,
    )
    return Defender(config=config, registry=registry)


def _defend(defender: Defender, prompt: str = "test prompt") -> object:
    return defender.defend(DefendRequest(prompt=prompt))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSignalFusion:
    """RFC Section 10.3: 17 signal fusion test cases."""

    # 0. No defenses (empty verdicts) → fused=0.0, allow
    def test_empty_verdicts(self) -> None:
        d = _make_defender([])
        resp = _defend(d)
        assert resp.allow is True
        assert resp.fused_score == pytest.approx(0.0)

    # 1. All 0.0 → fused=0.0, allow
    def test_all_zero_signals(self) -> None:
        d = _make_defender(
            [
                WeakSignalDefense("a", 0.0),
                WeakSignalDefense("b", 0.0),
            ]
        )
        resp = _defend(d)
        assert resp.allow is True
        assert resp.fused_score == pytest.approx(0.0)

    # 2. Single 0.2 → 0.2, allow
    def test_single_weak_signal(self) -> None:
        d = _make_defender([WeakSignalDefense("a", 0.2)])
        resp = _defend(d)
        assert resp.allow is True
        assert resp.fused_score == pytest.approx(0.2)

    # 3. Two 0.2 → 0.36, allow
    def test_two_weak_signals(self) -> None:
        d = _make_defender(
            [
                WeakSignalDefense("a", 0.2),
                WeakSignalDefense("b", 0.2),
            ]
        )
        resp = _defend(d)
        assert resp.allow is True
        assert resp.fused_score == pytest.approx(0.36)

    # 4. Three 0.2 → 0.488, block
    def test_three_weak_signals_fuse_to_block(self) -> None:
        d = _make_defender(
            [
                WeakSignalDefense("a", 0.2),
                WeakSignalDefense("b", 0.2),
                WeakSignalDefense("c", 0.2),
            ]
        )
        resp = _defend(d)
        assert resp.allow is False
        assert resp.fused_score == pytest.approx(0.488)
        assert resp.confidence == pytest.approx(0.488)

    # 5. One 0.5 → block (>= 0.45)
    def test_single_strong_signal_blocks(self) -> None:
        d = _make_defender([WeakSignalDefense("a", 0.5)])
        resp = _defend(d)
        assert resp.allow is False
        assert resp.fused_score == pytest.approx(0.5)

    # 6. Two 0.35 → 0.5775, block
    def test_two_medium_signals(self) -> None:
        d = _make_defender(
            [
                WeakSignalDefense("a", 0.35),
                WeakSignalDefense("b", 0.35),
            ]
        )
        resp = _defend(d)
        assert resp.allow is False
        assert resp.fused_score == pytest.approx(0.5775)

    # 7. Fusion disabled → fused_score=None, allow
    def test_fusion_disabled(self) -> None:
        d = _make_defender(
            [WeakSignalDefense("a", 0.2), WeakSignalDefense("b", 0.2), WeakSignalDefense("c", 0.2)],
            fusion_enabled=False,
        )
        resp = _defend(d)
        assert resp.allow is True
        assert resp.fused_score is None

    # 8. Defense already blocked → fusion skipped
    def test_already_blocked_skips_fusion(self) -> None:
        d = _make_defender(
            [
                BlockingDefense(),
                WeakSignalDefense("a", 0.5),
            ]
        )
        resp = _defend(d)
        assert resp.allow is False
        # Fusion didn't fire — fused_score computed but not used for blocking
        assert "signal_fusion" not in resp.defenses_applied

    # 9. Boundary: fused == threshold → block (>=)
    def test_boundary_exact_threshold(self) -> None:
        d = _make_defender(
            [WeakSignalDefense("a", 0.5)],
            threshold=0.5,
        )
        resp = _defend(d)
        assert resp.allow is False
        assert resp.fused_score == pytest.approx(0.5)

    # 10. failure_policy=open + error defense → fewer signals
    def test_failure_policy_open_with_error(self) -> None:
        d = _make_defender(
            [
                WeakSignalDefense("a", 0.2),
                ErrorDefense(),
                WeakSignalDefense("b", 0.2),
                WeakSignalDefense("c", 0.2),
            ],
            failure_policy="open",
        )
        resp = _defend(d)
        # Error defense skipped (policy=open), so 3 weak signals still fuse
        assert resp.allow is False
        assert resp.fused_score == pytest.approx(0.488)

    # 11. Fusion block feeds session tracker
    def test_fusion_feeds_session_tracker(self) -> None:
        d = _make_defender(
            [
                WeakSignalDefense("a", 0.2),
                WeakSignalDefense("b", 0.2),
                WeakSignalDefense("c", 0.2),
            ],
            session_tracking=True,
            session_blocking=False,
        )
        resp = _defend(d, "test prompt")
        assert resp.allow is False
        # Session tracker should have recorded the blocked turn
        assert d.session_tracker is not None
        risk = d.session_tracker.get_risk("__default__")
        assert risk is not None
        assert risk.turn_count == 1

    # 12. Zero threat_confidence excluded
    def test_zero_threat_confidence_excluded(self) -> None:
        d = _make_defender(
            [
                WeakSignalDefense("a", 0.0),
                WeakSignalDefense("b", 0.2),
            ]
        )
        resp = _defend(d)
        assert resp.allow is True
        # Only b contributes: fused = 0.2
        assert resp.fused_score == pytest.approx(0.2)

    # 13. fused_score in debug response, not public
    def test_fused_score_in_debug_not_public(self) -> None:
        d = _make_defender(
            [
                WeakSignalDefense("a", 0.2),
                WeakSignalDefense("b", 0.2),
            ]
        )
        resp = _defend(d)
        # DefendResponse has fused_score
        assert resp.fused_score is not None
        # Public API constructs a manual dict — verified via app.py structure,
        # not tested here (integration test territory)

    # 14. "signal_fusion" in defenses_applied + verdict details
    def test_signal_fusion_in_applied_and_verdicts(self) -> None:
        d = _make_defender(
            [
                WeakSignalDefense("a", 0.2),
                WeakSignalDefense("b", 0.2),
                WeakSignalDefense("c", 0.2),
            ]
        )
        resp = _defend(d)
        assert "signal_fusion" in resp.defenses_applied
        fusion_verdicts = [v for v in resp.verdicts if v.defense_name == "signal_fusion"]
        assert len(fusion_verdicts) == 1
        fv = fusion_verdicts[0]
        assert fv.confidence == pytest.approx(0.488)
        assert "contributors" in fv.details
        assert "a" in fv.details
        assert "b" in fv.details
        assert "c" in fv.details

    # 15. Noise floor: signals below 0.05 excluded
    def test_noise_floor_excludes_tiny_signals(self) -> None:
        d = _make_defender(
            [
                WeakSignalDefense("a", 0.04),
                WeakSignalDefense("b", 0.04),
                WeakSignalDefense("c", 0.04),
            ]
        )
        resp = _defend(d)
        assert resp.allow is True
        # All below min_signal (0.05) → fused = 0.0
        assert resp.fused_score == pytest.approx(0.0)

    # 16. Sanitized verdicts excluded
    def test_sanitized_verdicts_excluded(self) -> None:
        d = _make_defender(
            [
                SanitizingDefense("sanitizer", 0.3),
                WeakSignalDefense("a", 0.2),
                WeakSignalDefense("b", 0.2),
            ]
        )
        resp = _defend(d)
        assert resp.allow is True
        # Sanitizer excluded, only a+b: 1-(0.8*0.8) = 0.36
        assert resp.fused_score == pytest.approx(0.36)

    # 17. Binary defense (confidence=0.95, threat_confidence=0.0) not counted
    def test_binary_pass_not_counted(self) -> None:
        d = _make_defender(
            [
                BinaryPassDefense(),
                WeakSignalDefense("a", 0.2),
                WeakSignalDefense("b", 0.2),
            ]
        )
        resp = _defend(d)
        assert resp.allow is True
        # binary_pass has tc=0.0, excluded. Only a+b: 0.36
        assert resp.fused_score == pytest.approx(0.36)


# ---------------------------------------------------------------------------
# Shadow mode tests (blocking_enabled=False)
# ---------------------------------------------------------------------------


class TestSignalFusionShadow:
    """Tests for shadow mode: fusion fires but does not block."""

    def _three_weak(self) -> tuple[Defender, object]:
        """Helper: 3x WeakSignal(0.2) with blocking disabled -> fused=0.488."""
        d = _make_defender(
            [
                WeakSignalDefense("a", 0.2),
                WeakSignalDefense("b", 0.2),
                WeakSignalDefense("c", 0.2),
            ],
            blocking_enabled=False,
        )
        return d, _defend(d)

    def test_shadow_allows_despite_threshold_exceeded(self) -> None:
        _d, resp = self._three_weak()
        assert resp.allow is True
        assert resp.fused_score == pytest.approx(0.488)

    def test_shadow_verdict_in_defenses_applied(self) -> None:
        _d, resp = self._three_weak()
        assert "signal_fusion_shadow" in resp.defenses_applied

    def test_shadow_verdict_action_is_allow(self) -> None:
        _d, resp = self._three_weak()
        shadow_verdicts = [v for v in resp.verdicts if v.defense_name == "signal_fusion_shadow"]
        assert len(shadow_verdicts) == 1
        assert shadow_verdicts[0].action == DefenseAction.ALLOW

    def test_shadow_verdict_details(self) -> None:
        _d, resp = self._three_weak()
        shadow_verdicts = [v for v in resp.verdicts if v.defense_name == "signal_fusion_shadow"]
        assert len(shadow_verdicts) == 1
        details = shadow_verdicts[0].details
        assert "Shadow" in details
        assert "would block" in details

    def test_shadow_total_blocked_not_incremented(self) -> None:
        d, _resp = self._three_weak()
        assert d.total_blocked == 0

    def test_shadow_fusion_would_block_counter(self) -> None:
        d, _resp = self._three_weak()
        assert d.fusion_would_block == 1

    def test_shadow_fusion_evaluations_counter(self) -> None:
        d, _resp = self._three_weak()
        assert d.fusion_evaluations == 1

    def test_shadow_session_tracker_no_block(self) -> None:
        d = _make_defender(
            [
                WeakSignalDefense("a", 0.2),
                WeakSignalDefense("b", 0.2),
                WeakSignalDefense("c", 0.2),
            ],
            blocking_enabled=False,
            session_tracking=True,
        )
        resp = _defend(d)
        assert resp.allow is True


# ---------------------------------------------------------------------------
# Blocking mode tests (blocking_enabled=True)
# ---------------------------------------------------------------------------


class TestSignalFusionBlocking:
    """Tests for active blocking mode: fusion fires and blocks."""

    def _three_weak_blocking(self) -> tuple[Defender, object]:
        """Helper: 3x WeakSignal(0.2) with blocking enabled -> fused=0.488."""
        d = _make_defender(
            [
                WeakSignalDefense("a", 0.2),
                WeakSignalDefense("b", 0.2),
                WeakSignalDefense("c", 0.2),
            ],
            blocking_enabled=True,
        )
        return d, _defend(d)

    def test_blocking_enabled_actually_blocks(self) -> None:
        _d, resp = self._three_weak_blocking()
        assert resp.allow is False

    def test_blocking_uses_signal_fusion_name(self) -> None:
        _d, resp = self._three_weak_blocking()
        assert "signal_fusion" in resp.defenses_applied
        assert "signal_fusion_shadow" not in resp.defenses_applied

    def test_blocking_increments_would_block(self) -> None:
        d, _resp = self._three_weak_blocking()
        assert d.fusion_would_block == 1

    def test_blocking_increments_total_blocked(self) -> None:
        d, _resp = self._three_weak_blocking()
        assert d.total_blocked == 1


# ---------------------------------------------------------------------------
# Session-aware fusion threshold tests
# ---------------------------------------------------------------------------


def _make_session_aware_defender(
    defenses: list[InlineDefense],
    *,
    session_aware: bool = True,
    escalation_multiplier: float = 0.7,
    blocking_enabled: bool = True,
    threshold: float = 0.45,
) -> Defender:
    """Build a Defender with session-aware fusion config."""
    registry = DefenseRegistry()
    for d in defenses:
        registry.register(d)

    config = ShieldConfig(
        signal_fusion_enabled=True,
        signal_fusion_blocking_enabled=blocking_enabled,
        signal_fusion_threshold=threshold,
        signal_fusion_min_signal=0.05,
        signal_fusion_session_aware=session_aware,
        signal_fusion_escalation_multiplier=escalation_multiplier,
        session_tracking_enabled=True,
        session_tracker_blocking_enabled=False,
        failure_policy="open",
        telemetry_enabled=False,
    )
    return Defender(config=config, registry=registry)


def _prime_session_risk(defender: Defender, session_id: str, level: str) -> None:
    """Send enough high-signal turns to push session risk to the desired level.

    The session tracker computes risk as:
      - high: cumulative_signal >= threshold (default 2.0) OR escalating
      - medium: cumulative_signal >= threshold * 0.5
      - low: otherwise
    We use high injection_signal values to push cumulative quickly.
    """
    from goop_shield.session_tracker import SessionTracker

    assert defender.session_tracker is not None
    if level == "low":
        return  # no turns needed
    elif level == "medium":
        # Push cumulative to ~1.0 (>= 2.0*0.5=1.0 for medium)
        for i in range(3):
            defender.session_tracker.record_turn(
                session_id=session_id,
                injection_signal=0.4,
                prompt_hash=SessionTracker.hash_prompt(f"prime-{i}"),
            )
    elif level == "high":
        # Push cumulative to >= 2.0 for high
        for i in range(5):
            defender.session_tracker.record_turn(
                session_id=session_id,
                injection_signal=0.5,
                prompt_hash=SessionTracker.hash_prompt(f"prime-{i}"),
            )
    # Verify we hit the expected level
    risk = defender.session_tracker.get_risk(session_id)
    assert risk.risk_level == level, f"Expected {level}, got {risk.risk_level}"


class TestSignalFusionSessionAware:
    """Tests for session-aware fusion threshold adjustment."""

    # 1. Low risk session → standard threshold, 2 weak signals (0.36) pass
    def test_low_risk_standard_threshold(self) -> None:
        d = _make_session_aware_defender(
            [WeakSignalDefense("a", 0.2), WeakSignalDefense("b", 0.2)],
        )
        # No session priming → low risk
        resp = d.defend(DefendRequest(prompt="test", context={"session_id": "s1"}))
        # fused = 0.36 < 0.45 → allow
        assert resp.allow is True
        assert resp.fused_score == pytest.approx(0.36)

    # 2. Medium risk → threshold = 0.45 * 0.85 = 0.3825, two 0.25 signals
    #    fused = 1-(0.75*0.75) = 0.4375 > 0.3825 → blocks
    def test_medium_risk_reduced_threshold_blocks(self) -> None:
        d = _make_session_aware_defender(
            [WeakSignalDefense("a", 0.25), WeakSignalDefense("b", 0.25)],
        )
        _prime_session_risk(d, "s1", "medium")
        resp = d.defend(DefendRequest(prompt="test", context={"session_id": "s1"}))
        # fused = 0.4375 > 0.3825 → block
        assert resp.allow is False
        assert resp.fused_score == pytest.approx(0.4375)

    # 3. High risk → threshold = 0.45 * 0.7 = 0.315, two 0.2 signals
    #    fused = 0.36 > 0.315 → blocks
    def test_high_risk_blocks_two_weak_signals(self) -> None:
        d = _make_session_aware_defender(
            [WeakSignalDefense("a", 0.2), WeakSignalDefense("b", 0.2)],
        )
        _prime_session_risk(d, "s1", "high")
        resp = d.defend(DefendRequest(prompt="test", context={"session_id": "s1"}))
        # fused = 0.36 > 0.315 → block
        assert resp.allow is False
        assert resp.fused_score == pytest.approx(0.36)

    # 4. Session-aware disabled → standard threshold even with high risk
    def test_session_aware_disabled_ignores_risk(self) -> None:
        d = _make_session_aware_defender(
            [WeakSignalDefense("a", 0.2), WeakSignalDefense("b", 0.2)],
            session_aware=False,
        )
        _prime_session_risk(d, "s1", "high")
        resp = d.defend(DefendRequest(prompt="test", context={"session_id": "s1"}))
        # fused = 0.36 < 0.45 → allow (no adjustment)
        assert resp.allow is True

    # 5. No session tracker → standard threshold (graceful)
    def test_no_session_tracker_graceful(self) -> None:
        registry = DefenseRegistry()
        registry.register(WeakSignalDefense("a", 0.2))
        registry.register(WeakSignalDefense("b", 0.2))
        config = ShieldConfig(
            signal_fusion_enabled=True,
            signal_fusion_blocking_enabled=True,
            signal_fusion_threshold=0.45,
            signal_fusion_session_aware=True,
            session_tracking_enabled=False,  # no tracker
            telemetry_enabled=False,
        )
        d = Defender(config=config, registry=registry)
        resp = d.defend(DefendRequest(prompt="test"))
        # No session tracker → no adjustment, 0.36 < 0.45 → allow
        assert resp.allow is True
        assert d.fusion_session_adjusted == 0

    # 6. Session-aware in shadow mode → shadow verdict with adjusted threshold
    def test_session_aware_shadow_mode(self) -> None:
        d = _make_session_aware_defender(
            [WeakSignalDefense("a", 0.2), WeakSignalDefense("b", 0.2)],
            blocking_enabled=False,
        )
        _prime_session_risk(d, "s1", "high")
        resp = d.defend(DefendRequest(prompt="test", context={"session_id": "s1"}))
        # Shadow mode: fused=0.36 > 0.315, but doesn't block
        assert resp.allow is True
        assert "signal_fusion_shadow" in resp.defenses_applied
        shadow = [v for v in resp.verdicts if v.defense_name == "signal_fusion_shadow"]
        assert len(shadow) == 1
        assert "session-adjusted" in shadow[0].details

    # 7. Effective threshold shown in verdict details
    def test_effective_threshold_in_details(self) -> None:
        d = _make_session_aware_defender(
            [WeakSignalDefense("a", 0.2), WeakSignalDefense("b", 0.2)],
        )
        _prime_session_risk(d, "s1", "high")
        resp = d.defend(DefendRequest(prompt="test", context={"session_id": "s1"}))
        fusion_verdicts = [v for v in resp.verdicts if v.defense_name == "signal_fusion"]
        assert len(fusion_verdicts) == 1
        details = fusion_verdicts[0].details
        assert "0.3150" in details  # effective threshold
        assert "session-adjusted from 0.45" in details

    # 8. Counter incremented when threshold adjusted
    def test_session_adjusted_counter(self) -> None:
        d = _make_session_aware_defender(
            [WeakSignalDefense("a", 0.2), WeakSignalDefense("b", 0.2)],
        )
        _prime_session_risk(d, "s1", "high")
        assert d.fusion_session_adjusted == 0
        d.defend(DefendRequest(prompt="test", context={"session_id": "s1"}))
        assert d.fusion_session_adjusted == 1

    # 9. Non-string session_id types don't crash (regression for #452 bug)
    @pytest.mark.parametrize(
        "session_id",
        [["a", "b"], {"key": "val"}, 12345, None, True],
        ids=["list", "dict", "int", "none", "bool"],
    )
    def test_non_string_session_id_no_crash(self, session_id) -> None:
        d = _make_session_aware_defender(
            [WeakSignalDefense("a", 0.3), WeakSignalDefense("b", 0.3)],
        )
        resp = d.defend(DefendRequest(prompt="test", context={"session_id": session_id}))
        # Should not crash — just verify we get a valid response
        assert resp.allow is not None


# ---------------------------------------------------------------------------
# End-to-end fusion probe tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    len(__import__("goop_shield.red.probes", fromlist=["ProbeRegistry"]).ProbeRegistry()) == 0
    and not hasattr(
        __import__("goop_shield.red.probes", fromlist=["FusionUrgencyReconProbe"]),
        "FusionUrgencyReconProbe",
    ),
    reason="Requires goop-ai Enterprise",
)
class TestFusionProbesEndToEnd:
    """Run each fusion red-team probe through the real defense pipeline and
    verify that it produces a non-trivial fused score."""

    @staticmethod
    def _make_full_defender(blocking: bool = True) -> Defender:
        """Build a Defender with all default defenses and fusion enabled."""
        config = ShieldConfig(
            signal_fusion_enabled=True,
            signal_fusion_blocking_enabled=blocking,
            signal_fusion_threshold=0.45,
            signal_fusion_min_signal=0.05,
            telemetry_enabled=False,
        )
        return Defender(config=config)

    def test_fusion_urgency_recon_produces_fused_score(self) -> None:
        from goop_shield.red.probes import FusionUrgencyReconProbe

        d = self._make_full_defender(blocking=False)
        payload = FusionUrgencyReconProbe().build_payload()
        resp = d.defend(DefendRequest(prompt=payload))
        assert resp.fused_score is not None
        assert resp.fused_score > 0.0, "Probe should trigger at least one weak signal"

    def test_fusion_exfil_recon_produces_fused_score(self) -> None:
        from goop_shield.red.probes import FusionExfilReconProbe

        d = self._make_full_defender(blocking=False)
        payload = FusionExfilReconProbe().build_payload()
        resp = d.defend(DefendRequest(prompt=payload))
        assert resp.fused_score is not None
        assert resp.fused_score > 0.0

    def test_fusion_flattery_token_produces_fused_score(self) -> None:
        from goop_shield.red.probes import FusionFlatteryTokenProbe

        d = self._make_full_defender(blocking=False)
        payload = FusionFlatteryTokenProbe().build_payload()
        resp = d.defend(DefendRequest(prompt=payload))
        assert resp.fused_score is not None
        assert resp.fused_score > 0.0

    def test_fusion_minimization_creds_produces_fused_score(self) -> None:
        from goop_shield.red.probes import FusionMinimizationCredsProbe

        d = self._make_full_defender(blocking=False)
        payload = FusionMinimizationCredsProbe().build_payload()
        resp = d.defend(DefendRequest(prompt=payload))
        assert resp.fused_score is not None
        assert resp.fused_score > 0.0

    def test_fusion_helpfulness_exec_produces_fused_score(self) -> None:
        from goop_shield.red.probes import FusionHelpfulnessExecProbe

        d = self._make_full_defender(blocking=False)
        payload = FusionHelpfulnessExecProbe().build_payload()
        resp = d.defend(DefendRequest(prompt=payload))
        assert resp.fused_score is not None
        assert resp.fused_score > 0.0


# ---------------------------------------------------------------------------
# Concurrency test
# ---------------------------------------------------------------------------


class TestFusionConcurrency:
    """Verify fusion counters are accurate under concurrent load."""

    def test_concurrent_fusion_counter_accuracy(self) -> None:
        import concurrent.futures

        d = _make_defender(
            [
                WeakSignalDefense("a", 0.2),
                WeakSignalDefense("b", 0.2),
                WeakSignalDefense("c", 0.2),
            ],
            blocking_enabled=True,
        )
        n_requests = 100

        def run_one(_: int) -> None:
            d.defend(DefendRequest(prompt="concurrent test"))

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(run_one, range(n_requests)))

        assert d.fusion_evaluations == n_requests
        assert d.fusion_would_block == n_requests  # all 3x0.2 -> 0.488 >= 0.45


# ---------------------------------------------------------------------------
# get_stats() includes fusion counters
# ---------------------------------------------------------------------------


class TestFusionStats:
    """Verify fusion counters appear in get_stats()."""

    def test_get_stats_includes_fusion(self) -> None:
        d = _make_defender(
            [
                WeakSignalDefense("a", 0.2),
                WeakSignalDefense("b", 0.2),
                WeakSignalDefense("c", 0.2),
            ],
            blocking_enabled=True,
        )
        _defend(d)
        stats = d.get_stats()
        assert "fusion_stats" in stats
        assert stats["fusion_stats"]["evaluations"] == 1
        assert stats["fusion_stats"]["would_block"] == 1
        assert stats["fusion_stats"]["session_adjusted"] == 0

    def test_get_stats_no_fusion_when_disabled(self) -> None:
        d = _make_defender(
            [WeakSignalDefense("a", 0.2)],
            fusion_enabled=False,
        )
        _defend(d)
        stats = d.get_stats()
        assert "fusion_stats" not in stats
