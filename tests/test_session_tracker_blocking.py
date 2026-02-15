"""Tests for SessionTracker blocking integration (P1-2).

Verifies that the Defender blocks requests when session risk reaches
"high" and session_tracker_blocking_enabled is True.
"""

from __future__ import annotations

from goop_shield.config import ShieldConfig
from goop_shield.defender import Defender
from goop_shield.defenses import DefenseRegistry
from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict
from goop_shield.models import DefendRequest, DefenseAction

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FixedSignalDefense(InlineDefense):
    """Defense that reports a fixed confidence without blocking.

    Used to produce deterministic injection_signal values for the session
    tracker.  The defense does NOT block so that the session tracker's
    ``not blocked`` guard is satisfied.

    Signal contribution per turn (from defender logic):
      - Non-blocking with confidence > 0: confidence * 0.5
    """

    def __init__(self, confidence: float = 0.9) -> None:
        self._confidence = confidence

    @property
    def name(self) -> str:
        return "fixed_signal"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        return InlineVerdict(
            defense_name=self.name,
            blocked=False,
            filtered_prompt=context.current_prompt,
            confidence=self._confidence,
            details="fixed signal for testing",
        )


class _NoopMandatoryDefense(InlineDefense):
    """No-op stand-in for mandatory defenses to prevent real ones from being re-registered."""

    def __init__(self, defense_name: str) -> None:
        self._name = defense_name

    @property
    def name(self) -> str:
        return self._name

    def execute(self, context: DefenseContext) -> InlineVerdict:
        return InlineVerdict(
            defense_name=self.name,
            blocked=False,
            filtered_prompt=context.current_prompt,
            confidence=0.0,
            details="noop mandatory stand-in",
        )


class _BlockingDefense(InlineDefense):
    """Defense that always blocks with a fixed confidence."""

    def __init__(self, confidence: float = 0.9) -> None:
        self._confidence = confidence

    @property
    def name(self) -> str:
        return "blocking_signal"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        return InlineVerdict(
            defense_name=self.name,
            blocked=True,
            filtered_prompt=context.current_prompt,
            confidence=self._confidence,
            details="blocking signal for testing",
        )


def _make_request(prompt: str = "test prompt", session_id: str = "sess-1") -> DefendRequest:
    return DefendRequest(prompt=prompt, context={"session_id": session_id})


def _make_defender(
    *,
    blocking_enabled: bool,
    defense_confidence: float = 0.9,
) -> Defender:
    """Create a Defender with session tracking and a single controlled defense.

    Signal per turn = defense_confidence * 0.5 (non-blocking path).
    Registers no-op stand-ins for mandatory defenses to prevent the real
    implementations from being re-registered and producing uncontrolled signals.
    """
    config = ShieldConfig(
        session_tracking_enabled=True,
        session_tracker_blocking_enabled=blocking_enabled,
    )
    registry = DefenseRegistry()
    registry.register(_FixedSignalDefense(confidence=defense_confidence))
    # Register no-op stand-ins for mandatory defenses so they don't get
    # re-registered with real implementations that produce extra signals.
    for mname in ShieldConfig.MANDATORY_DEFENSES:
        registry.register(_NoopMandatoryDefense(mname))
    return Defender(config=config, registry=registry)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSessionTrackerBlockingDisabled:
    """When session_tracker_blocking_enabled=False (default), no session
    tracker verdict should ever appear."""

    def test_high_risk_does_not_produce_session_verdict(self):
        defender = _make_defender(blocking_enabled=False, defense_confidence=0.9)
        # Send 5 turns with high signal to push cumulative well above 2.0
        for _ in range(5):
            resp = defender.defend(_make_request())
        session_verdicts = [v for v in resp.verdicts if v.defense_name == "session_tracker"]
        assert len(session_verdicts) == 0

    def test_config_defaults_to_false(self):
        config = ShieldConfig()
        assert config.session_tracker_blocking_enabled is False


class TestSessionTrackerBlockingEnabled:
    """When session_tracker_blocking_enabled=True, the defender should append
    a session_tracker BLOCK verdict once cumulative risk reaches "high"."""

    def test_high_cumulative_signal_blocks(self):
        # Non-blocking defense with confidence=0.9 contributes 0.45 per turn.
        # After 5 turns: 5 * 0.45 = 2.25 >= 2.0 threshold => high risk.
        defender = _make_defender(blocking_enabled=True, defense_confidence=0.9)
        for _ in range(5):
            resp = defender.defend(_make_request())
        session_verdicts = [v for v in resp.verdicts if v.defense_name == "session_tracker"]
        assert len(session_verdicts) == 1
        assert session_verdicts[0].action == DefenseAction.BLOCK

    def test_verdict_defense_name_is_session_tracker(self):
        defender = _make_defender(blocking_enabled=True, defense_confidence=0.9)
        for _ in range(5):
            resp = defender.defend(_make_request())
        session_verdicts = [v for v in resp.verdicts if v.defense_name == "session_tracker"]
        assert len(session_verdicts) == 1
        assert session_verdicts[0].defense_name == "session_tracker"

    def test_verdict_details_contain_session_info(self):
        defender = _make_defender(blocking_enabled=True, defense_confidence=0.9)
        for _ in range(5):
            resp = defender.defend(_make_request())
        session_verdicts = [v for v in resp.verdicts if v.defense_name == "session_tracker"]
        assert len(session_verdicts) == 1
        assert "cumulative_signal=" in session_verdicts[0].details
        assert "turns=" in session_verdicts[0].details
        assert "escalating=" in session_verdicts[0].details

    def test_low_signal_does_not_block(self):
        # Signal per turn = 0.1 * 0.5 = 0.05.
        # After 5 turns: 0.25, well below 2.0 threshold.
        defender = _make_defender(blocking_enabled=True, defense_confidence=0.1)
        for _ in range(5):
            resp = defender.defend(_make_request())
        session_verdicts = [v for v in resp.verdicts if v.defense_name == "session_tracker"]
        assert len(session_verdicts) == 0

    def test_medium_signal_does_not_block(self):
        # Signal per turn = 0.6 * 0.5 = 0.3.
        # After 5 turns: 1.5, which is >= 1.0 (medium) but < 2.0 (high).
        defender = _make_defender(blocking_enabled=True, defense_confidence=0.6)
        for _ in range(5):
            resp = defender.defend(_make_request())
        session_verdicts = [v for v in resp.verdicts if v.defense_name == "session_tracker"]
        assert len(session_verdicts) == 0

    def test_already_blocked_skips_session_verdict(self):
        # When the defense already blocks, session_tracker should not add
        # a redundant verdict (the `not blocked` check in the condition).
        config = ShieldConfig(
            session_tracking_enabled=True,
            session_tracker_blocking_enabled=True,
        )
        registry = DefenseRegistry()
        registry.register(_BlockingDefense(confidence=0.9))
        # Register no-op stand-ins for mandatory defenses
        for mname in ShieldConfig.MANDATORY_DEFENSES:
            registry.register(_NoopMandatoryDefense(mname))
        defender = Defender(config=config, registry=registry)
        # Each blocking turn contributes 0.9 signal. After 3 turns: 2.7 >= 2.0.
        # But the defense already blocks, so session_tracker should not fire.
        for _ in range(3):
            resp = defender.defend(_make_request())
        assert resp.allow is False
        session_verdicts = [v for v in resp.verdicts if v.defense_name == "session_tracker"]
        assert len(session_verdicts) == 0

    def test_different_sessions_tracked_independently(self):
        defender = _make_defender(blocking_enabled=True, defense_confidence=0.9)
        # Build up risk on session A (5 turns to reach high)
        for _ in range(5):
            resp_a = defender.defend(_make_request(session_id="session-A"))
        # Session A should be blocked
        session_verdicts_a = [v for v in resp_a.verdicts if v.defense_name == "session_tracker"]
        assert len(session_verdicts_a) == 1
        # Session B should start fresh — 1 turn is not enough to reach high
        resp_b = defender.defend(_make_request(session_id="session-B"))
        session_verdicts_b = [v for v in resp_b.verdicts if v.defense_name == "session_tracker"]
        assert len(session_verdicts_b) == 0
