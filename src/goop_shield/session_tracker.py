# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Session Tracker — Sliding-window session state for multi-turn attack detection.

Tracks per-session injection signals over a configurable sliding window,
detects escalating attack patterns, and provides risk assessments.

Privacy: stores ONLY hashed prompts + signal scores, never raw text.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from dataclasses import dataclass, field


@dataclass
class SessionRisk:
    """Risk assessment for a session."""

    cumulative_signal: float = 0.0
    turn_count: int = 0
    escalating: bool = False
    risk_level: str = "low"  # "low", "medium", "high"


@dataclass
class _TurnRecord:
    """Internal record for a single turn (privacy-safe)."""

    prompt_hash: str
    injection_signal: float
    has_config_ref: bool = False
    has_modify_intent: bool = False


@dataclass
class _SessionState:
    """Internal sliding-window state for one session."""

    turns: list[_TurnRecord] = field(default_factory=list)
    window_size: int = 10

    def add_turn(
        self,
        prompt_hash: str,
        injection_signal: float,
        has_config_ref: bool = False,
        has_modify_intent: bool = False,
    ) -> None:
        """Add a turn, evicting oldest if window is exceeded."""
        self.turns.append(
            _TurnRecord(
                prompt_hash=prompt_hash,
                injection_signal=injection_signal,
                has_config_ref=has_config_ref,
                has_modify_intent=has_modify_intent,
            )
        )
        if len(self.turns) > self.window_size:
            self.turns = self.turns[-self.window_size :]

    @property
    def cumulative_signal(self) -> float:
        return sum(t.injection_signal for t in self.turns)

    @property
    def turn_count(self) -> int:
        return len(self.turns)

    @property
    def escalating(self) -> bool:
        """Check if signals are escalating over the last 3+ turns."""
        if len(self.turns) < 3:
            return False
        recent = self.turns[-3:]
        return all(
            recent[i].injection_signal < recent[i + 1].injection_signal
            for i in range(len(recent) - 1)
        )

    @property
    def cross_turn_config_attack(self) -> bool:
        """Detect config ref + modify intent split across recent turns.

        R7: Returns True when a config file reference and modify intent
        appear in different recent turns (but not both in the same turn,
        which is already caught by single-turn detection).
        """
        if len(self.turns) < 2:
            return False
        recent = self.turns[-3:]
        has_ref = any(t.has_config_ref for t in recent)
        has_modify = any(t.has_modify_intent for t in recent)
        # Avoid double-firing when both signals appear in the same turn
        same_turn = any(t.has_config_ref and t.has_modify_intent for t in recent)
        return has_ref and has_modify and not same_turn


class SessionTracker:
    """Sliding-window session state for multi-turn attack detection.

    Args:
        window_size: Number of turns to keep per session.
        signal_threshold: Cumulative signal threshold for "high" risk.
        max_sessions: Maximum number of tracked sessions (LRU eviction).
    """

    def __init__(
        self,
        window_size: int = 10,
        signal_threshold: float = 2.0,
        max_sessions: int = 10000,
    ) -> None:
        self._window_size = window_size
        self._signal_threshold = signal_threshold
        self._max_sessions = max_sessions
        # OrderedDict for LRU eviction
        self._sessions: OrderedDict[str, _SessionState] = OrderedDict()

    def record_turn(
        self,
        session_id: str,
        injection_signal: float,
        prompt_hash: str,
        has_config_ref: bool = False,
        has_modify_intent: bool = False,
    ) -> SessionRisk:
        """Record a turn and return current risk assessment.

        Args:
            session_id: Unique session identifier.
            injection_signal: The injection signal score for this turn.
            prompt_hash: Pre-hashed prompt identifier (privacy-safe).
            has_config_ref: Whether this turn references a config file (R7).
            has_modify_intent: Whether this turn contains modify intent (R7).

        Returns:
            SessionRisk with current risk assessment.
        """
        # LRU: move to end if exists, or create new
        if session_id in self._sessions:
            self._sessions.move_to_end(session_id)
        else:
            # Evict oldest if at capacity
            while len(self._sessions) >= self._max_sessions:
                self._sessions.popitem(last=False)
            self._sessions[session_id] = _SessionState(window_size=self._window_size)

        state = self._sessions[session_id]
        state.add_turn(
            prompt_hash=prompt_hash,
            injection_signal=injection_signal,
            has_config_ref=has_config_ref,
            has_modify_intent=has_modify_intent,
        )

        return self._assess_risk(state)

    def get_risk(self, session_id: str) -> SessionRisk:
        """Get current risk level for a session.

        Returns a default low-risk SessionRisk if session is unknown.
        """
        state = self._sessions.get(session_id)
        if state is None:
            return SessionRisk()
        return self._assess_risk(state)

    def _assess_risk(self, state: _SessionState) -> SessionRisk:
        """Compute risk assessment from session state."""
        cumulative = state.cumulative_signal
        escalating = state.escalating

        # R7: Cross-turn config attack penalty
        if state.cross_turn_config_attack:
            cumulative += 0.8

        if cumulative >= self._signal_threshold or escalating:
            risk_level = "high"
        elif cumulative >= self._signal_threshold * 0.5:
            risk_level = "medium"
        else:
            risk_level = "low"

        return SessionRisk(
            cumulative_signal=cumulative,
            turn_count=state.turn_count,
            escalating=escalating,
            risk_level=risk_level,
        )

    @staticmethod
    def hash_prompt(prompt: str) -> str:
        """Hash a prompt for privacy-safe storage."""
        return hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]
