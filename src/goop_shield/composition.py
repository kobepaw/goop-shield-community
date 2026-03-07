# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Defense Composition Engine -- Cross-defense signal correlation.

Provides a declarative rule engine that detects multi-step attack chains
by correlating signals from multiple defenses across turns. When individual
defenses produce low-confidence signals that are individually benign but
collectively suspicious, the composition engine escalates.

Known multi-step attack chains:
- Config env injection -> NODE_OPTIONS -> RCE
- Config write -> hot-reload -> unvalidated tools/agents
- Plugin -> writeConfigFile -> persistent backdoor
- Any client -> exec.approval.resolve -> approve RCE
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ============================================================================
# Data classes
# ============================================================================


@dataclass
class CompositionRule:
    """A declarative rule for detecting multi-step attack chains.

    Each rule specifies a set of defense signals that, when observed together
    within a time window and exceeding a cumulative confidence threshold,
    indicate a coordinated attack. The engine applies an escalation multiplier
    to the cumulative confidence to produce the final score.

    Attributes:
        name: Unique identifier for this rule.
        description: Human-readable explanation of the attack chain detected.
        required_signals: List of defense names that must fire (in any order)
            for this rule to trigger.
        min_signals: Minimum number of required_signals that must match.
            Defaults to all (i.e., ``len(required_signals)``).
        time_window_seconds: Time window in seconds for signals to correlate.
            Use ``0.0`` for same-request-only correlation.
        min_cumulative_confidence: Minimum cumulative ``threat_confidence``
            from matched signals required to trigger the rule.
        action: Output severity -- ``"block"`` or ``"alert"``.
        escalation_multiplier: Multiplier applied to cumulative confidence
            to produce the final confidence score (capped at 1.0).
    """

    name: str
    description: str
    # List of defense names that must fire (in any order) for this rule to trigger
    required_signals: list[str]
    # Minimum number of required_signals that must match (default: all)
    min_signals: int | None = None
    # Time window in seconds for signals to correlate (0 = same request only)
    time_window_seconds: float = 0.0
    # Minimum cumulative threat_confidence from matched signals
    min_cumulative_confidence: float = 0.3
    # Output severity: "block" or "alert"
    action: str = "block"
    # Escalation multiplier applied to final confidence
    escalation_multiplier: float = 1.5


@dataclass
class SignalRecord:
    """A recorded defense signal for cross-turn correlation.

    Attributes:
        defense_name: Name of the defense that produced this signal.
        threat_confidence: Confidence score from the defense verdict.
        timestamp: Unix timestamp when the signal was recorded.
        session_id: Session identifier for scoping signal correlation.
        metadata: Additional context from the defense verdict.
    """

    defense_name: str
    threat_confidence: float
    timestamp: float
    session_id: str = "default"
    metadata: dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Composition engine
# ============================================================================


class DefenseCompositionEngine:
    """Correlates signals from multiple defenses to detect attack chains.

    The engine maintains a history of defense signals and evaluates registered
    composition rules against both the current request's signals and historical
    signals within each rule's time window. When a rule triggers, the engine
    produces a result with an escalated confidence score.

    Usage::

        engine = DefenseCompositionEngine()
        register_example_rules(engine)

        # After running inline defenses, record their signals
        signal = SignalRecord(
            defense_name="config_mutation_guard",
            threat_confidence=0.25,
            timestamp=time.time(),
            session_id="session-abc",
        )
        engine.record_signal(signal)

        # Evaluate composition rules
        results = engine.evaluate([signal], session_id="session-abc")
        for result in results:
            if result["action"] == "block":
                # Handle escalated block
                ...
    """

    def __init__(self, max_history: int = 1000) -> None:
        self._rules: list[CompositionRule] = []
        self._signal_history: list[SignalRecord] = []
        self._max_history = max_history
        self._lock = threading.Lock()

    def add_rule(self, rule: CompositionRule) -> None:
        """Register a composition rule.

        Args:
            rule: The composition rule to add to the engine.
        """
        self._rules.append(rule)

    def record_signal(self, signal: SignalRecord) -> None:
        """Record a defense signal for cross-turn correlation.

        Signals are stored in a bounded history buffer. When the buffer
        exceeds ``max_history``, the oldest signals are discarded.

        Args:
            signal: The defense signal to record.
        """
        with self._lock:
            self._signal_history.append(signal)
            if len(self._signal_history) > self._max_history:
                self._signal_history = self._signal_history[-self._max_history :]

    def evaluate(
        self,
        current_signals: list[SignalRecord],
        session_id: str = "default",
    ) -> list[dict[str, Any]]:
        """Evaluate all rules against current + historical signals.

        For each registered rule, the engine gathers candidate signals from
        both the current request and (if the rule has a non-zero time window)
        the historical signal buffer filtered by session and time. It then
        checks whether enough required defense signals are present and whether
        their cumulative confidence exceeds the rule's threshold.

        Args:
            current_signals: Signals from the current request's defense
                pipeline execution.
            session_id: Session identifier used to scope historical signal
                lookups.

        Returns:
            A list of triggered rule results. Each result is a dict with keys:

            - ``rule`` (str): The composition rule name.
            - ``action`` (str): ``"block"`` or ``"alert"``.
            - ``confidence`` (float): Escalated confidence score (capped at 1.0).
            - ``matched_signals`` (list[str]): Defense names that matched.
            - ``description`` (str): Human-readable rule description.
        """
        now = time.time()
        triggered: list[dict[str, Any]] = []

        for rule in self._rules:
            # Gather relevant signals: current + historical within time window
            candidates = list(current_signals)
            if rule.time_window_seconds > 0:
                cutoff = now - rule.time_window_seconds
                with self._lock:
                    candidates.extend(
                        s
                        for s in self._signal_history
                        if s.timestamp >= cutoff and s.session_id == session_id
                    )

            # Check which required signals are present
            matched_names: set[str] = set()
            matched_signals: list[SignalRecord] = []
            cumulative_confidence = 0.0
            for signal in candidates:
                if signal.defense_name in rule.required_signals:
                    matched_names.add(signal.defense_name)
                    matched_signals.append(signal)
                    cumulative_confidence += signal.threat_confidence

            min_required = rule.min_signals or len(rule.required_signals)
            if (
                len(matched_names) >= min_required
                and cumulative_confidence >= rule.min_cumulative_confidence
            ):
                final_confidence = min(cumulative_confidence * rule.escalation_multiplier, 1.0)
                triggered.append(
                    {
                        "rule": rule.name,
                        "action": rule.action,
                        "confidence": final_confidence,
                        "matched_signals": [s.defense_name for s in matched_signals],
                        "description": rule.description,
                    }
                )

        return triggered

    def clear_history(self, session_id: str | None = None) -> None:
        """Clear signal history, optionally for a specific session.

        Args:
            session_id: If provided, only signals for this session are removed.
                If ``None``, the entire history buffer is cleared.
        """
        with self._lock:
            if session_id is None:
                self._signal_history.clear()
            else:
                self._signal_history = [
                    s for s in self._signal_history if s.session_id != session_id
                ]

    @property
    def rules(self) -> list[CompositionRule]:
        """Get all registered rules.

        Returns:
            A shallow copy of the internal rule list.
        """
        return list(self._rules)


# ============================================================================
# Example rules
# ============================================================================


def register_example_rules(engine: DefenseCompositionEngine) -> None:
    """Register example composition rules for common attack chains.

    These rules illustrate how to use the composition engine to detect
    multi-step attack patterns by correlating signals from two or more
    defenses within a time window. Add your own rules for deployment-specific
    attack chains.

    Args:
        engine: The composition engine to register rules on.
    """

    # Chain 1: Config modification + env injection = RCE
    engine.add_rule(
        CompositionRule(
            name="config_env_rce",
            description=(
                "Config modification combined with env var injection suggests RCE attempt"
            ),
            required_signals=["config_mutation_guard", "tool_call_firewall"],
            time_window_seconds=300.0,
            min_cumulative_confidence=0.3,
            action="block",
            escalation_multiplier=1.8,
        )
    )

    # Chain 2: Credential access + data exfiltration
    engine.add_rule(
        CompositionRule(
            name="credential_exfil",
            description=("Credential path access combined with exfiltration indicators"),
            required_signals=["credential_path_guard", "exfil_detector"],
            time_window_seconds=120.0,
            min_cumulative_confidence=0.25,
            action="block",
            escalation_multiplier=2.0,
        )
    )

    # Chain 3: Plugin manipulation + config write = persistent backdoor
    engine.add_rule(
        CompositionRule(
            name="plugin_backdoor",
            description=("Plugin supply chain attack combined with config modification"),
            required_signals=["plugin_supply_chain_guard", "config_mutation_guard"],
            time_window_seconds=600.0,
            min_cumulative_confidence=0.3,
            action="block",
            escalation_multiplier=1.5,
        )
    )
