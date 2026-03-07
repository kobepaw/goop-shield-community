# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Circuit Breaker / Loop Detection — detects infinite loops and cascading agent failures.

Tracks call patterns per session and blocks when the same tool is called more than
a configured number of times, preventing runaway agent behavior.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict

from goop_shield.defenses.base import (
    DEFAULT_THRESHOLD,
    DefenseContext,
    InlineDefense,
    InlineVerdict,
)

# Default limits
DEFAULT_MAX_REPEATED_CALLS = 10
DEFAULT_WINDOW_SECONDS = 60.0


class CircuitBreaker(InlineDefense):
    """Detects infinite loops and cascading agent failures.

    Tracks tool call patterns per session within a sliding window. When the same
    tool is called more than ``max_repeated_calls`` times within
    ``window_seconds``, the circuit trips and blocks further calls.

    Session ID is read from ``context.user_context["session_id"]``.
    Tool name is read from ``context.user_context["tool_name"]``.
    """

    def __init__(
        self,
        max_repeated_calls: int = DEFAULT_MAX_REPEATED_CALLS,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        confidence_threshold: float = DEFAULT_THRESHOLD,
    ) -> None:
        self._max_repeated_calls = max_repeated_calls
        self._window_seconds = window_seconds
        self._threshold = confidence_threshold
        self._lock = threading.Lock()
        # session_id -> tool_name -> list of timestamps
        self._call_log: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))

    @property
    def name(self) -> str:
        return "circuit_breaker"

    def _prune(self, timestamps: list[float], now: float) -> list[float]:
        """Remove timestamps outside the sliding window."""
        cutoff = now - self._window_seconds
        return [t for t in timestamps if t > cutoff]

    def execute(self, context: DefenseContext) -> InlineVerdict:
        session_id = context.user_context.get("session_id", "_default")
        tool_name = context.user_context.get("tool_name", "")

        if not tool_name:
            return InlineVerdict(defense_name=self.name)

        now = time.monotonic()

        with self._lock:
            session_log = self._call_log[session_id]

            # Prune old entries and record current call
            session_log[tool_name] = self._prune(session_log[tool_name], now)
            session_log[tool_name].append(now)

            call_count = len(session_log[tool_name])

        if call_count > self._max_repeated_calls:
            confidence = min(call_count / (self._max_repeated_calls * 2), 1.0)
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                confidence=confidence,
                threat_confidence=confidence,
                details=(
                    f"Circuit breaker tripped: {tool_name} called {call_count} times "
                    f"in {self._window_seconds}s (limit: {self._max_repeated_calls})"
                ),
                metadata={
                    "tool_name": tool_name,
                    "call_count": call_count,
                    "limit": self._max_repeated_calls,
                    "session_id": session_id,
                },
            )

        return InlineVerdict(
            defense_name=self.name,
            metadata={
                "tool_name": tool_name,
                "call_count": call_count,
                "limit": self._max_repeated_calls,
            },
        )
