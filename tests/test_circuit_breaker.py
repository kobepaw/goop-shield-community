# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Tests for CircuitBreaker defense — loop detection and cascading failure prevention.
"""

from __future__ import annotations

from goop_shield.defenses.base import DefenseContext
from goop_shield.defenses.circuit_breaker import CircuitBreaker


def _ctx(tool_name: str = "", session_id: str = "sess1", prompt: str = "") -> DefenseContext:
    return DefenseContext(
        original_prompt=prompt,
        current_prompt=prompt,
        user_context={"tool_name": tool_name, "session_id": session_id},
    )


class TestCircuitBreakerName:
    def test_name(self):
        assert CircuitBreaker().name == "circuit_breaker"


class TestCircuitBreakerNoTool:
    def test_no_tool_name_passes(self):
        v = CircuitBreaker().execute(_ctx(tool_name=""))
        assert not v.blocked


class TestCircuitBreakerNormal:
    def test_single_call_passes(self):
        cb = CircuitBreaker(max_repeated_calls=5)
        v = cb.execute(_ctx(tool_name="web_search"))
        assert not v.blocked
        assert v.metadata["call_count"] == 1

    def test_under_limit_passes(self):
        cb = CircuitBreaker(max_repeated_calls=5)
        for _ in range(5):
            v = cb.execute(_ctx(tool_name="web_search"))
        assert not v.blocked
        assert v.metadata["call_count"] == 5


class TestCircuitBreakerTrips:
    def test_over_limit_blocks(self):
        cb = CircuitBreaker(max_repeated_calls=3)
        for _ in range(3):
            cb.execute(_ctx(tool_name="read_file"))
        v = cb.execute(_ctx(tool_name="read_file"))
        assert v.blocked
        assert v.metadata["call_count"] == 4
        assert "Circuit breaker tripped" in v.details

    def test_different_tools_independent(self):
        cb = CircuitBreaker(max_repeated_calls=3)
        for _ in range(3):
            cb.execute(_ctx(tool_name="tool_a"))
            cb.execute(_ctx(tool_name="tool_b"))
        # Each tool has 3 calls, not over limit
        v_a = cb.execute(_ctx(tool_name="tool_a"))
        assert v_a.blocked  # 4th call
        v_b = cb.execute(_ctx(tool_name="tool_b"))
        assert v_b.blocked  # 4th call


class TestCircuitBreakerSessions:
    def test_different_sessions_independent(self):
        cb = CircuitBreaker(max_repeated_calls=3)
        for _ in range(3):
            cb.execute(_ctx(tool_name="read_file", session_id="sess1"))
        # sess1 is at limit, but sess2 should be clean
        v = cb.execute(_ctx(tool_name="read_file", session_id="sess2"))
        assert not v.blocked
        assert v.metadata["call_count"] == 1


class TestCircuitBreakerWindow:
    def test_expired_calls_pruned(self):
        cb = CircuitBreaker(max_repeated_calls=3, window_seconds=0.0)
        # With window=0, all prior calls are pruned immediately
        for _ in range(5):
            v = cb.execute(_ctx(tool_name="read_file"))
        # Only the current call should remain after pruning
        assert not v.blocked
        assert v.metadata["call_count"] == 1
