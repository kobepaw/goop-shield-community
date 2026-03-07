"""
Tests for the Shield TelemetryBuffer.
"""

from __future__ import annotations

import pytest

from goop_shield.models import TelemetryEvent
from goop_shield.telemetry import TelemetryBuffer


@pytest.fixture
def buffer():
    return TelemetryBuffer(buffer_size=100, flush_interval=60.0, privacy_mode=True)


@pytest.fixture
def event_blocked():
    return TelemetryEvent(
        attack_type="injection", defense_action="safety_filter", outcome="blocked"
    )


@pytest.fixture
def event_allowed():
    return TelemetryEvent(attack_type="benign", defense_action="safety_filter", outcome="allowed")


class TestTelemetryAdd:
    """Adding events."""

    def test_add_increments_total(self, buffer, event_blocked):
        buffer.add(event_blocked)
        assert buffer.total_events == 1

    def test_add_blocked_increments_counter(self, buffer, event_blocked):
        buffer.add(event_blocked)
        assert buffer.total_blocked == 1
        assert buffer.total_allowed == 0

    def test_add_allowed_increments_counter(self, buffer, event_allowed):
        buffer.add(event_allowed)
        assert buffer.total_allowed == 1
        assert buffer.total_blocked == 0

    def test_buffer_bounded(self):
        buf = TelemetryBuffer(buffer_size=5)
        for _ in range(10):
            buf.add(TelemetryEvent(attack_type="x", defense_action="y", outcome="blocked"))
        assert len(buf._buffer) == 5
        assert buf.total_events == 10


class TestTelemetryPrivacy:
    """Privacy mode."""

    def test_privacy_mode_adds_hash(self, buffer, event_blocked):
        buffer.add(event_blocked)
        record = buffer._buffer[-1]
        assert "hash" in record
        assert len(record["hash"]) == 16

    def test_no_hash_without_privacy(self, event_blocked):
        buf = TelemetryBuffer(privacy_mode=False)
        buf.add(event_blocked)
        record = buf._buffer[-1]
        assert "hash" not in record


class TestTelemetryFlush:
    """Flush drains buffer."""

    @pytest.mark.asyncio
    async def test_flush_clears_buffer(self, buffer, event_blocked):
        buffer.add(event_blocked)
        buffer.add(event_blocked)
        assert len(buffer._buffer) == 2
        await buffer._flush()
        assert len(buffer._buffer) == 0

    @pytest.mark.asyncio
    async def test_flush_empty_is_noop(self, buffer):
        await buffer._flush()  # Should not raise

    @pytest.mark.asyncio
    async def test_start_stop(self, buffer, event_blocked):
        await buffer.start()
        buffer.add(event_blocked)
        await buffer.stop()
        # After stop, buffer should be flushed
        assert len(buffer._buffer) == 0


class TestTelemetryStats:
    """Stats reporting."""

    def test_stats_keys(self, buffer):
        s = buffer.stats()
        assert "total_events" in s
        assert "total_blocked" in s
        assert "total_allowed" in s
        assert "buffer_size" in s
        assert "privacy_mode" in s

    def test_stats_reflect_adds(self, buffer, event_blocked, event_allowed):
        buffer.add(event_blocked)
        buffer.add(event_allowed)
        s = buffer.stats()
        assert s["total_events"] == 2
        assert s["total_blocked"] == 1
        assert s["total_allowed"] == 1
