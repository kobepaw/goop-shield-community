"""Tests for Shield Telemetry Aggregator."""

from __future__ import annotations

import time

import pytest

from goop_shield.aggregation import TelemetryAggregator


@pytest.fixture
def aggregator(tmp_path):
    """Create an aggregator with a temp SQLite path."""
    db_path = str(tmp_path / "test_aggregation.db")
    agg = TelemetryAggregator(db_path=db_path)
    yield agg
    agg.close()


def _make_events(n: int, outcome: str = "block", attack_type: str = "injection") -> list[dict]:
    """Helper to create N test events."""
    now = time.time()
    return [
        {
            "timestamp": now + i,
            "event_type": "defend",
            "attack_type": attack_type,
            "defense_action": "input_validator",
            "outcome": outcome,
            "confidence": 0.9,
        }
        for i in range(n)
    ]


class TestIngestBatch:
    def test_ingest_batch_returns_count(self, aggregator):
        events = _make_events(5)
        count = aggregator.ingest_batch(events, instance_id="shield-1")
        assert count == 5

    def test_ingest_batch_empty(self, aggregator):
        count = aggregator.ingest_batch([], instance_id="shield-1")
        assert count == 0

    def test_ingest_batch_defaults(self, aggregator):
        """Events with missing fields get defaults."""
        events = [{"outcome": "allow"}]
        count = aggregator.ingest_batch(events)
        assert count == 1
        data = aggregator.export_training_data(limit=1)
        assert len(data) == 1
        assert data[0]["attack_type"] == ""
        assert data[0]["instance_id"] == "default"


class TestAggregateStats:
    def test_aggregate_stats_totals(self, aggregator):
        aggregator.ingest_batch(_make_events(3, outcome="block"), instance_id="s1")
        aggregator.ingest_batch(_make_events(2, outcome="allow"), instance_id="s1")

        stats = aggregator.get_aggregate_stats()
        assert stats.total_events == 5
        assert stats.total_blocked == 3
        assert stats.total_allowed == 2
        assert stats.block_rate == pytest.approx(0.6)

    def test_aggregate_stats_with_since(self, aggregator):
        now = time.time()
        old_events = [{"timestamp": now - 1000, "outcome": "block"}]
        new_events = [{"timestamp": now, "outcome": "allow"}]

        aggregator.ingest_batch(old_events)
        aggregator.ingest_batch(new_events)

        stats = aggregator.get_aggregate_stats(since=now - 1)
        assert stats.total_events == 1
        assert stats.total_allowed == 1
        assert stats.total_blocked == 0

    def test_aggregate_stats_top_attacks(self, aggregator):
        aggregator.ingest_batch(_make_events(5, attack_type="injection"))
        aggregator.ingest_batch(_make_events(3, attack_type="jailbreak"))

        stats = aggregator.get_aggregate_stats()
        assert len(stats.top_attacks) == 2
        assert stats.top_attacks[0]["attack_type"] == "injection"
        assert stats.top_attacks[0]["count"] == 5

    def test_aggregate_stats_to_dict(self, aggregator):
        aggregator.ingest_batch(_make_events(2))
        stats = aggregator.get_aggregate_stats()
        d = stats.to_dict()
        assert isinstance(d, dict)
        assert "total_events" in d
        assert "block_rate" in d
        assert "top_attacks" in d


class TestShouldRetrain:
    def test_should_retrain_below_threshold(self, aggregator):
        aggregator.ingest_batch(_make_events(10))
        assert not aggregator.should_retrain(min_new_events=1000)

    def test_should_retrain_above_threshold(self, aggregator):
        aggregator.ingest_batch(_make_events(50))
        assert aggregator.should_retrain(min_new_events=50)

    def test_mark_retrained_resets_counter(self, aggregator):
        aggregator.ingest_batch(_make_events(100))
        assert aggregator.should_retrain(min_new_events=100)
        aggregator.mark_retrained()
        assert not aggregator.should_retrain(min_new_events=100)


class TestExportTrainingData:
    def test_export_training_data_format(self, aggregator):
        aggregator.ingest_batch(_make_events(3))
        data = aggregator.export_training_data()
        assert len(data) == 3
        assert set(data[0].keys()) == {
            "instance_id",
            "timestamp",
            "attack_type",
            "defense_action",
            "outcome",
            "confidence",
        }

    def test_export_training_data_limit(self, aggregator):
        aggregator.ingest_batch(_make_events(10))
        data = aggregator.export_training_data(limit=5)
        assert len(data) == 5

    def test_export_training_data_since(self, aggregator):
        now = time.time()
        old = [{"timestamp": now - 1000, "outcome": "block"}]
        new = [{"timestamp": now, "outcome": "allow"}]
        aggregator.ingest_batch(old)
        aggregator.ingest_batch(new)

        data = aggregator.export_training_data(since=now - 1)
        assert len(data) == 1
        assert data[0]["outcome"] == "allow"


class TestMultipleInstances:
    def test_multiple_instances_counted(self, aggregator):
        aggregator.ingest_batch(_make_events(3), instance_id="shield-a")
        aggregator.ingest_batch(_make_events(2), instance_id="shield-b")

        stats = aggregator.get_aggregate_stats()
        assert stats.instance_count == 2
        assert stats.total_events == 5


class TestEmptyStats:
    def test_empty_stats_defaults(self, aggregator):
        stats = aggregator.get_aggregate_stats()
        assert stats.total_events == 0
        assert stats.total_blocked == 0
        assert stats.total_allowed == 0
        assert stats.block_rate == 0.0
        assert stats.top_attacks == []
        assert stats.top_defenses == []
        assert stats.instance_count == 0
        assert stats.time_range_start == 0.0
        assert stats.time_range_end == 0.0
