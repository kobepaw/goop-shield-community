"""
Tests for the Shield ranking abstraction layer.

Covers:
  - RankingBackend ABC cannot be instantiated
  - StaticRanking: rank_defenses, record_outcome, get_weights/load_weights,
    register_defense, get_stats, set_priority, get_priority
"""

from __future__ import annotations

import pytest

from goop_shield.ranking.base import RankingBackend
from goop_shield.ranking.static import StaticRanking

# ============================================================================
# RankingBackend ABC
# ============================================================================


class TestRankingBackendABC:
    """The abstract base class cannot be instantiated directly."""

    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            RankingBackend()

    def test_subclass_must_implement_all_methods(self):
        class IncompleteBackend(RankingBackend):
            pass

        with pytest.raises(TypeError):
            IncompleteBackend()

    def test_concrete_subclass_works(self):
        """A fully-implemented subclass can be instantiated."""

        class MinimalBackend(RankingBackend):
            def rank_defenses(self, defense_names):
                return [(n, 1.0) for n in defense_names]

            def record_outcome(self, defense_name, blocked):
                pass

            def get_weights(self):
                return {}

            def load_weights(self, weights):
                pass

        backend = MinimalBackend()
        assert backend.rank_defenses(["a"]) == [("a", 1.0)]

    def test_default_register_defense_is_noop(self):
        """Default register_defense does nothing (no error)."""

        class MinimalBackend(RankingBackend):
            def rank_defenses(self, defense_names):
                return [(n, 1.0) for n in defense_names]

            def record_outcome(self, defense_name, blocked):
                pass

            def get_weights(self):
                return {}

            def load_weights(self, weights):
                pass

        backend = MinimalBackend()
        backend.register_defense("test")  # Should not raise

    def test_default_get_stats_returns_empty_dict(self):
        """Default get_stats returns {}."""

        class MinimalBackend(RankingBackend):
            def rank_defenses(self, defense_names):
                return [(n, 1.0) for n in defense_names]

            def record_outcome(self, defense_name, blocked):
                pass

            def get_weights(self):
                return {}

            def load_weights(self, weights):
                pass

        backend = MinimalBackend()
        assert backend.get_stats() == {}


# ============================================================================
# StaticRanking
# ============================================================================


class TestStaticRankingDefaults:
    """StaticRanking with no priorities uses default_priority=50."""

    def test_empty_priorities(self):
        r = StaticRanking()
        result = r.rank_defenses(["a", "b"])
        assert len(result) == 2
        assert all(score == 50.0 for _, score in result)

    def test_custom_default_priority(self):
        r = StaticRanking(default_priority=10.0)
        result = r.rank_defenses(["x"])
        assert result == [("x", 10.0)]


class TestStaticRankingOrder:
    """rank_defenses returns defenses sorted by descending priority."""

    def test_sorted_by_priority(self):
        r = StaticRanking(priorities={"high": 100, "mid": 50, "low": 10})
        result = r.rank_defenses(["low", "high", "mid"])
        names = [name for name, _ in result]
        assert names == ["high", "mid", "low"]

    def test_scores_match_priorities(self):
        r = StaticRanking(priorities={"a": 90, "b": 30})
        result = r.rank_defenses(["a", "b"])
        assert result == [("a", 90.0), ("b", 30.0)]

    def test_unknown_defense_gets_default(self):
        r = StaticRanking(priorities={"known": 100}, default_priority=25.0)
        result = r.rank_defenses(["known", "unknown"])
        assert result == [("known", 100.0), ("unknown", 25.0)]

    def test_all_names_present_in_output(self):
        names = ["d1", "d2", "d3"]
        r = StaticRanking()
        result = r.rank_defenses(names)
        result_names = {name for name, _ in result}
        assert result_names == set(names)

    def test_empty_input(self):
        r = StaticRanking()
        assert r.rank_defenses([]) == []


class TestStaticRankingRecordOutcome:
    """record_outcome is a no-op for static ranking."""

    def test_record_outcome_does_nothing(self):
        r = StaticRanking(priorities={"a": 100})
        weights_before = r.get_weights()
        r.record_outcome("a", blocked=True)
        r.record_outcome("a", blocked=False)
        r.record_outcome("nonexistent", blocked=True)
        weights_after = r.get_weights()
        assert weights_before == weights_after


class TestStaticRankingWeightsRoundTrip:
    """get_weights / load_weights round-trip."""

    def test_round_trip(self):
        r1 = StaticRanking(priorities={"x": 99, "y": 11}, default_priority=42.0)
        weights = r1.get_weights()

        r2 = StaticRanking()
        r2.load_weights(weights)

        assert r2.get_weights() == weights

    def test_weights_structure(self):
        r = StaticRanking(priorities={"a": 1}, default_priority=7.0)
        w = r.get_weights()
        assert "priorities" in w
        assert "default_priority" in w
        assert w["priorities"] == {"a": 1.0}
        assert w["default_priority"] == 7.0

    def test_load_partial_weights(self):
        r = StaticRanking(priorities={"old": 10}, default_priority=50.0)
        r.load_weights({"priorities": {"new": 99}})
        assert r.get_priority("new") == 99
        # default_priority unchanged because it wasn't in the partial weights
        assert r.get_weights()["default_priority"] == 50.0

    def test_load_only_default_priority(self):
        r = StaticRanking(priorities={"a": 1})
        r.load_weights({"default_priority": 77.0})
        # priorities unchanged
        assert r.get_priority("a") == 1.0
        assert r.get_weights()["default_priority"] == 77.0


class TestStaticRankingRegisterDefense:
    """register_defense adds unknown defenses with default priority."""

    def test_register_new_defense(self):
        r = StaticRanking(default_priority=42.0)
        r.register_defense("new_def")
        assert r.get_priority("new_def") == 42.0

    def test_register_existing_does_not_overwrite(self):
        r = StaticRanking(priorities={"existing": 100})
        r.register_defense("existing")
        assert r.get_priority("existing") == 100

    def test_registered_defense_appears_in_weights(self):
        r = StaticRanking()
        r.register_defense("freshly_added")
        assert "freshly_added" in r.get_weights()["priorities"]


class TestStaticRankingStats:
    """get_stats returns backend metadata."""

    def test_stats_fields(self):
        r = StaticRanking(priorities={"a": 1, "b": 2})
        stats = r.get_stats()
        assert stats["backend"] == "static"
        assert stats["num_defenses"] == 2
        assert "default_priority" in stats

    def test_stats_count_after_register(self):
        r = StaticRanking()
        r.register_defense("d1")
        r.register_defense("d2")
        assert r.get_stats()["num_defenses"] == 2


class TestStaticRankingConvenience:
    """set_priority / get_priority helpers."""

    def test_set_and_get(self):
        r = StaticRanking()
        r.set_priority("foo", 77.0)
        assert r.get_priority("foo") == 77.0

    def test_get_unknown_returns_default(self):
        r = StaticRanking(default_priority=33.0)
        assert r.get_priority("missing") == 33.0

    def test_set_priority_overrides_existing(self):
        r = StaticRanking(priorities={"a": 10})
        r.set_priority("a", 99)
        assert r.get_priority("a") == 99
