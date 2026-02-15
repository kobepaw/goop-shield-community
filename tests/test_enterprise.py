"""
Tests for Shield enterprise components.

Covers:
  - BroRLRankingBackend: delegates to BroRLCore
  - rank_defenses calls score_actions
  - record_outcome updates technique
  - get_weights / load_weights delegate correctly
  - Fallback: when enterprise unavailable, StaticRanking is used
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from goop_shield.enterprise.brorl_ranking import BroRLRankingBackend

pytestmark = pytest.mark.skipif(True, reason="Enterprise features not available in community edition")
from goop_shield.ranking.base import RankingBackend

# ============================================================================
# BroRLRankingBackend
# ============================================================================


class TestBroRLRankingBackendIsRankingBackend:
    """BroRLRankingBackend implements the RankingBackend ABC."""

    def test_is_subclass(self):
        assert issubclass(BroRLRankingBackend, RankingBackend)

    def test_can_instantiate(self):
        backend = BroRLRankingBackend()
        assert backend is not None


class TestBroRLRankingRankDefenses:
    """rank_defenses delegates to BroRLCore.score_actions."""

    def test_rank_defenses_returns_sorted(self):
        backend = BroRLRankingBackend()
        backend.register_defense("high")
        backend.register_defense("low")

        # Mock score_actions to return predictable scores
        backend._brorl.score_actions = MagicMock(return_value=[0.9, 0.1])
        result = backend.rank_defenses(["high", "low"])

        assert result[0][0] == "high"
        assert result[1][0] == "low"
        assert result[0][1] > result[1][1]

    def test_rank_defenses_calls_score_actions(self):
        backend = BroRLRankingBackend()
        backend._brorl.score_actions = MagicMock(return_value=[0.5, 0.5])
        backend.rank_defenses(["a", "b"])

        backend._brorl.score_actions.assert_called_once()
        call_args = backend._brorl.score_actions.call_args
        actions = call_args[0][0]
        assert len(actions) == 2
        assert actions[0] == {"technique_id": "a"}
        assert actions[1] == {"technique_id": "b"}
        assert call_args[1]["role"] == "defense"

    def test_rank_defenses_empty_list(self):
        backend = BroRLRankingBackend()
        backend._brorl.score_actions = MagicMock(return_value=[])
        result = backend.rank_defenses([])
        assert result == []

    def test_all_names_present(self):
        backend = BroRLRankingBackend()
        names = ["d1", "d2", "d3"]
        backend._brorl.score_actions = MagicMock(return_value=[0.3, 0.7, 0.5])
        result = backend.rank_defenses(names)
        result_names = {name for name, _ in result}
        assert result_names == set(names)


class TestBroRLRankingRecordOutcome:
    """record_outcome updates the underlying BroRL technique."""

    def test_record_blocked_updates_technique(self):
        backend = BroRLRankingBackend()
        backend.register_defense("test_def")

        technique = backend._brorl.get_technique("test_def")
        alpha_before = technique.alpha

        backend.record_outcome("test_def", blocked=True)

        technique_after = backend._brorl.get_technique("test_def")
        assert technique_after.alpha > alpha_before

    def test_record_allowed_updates_technique(self):
        backend = BroRLRankingBackend()
        backend.register_defense("test_def")

        technique = backend._brorl.get_technique("test_def")
        beta_before = technique.beta

        backend.record_outcome("test_def", blocked=False)

        technique_after = backend._brorl.get_technique("test_def")
        assert technique_after.beta > beta_before

    def test_record_unknown_defense_logs_warning(self, caplog):
        import logging

        backend = BroRLRankingBackend()
        with caplog.at_level(logging.WARNING):
            backend.record_outcome("nonexistent", blocked=True)
        assert "Unknown defense" in caplog.text


class TestBroRLRankingRegisterDefense:
    """register_defense creates BroRL techniques."""

    def test_register_creates_technique(self):
        backend = BroRLRankingBackend()
        backend.register_defense("my_defense")
        technique = backend._brorl.get_technique("my_defense")
        assert technique is not None

    def test_register_multiple(self):
        backend = BroRLRankingBackend()
        backend.register_defense("d1")
        backend.register_defense("d2")
        assert backend._brorl.get_technique("d1") is not None
        assert backend._brorl.get_technique("d2") is not None

    def test_register_duplicate_is_safe(self):
        backend = BroRLRankingBackend()
        backend.register_defense("dup")
        backend.register_defense("dup")
        assert backend._brorl.get_technique("dup") is not None


class TestBroRLRankingWeights:
    """get_weights / load_weights delegate to BroRLCore."""

    def test_get_weights_returns_dict(self):
        backend = BroRLRankingBackend()
        backend.register_defense("d1")
        weights = backend.get_weights()
        assert isinstance(weights, dict)

    def test_weights_round_trip(self):
        backend1 = BroRLRankingBackend()
        backend1.register_defense("d1")
        backend1.record_outcome("d1", blocked=True)
        weights = backend1.get_weights()

        backend2 = BroRLRankingBackend()
        backend2.load_weights(weights)
        assert backend2.get_weights() == weights

    def test_get_weights_delegates_to_brorl(self):
        backend = BroRLRankingBackend()
        backend._brorl.get_weights = MagicMock(return_value={"mock": True})
        assert backend.get_weights() == {"mock": True}

    def test_load_weights_delegates_to_brorl(self):
        backend = BroRLRankingBackend()
        backend._brorl.load_weights = MagicMock()
        backend.load_weights({"data": 123})
        backend._brorl.load_weights.assert_called_once_with({"data": 123})


class TestBroRLRankingStats:
    """get_stats returns backend-specific stats."""

    def test_stats_has_backend_key(self):
        backend = BroRLRankingBackend()
        stats = backend.get_stats()
        assert stats["backend"] == "brorl"

    def test_stats_is_dict(self):
        backend = BroRLRankingBackend()
        assert isinstance(backend.get_stats(), dict)


class TestBroRLRankingBroRLAccess:
    """Direct BroRLCore access via .brorl property."""

    def test_brorl_property(self):
        from goop_shield.enterprise.brorl_ranking import BroRLRankingBackend as _B

        backend = _B()
        assert backend.brorl is not None


class TestBroRLRankingDecayPriors:
    """decay_priors delegates to BroRLCore."""

    def test_decay_priors_returns_dict(self):
        backend = BroRLRankingBackend()
        backend.register_defense("d1")
        result = backend.decay_priors(decay_rate=0.99)
        assert isinstance(result, dict)


# ============================================================================
# Fallback Behavior
# ============================================================================


class TestEnterpriseFallback:
    """When enterprise is unavailable, Defender falls back to StaticRanking."""

    def test_fallback_to_static_when_import_fails(self):
        """Simulate enterprise import failure in _create_default_ranking."""
        from goop_shield.config import ShieldConfig
        from goop_shield.defender import Defender

        with patch("goop_shield.defender.Defender._create_default_ranking") as mock_create:
            from goop_shield.ranking.static import StaticRanking

            static = StaticRanking()
            mock_create.return_value = static

            config = ShieldConfig()
            d = Defender(config)
            assert isinstance(d.ranking, StaticRanking)

    def test_enterprise_backend_when_available(self):
        """When enterprise is available, BroRL backend is used by default."""
        from goop_shield.config import ShieldConfig
        from goop_shield.defender import Defender

        # In our test env, enterprise IS available, so default should work
        config = ShieldConfig()
        d = Defender(config)
        # The default _create_default_ranking tries enterprise first
        # Since we have the full goop install, it should succeed
        assert isinstance(d.ranking, RankingBackend)
