# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Tests for the BayesianRankingBackend.

Covers:
  - Thompson sampling, posterior updates, weights round-trip, get_posterior
  - Fallback behaviour: auto -> StaticRanking in community edition
"""

from __future__ import annotations

import pytest

from goop_shield.config import ShieldConfig
from goop_shield.defender import Defender
from goop_shield.ranking.base import RankingBackend
from goop_shield.ranking.bayesian import BayesianRankingBackend

# ============================================================================
# BayesianRankingBackend
# ============================================================================


class TestBayesianRankingBackendBasics:
    """Core functionality: implements RankingBackend ABC."""

    def test_is_ranking_backend(self):
        backend = BayesianRankingBackend()
        assert isinstance(backend, RankingBackend)

    def test_rank_defenses_returns_pairs(self):
        backend = BayesianRankingBackend()
        result = backend.rank_defenses(["a", "b", "c"])
        assert len(result) == 3
        for name, score in result:
            assert isinstance(name, str)
            assert 0.0 <= score <= 1.0

    def test_rank_defenses_empty_input(self):
        backend = BayesianRankingBackend()
        assert backend.rank_defenses([]) == []

    def test_rank_defenses_sorted_descending(self):
        backend = BayesianRankingBackend()
        result = backend.rank_defenses(["a", "b"])
        scores = [s for _, s in result]
        assert scores == sorted(scores, reverse=True)


class TestBayesianPosteriorUpdates:
    """record_outcome updates posteriors correctly."""

    def test_block_increases_alpha(self):
        backend = BayesianRankingBackend(learning_rate=0.5)
        backend.register_defense("d")
        alpha_before, _ = backend.get_posterior("d")
        backend.record_outcome("d", blocked=True)
        alpha_after, _ = backend.get_posterior("d")
        assert alpha_after == alpha_before + 0.5

    def test_allow_increases_beta(self):
        backend = BayesianRankingBackend(learning_rate=0.3)
        backend.register_defense("d")
        _, beta_before = backend.get_posterior("d")
        backend.record_outcome("d", blocked=False)
        _, beta_after = backend.get_posterior("d")
        assert beta_after == beta_before + 0.3

    def test_unregistered_defense_gets_prior(self):
        backend = BayesianRankingBackend(prior_alpha=2.0, prior_beta=3.0)
        alpha, beta = backend.get_posterior("unknown")
        assert alpha == 2.0
        assert beta == 3.0

    def test_record_creates_posterior_implicitly(self):
        backend = BayesianRankingBackend()
        backend.record_outcome("new_def", blocked=True)
        alpha, beta = backend.get_posterior("new_def")
        assert alpha > 1.0  # prior(1.0) + lr(0.1)
        assert beta == 1.0


class TestBayesianWeightsRoundTrip:
    """get_weights / load_weights round-trip."""

    def test_round_trip(self):
        b1 = BayesianRankingBackend(learning_rate=0.2, prior_alpha=1.5, prior_beta=2.0)
        b1.register_defense("x")
        b1.record_outcome("x", blocked=True)
        b1.record_outcome("x", blocked=False)
        weights = b1.get_weights()

        b2 = BayesianRankingBackend()
        b2.load_weights(weights)
        assert b2.get_weights() == weights

    def test_weights_structure(self):
        backend = BayesianRankingBackend()
        backend.register_defense("a")
        w = backend.get_weights()
        assert "posteriors" in w
        assert "learning_rate" in w
        assert "a" in w["posteriors"]
        assert "alpha" in w["posteriors"]["a"]
        assert "beta" in w["posteriors"]["a"]


class TestBayesianRegisterDefense:
    """register_defense initialises posteriors."""

    def test_register_new(self):
        backend = BayesianRankingBackend(prior_alpha=2.0, prior_beta=3.0)
        backend.register_defense("d")
        assert backend.get_posterior("d") == (2.0, 3.0)

    def test_register_existing_is_noop(self):
        backend = BayesianRankingBackend()
        backend.register_defense("d")
        backend.record_outcome("d", blocked=True)
        alpha_before, _ = backend.get_posterior("d")
        backend.register_defense("d")
        alpha_after, _ = backend.get_posterior("d")
        assert alpha_after == alpha_before


class TestBayesianStats:
    """get_stats returns useful metadata."""

    def test_stats_fields(self):
        backend = BayesianRankingBackend()
        backend.register_defense("a")
        backend.register_defense("b")
        stats = backend.get_stats()
        assert stats["backend"] == "bayesian"
        assert stats["num_defenses"] == 2
        assert "posteriors" in stats
        assert "a" in stats["posteriors"]
        assert "mean" in stats["posteriors"]["a"]


class TestBayesianGetPosterior:
    """get_posterior returns (alpha, beta) tuple."""

    def test_get_posterior(self):
        backend = BayesianRankingBackend()
        backend.register_defense("d")
        result = backend.get_posterior("d")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_get_posterior_unregistered(self):
        backend = BayesianRankingBackend(prior_alpha=2.0, prior_beta=3.0)
        result = backend.get_posterior("unknown")
        assert result == (2.0, 3.0)


# ============================================================================
# Fallback behaviour
# ============================================================================


class TestAutoFallbackToStatic:
    """``ranking_backend='auto'`` falls back to StaticRanking in community edition."""

    def test_auto_creates_static_backend(self):
        """Auto mode should produce a StaticRanking in community edition."""
        from goop_shield.ranking.static import StaticRanking

        config = ShieldConfig(ranking_backend="auto")
        defender = Defender(config=config)
        assert isinstance(defender.ranking, StaticRanking)

    def test_explicit_bayesian_can_be_injected(self):
        """BayesianRankingBackend can be used when explicitly injected."""
        lr = 0.42
        backend = BayesianRankingBackend(learning_rate=lr)
        config = ShieldConfig()
        defender = Defender(config=config, ranking_backend=backend)
        assert isinstance(defender.ranking, BayesianRankingBackend)
        assert defender.ranking._learning_rate == pytest.approx(lr)
