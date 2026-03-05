# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Bayesian Ranking -- Adaptive Thompson sampling defense prioritization.

This backend maintains a Beta(alpha, beta) posterior per defense and uses
Thompson sampling to produce stochastic rankings that balance exploration
and exploitation.

Usage::

    ranking = BayesianRankingBackend(learning_rate=0.1)
    ranking.register_defense("injection_blocker")
    ranking.register_defense("safety_filter")
    ranking.record_outcome("injection_blocker", blocked=True)
    ordered = ranking.rank_defenses(["injection_blocker", "safety_filter"])
"""

from __future__ import annotations

import json
import logging
import random
from pathlib import Path
from typing import Any

from goop_shield.ranking.base import RankingBackend

logger = logging.getLogger(__name__)


class BayesianRankingBackend(RankingBackend):
    """Adaptive Thompson sampling ranking using Beta-Bernoulli posteriors.

    Each defense tracks a ``Beta(alpha, beta)`` posterior.  On each call
    to :meth:`rank_defenses`, a sample is drawn from each posterior and
    defenses are sorted by descending sample value.

    Args:
        learning_rate: Increment applied to alpha/beta on each outcome.
        prior_alpha: Initial alpha for new defenses.
        prior_beta: Initial beta for new defenses.
        state_path: Optional file path for persisting posteriors across
            restarts.  When set, posteriors are loaded on init and saved
            after every ``record_outcome`` call.
    """

    def __init__(
        self,
        learning_rate: float = 0.1,
        prior_alpha: float = 1.0,
        prior_beta: float = 1.0,
        state_path: str | None = None,
    ) -> None:
        self._learning_rate = learning_rate
        self._prior_alpha = prior_alpha
        self._prior_beta = prior_beta
        self._posteriors: dict[str, tuple[float, float]] = {}
        self._state_path = state_path
        self._outcome_count = 0
        # Load persisted state if available
        if state_path:
            self._load_from_disk()

    # -- RankingBackend interface ------------------------------------------

    def rank_defenses(self, defense_names: list[str]) -> list[tuple[str, float]]:
        scored: list[tuple[str, float]] = []
        for name in defense_names:
            alpha, beta = self._posteriors.get(name, (self._prior_alpha, self._prior_beta))
            sample = random.betavariate(alpha, beta)
            scored.append((name, sample))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored

    def record_outcome(self, defense_name: str, blocked: bool) -> None:
        alpha, beta = self._posteriors.get(defense_name, (self._prior_alpha, self._prior_beta))
        if blocked:
            alpha += self._learning_rate
        else:
            beta += self._learning_rate
        self._posteriors[defense_name] = (alpha, beta)
        self._outcome_count += 1
        # Persist every 10 outcomes to avoid excessive I/O
        if self._state_path and self._outcome_count % 10 == 0:
            self._save_to_disk()

    def get_weights(self) -> dict[str, Any]:
        return {
            "posteriors": {
                name: {"alpha": a, "beta": b} for name, (a, b) in self._posteriors.items()
            },
            "learning_rate": self._learning_rate,
            "prior_alpha": self._prior_alpha,
            "prior_beta": self._prior_beta,
        }

    def load_weights(self, weights: dict[str, Any]) -> None:
        if "posteriors" in weights:
            self._posteriors = {
                name: (vals["alpha"], vals["beta"]) for name, vals in weights["posteriors"].items()
            }
        if "learning_rate" in weights:
            self._learning_rate = float(weights["learning_rate"])
        if "prior_alpha" in weights:
            self._prior_alpha = float(weights["prior_alpha"])
        if "prior_beta" in weights:
            self._prior_beta = float(weights["prior_beta"])

    def register_defense(self, defense_name: str) -> None:
        if defense_name not in self._posteriors:
            self._posteriors[defense_name] = (self._prior_alpha, self._prior_beta)

    def get_posterior(self, defense_name: str) -> tuple[float, float]:
        """Return the (alpha, beta) posterior for a defense.

        If the defense has not been registered, returns the prior values.
        """
        return self._posteriors.get(defense_name, (self._prior_alpha, self._prior_beta))

    def get_stats(self) -> dict[str, Any]:
        return {
            "backend": "bayesian",
            "num_defenses": len(self._posteriors),
            "learning_rate": self._learning_rate,
            "posteriors": {
                name: {"alpha": a, "beta": b, "mean": a / (a + b)}
                for name, (a, b) in self._posteriors.items()
            },
        }

    # -- Persistence -----------------------------------------------------------

    def _save_to_disk(self) -> None:
        """Persist current posteriors to JSON file."""
        if not self._state_path:
            return
        try:
            path = Path(self._state_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.get_weights(), indent=2))
            tmp.replace(path)  # atomic on POSIX
        except Exception:
            logger.warning("Failed to save BroRL state to %s", self._state_path, exc_info=True)

    def _load_from_disk(self) -> None:
        """Load posteriors from JSON file if it exists.

        Only restores the defense posteriors -- learning_rate and priors
        are always taken from the constructor (i.e. from ShieldConfig).
        """
        if not self._state_path:
            return
        path = Path(self._state_path)
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            # Only load posteriors, not learning_rate/priors (those come from config)
            if "posteriors" in data:
                self._posteriors = {
                    name: (vals["alpha"], vals["beta"]) for name, vals in data["posteriors"].items()
                }
            logger.info(
                "Loaded BroRL state from %s (%d defenses)",
                self._state_path,
                len(self._posteriors),
            )
        except Exception:
            logger.warning(
                "Failed to load BroRL state from %s, starting fresh",
                self._state_path,
                exc_info=True,
            )

    def save(self) -> None:
        """Explicitly save current state to disk (for shutdown hooks)."""
        self._save_to_disk()
