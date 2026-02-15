# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Static Ranking — Config-driven fixed-priority defense ordering.

This is the default ranking backend for Shield CE (Community Edition).
It requires no external dependencies and provides deterministic,
reproducible defense ordering based on a priority map supplied at
construction time.

Usage::

    ranking = StaticRanking(priorities={
        "injection_blocker": 100,
        "safety_filter": 90,
        "input_validator": 80,
    })
    ordered = ranking.rank_defenses(["safety_filter", "injection_blocker"])
    # => [("injection_blocker", 100.0), ("safety_filter", 90.0)]

Defenses not listed in *priorities* receive ``default_priority`` (50).
"""

from __future__ import annotations

from typing import Any

from goop_shield.ranking.base import RankingBackend


class StaticRanking(RankingBackend):
    """Fixed-priority defense ranking driven by a config dict.

    Args:
        priorities: Mapping of defense name to numeric priority.
            Higher values run first.  Defenses absent from this map
            receive *default_priority*.
        default_priority: Score assigned to unknown defenses.
    """

    def __init__(
        self,
        priorities: dict[str, float] | None = None,
        default_priority: float = 50.0,
    ) -> None:
        self._priorities: dict[str, float] = dict(priorities or {})
        self._default_priority = default_priority

    # -- RankingBackend interface ------------------------------------------

    def rank_defenses(self, defense_names: list[str]) -> list[tuple[str, float]]:
        scored = [
            (name, self._priorities.get(name, self._default_priority)) for name in defense_names
        ]
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored

    def record_outcome(self, defense_name: str, blocked: bool) -> None:
        # Static ranking does not learn from outcomes.
        pass

    def get_weights(self) -> dict[str, Any]:
        return {
            "priorities": dict(self._priorities),
            "default_priority": self._default_priority,
        }

    def load_weights(self, weights: dict[str, Any]) -> None:
        if "priorities" in weights:
            self._priorities = dict(weights["priorities"])
        if "default_priority" in weights:
            self._default_priority = float(weights["default_priority"])

    def register_defense(self, defense_name: str) -> None:
        # Ensure the defense has an entry so it appears in get_weights().
        if defense_name not in self._priorities:
            self._priorities[defense_name] = self._default_priority

    def get_stats(self) -> dict[str, Any]:
        return {
            "backend": "static",
            "num_defenses": len(self._priorities),
            "default_priority": self._default_priority,
        }

    # -- Convenience -------------------------------------------------------

    def set_priority(self, defense_name: str, priority: float) -> None:
        """Update the priority for a single defense at runtime."""
        self._priorities[defense_name] = priority

    def get_priority(self, defense_name: str) -> float:
        """Return the current priority for *defense_name*."""
        return self._priorities.get(defense_name, self._default_priority)
