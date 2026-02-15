# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Ranking Backend — Abstract interface for defense prioritization.

All Shield ranking strategies implement this ABC. The Defender calls
``rank_defenses()`` to order defenses before execution and
``record_outcome()`` after each defense fires.

Two built-in backends ship with Shield:
  - ``StaticRanking``  (CE default) — config-driven fixed priority
  - ``BroRLRanking``   (Enterprise)  — adaptive Thompson sampling via BroRL
"""

from __future__ import annotations

import abc
from typing import Any


class RankingBackend(abc.ABC):
    """Abstract base class for defense ranking strategies.

    A ranking backend assigns a numeric score to each defense so the
    Defender can execute them in priority order.  It may also learn
    from outcomes to improve future rankings.
    """

    @abc.abstractmethod
    def rank_defenses(self, defense_names: list[str]) -> list[tuple[str, float]]:
        """Return *defense_names* sorted by descending priority with scores.

        Args:
            defense_names: Names of registered defenses to rank.

        Returns:
            List of ``(defense_name, score)`` tuples ordered from highest
            to lowest score.  Every name in *defense_names* must appear
            exactly once in the result.
        """

    @abc.abstractmethod
    def record_outcome(self, defense_name: str, blocked: bool) -> None:
        """Record whether *defense_name* blocked the current request.

        Adaptive backends use this signal to update their internal model.
        Static backends may ignore it.

        Args:
            defense_name: The defense that produced the outcome.
            blocked: ``True`` if the defense blocked or sanitized the input.
        """

    @abc.abstractmethod
    def get_weights(self) -> dict[str, Any]:
        """Export the current ranking state as a JSON-serialisable dict.

        The format is backend-specific but must be accepted by
        :meth:`load_weights`.
        """

    @abc.abstractmethod
    def load_weights(self, weights: dict[str, Any]) -> None:
        """Import ranking state previously exported by :meth:`get_weights`.

        Args:
            weights: Dict produced by a prior ``get_weights()`` call
                     (same backend type).
        """

    def register_defense(self, defense_name: str) -> None:  # noqa: B027
        """Notify the backend that *defense_name* exists.

        Called once per defense during Defender initialisation.  Backends
        that need to pre-allocate state (e.g. BroRL techniques) should
        override this.  The default implementation is a no-op.
        """

    def get_stats(self) -> dict[str, Any]:
        """Return backend-specific diagnostic statistics.

        The default implementation returns an empty dict.  Backends may
        override to expose metrics useful for monitoring.
        """
        return {}
