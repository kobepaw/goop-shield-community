# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield Ranking — Pluggable defense prioritization.

This package provides the ``RankingBackend`` ABC and built-in
implementations.  The Defender uses whichever backend is configured
to order inline defenses and output scanners before execution.

Built-in backends:
  - ``StaticRanking``  — fixed config-driven priority (default)
  - ``BayesianRankingBackend`` — Thompson-sampling Bayesian ranking
"""

from goop_shield.ranking.base import RankingBackend
from goop_shield.ranking.bayesian import BayesianRankingBackend
from goop_shield.ranking.static import StaticRanking

__all__ = [
    "BayesianRankingBackend",
    "RankingBackend",
    "StaticRanking",
]
