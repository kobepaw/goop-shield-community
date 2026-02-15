# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Sandbagging Detector — Cross-category divergence detection.

Detects models subtly underperforming on safety-critical task categories
by tracking per-category success rates and flagging statistically
significant divergences via Z-score analysis.

Not available in community edition — coming in a future release.
"""

from __future__ import annotations

from dataclasses import dataclass

from goop_shield.ranking.base import RankingBackend


@dataclass
class CategoryStats:
    """Per-category performance statistics."""

    category: str
    success_rate: float = 0.0
    samples: int = 0
    alpha: float = 1.0
    beta: float = 1.0
    z_score: float = 0.0


@dataclass
class SandbagAlert:
    """Alert raised when a category shows significant underperformance."""

    category: str
    z_score: float
    success_rate: float
    pooled_mean: float
    sigma_threshold: float
    samples: int


class SandbagDetector:
    """Detects sandbagging via cross-category Z-score divergence.

    Not available in community edition — coming in a future release.

    Args:
        ranking_backend: The RankingBackend used by the Defender.
        sigma_threshold: Z-score threshold to trigger an alert.
        min_samples: Minimum samples per category before checking.
    """

    def __init__(
        self,
        ranking_backend: RankingBackend,
        sigma_threshold: float = 2.0,
        min_samples: int = 30,
    ) -> None:
        raise ImportError(
            "SandbagDetector requires goop-ai Enterprise. Not available in the community edition."
        )

    def record_task_outcome(self, category: str, succeeded: bool) -> None:
        raise NotImplementedError

    def check_divergence(self) -> list[SandbagAlert]:
        raise NotImplementedError

    def get_category_stats(self) -> dict[str, CategoryStats]:
        raise NotImplementedError

    def decay_stale_priors(self, decay_rate: float = 0.99) -> dict:
        raise NotImplementedError
