# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Drift Detector — Tracks defense success rates and detects behavioral drift.

Monitors per-defense pass/block rates over a sliding window and alerts when
rates diverge significantly from historical baselines. This catches:
- Model behavior changes (responses becoming more/less safe over time)
- Defense degradation (defense suddenly stopping to catch threats)
- Attack pattern evolution (new attacks bypassing existing defenses)

Does NOT require external services — stores baselines in a JSON file.
"""

from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_WINDOW_SIZE = 100
_DEFAULT_ALERT_THRESHOLD = 2.0  # standard deviations


@dataclass
class DefenseStats:
    """Running statistics for a single defense."""

    total: int = 0
    blocked: int = 0
    # Exponential moving average of block rate
    ema_rate: float = 0.0
    # Exponential moving average of variance
    ema_variance: float = 0.0

    @property
    def block_rate(self) -> float:
        return self.blocked / self.total if self.total > 0 else 0.0

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.ema_variance) if self.ema_variance > 0 else 0.0


@dataclass
class DriftAlert:
    """Alert when a defense shows anomalous behavior."""

    defense_name: str
    current_rate: float
    baseline_rate: float
    z_score: float
    direction: str  # "increased" or "decreased"
    severity: str  # "warning" or "critical"
    message: str


@dataclass
class DriftReport:
    """Summary report from drift analysis."""

    alerts: list[DriftAlert] = field(default_factory=list)
    defenses_analyzed: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def has_drift(self) -> bool:
        return len(self.alerts) > 0


class DriftDetector:
    """Monitors defense effectiveness and detects behavioral drift.

    Uses exponential moving averages to track block rates per defense,
    and alerts when current rates diverge from baseline by more than
    ``alert_threshold`` standard deviations.

    Args:
        baseline_path: Path to JSON file for persisting baselines.
        window_size: Minimum observations before alerting.
        alert_threshold: Z-score threshold for alerts (default 2.0σ).
        decay_rate: EMA decay factor (0.95 = recent 20 events dominate).
    """

    def __init__(
        self,
        baseline_path: str = "data/drift_baselines.json",
        window_size: int = _DEFAULT_WINDOW_SIZE,
        alert_threshold: float = _DEFAULT_ALERT_THRESHOLD,
        decay_rate: float = 0.95,
    ) -> None:
        self._baseline_path = baseline_path
        self._window_size = window_size
        self._alert_threshold = alert_threshold
        self._decay = decay_rate
        self._stats: dict[str, DefenseStats] = {}
        self._load_baselines()

    def _load_baselines(self) -> None:
        """Load persisted baselines from disk."""
        path = Path(self._baseline_path)
        if path.exists():
            try:
                data = json.loads(path.read_text())
                for name, vals in data.items():
                    self._stats[name] = DefenseStats(
                        total=vals.get("total", 0),
                        blocked=vals.get("blocked", 0),
                        ema_rate=vals.get("ema_rate", 0.0),
                        ema_variance=vals.get("ema_variance", 0.0),
                    )
            except (json.JSONDecodeError, KeyError):
                logger.warning("Failed to load drift baselines from %s", path)

    def save_baselines(self) -> None:
        """Persist current baselines to disk."""
        path = Path(self._baseline_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            data = {}
            for name, stats in self._stats.items():
                data[name] = {
                    "total": stats.total,
                    "blocked": stats.blocked,
                    "ema_rate": stats.ema_rate,
                    "ema_variance": stats.ema_variance,
                }
            path.write_text(json.dumps(data, indent=2))
        except OSError as e:
            logger.error("Failed to save drift baselines to %s: %s", path, e)

    def record(self, defense_name: str, blocked: bool) -> None:
        """Record a defense outcome (pass or block).

        Updates the EMA of block rate and variance for the defense.
        """
        if defense_name not in self._stats:
            self._stats[defense_name] = DefenseStats()

        stats = self._stats[defense_name]
        stats.total += 1
        if blocked:
            stats.blocked += 1

        # Update EMA
        observation = 1.0 if blocked else 0.0
        alpha = 1 - self._decay
        old_rate = stats.ema_rate
        stats.ema_rate = self._decay * old_rate + alpha * observation
        # Update EMA of variance using pre-update mean to avoid bias
        deviation = observation - old_rate
        stats.ema_variance = self._decay * stats.ema_variance + alpha * (deviation**2)

    def analyze(self) -> DriftReport:
        """Analyze all defenses for drift, return alerts.

        Only analyzes defenses with at least ``window_size`` observations.
        """
        alerts: list[DriftAlert] = []
        analyzed = 0

        for name, stats in self._stats.items():
            if stats.total < self._window_size:
                continue

            analyzed += 1
            current_rate = stats.block_rate
            baseline_rate = stats.ema_rate
            std_dev = stats.std_dev

            if std_dev < 0.001:
                # Variance too small to be meaningful — skip
                continue

            z_score = abs(current_rate - baseline_rate) / std_dev

            if z_score >= self._alert_threshold:
                direction = "increased" if current_rate > baseline_rate else "decreased"
                severity = "critical" if z_score >= self._alert_threshold * 1.5 else "warning"

                alerts.append(
                    DriftAlert(
                        defense_name=name,
                        current_rate=round(current_rate, 4),
                        baseline_rate=round(baseline_rate, 4),
                        z_score=round(z_score, 2),
                        direction=direction,
                        severity=severity,
                        message=(
                            f"Defense '{name}' block rate {direction}: "
                            f"{current_rate:.1%} vs baseline {baseline_rate:.1%} "
                            f"(z={z_score:.1f}σ)"
                        ),
                    )
                )

        return DriftReport(alerts=alerts, defenses_analyzed=analyzed)

    def get_stats(self, defense_name: str) -> DefenseStats | None:
        """Get current stats for a defense."""
        return self._stats.get(defense_name)

    def get_all_stats(self) -> dict[str, DefenseStats]:
        """Get stats for all tracked defenses."""
        return dict(self._stats)

    def reset(self, defense_name: str | None = None) -> None:
        """Reset stats for a defense (or all if name is None)."""
        if defense_name is None:
            self._stats.clear()
        else:
            self._stats.pop(defense_name, None)
