# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Training Data Gate — Trust scoring for training data.

Computes trust scores for training data using source provenance and
defense penalty signals. Provides allow/quarantine/reject recommendations
based on configurable thresholds.

Requires goop-ai Enterprise. Not available in community edition.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TrainingDataVerdict:
    """Result of training data validation."""

    trust_score: float
    recommendation: str  # "allow", "quarantine", "reject"
    triggered_defenses: list[str] = field(default_factory=list)
    source_trust: float = 0.0
    scan_confidence: float = 0.0
    scan_details: dict[str, Any] = field(default_factory=dict)


class TrainingDataGate:
    """Validates training data using Shield's defense pipeline in scan-only mode.

    Requires goop-ai Enterprise. Not available in community edition.

    Args:
        defender: The Defender instance.
        trust_threshold: Minimum trust score to allow data.
        trust_thresholds: Per-pipeline threshold overrides.
        quarantine_store: Optional QuarantineStore for auto-quarantine.
    """

    def __init__(
        self,
        defender: Any,
        trust_threshold: float = 0.7,
        trust_thresholds: dict[str, float] | None = None,
        quarantine_store: Any | None = None,
    ) -> None:
        raise ImportError(
            "TrainingDataGate requires goop-ai Enterprise. Not available in the community edition."
        )

    def validate(
        self,
        content: str,
        source: str = "unknown",
        pipeline: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TrainingDataVerdict:
        raise NotImplementedError

    def validate_batch(
        self,
        items: list[dict[str, Any]],
        pipeline: str | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError
