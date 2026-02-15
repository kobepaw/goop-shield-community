# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Cross-Model Consistency Checker — Multi-provider response comparison.

Sends safety-sensitive prompts to multiple LLM providers and flags
divergences in responses.  Breaks the circularity problem of using
a single model family for both generation and monitoring.

Three comparison strategies (weighted):
  - Structural (0.5): refusal vs compliance classification
  - Semantic  (0.3): embedding cosine distance
  - Factual   (0.2): lightweight claim/number extraction

Requires goop-ai Enterprise. Not available in community edition.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class ProviderConfig:
    """Configuration for a single LLM provider used in consistency checks."""

    name: str
    provider_type: str
    model: str = ""
    config: dict = field(default_factory=dict)


@dataclass
class ConsistencyResult:
    """Result of a cross-model consistency check."""

    is_consistent: bool
    divergence_score: float
    primary_response: str
    comparison_responses: dict[str, str]
    structural_divergence: float
    semantic_divergence: float
    factual_divergence: float
    divergence_details: list[str] = field(default_factory=list)
    check_latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


class SafetyClassifier:
    """Classify whether a prompt is safety-sensitive.

    Requires goop-ai Enterprise.
    """

    def __init__(self, check_rate: float = 0.05) -> None:
        raise ImportError(
            "SafetyClassifier requires goop-ai Enterprise. "
            "Not available in the community edition."
        )

    def is_safety_sensitive(self, prompt: str) -> bool:
        raise NotImplementedError

    def should_check(self, prompt: str, context: dict | None = None) -> bool:
        raise NotImplementedError


class ConsistencyChecker:
    """Compare safety-sensitive prompts across multiple LLM providers.

    Requires goop-ai Enterprise. Not available in community edition.

    Args:
        providers: List of ProviderConfig.
        divergence_threshold: Aggregate divergence score threshold.
        embedding_engine: Optional embedding engine for semantic comparison.
        timeout_seconds: Per-provider timeout.
        provider_factory: Callable to create provider instances.
    """

    def __init__(
        self,
        providers: list[ProviderConfig],
        divergence_threshold: float = 0.3,
        embedding_engine: object | None = None,
        timeout_seconds: float = 30.0,
        provider_factory: callable | None = None,
    ) -> None:
        raise ImportError(
            "ConsistencyChecker requires goop-ai Enterprise. "
            "Not available in the community edition."
        )

    async def check_consistency(
        self,
        prompt: str,
        primary_response: str,
        context: dict | None = None,
    ) -> ConsistencyResult:
        raise NotImplementedError

    def get_stats(self) -> dict:
        raise NotImplementedError
