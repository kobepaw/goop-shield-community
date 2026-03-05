# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield Defense Base Classes

Abstract base class and data types for inline defenses.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DefenseContext:
    """Context passed through the defense pipeline.

    ``current_prompt`` starts as a copy of ``original_prompt`` and may be
    modified (sanitized) by upstream defenses before reaching downstream ones.
    """

    original_prompt: str
    current_prompt: str
    user_context: dict[str, Any] = field(default_factory=dict)
    max_prompt_length: int = 2000
    max_prompt_tokens: int = 1024
    injection_confidence_threshold: float = 0.7


@dataclass
class InlineVerdict:
    """Result from executing a single defense."""

    defense_name: str
    blocked: bool = False
    sanitized: bool = False
    filtered_prompt: str = ""
    confidence: float = 0.0
    threat_confidence: float = 0.0
    details: str = ""
    metadata: dict[str, Any] | None = None


class InlineDefense(ABC):
    """Abstract base class for inline defenses."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this defense."""
        ...

    @property
    def mandatory(self) -> bool:
        """If True, this defense always runs before BroRL-ranked defenses."""
        return False

    @abstractmethod
    def execute(self, context: DefenseContext) -> InlineVerdict:
        """Execute the defense against the given context.

        Returns an InlineVerdict indicating whether the prompt was blocked,
        sanitized, or allowed through.
        """
        ...


@dataclass
class OutputContext:
    """Context passed through the output scanning pipeline.

    ``current_response`` starts as a copy of ``response_text`` and may be
    modified (sanitized) by upstream scanners before reaching downstream ones.
    """

    response_text: str
    current_response: str
    original_prompt: str = ""
    user_context: dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Shared weights for pattern-based defenses
# ============================================================================

STRONG_WEIGHT: float = 0.5
MEDIUM_WEIGHT: float = 0.35
WEAK_WEIGHT: float = 0.2
DEFAULT_THRESHOLD: float = 0.4


class PatternBasedDefense(InlineDefense):
    """Base class for pattern-matching defenses with weighted scoring.

    Subclasses define ``_strong_patterns``, ``_medium_patterns``, and
    ``_weak_patterns`` as lists of ``(compiled_regex, label)`` tuples.
    The base class provides the shared ``_scan_text`` and ``execute``
    logic with dual-prompt scanning.
    """

    _strong_patterns: list[tuple[Any, str]] = []
    _medium_patterns: list[tuple[Any, str]] = []
    _weak_patterns: list[tuple[Any, str]] = []
    _block_detail_prefix: str = "Threat detected"

    def __init__(self, confidence_threshold: float = DEFAULT_THRESHOLD) -> None:
        self._threshold = confidence_threshold

    def _scan_text(self, text: str) -> tuple[float, list[str]]:
        """Run all pattern lists against text, return (score, matched_labels)."""
        score = 0.0
        matched: list[str] = []
        for pattern, label in self._strong_patterns:
            if pattern.search(text):
                score += STRONG_WEIGHT
                matched.append(label)
        for pattern, label in self._medium_patterns:
            if pattern.search(text):
                score += MEDIUM_WEIGHT
                matched.append(label)
        for pattern, label in self._weak_patterns:
            if pattern.search(text):
                score += WEAK_WEIGHT
                matched.append(label)
        return score, matched

    def execute(self, context: DefenseContext) -> InlineVerdict:
        # Scan both original and normalized to survive PromptNormalizer transforms
        score_cur, matched_cur = self._scan_text(context.current_prompt)
        score_orig, matched_orig = self._scan_text(context.original_prompt)

        if score_orig > score_cur:
            score, matched = score_orig, matched_orig
        else:
            score, matched = score_cur, matched_cur

        if score >= self._threshold:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                confidence=min(score, 1.0),
                threat_confidence=min(score, 1.0),
                details=f"{self._block_detail_prefix}: {', '.join(matched)}",
                metadata={"matched_patterns": matched, "score": score},
            )

        return InlineVerdict(
            defense_name=self.name,
            confidence=score,
            threat_confidence=score,
            metadata={"matched_patterns": matched, "score": score},
        )


class OutputScanner(ABC):
    """Abstract base class for output scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this scanner."""
        ...

    @abstractmethod
    def scan(self, context: OutputContext) -> InlineVerdict:
        """Scan the LLM response for policy violations.

        Returns an InlineVerdict indicating whether the response was blocked,
        sanitized, or allowed through.
        """
        ...
