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
