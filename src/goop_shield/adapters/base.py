# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Base Shield Adapter

Abstract interface for framework-specific Shield integrations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ShieldResult:
    """Result from Shield prompt/tool interception."""

    allowed: bool = True
    filtered_prompt: str = ""
    blocked_by: str | None = None
    confidence: float = 0.0
    defenses_applied: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Result from Shield response scanning."""

    safe: bool = True
    filtered_response: str = ""
    flagged_by: str | None = None
    confidence: float = 0.0
    scanners_applied: list[str] = field(default_factory=list)


@dataclass
class ToolOutputResult:
    """Result from Shield tool output scanning."""

    safe: bool = True
    filtered_content: str = ""
    action: str = "pass"  # pass | sanitize | block
    confidence: float = 0.0
    scanners_applied: list[str] = field(default_factory=list)


class BaseShieldAdapter(ABC):
    """Abstract base for all Shield framework adapters."""

    @abstractmethod
    def intercept_prompt(self, prompt: str, context: dict | None = None) -> ShieldResult:
        """Intercept and defend a prompt before sending to LLM."""
        ...

    @abstractmethod
    def intercept_tool_call(self, tool: str, args: dict | None = None) -> ShieldResult:
        """Intercept a tool call before execution."""
        ...

    @abstractmethod
    def scan_response(self, response: str, original_prompt: str = "") -> ScanResult:
        """Scan an LLM response for policy violations."""
        ...

    @abstractmethod
    def scan_tool_output(
        self,
        content: str,
        tool_name: str = "unknown",
        *,
        source_url: str = "",
        trust_level: str = "untrusted",
        context: dict | None = None,
    ) -> ToolOutputResult:
        """Scan tool output before it enters agent context."""
        ...
