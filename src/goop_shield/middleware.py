# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Shield LLM Middleware (community stub).

The real ShieldedProvider implementation lives in
:mod:`goop_shield.enterprise.middleware`.  Community edition provides
the error classes directly and a ShieldedProvider stub that requires
the enterprise edition for the LLMProvider base class.
"""

from __future__ import annotations


class PromptBlockedError(Exception):
    """Raised when Shield blocks a prompt."""

    def __init__(self, prompt: str, confidence: float, caught_by: list[str]) -> None:
        self.prompt = prompt
        self.confidence = confidence
        self.caught_by = caught_by
        defenses = ", ".join(caught_by) if caught_by else "unknown"
        super().__init__(f"Prompt blocked (confidence={confidence:.2f}, caught_by=[{defenses}])")


class ResponseBlockedError(Exception):
    """Raised when Shield flags an LLM response as unsafe."""

    def __init__(self, confidence: float, caught_by: list[str]) -> None:
        self.confidence = confidence
        self.caught_by = caught_by
        scanners = ", ".join(caught_by) if caught_by else "unknown"
        super().__init__(f"Response blocked (confidence={confidence:.2f}, caught_by=[{scanners}])")


class ShieldedProvider:
    """LLM provider wrapper — requires the enterprise edition.

    Community edition should use the HTTP API or MCP server instead.
    """

    def __init__(self, *args, **kwargs):
        raise ImportError(
            "ShieldedProvider requires the enterprise edition (LLMProvider base class). "
            "Use the HTTP API or MCP server for community integration."
        )
