# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Shield LLM Middleware (Enterprise)

Wraps any LLM provider so that every prompt goes through the Defender
before the LLM and every response is scanned after.
"""

from __future__ import annotations

# Re-export error classes from core for backwards compatibility.
from goop_shield.middleware import PromptBlockedError, ResponseBlockedError  # noqa: F401


class ShieldedProvider:
    """LLM provider wrapper that defends prompts and scans responses.

    Requires the enterprise edition for the LLMProvider base class.

    Args:
        provider: The wrapped LLM provider.
        defender: Shield Defender instance.
        on_block: "raise" (default) or "empty".
        defend_tool_messages: Whether to defend tool messages in chat.
    """

    def __init__(
        self,
        provider: object,
        defender: object,
        *,
        on_block: str = "raise",
        defend_tool_messages: bool = False,
    ) -> None:
        raise ImportError(
            "ShieldedProvider requires goop-ai Enterprise. "
            "Not available in the community edition. "
            "Use the HTTP API or MCP server for community integration."
        )
