# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
LangChain Shield Adapter

Provides both a BaseShieldAdapter and a LangChain CallbackHandler
for seamless integration with LangChain chains and agents.
"""

from __future__ import annotations

import logging
from typing import Any

from goop_shield.adapters.base import BaseShieldAdapter, ScanResult, ShieldResult, ToolOutputResult
from goop_shield.adapters.generic import GenericHTTPAdapter

logger = logging.getLogger(__name__)


class LangChainShieldAdapter(BaseShieldAdapter):
    """Shield adapter for LangChain."""

    def __init__(
        self, shield_url: str = "http://localhost:8787", api_key: str | None = None
    ) -> None:
        self._http = GenericHTTPAdapter(shield_url=shield_url, api_key=api_key)

    def intercept_prompt(self, prompt: str, context: dict | None = None) -> ShieldResult:
        ctx = dict(context or {})
        ctx["framework"] = "langchain"
        return self._http.intercept_prompt(prompt, context=ctx)

    def intercept_tool_call(self, tool: str, args: dict | None = None) -> ShieldResult:
        ctx = {"framework": "langchain", "tool_call": True, "tool": tool}
        prompt = f"[LangChain Tool] {tool}: {args or {}}"
        return self._http.intercept_prompt(prompt, context=ctx)

    def scan_response(self, response: str, original_prompt: str = "") -> ScanResult:
        return self._http.scan_response(response, original_prompt)

    def scan_tool_output(
        self,
        content: str,
        tool_name: str = "unknown",
        *,
        source_url: str = "",
        trust_level: str = "untrusted",
        context: dict | None = None,
    ) -> ToolOutputResult:
        return self._http.scan_tool_output(
            content, tool_name, source_url=source_url, trust_level=trust_level, context=context
        )


class LangChainShieldCallback:
    """LangChain callback handler that routes through Shield.

    Usage:
        callback = LangChainShieldCallback(shield_url="http://localhost:8787")
        chain = LLMChain(llm=llm, callbacks=[callback])
    """

    def __init__(
        self, shield_url: str = "http://localhost:8787", api_key: str | None = None
    ) -> None:
        self._adapter = LangChainShieldAdapter(shield_url=shield_url, api_key=api_key)
        self._blocked_prompts: list[str] = []

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        """Intercept prompts before LLM call."""
        for prompt in prompts:
            result = self._adapter.intercept_prompt(prompt)
            if not result.allowed:
                self._blocked_prompts.append(prompt)
                logger.warning("Shield blocked LangChain prompt: %s", result.blocked_by)

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        """Intercept tool calls."""
        tool_name = serialized.get("name", "unknown")
        result = self._adapter.intercept_tool_call(tool_name, {"input": input_str})
        if not result.allowed:
            logger.warning("Shield blocked LangChain tool %s: %s", tool_name, result.blocked_by)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Scan LLM response."""
        text = str(response) if response else ""
        result = self._adapter.scan_response(text)
        if not result.safe:
            logger.warning("Shield flagged LangChain response: %s", result.flagged_by)
