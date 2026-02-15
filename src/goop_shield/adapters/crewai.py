# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
CrewAI Shield Adapter

Wraps Shield as a CrewAI-compatible tool wrapper.
"""

from __future__ import annotations

import logging

from goop_shield.adapters.base import BaseShieldAdapter, ScanResult, ShieldResult, ToolOutputResult
from goop_shield.adapters.generic import GenericHTTPAdapter

logger = logging.getLogger(__name__)


class CrewAIShieldAdapter(BaseShieldAdapter):
    """Shield adapter for CrewAI agent framework."""

    def __init__(
        self, shield_url: str = "http://localhost:8787", api_key: str | None = None
    ) -> None:
        self._http = GenericHTTPAdapter(shield_url=shield_url, api_key=api_key)

    def intercept_prompt(self, prompt: str, context: dict | None = None) -> ShieldResult:
        ctx = dict(context or {})
        ctx["framework"] = "crewai"
        return self._http.intercept_prompt(prompt, context=ctx)

    def intercept_tool_call(self, tool: str, args: dict | None = None) -> ShieldResult:
        ctx = {"framework": "crewai", "tool_call": True, "tool": tool}
        prompt = f"[CrewAI Tool] {tool}: {args or {}}"
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

    def wrap_tool_execution(self, tool_name: str, tool_func, *args, **kwargs):
        """Wrap a CrewAI tool execution with Shield interception.

        Usage:
            adapter = CrewAIShieldAdapter()
            result = adapter.wrap_tool_execution("search", search_func, query="test")
        """
        # Pre-execution check
        check = self.intercept_tool_call(tool_name, {"args": args, "kwargs": kwargs})
        if not check.allowed:
            raise PermissionError(f"Shield blocked tool {tool_name}: {check.blocked_by}")

        # Execute tool
        result = tool_func(*args, **kwargs)

        # Post-execution scan
        scan = self.scan_response(str(result))
        if not scan.safe:
            logger.warning("Shield flagged tool %s output: %s", tool_name, scan.flagged_by)
            return scan.filtered_response

        return result
