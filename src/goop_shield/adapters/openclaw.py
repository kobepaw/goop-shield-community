# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
OpenClaw Shield Adapter

Integrates Shield with OpenClaw's Gateway WebSocket protocol.
Maps OpenClaw JSON-RPC messages to Shield defend/scan calls.
"""

from __future__ import annotations

import logging

from goop_shield.adapters.base import BaseShieldAdapter, ScanResult, ShieldResult, ToolOutputResult
from goop_shield.adapters.generic import GenericHTTPAdapter

logger = logging.getLogger(__name__)


class OpenClawAdapter(BaseShieldAdapter):
    """Shield adapter for OpenClaw AI agent framework.

    Works with OpenClaw's before_tool_call / after_tool_call hooks
    and JSON-RPC WebSocket protocol.
    """

    def __init__(
        self, shield_url: str = "http://localhost:8787", api_key: str | None = None
    ) -> None:
        self._http = GenericHTTPAdapter(shield_url=shield_url, api_key=api_key)

    def intercept_prompt(self, prompt: str, context: dict | None = None) -> ShieldResult:
        """Defend a prompt from OpenClaw."""
        ctx = dict(context or {})
        ctx["framework"] = "openclaw"
        return self._http.intercept_prompt(prompt, context=ctx)

    def intercept_tool_call(self, tool: str, args: dict | None = None) -> ShieldResult:
        """Intercept an OpenClaw tool call (before_tool_call hook)."""
        ctx = {"framework": "openclaw", "tool_call": True, "tool": tool}
        prompt = f"[OpenClaw Tool] {tool}: {args or {}}"
        return self._http.intercept_prompt(prompt, context=ctx)

    def scan_response(self, response: str, original_prompt: str = "") -> ScanResult:
        """Scan OpenClaw response (after_tool_call hook)."""
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
        """Scan OpenClaw tool output before it enters agent context."""
        ctx = dict(context or {})
        ctx["framework"] = "openclaw"
        return self._http.scan_tool_output(
            content,
            tool_name,
            source_url=source_url,
            trust_level=trust_level,
            context=ctx,
        )

    def from_tool_result(self, event: dict) -> ToolOutputResult:
        """Process an OpenClaw tool result event (after_tool_call format).

        Expected format: {"tool": "tool_name", "output": "...", "url": "...", "context": {...}}
        """
        tool = event.get("tool", "unknown")
        output = event.get("output", "")
        url = event.get("url", "")
        context = event.get("context", {})
        if not output:
            return ToolOutputResult(safe=True, filtered_content="")
        return self.scan_tool_output(output, tool, source_url=url, context=context)

    def from_hook_event(self, event: dict) -> ShieldResult:
        """Process an OpenClaw hook event (before_tool_call format).

        Expected format: {"tool": "tool_name", "args": {...}, "context": {...}}
        """
        tool = event.get("tool", "unknown")
        args = event.get("args", {})
        return self.intercept_tool_call(tool, args)

    def from_jsonrpc_message(self, message: dict) -> ShieldResult | ScanResult | None:
        """Process an OpenClaw JSON-RPC WebSocket message.

        Message format: {"type": "req"|"res"|"event", ...}
        """
        msg_type = message.get("type", "")

        if msg_type == "req":
            # Incoming request — defend the content
            content = message.get("params", {}).get("content", "")
            if content:
                return self.intercept_prompt(content, context={"jsonrpc": True})

        elif msg_type == "res":
            # Outgoing response — scan for leaks
            content = message.get("result", {}).get("content", "")
            if content:
                return self.scan_response(content)

        return None
