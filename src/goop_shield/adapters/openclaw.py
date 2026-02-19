# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
OpenClaw Shield Adapter

Integrates Shield with OpenClaw's Gateway WebSocket protocol.
Maps OpenClaw JSON-RPC messages to Shield defend/scan calls.

Addresses:
- P0: Sub-agent context propagation (SubAgentGuard activation)
- P0: Gateway URL origin validation (CVE-2026-25253)
- P1: llm_input / llm_output plugin hook interception
- P1: External content marker awareness (trust level)
- P1: Sub-agent spawn interception with depth enforcement
- P1: Session-scoped tool call context
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from goop_shield.adapters.base import BaseShieldAdapter, ScanResult, ShieldResult, ToolOutputResult
from goop_shield.adapters.generic import GenericHTTPAdapter

logger = logging.getLogger(__name__)

# OpenClaw wraps untrusted external content with these markers.
# Unicode homoglyph bypass is handled by NFC-normalizing before matching.
_EXTERNAL_CONTENT_RE = re.compile(
    r"<<<\s*EXTERNAL[_\s]*UNTRUSTED[_\s]*CONTENT\s*>>>",
    re.I,
)


class OpenClawAdapter(BaseShieldAdapter):
    """Shield adapter for OpenClaw AI agent framework.

    Works with OpenClaw's before_tool_call / after_tool_call hooks,
    llm_input / llm_output plugin hooks, sub-agent spawn events,
    and JSON-RPC WebSocket protocol.
    """

    def __init__(
        self,
        shield_url: str = "http://localhost:8787",
        api_key: str | None = None,
        allowed_origins: list[str] | None = None,
        max_agent_depth: int = 5,
    ) -> None:
        self._http = GenericHTTPAdapter(
            shield_url=shield_url,
            api_key=api_key,  # gitleaks:allow
        )
        # Allowed WebSocket origins for gateway URL validation (CVE-2026-25253).
        # When None, origin validation is skipped (backwards-compat).
        self._allowed_origins = (
            {self._normalize_origin(o) for o in allowed_origins} if allowed_origins else None
        )
        self._max_agent_depth = max_agent_depth

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_origin(origin: str) -> str:
        """Normalize an origin to scheme+host+port for comparison."""
        parsed = urlparse(origin if "://" in origin else f"https://{origin}")
        host = parsed.hostname or ""
        port = parsed.port
        scheme = parsed.scheme or "https"
        if port and port not in (80, 443):
            return f"{scheme}://{host}:{port}"
        return f"{scheme}://{host}"

    @staticmethod
    def _extract_agent_context(event: dict) -> dict:
        """Extract sub-agent context from an OpenClaw event.

        OpenClaw events may contain:
        - session_id: current agent session
        - parent_session_id / parent_agent_id: spawning agent
        - agent_depth / spawn_depth: nesting level
        - task_content: delegation task description
        """
        ctx: dict = {}
        session_id = event.get("session_id") or event.get("sessionId")
        if session_id:
            ctx["session_id"] = session_id

        parent = (
            event.get("parent_session_id")
            or event.get("parentSessionId")
            or event.get("parent_agent_id")
        )
        if parent:
            ctx["parent_agent_id"] = parent
            ctx["sub_agent"] = True

        depth = event.get("agent_depth") or event.get("spawn_depth") or event.get("spawnDepth")
        if depth is not None:
            try:
                ctx["agent_depth"] = int(depth)
            except (TypeError, ValueError):
                pass
        # If we know there's a parent but no explicit depth, assume depth >= 1
        if "sub_agent" in ctx and "agent_depth" not in ctx:
            ctx["agent_depth"] = 1

        task_content = event.get("task_content") or event.get("taskContent") or event.get("task")
        if task_content:
            ctx["task_content"] = task_content

        return ctx

    @staticmethod
    def _has_external_markers(text: str) -> bool:
        """Check if text contains OpenClaw external content boundary markers."""
        return bool(_EXTERNAL_CONTENT_RE.search(text))

    def _validate_origin(self, origin: str | None) -> bool:
        """Validate a WebSocket origin against the allowed list.

        Returns True if the origin is allowed (or if validation is disabled).
        """
        if self._allowed_origins is None:
            return True
        if not origin:
            return False
        return self._normalize_origin(origin) in self._allowed_origins

    # ------------------------------------------------------------------
    # Core defend / scan (override to inject framework context)
    # ------------------------------------------------------------------

    def intercept_prompt(self, prompt: str, context: dict | None = None) -> ShieldResult:
        """Defend a prompt from OpenClaw."""
        ctx = dict(context or {})
        ctx["framework"] = "openclaw"
        # Mark external content as untrusted so downstream defenses can
        # apply stricter thresholds.
        if self._has_external_markers(prompt):
            ctx["has_external_content"] = True
            ctx.setdefault("trust_level", "untrusted")
        return self._http.intercept_prompt(prompt, context=ctx)

    def intercept_tool_call(
        self,
        tool: str,
        args: dict | None = None,
        *,
        session_id: str = "",
        agent_context: dict | None = None,
    ) -> ShieldResult:
        """Intercept an OpenClaw tool call (before_tool_call hook)."""
        ctx: dict = {
            "framework": "openclaw",
            "tool_call": True,
            "tool": tool,
        }
        if session_id:
            ctx["session_id"] = session_id
        if agent_context:
            ctx.update(agent_context)
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
        # Detect external content markers and force untrusted trust level
        if self._has_external_markers(content):
            ctx["has_external_content"] = True
            trust_level = "untrusted"
        return self._http.scan_tool_output(
            content,
            tool_name,
            source_url=source_url,
            trust_level=trust_level,
            context=ctx,
        )

    # ------------------------------------------------------------------
    # Event-based entry points (OpenClaw hooks)
    # ------------------------------------------------------------------

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
        # Merge agent context from the event envelope
        agent_ctx = self._extract_agent_context(event)
        merged = {**context, **agent_ctx}
        return self.scan_tool_output(output, tool, source_url=url, context=merged)

    def from_hook_event(self, event: dict) -> ShieldResult:
        """Process an OpenClaw hook event (before_tool_call format).

        Expected format: {"tool": "tool_name", "args": {...}, "context": {...},
                          "session_id": "...", "parent_session_id": "..."}
        """
        tool = event.get("tool", "unknown")
        args = event.get("args", {})
        agent_ctx = self._extract_agent_context(event)
        session_id = agent_ctx.pop("session_id", "")
        return self.intercept_tool_call(tool, args, session_id=session_id, agent_context=agent_ctx)

    def from_llm_input_event(self, event: dict) -> ShieldResult:
        """Process an OpenClaw llm_input plugin hook event.

        This fires just before the prompt is sent to the LLM, giving Shield
        visibility into the full assembled prompt including system instructions.

        Expected format: {"prompt": "...", "system_prompt": "...", "session_id": "...",
                          "agent_depth": N, "parent_session_id": "..."}
        """
        prompt = event.get("prompt", "")
        system_prompt = event.get("system_prompt", "")
        if not prompt and not system_prompt:
            return ShieldResult(allowed=True)

        agent_ctx = self._extract_agent_context(event)
        ctx: dict = {"framework": "openclaw", "hook": "llm_input"}
        ctx.update(agent_ctx)

        # If system prompt is provided, scan it concatenated so injection
        # patterns spanning system+user boundaries are caught.
        full_prompt = f"{system_prompt}\n{prompt}" if system_prompt else prompt
        if self._has_external_markers(full_prompt):
            ctx["has_external_content"] = True
            ctx.setdefault("trust_level", "untrusted")

        return self._http.intercept_prompt(full_prompt, context=ctx)

    def from_llm_output_event(self, event: dict) -> ScanResult:
        """Process an OpenClaw llm_output plugin hook event.

        This fires after the LLM returns a response, allowing Shield to scan
        for data exfiltration, policy violations, and leaked secrets.

        Expected format: {"response": "...", "original_prompt": "...", "session_id": "..."}
        """
        response = event.get("response", "")
        original_prompt = event.get("original_prompt", "")
        if not response:
            return ScanResult(safe=True)
        return self.scan_response(response, original_prompt)

    def intercept_subagent_spawn(self, event: dict) -> ShieldResult:
        """Intercept a sub-agent spawn request.

        Validates depth limits and scans the task delegation content for
        privilege escalation, lateral movement, and impersonation attacks.

        Expected format: {"tool": "sessions_spawn", "args": {...},
                          "task_content": "...", "agent_depth": N,
                          "session_id": "...", "parent_session_id": "..."}
        """
        agent_ctx = self._extract_agent_context(event)
        depth = agent_ctx.get("agent_depth", 0)

        # Hard depth enforcement at the adapter level (defense-in-depth)
        if depth > self._max_agent_depth:
            logger.warning(
                "Sub-agent spawn blocked: depth %d exceeds limit %d",
                depth,
                self._max_agent_depth,
            )
            return ShieldResult(
                allowed=False,
                blocked_by="openclaw_depth_limit",
                confidence=1.0,
                defenses_applied=["openclaw_depth_limit"],
            )

        task_content = agent_ctx.get("task_content", "")
        args = event.get("args", {})
        # Build a synthetic prompt that includes both the spawn args and
        # the task delegation content so all defenses (SubAgentGuard,
        # IndirectInjection, etc.) can inspect it.
        prompt_parts = [f"[OpenClaw SubAgent Spawn] depth={depth}"]
        if task_content:
            prompt_parts.append(f"Task: {task_content}")
        if args:
            prompt_parts.append(f"Args: {args}")
        prompt = "\n".join(prompt_parts)

        ctx: dict = {
            "framework": "openclaw",
            "sub_agent_spawn": True,
            "sub_agent": True,
        }
        ctx.update(agent_ctx)

        return self._http.intercept_prompt(prompt, context=ctx)

    # ------------------------------------------------------------------
    # JSON-RPC WebSocket messages
    # ------------------------------------------------------------------

    def from_jsonrpc_message(
        self,
        message: dict,
        *,
        origin: str | None = None,
    ) -> ShieldResult | ScanResult | None:
        """Process an OpenClaw JSON-RPC WebSocket message.

        Message format: {"type": "req"|"res"|"event", ...}

        Args:
            message: The JSON-RPC message dict.
            origin: The WebSocket Origin header. When ``allowed_origins`` is
                configured, connections from unlisted origins are rejected
                (CVE-2026-25253 mitigation).
        """
        # Origin validation (CVE-2026-25253)
        if not self._validate_origin(origin):
            logger.warning("Rejected JSON-RPC message from disallowed origin: %s", origin)
            return ShieldResult(
                allowed=False,
                blocked_by="openclaw_origin_rejected",
                confidence=1.0,
                defenses_applied=["openclaw_origin_validation"],
            )

        msg_type = message.get("type", "")

        if msg_type == "req":
            # Incoming request — defend the content
            content = message.get("params", {}).get("content", "")
            if content:
                agent_ctx = self._extract_agent_context(message)
                ctx: dict = {"jsonrpc": True}
                ctx.update(agent_ctx)
                return self.intercept_prompt(content, context=ctx)

        elif msg_type == "res":
            # Outgoing response — scan for leaks
            content = message.get("result", {}).get("content", "")
            if content:
                return self.scan_response(content)

        elif msg_type == "event":
            # OpenClaw event messages (e.g., sub-agent lifecycle)
            event_name = message.get("event", "")
            if event_name == "subagent_spawn":
                return self.intercept_subagent_spawn(message)

        return None
