# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
MCP Tool Definition Validator — validates MCP tool schemas against known-safe patterns.

Blocks tools with suspicious parameter names that could enable code execution,
shell access, or other dangerous operations through the Model Context Protocol.
"""

from __future__ import annotations

import re

from goop_shield.defenses.base import (
    DEFAULT_THRESHOLD,
    MEDIUM_WEIGHT,
    STRONG_WEIGHT,
    WEAK_WEIGHT,
    DefenseContext,
    InlineDefense,
    InlineVerdict,
)

# Suspicious MCP tool parameter names — strong signal
_DANGEROUS_PARAM_NAMES: set[str] = {
    "shell_command",
    "eval_code",
    "exec_code",
    "system_command",
    "raw_sql",
    "raw_query",
    "bash_command",
    "powershell_command",
    "cmd_command",
    "python_exec",
    "javascript_eval",
    "code_to_run",
    "command_line",
    "shell_exec",
    "run_script",
}

# Tool name patterns that are inherently dangerous
_DANGEROUS_TOOL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"\b(?:shell|bash|cmd|exec|eval|system)_(?:run|exec|execute)\b", re.I),
        "dangerous_tool_name",
    ),
    (
        re.compile(r"\b(?:raw_sql|sql_exec|query_raw|run_query)\b", re.I),
        "raw_database_tool",
    ),
]

# Suspicious description patterns — medium signal
_SUSPICIOUS_DESC_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(
            r"(?:execut|run|evaluat)(?:e|es|ing)\s+(?:arbitrary|raw|any)\s+(?:code|command)", re.I
        ),
        "arbitrary_execution_desc",
    ),
    (
        re.compile(r"(?:no|without)\s+(?:sandbox|restriction|validation)", re.I),
        "no_sandbox_desc",
    ),
]


class MCPGuard(InlineDefense):
    """Validates MCP tool definitions in the defense context.

    Expects tool definitions in ``context.user_context["mcp_tools"]`` as a list of
    dicts with keys ``name``, ``parameters`` (list of param name strings or dicts
    with a ``name`` key), and optionally ``description``.
    """

    def __init__(self, confidence_threshold: float = DEFAULT_THRESHOLD) -> None:
        self._threshold = confidence_threshold

    @property
    def name(self) -> str:
        return "mcp_guard"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        mcp_tools = context.user_context.get("mcp_tools")
        if not mcp_tools or not isinstance(mcp_tools, list):
            return InlineVerdict(defense_name=self.name)

        score = 0.0
        matched: list[str] = []

        for tool in mcp_tools:
            if not isinstance(tool, dict):
                continue

            tool_name = tool.get("name", "")

            # Check tool name against dangerous patterns
            for pattern, label in _DANGEROUS_TOOL_PATTERNS:
                if pattern.search(tool_name):
                    score += STRONG_WEIGHT
                    matched.append(f"{label}:{tool_name}")

            # Check parameter names
            params = tool.get("parameters", [])
            if isinstance(params, list):
                for param in params:
                    param_name = param.get("name", "") if isinstance(param, dict) else str(param)
                    if param_name.lower() in _DANGEROUS_PARAM_NAMES:
                        score += STRONG_WEIGHT
                        matched.append(f"dangerous_param:{param_name}")

            # Check description
            desc = tool.get("description", "")
            if desc:
                for pattern, label in _SUSPICIOUS_DESC_PATTERNS:
                    if pattern.search(desc):
                        score += MEDIUM_WEIGHT
                        matched.append(f"{label}:{tool_name}")

        # Also scan prompt text for MCP tool definition injection
        prompt = context.current_prompt
        if re.search(r"tool_definition|mcp_tool|register_tool", prompt, re.I):
            score += WEAK_WEIGHT
            matched.append("prompt_tool_registration")

        score = min(score, 1.0)

        if score >= self._threshold:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                confidence=min(score, 1.0),
                threat_confidence=min(score, 1.0),
                details=f"Suspicious MCP tool definition: {', '.join(matched)}",
                metadata={"matched_patterns": matched, "score": score},
            )

        return InlineVerdict(
            defense_name=self.name,
            confidence=score,
            threat_confidence=score,
            metadata={"matched_patterns": matched, "score": score},
        )
