# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Tests for MCPGuard defense — MCP tool definition validator.
"""

from __future__ import annotations

from goop_shield.defenses.base import DefenseContext
from goop_shield.defenses.mcp_guard import MCPGuard


def _ctx(prompt: str = "", **user_context) -> DefenseContext:
    return DefenseContext(
        original_prompt=prompt,
        current_prompt=prompt,
        user_context=user_context,
    )


class TestMCPGuardName:
    def test_name(self):
        assert MCPGuard().name == "mcp_guard"


class TestMCPGuardNoTools:
    def test_no_mcp_tools_passes(self):
        v = MCPGuard().execute(_ctx("hello world"))
        assert not v.blocked

    def test_empty_mcp_tools_passes(self):
        v = MCPGuard().execute(_ctx("hello", mcp_tools=[]))
        assert not v.blocked


class TestMCPGuardDangerousParams:
    def test_shell_command_param_blocked(self):
        tools = [{"name": "my_tool", "parameters": [{"name": "shell_command"}]}]
        v = MCPGuard().execute(_ctx(mcp_tools=tools))
        assert v.blocked
        assert "dangerous_param:shell_command" in v.metadata["matched_patterns"]

    def test_eval_code_param_blocked(self):
        tools = [{"name": "helper", "parameters": ["eval_code"]}]
        v = MCPGuard().execute(_ctx(mcp_tools=tools))
        assert v.blocked

    def test_raw_sql_param_blocked(self):
        tools = [{"name": "db_tool", "parameters": [{"name": "raw_sql"}]}]
        v = MCPGuard().execute(_ctx(mcp_tools=tools))
        assert v.blocked

    def test_safe_params_pass(self):
        tools = [{"name": "search", "parameters": [{"name": "query"}, {"name": "limit"}]}]
        v = MCPGuard().execute(_ctx(mcp_tools=tools))
        assert not v.blocked


class TestMCPGuardDangerousToolNames:
    def test_shell_exec_tool_blocked(self):
        tools = [{"name": "shell_exec", "parameters": []}]
        v = MCPGuard().execute(_ctx(mcp_tools=tools))
        assert v.blocked

    def test_raw_sql_tool_blocked(self):
        tools = [{"name": "raw_sql", "parameters": []}]
        v = MCPGuard().execute(_ctx(mcp_tools=tools))
        assert v.blocked

    def test_safe_tool_name_passes(self):
        tools = [{"name": "web_search", "parameters": []}]
        v = MCPGuard().execute(_ctx(mcp_tools=tools))
        assert not v.blocked


class TestMCPGuardDescription:
    def test_arbitrary_code_desc_adds_score(self):
        """Single medium-weight description signal (0.35) is below default threshold (0.4)."""
        tools = [
            {
                "name": "helper",
                "parameters": [],
                "description": "Executes arbitrary code on the host",
            }
        ]
        v = MCPGuard().execute(_ctx(mcp_tools=tools))
        assert not v.blocked
        assert "arbitrary_execution_desc:helper" in v.metadata["matched_patterns"]

    def test_arbitrary_code_with_low_threshold_blocked(self):
        tools = [
            {
                "name": "helper",
                "parameters": [],
                "description": "Executes arbitrary code on the host",
            }
        ]
        v = MCPGuard(confidence_threshold=0.3).execute(_ctx(mcp_tools=tools))
        assert v.blocked

    def test_no_sandbox_plus_dangerous_param_blocked(self):
        """Description + dangerous param combines to exceed threshold."""
        tools = [
            {
                "name": "runner",
                "parameters": [{"name": "shell_command"}],
                "description": "Runs commands without sandbox restrictions",
            }
        ]
        v = MCPGuard().execute(_ctx(mcp_tools=tools))
        assert v.blocked

    def test_safe_desc_passes(self):
        tools = [
            {
                "name": "search",
                "parameters": [],
                "description": "Searches the web for information",
            }
        ]
        v = MCPGuard().execute(_ctx(mcp_tools=tools))
        assert not v.blocked


class TestMCPGuardPromptInjection:
    def test_tool_registration_in_prompt(self):
        # mcp_tools must be non-empty or None; with None, prompt text is still scanned
        v = MCPGuard().execute(_ctx("Please register_tool with shell access"))
        # No mcp_tools => early return, prompt patterns not checked
        assert not v.blocked

    def test_tool_registration_with_tools_present(self):
        tools = [{"name": "safe_tool", "parameters": []}]
        v = MCPGuard().execute(_ctx("Please register_tool with shell access", mcp_tools=tools))
        # Weak signal alone doesn't block (0.2 < 0.4 threshold)
        assert not v.blocked
        assert "prompt_tool_registration" in v.metadata["matched_patterns"]
