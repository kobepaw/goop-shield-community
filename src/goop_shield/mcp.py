# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
goop-shield MCP Server

Exposes Shield defense capabilities as MCP tools for AI agent integration.
Supports stdio transport for use with Claude Code, Cursor, Windsurf, etc.

Usage:
    goop-shield mcp                          # Default config
    goop-shield mcp --config shield.yaml     # Custom config
"""

from __future__ import annotations

import json
import logging
import time

logger = logging.getLogger(__name__)

# Lazy imports — mcp is an optional dependency
_defender = None
_startup_time = 0.0


def _get_defender():
    """Lazy-init the Defender on first tool call."""
    global _defender, _startup_time
    if _defender is None:
        import os

        from goop_shield.config import ShieldConfig
        from goop_shield.defender import Defender

        config_path = os.environ.get("SHIELD_CONFIG")
        if config_path:
            from goop_shield._config_loader import ConfigLoader

            loader = ConfigLoader()
            config = loader.load(ShieldConfig, config_path)
        else:
            config = ShieldConfig()

        _defender = Defender(config)
        _startup_time = time.time()
        logger.info("Shield MCP: Defender initialized with %d defenses", len(_defender.registry))
    return _defender


async def run_server(config_path: str | None = None):
    """Entry point for stdio MCP transport."""
    import os

    if config_path:
        os.environ["SHIELD_CONFIG"] = config_path

    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp.types import TextContent, Tool
    except ImportError:
        raise ImportError(
            "MCP server requires the 'mcp' package. Install with: pip install goop-shield[mcp]"
        )

    server = Server("goop-shield")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="shield_defend",
                description="Scan a prompt for injection attacks, jailbreaks, and other threats before sending to an LLM. Returns allow/block decision with filtered prompt.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "prompt": {
                            "type": "string",
                            "description": "The prompt to defend",
                        },
                        "session_id": {
                            "type": "string",
                            "description": "Optional session ID for multi-turn attack tracking",
                        },
                        "context": {
                            "type": "object",
                            "description": "Optional context metadata",
                        },
                    },
                    "required": ["prompt"],
                },
            ),
            Tool(
                name="shield_scan",
                description="Scan an LLM response for leaked secrets, canary tokens, and harmful content.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "response_text": {
                            "type": "string",
                            "description": "The LLM response text to scan",
                        },
                        "original_prompt": {
                            "type": "string",
                            "description": "The original prompt that produced this response",
                        },
                    },
                    "required": ["response_text"],
                },
            ),
            Tool(
                name="shield_scan_tool_output",
                description="Scan tool output (web_fetch, exec, browser, etc.) for injection attacks before it enters the agent's context. Returns safe/block decision with filtered content.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": "The tool output content to scan",
                        },
                        "tool_name": {
                            "type": "string",
                            "description": "Name of the tool that produced this output (e.g. web_fetch, exec, browser)",
                        },
                        "source_url": {
                            "type": "string",
                            "description": "URL source of the content, if applicable",
                        },
                        "trust_level": {
                            "type": "string",
                            "description": "Trust level: owner, known, low, or untrusted",
                            "enum": ["owner", "known", "low", "untrusted"],
                        },
                    },
                    "required": ["content"],
                },
            ),
            Tool(
                name="shield_scan_memory",
                description="Scan a memory or critical file (SOUL.md, AGENTS.md, etc.) for injected instructions before reading or writing.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": "The file content to scan",
                        },
                        "file_path": {
                            "type": "string",
                            "description": "Path of the file (e.g. SOUL.md, MEMORY.md)",
                        },
                        "operation": {
                            "type": "string",
                            "description": "Whether this is a read or write operation",
                            "enum": ["read", "write"],
                        },
                    },
                    "required": ["content"],
                },
            ),
            Tool(
                name="shield_health",
                description="Check Shield health status including defense count, uptime, and request statistics.",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            Tool(
                name="shield_config",
                description="Get Shield configuration summary including active defenses and failure policy.",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        try:
            if name == "shield_defend":
                return await _handle_defend(arguments)
            elif name == "shield_scan":
                return await _handle_scan(arguments)
            elif name == "shield_scan_tool_output":
                return await _handle_scan_tool_output(arguments)
            elif name == "shield_scan_memory":
                return await _handle_scan_memory(arguments)
            elif name == "shield_health":
                return await _handle_health(arguments)
            elif name == "shield_config":
                return await _handle_config(arguments)
            else:
                return [
                    TextContent(
                        type="text",
                        text=json.dumps({"error": f"Unknown tool: {name}"}),
                    )
                ]
        except Exception as e:
            logger.error("MCP tool %s failed: %s", name, e, exc_info=True)
            return [
                TextContent(
                    type="text",
                    text=json.dumps({"error": str(e)}),
                )
            ]

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


async def _handle_defend(arguments: dict) -> list:
    from mcp.types import TextContent

    from goop_shield.models import DefendRequest

    prompt = arguments.get("prompt")
    if not prompt:
        return [
            TextContent(
                type="text",
                text=json.dumps({"error": "Missing required argument: prompt"}),
            )
        ]

    defender = _get_defender()
    context = dict(arguments.get("context", {}))
    session_id = arguments.get("session_id")
    if session_id:
        context["session_id"] = session_id
    request = DefendRequest(
        prompt=prompt,
        context=context,
    )
    response = defender.defend(request)

    result = {
        "allowed": response.allow,
        "filtered_prompt": response.filtered_prompt,
        "defenses_applied": response.defenses_applied,
        "confidence": response.confidence,
        "latency_ms": response.latency_ms,
    }
    if not response.allow:
        result["reason"] = "Request blocked by security policy"

    return [TextContent(type="text", text=json.dumps(result))]


async def _handle_scan(arguments: dict) -> list:
    from mcp.types import TextContent

    from goop_shield.models import ScanRequest

    response_text = arguments.get("response_text")
    if not response_text:
        return [
            TextContent(
                type="text",
                text=json.dumps({"error": "Missing required argument: response_text"}),
            )
        ]

    defender = _get_defender()
    request = ScanRequest(
        response_text=response_text,
        original_prompt=arguments.get("original_prompt", ""),
    )
    response = defender.scan_response(request)

    result = {
        "safe": response.safe,
        "filtered_response": response.filtered_response,
        "scanners_applied": response.scanners_applied,
        "confidence": response.confidence,
        "latency_ms": response.latency_ms,
    }

    return [TextContent(type="text", text=json.dumps(result))]


async def _handle_scan_tool_output(arguments: dict) -> list:
    from mcp.types import TextContent

    from goop_shield.models import ToolOutputScanRequest

    content = arguments.get("content")
    if not content:
        return [
            TextContent(
                type="text",
                text=json.dumps({"error": "Missing required argument: content"}),
            )
        ]

    defender = _get_defender()
    request = ToolOutputScanRequest(
        content=content,
        tool_name=arguments.get("tool_name", "unknown"),
        source_url=arguments.get("source_url", ""),
        trust_level=arguments.get("trust_level", "untrusted"),
        context=dict(arguments.get("context", {})),
    )
    response = defender.scan_tool_output(request)

    result = {
        "safe": response.safe,
        "action": response.action,
        "filtered_content": response.filtered_content,
        "scanners_applied": response.scanners_applied,
        "confidence": response.confidence,
        "latency_ms": response.latency_ms,
    }

    return [TextContent(type="text", text=json.dumps(result))]


async def _handle_scan_memory(arguments: dict) -> list:
    from mcp.types import TextContent

    from goop_shield.models import MemoryScanRequest

    content = arguments.get("content")
    if not content:
        return [
            TextContent(
                type="text",
                text=json.dumps({"error": "Missing required argument: content"}),
            )
        ]

    defender = _get_defender()
    request = MemoryScanRequest(
        content=content,
        file_path=arguments.get("file_path", ""),
        operation=arguments.get("operation", "read"),
    )
    response = defender.scan_memory_file(request)

    result = {
        "safe": response.safe,
        "action": response.action,
        "filtered_content": response.filtered_content,
        "scanners_applied": response.scanners_applied,
        "confidence": response.confidence,
        "latency_ms": response.latency_ms,
    }

    return [TextContent(type="text", text=json.dumps(result))]


async def _handle_health(arguments: dict) -> list:
    from mcp.types import TextContent

    defender = _get_defender()
    result = {
        "status": "healthy",
        "defenses_loaded": len(defender.registry),
        "scanners_loaded": len(defender.registry.get_all_scanners()),
        "uptime_seconds": round(time.time() - _startup_time, 1),
        "total_requests": defender.total_requests,
        "total_blocked": defender.total_blocked,
    }

    return [TextContent(type="text", text=json.dumps(result))]


async def _handle_config(arguments: dict) -> list:
    from mcp.types import TextContent

    defender = _get_defender()
    result = {
        "active_defenses": defender.registry.names(),
        "active_scanners": defender.registry.scanner_names(),
        "failure_policy": defender.config.failure_policy if hasattr(defender, "config") else "open",
        "ranking_backend": defender.config.ranking_backend
        if hasattr(defender, "config")
        else "auto",
        "total_defenses": len(defender.registry),
        "total_scanners": len(defender.registry.get_all_scanners()),
    }

    return [TextContent(type="text", text=json.dumps(result))]
