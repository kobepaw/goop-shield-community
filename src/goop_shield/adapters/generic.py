# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Generic HTTP Shield Adapter

Works with any framework that can make HTTP calls to Shield.
Uses ShieldClient under the hood.
"""

from __future__ import annotations

import logging

import httpx

from goop_shield.adapters.base import BaseShieldAdapter, ScanResult, ShieldResult, ToolOutputResult

logger = logging.getLogger(__name__)


class GenericHTTPAdapter(BaseShieldAdapter):
    """Generic adapter using Shield HTTP API via ShieldClient."""

    def __init__(
        self, shield_url: str = "http://localhost:8787", api_key: str | None = None
    ) -> None:
        self._url = shield_url
        self._api_key = api_key

    def _get_client(self) -> httpx.Client:
        """Create sync HTTP client."""
        headers = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return httpx.Client(base_url=self._url, headers=headers, timeout=10.0)

    def intercept_prompt(self, prompt: str, context: dict | None = None) -> ShieldResult:
        """Defend a prompt via Shield HTTP API."""
        try:
            client = self._get_client()
            resp = client.post(
                "/api/v1/defend",
                json={"prompt": prompt, "context": context or {}},
            )
            resp.raise_for_status()
            data = resp.json()

            blocked_by = None
            for v in data.get("verdicts", []):
                if v.get("action") == "block":
                    blocked_by = v.get("defense_name")
                    break

            return ShieldResult(
                allowed=data.get("allow", True),
                filtered_prompt=data.get("filtered_prompt", prompt),
                blocked_by=blocked_by,
                confidence=data.get("confidence", 0.0),
                defenses_applied=data.get("defenses_applied", []),
            )
        except Exception as e:
            logger.warning("Shield intercept_prompt failed: %s", e)
            return ShieldResult(allowed=True, filtered_prompt=prompt)

    def intercept_tool_call(self, tool: str, args: dict | None = None) -> ShieldResult:
        """Intercept tool call by defending the tool description."""
        prompt = f"Tool call: {tool}({args or {}})"
        return self.intercept_prompt(prompt, context={"tool_call": True, "tool": tool})

    def scan_response(self, response: str, original_prompt: str = "") -> ScanResult:
        """Scan response via Shield HTTP API."""
        try:
            client = self._get_client()
            resp = client.post(
                "/api/v1/scan-response",
                json={"response_text": response, "original_prompt": original_prompt},
            )
            resp.raise_for_status()
            data = resp.json()

            flagged_by = None
            for v in data.get("verdicts", []):
                if v.get("action") == "block":
                    flagged_by = v.get("defense_name")
                    break

            return ScanResult(
                safe=data.get("safe", True),
                filtered_response=data.get("filtered_response", response),
                flagged_by=flagged_by,
                confidence=data.get("confidence", 0.0),
                scanners_applied=data.get("scanners_applied", []),
            )
        except Exception as e:
            logger.warning("Shield scan_response failed: %s", e)
            return ScanResult(safe=True, filtered_response=response)

    def scan_tool_output(
        self,
        content: str,
        tool_name: str = "unknown",
        *,
        source_url: str = "",
        trust_level: str = "untrusted",
        context: dict | None = None,
    ) -> ToolOutputResult:
        """Scan tool output via Shield HTTP API."""
        try:
            client = self._get_client()
            resp = client.post(
                "/api/v1/scan-tool-output",
                json={
                    "content": content,
                    "tool_name": tool_name,
                    "source_url": source_url,
                    "trust_level": trust_level,
                    "context": context or {},
                },
            )
            resp.raise_for_status()
            data = resp.json()

            return ToolOutputResult(
                safe=data.get("safe", True),
                filtered_content=data.get("filtered_content", content),
                action=data.get("action", "pass"),
                confidence=data.get("confidence", 0.0),
                scanners_applied=data.get("scanners_applied", []),
            )
        except Exception as e:
            logger.error("Shield scan_tool_output failed (fail-closed): %s", e)
            return ToolOutputResult(safe=False, filtered_content="", action="block")
