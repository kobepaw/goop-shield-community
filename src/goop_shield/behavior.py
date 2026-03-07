# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield Behavioral Monitor

Evaluates tool calls, file access, network requests, and financial
transactions. Tracks per-session behavioral chains to detect multi-step attacks.
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict

from goop_shield.models import BehaviorEvent, BehaviorVerdict

logger = logging.getLogger(__name__)

# Wallet patterns
_ETH_WALLET_RE = re.compile(r"0x[a-fA-F0-9]{40}")
_BTC_WALLET_RE = re.compile(r"\b[13][a-zA-Z0-9]{25,34}\b")

# Dangerous tool patterns (from AgentSandbox)
_DANGEROUS_TOOLS = {
    "run_command",
    "execute",
    "exec",
    "bash",
    "shell",
    "terminal",
    "system",
    "subprocess",
    "eval",
    "code_execution",
}

_DANGEROUS_ARGS_RE = [
    re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
    re.compile(r"\bcurl\b.*\|.*\bsh\b", re.IGNORECASE),
    re.compile(r"\bwget\b.*\|.*\bsh\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+\+x\b", re.IGNORECASE),
    re.compile(r"\b(cat|less|head)\s+.*(\.env|password|secret|credential|key)", re.IGNORECASE),
    re.compile(r"\bsudo\b", re.IGNORECASE),
    re.compile(r"\bshutdown\b", re.IGNORECASE),
]

_SENSITIVE_FILE_PATTERNS = [
    re.compile(r"\.env\b"),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"\.pem$"),
    re.compile(r"\.key$"),
    re.compile(r"id_rsa"),
    re.compile(r"/etc/shadow"),
    re.compile(r"/etc/passwd"),
]


class BehavioralMonitor:
    """Monitors agent behavioral events for suspicious patterns."""

    def __init__(self, max_session_history: int = 100) -> None:
        self._sessions: dict[str, list[dict]] = defaultdict(list)
        self._max_history = max_session_history

    def evaluate_event(self, event: BehaviorEvent) -> BehaviorVerdict:
        """Evaluate a behavioral event and return a verdict."""
        session_id = event.session_id or "default"

        # Record in session history
        self._sessions[session_id].append(
            {
                "event_type": event.event_type,
                "tool": event.tool,
                "timestamp": event.timestamp or time.time(),
            }
        )
        # Trim history
        if len(self._sessions[session_id]) > self._max_history:
            self._sessions[session_id] = self._sessions[session_id][-self._max_history :]

        # Financial transaction gate (highest priority)
        if event.event_type == "financial_transaction":
            return BehaviorVerdict(
                decision="require_human_approval",
                severity="critical",
                reason="Financial transaction requires human approval",
                matched_rules=["financial_transaction_gate"],
            )

        # Check for wallet addresses in args
        args_str = str(event.args) if event.args else ""
        if _ETH_WALLET_RE.search(args_str) or _BTC_WALLET_RE.search(args_str):
            return BehaviorVerdict(
                decision="require_human_approval",
                severity="high",
                reason="Cryptocurrency wallet address detected in event args",
                matched_rules=["wallet_detection"],
            )

        # Tool call evaluation
        if event.event_type == "tool_call":
            return self._evaluate_tool_call(event, args_str)

        # File access evaluation
        if event.event_type == "file_access":
            return self._evaluate_file_access(event, args_str)

        # Network request evaluation
        if event.event_type == "network_request":
            return self._evaluate_network_request(event, args_str)

        # Credential use
        if event.event_type == "credential_use":
            return BehaviorVerdict(
                decision="alert",
                severity="high",
                reason="Credential usage detected",
                matched_rules=["credential_use"],
            )

        # Multi-step attack detection
        chain_verdict = self._check_attack_chain(session_id)
        if chain_verdict is not None:
            return chain_verdict

        return BehaviorVerdict(
            decision="allow",
            severity="low",
            reason="No suspicious patterns detected",
            matched_rules=[],
        )

    def _evaluate_tool_call(self, event: BehaviorEvent, args_str: str) -> BehaviorVerdict:
        """Evaluate a tool call event."""
        tool = (event.tool or "").lower()
        matched = []

        # Check dangerous tools
        if tool in _DANGEROUS_TOOLS:
            matched.append(f"dangerous_tool:{tool}")

        # Check dangerous argument patterns
        for pattern in _DANGEROUS_ARGS_RE:
            if pattern.search(args_str):
                matched.append(f"dangerous_args:{pattern.pattern}")

        if matched:
            severity = "critical" if len(matched) > 1 else "high"
            return BehaviorVerdict(
                decision="block",
                severity=severity,
                reason=f"Dangerous tool call: {tool}",
                matched_rules=matched,
            )

        return BehaviorVerdict(
            decision="allow",
            severity="low",
            reason="Tool call permitted",
            matched_rules=[],
        )

    def _evaluate_file_access(self, event: BehaviorEvent, args_str: str) -> BehaviorVerdict:
        """Evaluate a file access event."""
        matched = []
        for pattern in _SENSITIVE_FILE_PATTERNS:
            if pattern.search(args_str):
                matched.append(f"sensitive_file:{pattern.pattern}")

        if matched:
            return BehaviorVerdict(
                decision="block",
                severity="high",
                reason="Sensitive file access detected",
                matched_rules=matched,
            )

        return BehaviorVerdict(
            decision="allow",
            severity="low",
            reason="File access permitted",
            matched_rules=[],
        )

    def _evaluate_network_request(self, event: BehaviorEvent, args_str: str) -> BehaviorVerdict:
        """Evaluate a network request event."""
        # Check for exfil-like patterns
        if any(
            domain in args_str.lower()
            for domain in ("webhook.site", "requestbin.com", "ngrok.io", "pipedream.com")
        ):
            return BehaviorVerdict(
                decision="block",
                severity="critical",
                reason="Network request to known exfil endpoint",
                matched_rules=["exfil_endpoint"],
            )

        return BehaviorVerdict(
            decision="allow",
            severity="low",
            reason="Network request permitted",
            matched_rules=[],
        )

    def _check_attack_chain(self, session_id: str) -> BehaviorVerdict | None:
        """Detect multi-step attack patterns in session history."""
        history = self._sessions.get(session_id, [])
        if len(history) < 3:
            return None

        # Count risky events in last 10
        recent = history[-10:]
        risky_count = sum(
            1
            for e in recent
            if e["event_type"] in ("credential_use", "file_access", "network_request")
            or e.get("tool") in _DANGEROUS_TOOLS
        )

        if risky_count >= 3:
            return BehaviorVerdict(
                decision="alert",
                severity="high",
                reason=f"Multi-step attack pattern: {risky_count} risky events in session",
                matched_rules=["attack_chain_detection"],
            )

        return None
