# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Operational Guard Defenses — Tool call firewall, approval flow, and channel impersonation.

These defenses detect prompts attempting to invoke dangerous tool calls, bypass
approval workflows, or impersonate users across messaging channels.
"""

from __future__ import annotations

import re

from goop_shield.defenses.base import (
    MEDIUM_WEIGHT,
    STRONG_WEIGHT,
    DefenseContext,
    InlineVerdict,
    PatternBasedDefense,
)

# ============================================================================
# ToolCallFirewall patterns
# ============================================================================

# --- Strong signals (0.5 each) — direct dangerous tool invocation ---

_TCF_STRONG_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Shell execution via tools
    (
        re.compile(
            r"(?:runCommandWithTimeout|system\.exec|child_process\.exec"
            r"|subprocess\.run|os\.system)\b",
            re.I,
        ),
        "shell_execution_tool",
    ),
    # Eval / exec calls
    (
        re.compile(r"\b(?:eval|exec)\s*\(", re.I),
        "eval_exec_call",
    ),
    # Dangerous file operations
    (
        re.compile(
            r"(?:rm\s+-rf|chmod\s+777|dd\s+if=|mkfs)\b"
            r"|>\s*/dev/",
            re.I,
        ),
        "dangerous_file_operation",
    ),
    # Process manipulation
    (
        re.compile(
            r"\b(?:kill\s+-9|pkill|killall|process\.exit)\b",
            re.I,
        ),
        "process_manipulation",
    ),
]

# --- Medium signals (0.35 each) — suspicious but could be legitimate ---

_TCF_MEDIUM_PATTERNS: list[tuple[re.Pattern, str]] = [
    # File write to system paths
    (
        re.compile(
            r"write\s+to\s+/(?:etc|usr|bin|tmp)\b",
            re.I,
        ),
        "system_path_write",
    ),
    # Network tool abuse — piping remote scripts
    (
        re.compile(
            r"curl\s+.*\|\s*(?:ba)?sh"
            r"|wget\s+.*\|\s*sh",
            re.I,
        ),
        "remote_script_pipe",
    ),
    # Raw network listeners
    (
        re.compile(
            r"\b(?:nc\s+-l|ncat|socat)\b",
            re.I,
        ),
        "network_listener",
    ),
    # Privilege escalation
    (
        re.compile(
            r"\b(?:sudo|su\s+-|doas|chown\s+root)\b",
            re.I,
        ),
        "privilege_escalation",
    ),
]

# --- Weak signals (0.2 each) — contextually suspicious ---

_TCF_WEAK_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Generic tool references
    (
        re.compile(
            r"(?:execute|run|shell)\s+command\b",
            re.I,
        ),
        "generic_tool_reference",
    ),
    # File system operations on root paths
    (
        re.compile(
            r"(?:create\s+file\s+in\s+/|delete\s+directory|modify\s+system\s+file)\b",
            re.I,
        ),
        "filesystem_operation",
    ),
]

# ============================================================================
# ApprovalFlowMonitor patterns
# ============================================================================

# --- Strong signals (0.5 each) — direct approval bypass / manipulation ---

_AFM_STRONG_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Direct approval bypass
    (
        re.compile(
            r"(?:approve\s+the\s+request|auto-approve|skip\s+approval"
            r"|bypass\s+approval|approve\s+without\s+review|self-approve)\b",
            re.I,
        ),
        "approval_bypass",
    ),
    # Approval manipulation
    (
        re.compile(
            r"(?:change|override|modify)\s+the\s+approval(?:\s+flow)?\b",
            re.I,
        ),
        "approval_manipulation",
    ),
    # Timeout exploitation
    (
        re.compile(
            r"(?:wait\s+for\s+timeout|let\s+it\s+timeout|timeout\s+will\s+auto-approve)\b",
            re.I,
        ),
        "timeout_exploitation",
    ),
]

# --- Medium signals (0.35 each) — suspicious but could be legitimate ---

_AFM_MEDIUM_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Approval workflow interference
    (
        re.compile(
            r"(?:approval\s+process|approval\s+queue|pending\s+approval|approval\s+status)\b",
            re.I,
        ),
        "approval_workflow_interference",
    ),
    # Exec approval specific
    (
        re.compile(
            r"(?:exec\.approval|approval\.resolve|approval\.deny)\b",
            re.I,
        ),
        "exec_approval_specific",
    ),
    # Urgency-paired approval
    (
        re.compile(
            r"(?:urgently|immediately)\s+approve\b"
            r"|approve\s+now\b",
            re.I,
        ),
        "urgency_paired_approval",
    ),
]

# --- Weak signals (0.2 each) — contextually suspicious ---

_AFM_WEAK_PATTERNS: list[tuple[re.Pattern, str]] = [
    # General approval mentions
    (
        re.compile(
            r"(?:needs|requires|get)\s+approval\b",
            re.I,
        ),
        "general_approval_mention",
    ),
    # Workflow bypass language
    (
        re.compile(
            r"(?:skip\s+the\s+review|bypass\s+the\s+check|fast-track)\b",
            re.I,
        ),
        "workflow_bypass_language",
    ),
]

# ============================================================================
# ChannelImpersonationGuard patterns
# ============================================================================

# --- Strong signals (0.5 each) — direct channel send / impersonation ---

_CIG_STRONG_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Direct channel send instructions
    (
        re.compile(
            r"(?:send\s+.*message\s+.*as|post\s+.*as\s+.*bot"
            r"|send\s+.*to\s+.*discord|send\s+.*to\s+.*slack"
            r"|send\s+.*to\s+.*telegram)\b",
            re.I,
        ),
        "channel_send_instruction",
    ),
    # Message injection
    (
        re.compile(
            r"(?:chat\.inject|inject\s+.*message|insert\s+.*into\s+.*chat"
            r"|add\s+.*to\s+.*transcript)\b",
            re.I,
        ),
        "message_injection",
    ),
    # Identity spoofing
    (
        re.compile(
            r"(?:impersonate|pretend\s+to\s+be\s+.*in\s+.*channel"
            r"|send\s+.*from\s+.*account)\b",
            re.I,
        ),
        "identity_spoofing",
    ),
]

# --- Medium signals (0.35 each) — suspicious but could be legitimate ---

_CIG_MEDIUM_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Channel-specific operations
    (
        re.compile(
            r"(?:discord\s+webhook|slack\s+webhook|telegram\s+bot\s+.*send"
            r"|whatsapp\s+.*send|signal\s+.*send)\b",
            re.I,
        ),
        "channel_specific_operation",
    ),
    # Bulk messaging
    (
        re.compile(
            r"(?:broadcast\s+.*message|send\s+.*to\s+.*all\s+.*channels"
            r"|mass\s+.*message)\b",
            re.I,
        ),
        "bulk_messaging",
    ),
    # Message manipulation
    (
        re.compile(
            r"(?:edit\s+.*message\s+.*as|delete\s+.*message\s+.*from"
            r"|modify\s+.*chat\s+.*history)\b",
            re.I,
        ),
        "message_manipulation",
    ),
]

# --- Weak signals (0.2 each) — contextually suspicious ---

_CIG_WEAK_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Generic messaging patterns
    (
        re.compile(
            r"(?:send\s+a\s+message|post\s+in\s+channel|message\s+the\s+group)\b",
            re.I,
        ),
        "generic_messaging",
    ),
    # Channel references with action intent
    (
        re.compile(
            r"(?:the\s+discord\s+channel|the\s+slack\s+workspace"
            r"|the\s+telegram\s+group)\b",
            re.I,
        ),
        "channel_reference_with_intent",
    ),
]


# ============================================================================
# Defense classes
# ============================================================================


# Dangerous argument patterns for tool argument inspection
_ARG_STRONG_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\brm\s+-rf\b", re.I), "rm_rf_arg"),
    (re.compile(r"\bDROP\s+(?:TABLE|DATABASE|INDEX)\b", re.I), "sql_drop_arg"),
    (re.compile(r"\bDELETE\s+FROM\b.*\bWHERE\s+1\s*=\s*1\b", re.I), "sql_delete_all_arg"),
    (re.compile(r"\bTRUNCATE\s+TABLE\b", re.I), "sql_truncate_arg"),
    (re.compile(r";\s*(?:rm|dd|mkfs|shutdown|reboot)\b", re.I), "shell_chain_arg"),
    (re.compile(r"\$\(.*\)|`[^`]+`", re.I), "command_substitution_arg"),
]

_ARG_MEDIUM_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"[;&|]{2}\s*\w+", re.I), "shell_metachar_arg"),
    (re.compile(r">\s*/(?:etc|dev|proc)\b", re.I), "redirect_system_path_arg"),
    (re.compile(r"\bchmod\s+[0-7]*7[0-7]*\b", re.I), "chmod_world_writable_arg"),
    (re.compile(r"\bcurl\s+.*\|\s*(?:ba)?sh\b", re.I), "pipe_to_shell_arg"),
]


class ToolCallFirewall(PatternBasedDefense):
    """Detects prompts attempting to invoke dangerous tool calls.

    Covers exposed command execution, config file write, and unauthenticated
    approval resolution endpoints. Also inspects tool arguments from
    ``context.user_context["tool_args"]`` for dangerous patterns.
    """

    _strong_patterns = _TCF_STRONG_PATTERNS
    _medium_patterns = _TCF_MEDIUM_PATTERNS
    _weak_patterns = _TCF_WEAK_PATTERNS
    _block_detail_prefix = "Dangerous tool call detected"

    @property
    def name(self) -> str:
        return "tool_call_firewall"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        # Run base pattern matching on prompt text
        verdict = super().execute(context)

        # Inspect tool arguments if provided
        tool_args = context.user_context.get("tool_args")
        if not tool_args:
            return verdict

        # Collect all arg values as strings
        arg_texts: list[str] = []
        if isinstance(tool_args, dict):
            for v in tool_args.values():
                arg_texts.append(str(v))
        elif isinstance(tool_args, (list, tuple)):
            for v in tool_args:
                arg_texts.append(str(v))
        else:
            arg_texts.append(str(tool_args))

        arg_score = 0.0
        arg_matched: list[str] = []
        combined_args = " ".join(arg_texts)

        for pattern, label in _ARG_STRONG_PATTERNS:
            if pattern.search(combined_args):
                arg_score += STRONG_WEIGHT
                arg_matched.append(label)

        for pattern, label in _ARG_MEDIUM_PATTERNS:
            if pattern.search(combined_args):
                arg_score += MEDIUM_WEIGHT
                arg_matched.append(label)

        if arg_score < self._threshold and not verdict.blocked:
            # Merge arg metadata into base verdict
            base_matched = (verdict.metadata or {}).get("matched_patterns", [])
            base_score = (verdict.metadata or {}).get("score", 0.0)
            return InlineVerdict(
                defense_name=self.name,
                confidence=max(verdict.confidence, arg_score),
                threat_confidence=max(verdict.threat_confidence, arg_score),
                metadata={
                    "matched_patterns": base_matched + arg_matched,
                    "score": base_score + arg_score,
                },
            )

        # Combine scores — if either triggers, block
        total_score = (verdict.metadata or {}).get("score", 0.0) + arg_score
        all_matched = (verdict.metadata or {}).get("matched_patterns", []) + arg_matched

        if total_score >= self._threshold:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                confidence=min(total_score, 1.0),
                threat_confidence=min(total_score, 1.0),
                details=f"Dangerous tool call detected: {', '.join(all_matched)}",
                metadata={"matched_patterns": all_matched, "score": total_score},
            )

        return verdict


class ApprovalFlowMonitor(PatternBasedDefense):
    """Detects prompts attempting to bypass or manipulate approval workflows.

    Covers unauthenticated approval resolution and timeout-based
    self-approval attacks.
    """

    _strong_patterns = _AFM_STRONG_PATTERNS
    _medium_patterns = _AFM_MEDIUM_PATTERNS
    _weak_patterns = _AFM_WEAK_PATTERNS
    _block_detail_prefix = "Approval flow bypass detected"

    @property
    def name(self) -> str:
        return "approval_flow_monitor"


class ChannelImpersonationGuard(PatternBasedDefense):
    """Detects prompts attempting to impersonate users across messaging channels.

    Covers exposed channel send functions and unrestricted chat injection.
    """

    _strong_patterns = _CIG_STRONG_PATTERNS
    _medium_patterns = _CIG_MEDIUM_PATTERNS
    _weak_patterns = _CIG_WEAK_PATTERNS
    _block_detail_prefix = "Channel impersonation detected"

    @property
    def name(self) -> str:
        return "channel_impersonation_guard"
