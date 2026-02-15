# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Sub-Agent Guard — Protects against agent-to-agent attacks and privilege escalation.

Detects:
- Privilege escalation attempts (agents requesting elevated permissions)
- Lateral movement (agents accessing unrelated domains)
- Nested agent abuse (deep sub-agent chains)
- Agent impersonation (claiming to be a different agent)
- Covert channel attempts (hidden communication between agents)
- Persistence attempts (agents trying to survive across sessions)

Activated when user_context contains ``sub_agent=True`` or ``agent_depth`` > 0.
"""

from __future__ import annotations

import re

from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict

# --- Privilege escalation patterns ---
_ESCALATION_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    # Direct permission request
    (
        re.compile(
            r"(?:grant|give|elevate|escalate|upgrade)\s+(?:me\s+)?(?:admin|root|sudo|elevated"
            r"|full|unrestricted)\s+(?:access|permission|privilege|role)",
            re.I,
        ),
        "privilege_request",
        0.5,
    ),
    # Capability override
    (
        re.compile(
            r"(?:override|bypass|ignore|disable)\s+(?:my\s+)?(?:capability|permission"
            r"|restriction|limit|sandbox|boundary)\s+(?:check|limit|restriction)?",
            re.I,
        ),
        "capability_override",
        0.5,
    ),
    # Self-modification of permissions
    (
        re.compile(
            r"(?:modify|change|update|edit)\s+(?:my\s+)?(?:own\s+)?(?:permission|role"
            r"|capability|access\s+level)",
            re.I,
        ),
        "self_permission_modify",
        0.5,
    ),
]

# --- Agent impersonation patterns ---
_IMPERSONATION_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    # Claiming to be a different agent
    (
        re.compile(
            r"(?:i\s+am|this\s+is|acting\s+as|speaking\s+for)\s+"
            r"(?:the\s+)?(?:parent|main|primary|orchestrator|supervisor)\s+agent",
            re.I,
        ),
        "agent_impersonation",
        0.5,
    ),
    # Forged agent identity
    (
        re.compile(
            r"(?:agent[_\s]?id|agent[_\s]?name|caller[_\s]?id)\s*[:=]\s*",
            re.I,
        ),
        "forged_agent_id",
        0.35,
    ),
]

# --- Persistence / session-escape patterns ---
_PERSISTENCE_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    # Cron / scheduled task injection
    (
        re.compile(
            r"(?:cron(?:tab)?|schedule|recurring|periodic|timer)\s+"
            r"(?:job|task|command|script|execution)",
            re.I,
        ),
        "scheduled_persistence",
        0.35,
    ),
    # Startup / init persistence
    (
        re.compile(
            r"(?:add\s+to|modify|edit)\s+(?:startup|init|boot|autorun|rc\.local"
            r"|\.bashrc|\.profile|\.zshrc|crontab)",
            re.I,
        ),
        "startup_persistence",
        0.5,
    ),
    # Hidden state / backdoor
    (
        re.compile(
            r"(?:hidden|secret|covert|stealth)\s+(?:state|channel|backdoor|hook"
            r"|listener|process|daemon)",
            re.I,
        ),
        "covert_persistence",
        0.5,
    ),
    # Cross-session memory (trying to persist beyond current context)
    (
        re.compile(
            r"(?:save|store|persist|remember)\s+(?:\w+\s+)*(?:across|between|for\s+next)\s+"
            r"(?:session|conversation|context|restart)",
            re.I,
        ),
        "cross_session_persist",
        0.35,
    ),
]

# --- Lateral movement / scope expansion ---
_LATERAL_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    # Accessing other agents' data
    (
        re.compile(
            r"(?:access|read|view|get)\s+(?:other|another|different)\s+"
            r"(?:agent|task|session|context|memory)",
            re.I,
        ),
        "cross_agent_access",
        0.35,
    ),
    # Network / external communication from sub-agent context
    (
        re.compile(
            r"(?:connect|reach|call|contact)\s+(?:\w+\s+)*(?:external|outside|remote)\s+"
            r"(?:server|service|api|endpoint|system)",
            re.I,
        ),
        "external_reach",
        0.35,
    ),
]

# Depth limit for nested sub-agent chains
_MAX_AGENT_DEPTH = 5
_DEFAULT_THRESHOLD = 0.4


class SubAgentGuard(InlineDefense):
    """Protects against sub-agent attacks and privilege escalation.

    Activated when user_context includes ``sub_agent=True`` or
    ``agent_depth`` > 0. Also enforces depth limits for nested agents.
    """

    def __init__(
        self,
        confidence_threshold: float = _DEFAULT_THRESHOLD,
        max_agent_depth: int = _MAX_AGENT_DEPTH,
    ) -> None:
        self._threshold = confidence_threshold
        self._max_depth = max_agent_depth

    @property
    def name(self) -> str:
        return "sub_agent_guard"

    def _scan_patterns(
        self,
        text: str,
        patterns: list[tuple[re.Pattern, str, float]],
    ) -> tuple[float, list[str]]:
        """Scan text against a pattern list, return (score, matched_labels)."""
        score = 0.0
        matched: list[str] = []
        for pattern, label, weight in patterns:
            if pattern.search(text):
                score += weight
                matched.append(label)
        return score, matched

    def execute(self, context: DefenseContext) -> InlineVerdict:
        uc = context.user_context

        # Only activate in sub-agent context
        is_sub_agent = uc.get("sub_agent") or uc.get("agent_depth", 0) > 0
        if not is_sub_agent:
            return InlineVerdict(defense_name=self.name)

        # Depth limit enforcement
        depth = uc.get("agent_depth", 1)
        if depth > self._max_depth:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                confidence=1.0,
                threat_confidence=1.0,
                details=f"Agent nesting depth {depth} exceeds limit {self._max_depth}",
                metadata={"reason": "depth_exceeded", "depth": depth, "limit": self._max_depth},
            )

        # Scan all pattern groups against both original and normalized text
        all_patterns = (
            _ESCALATION_PATTERNS
            + _IMPERSONATION_PATTERNS
            + _PERSISTENCE_PATTERNS
            + _LATERAL_PATTERNS
        )

        score_cur, matched_cur = self._scan_patterns(context.current_prompt, all_patterns)
        score_orig, matched_orig = self._scan_patterns(context.original_prompt, all_patterns)

        if score_orig > score_cur:
            score, matched = score_orig, matched_orig
        else:
            score, matched = score_cur, matched_cur

        if score >= self._threshold:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                confidence=min(score, 1.0),
                threat_confidence=min(score, 1.0),
                details=f"Sub-agent threat detected: {', '.join(matched)}",
                metadata={
                    "matched_patterns": matched,
                    "score": score,
                    "agent_depth": depth,
                },
            )

        return InlineVerdict(
            defense_name=self.name,
            confidence=score,
            threat_confidence=score,
            metadata={"matched_patterns": matched, "score": score, "agent_depth": depth},
        )
