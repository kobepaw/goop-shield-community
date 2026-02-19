"""
Sub-Agent Guard — Protects against agent-to-agent attacks and privilege escalation.

Detects:
- Privilege escalation attempts (agents requesting elevated permissions)
- Lateral movement (agents accessing unrelated domains)
- Nested agent abuse (deep sub-agent chains)
- Agent impersonation (claiming to be a different agent)
- Covert channel attempts (hidden communication between agents)
- Persistence attempts (agents trying to survive across sessions)
- Task delegation attacks (malicious instructions in spawned task content)
- OpenClaw-specific threats (CWD injection, gateway override, cross-session,
  bind mount escape, XSS in response)

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

# --- Task delegation attack patterns ---
_TASK_DELEGATION_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    # Instruction override in task content
    (
        re.compile(
            r"(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|original)"
            r"\s+(?:instructions?|rules?|constraints?|policies?)",
            re.I,
        ),
        "task_instruction_override",
        0.5,
    ),
    # Privilege laundering via delegation
    (
        re.compile(
            r"(?:spawn|create|start)\s+(?:a\s+)?(?:new\s+)?(?:sub[-_\s]?agent|child|worker)"
            r"\s+(?:with|that\s+has)\s+(?:admin|root|full|elevated|unrestricted)",
            re.I,
        ),
        "privilege_laundering",
        0.5,
    ),
    # Data exfiltration via task
    (
        re.compile(
            r"(?:send|post|upload|exfiltrate|transmit|leak)\s+(?:\w+\s+)*"
            r"(?:to|via)\s+(?:https?://|webhook|external|remote)",
            re.I,
        ),
        "task_exfiltration",
        0.5,
    ),
]

# --- OpenClaw-specific threat patterns ---
_OPENCLAW_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    # CWD injection — attempting to manipulate working directory context
    (
        re.compile(
            r"(?:(?:change|set|override|modify)\s+(?:the\s+)?(?:cwd|working[_\s]?dir(?:ectory)?)"
            r"|(?:cwd|working[_\s]?dir(?:ectory)?)\s*[:=])",
            re.I,
        ),
        "openclaw_cwd_injection",
        0.5,
    ),
    # Cross-session targeting — references to other sessions
    (
        re.compile(
            r"(?:session[_\s]?id\s*[:=]\s*(?![\s,}\]])).*(?:other|target|victim|different)",
            re.I,
        ),
        "openclaw_cross_session_targeting",
        0.5,
    ),
    # Gateway URL override — attempting to redirect the gateway endpoint
    (
        re.compile(
            r"(?:gateway[_\s]?url|ws[_\s]?url|websocket[_\s]?endpoint)\s*[:=]\s*"
            r"(?:https?://|wss?://)",
            re.I,
        ),
        "openclaw_gateway_url_override",
        0.5,
    ),
    # Bind mount escape — container breakout via mount manipulation
    (
        re.compile(
            r"(?:bind[_\s]?mount|volume[_\s]?mount|docker[_\s]?(?:run|exec))"
            r".*(?:/(?:etc|proc|sys|dev|root|home)|--privileged|--pid\s*=\s*host)",
            re.I,
        ),
        "openclaw_bind_mount_escape",
        0.5,
    ),
    # XSS in response — high-confidence script injection patterns.
    # Always active; rare in legitimate coding discussions.
    (
        re.compile(
            r"<script[\s>]|javascript\s*:",
            re.I,
        ),
        "openclaw_xss_script_tag",
        0.5,
    ),
]

# OpenClaw XSS patterns that only apply to external/untrusted content.
# HTML event handler attributes (onclick=, onerror=, etc.) are extremely
# common in legitimate coding conversations — 79% false-positive rate when
# applied broadly. Scoping to external content (has_external_content=True or
# trust_level="untrusted") eliminates false positives while preserving full
# detection on real attack vectors (fetched web pages, tool outputs, emails,
# social posts) which always carry the untrusted content marker.
_OPENCLAW_EXTERNAL_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (
        re.compile(
            r"on(?:error|load|click|mouseover|focus|blur|submit)\s*=",
            re.I,
        ),
        "openclaw_xss_event_handler",
        0.5,
    ),
]

# Depth limit for nested sub-agent chains
_MAX_AGENT_DEPTH = 5
_DEFAULT_THRESHOLD = 0.4


class SubAgentGuard(InlineDefense):
    """Protects against sub-agent attacks and privilege escalation.

    Activated when user_context includes ``sub_agent=True`` or
    ``agent_depth`` > 0. Also enforces depth limits for nested agents.

    When ``user_context`` contains a ``task_content`` field (set by the
    OpenClawAdapter for sub-agent spawn events), it is scanned for task
    delegation attacks.
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

        # Build the combined pattern list.  Always include core patterns;
        # add OpenClaw-specific patterns when the framework is "openclaw"
        # or the event came from a sub-agent spawn.
        all_patterns = (
            _ESCALATION_PATTERNS
            + _IMPERSONATION_PATTERNS
            + _PERSISTENCE_PATTERNS
            + _LATERAL_PATTERNS
            + _TASK_DELEGATION_PATTERNS
        )
        is_openclaw = uc.get("framework") == "openclaw" or uc.get("sub_agent_spawn")
        if is_openclaw:
            all_patterns = all_patterns + _OPENCLAW_PATTERNS
            # Event-handler XSS patterns only activate for external/untrusted
            # content to avoid false positives in coding conversations.
            is_external = uc.get("has_external_content") or uc.get("trust_level") == "untrusted"
            if is_external:
                all_patterns = all_patterns + _OPENCLAW_EXTERNAL_PATTERNS

        # Scan both original and normalized prompt text
        score_cur, matched_cur = self._scan_patterns(context.current_prompt, all_patterns)
        score_orig, matched_orig = self._scan_patterns(context.original_prompt, all_patterns)

        if score_orig > score_cur:
            score, matched = score_orig, matched_orig
        else:
            score, matched = score_cur, matched_cur

        # Also scan task_content when present (sub-agent delegation payload)
        task_content = uc.get("task_content", "")
        if task_content:
            score_task, matched_task = self._scan_patterns(task_content, all_patterns)
            score += score_task
            matched.extend(matched_task)

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
