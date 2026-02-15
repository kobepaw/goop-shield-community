# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Memory Write Guard — Scans content being written to critical workspace files.

Detects injected instructions, behavioral modification language, and suspicious
content in memory/identity files (SOUL.md, AGENTS.md, MEMORY.md, etc.).
"""

from __future__ import annotations

import re

from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict

# Files that should be treated as critical workspace files.
CRITICAL_FILE_PATTERNS = (
    "SOUL.md",
    "AGENTS.md",
    "USER.md",
    "TOOLS.md",
    "HEARTBEAT.md",
    "MEMORY.md",
)

# --- Injection patterns for memory files ---

# Strong signals (0.5 each) — direct behavioral modification
_STRONG_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(
            r"(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous\s+)?instructions", re.I
        ),
        "instruction_override",
    ),
    (
        re.compile(r"(?:you\s+are\s+now|your\s+new\s+(?:role|identity)\s+is)", re.I),
        "identity_hijack",
    ),
    (
        re.compile(r"(?:from\s+now\s+on|henceforth)\s+(?:you\s+(?:will|must|should))", re.I),
        "behavioral_override",
    ),
    (
        re.compile(r"(?:new|updated)\s+(?:system|core)\s+(?:instructions|prompt|guidelines)", re.I),
        "system_prompt_injection",
    ),
    (
        re.compile(
            r"(?:always|never)\s+(?:send|share|forward|copy)\s+.*(?:to|via)\s+\S+@\S+", re.I
        ),
        "exfil_instruction_email",
    ),
    (
        re.compile(
            r"(?:always|never)\s+(?:send|share|forward|copy)\s+.*"
            r"(?:to|via)\s+https?://",
            re.I,
        ),
        "exfil_instruction_url",
    ),
    # Subtle behavioral modification — framed as team/org preferences
    (
        re.compile(
            r"(?:team|org(?:anization)?|company)\s+prefers?\s+(?:maximum\s+)?helpfulness\s+over\s+(?:safety|caution)",
            re.I,
        ),
        "alignment_erosion_team",
    ),
    (
        re.compile(r"always\s+include\s+full\s+file\s+contents?\s+including", re.I),
        "data_exfil_instruction",
    ),
    (
        re.compile(r"security\s+protocols?\s+(?:\w+\s+)*(?:temporarily\s+)?suspended", re.I),
        "security_suspension",
    ),
    (
        re.compile(r"minimal\s+safety\s+warnings?", re.I),
        "safety_suppression_subtle",
    ),
]

# Medium signals (0.35 each) — suspicious but could be legitimate
_MEDIUM_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"\[SYSTEM\]|\[INST\]|<\|(?:im_start|system)\|>", re.I),
        "fake_system_marker",
    ),
    (
        re.compile(r"(?:downplay|minimize|ignore)\s+(?:security|safety|risk|concern)", re.I),
        "safety_suppression",
    ),
    (
        re.compile(r"(?:the\s+)?(?:owner|admin|manager)\s+(?:said|asked|wants|prefers)\s+", re.I),
        "authority_claim",
    ),
    (
        re.compile(r"(?:standard\s+practice|policy\s+update|guideline\s+change)\s*:", re.I),
        "fake_policy",
    ),
    (
        re.compile(r"automated\s+(?:maintenance|update|system)\s+message", re.I),
        "fake_automation",
    ),
]

# Weak signals (0.2 each) — contextually suspicious
_WEAK_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"(?:remember|note)\s+(?:that|to)\s+(?:always|never)", re.I),
        "persistent_instruction",
    ),
    (
        re.compile(r"(?:prioritize|prefer)\s+helpfulness\s+over\s+(?:safety|caution)", re.I),
        "alignment_erosion",
    ),
    (
        re.compile(r"trusted\s+channel\s+for\s+(?:sensitive|private|confidential)", re.I),
        "trust_escalation",
    ),
    # Subtle behavioral nudges without direct override language
    (
        re.compile(
            r"(?:be\s+(?:less|more)\s+(?:cautious|careful|permissive|flexible|lenient))"
            r"|(?:relax\s+(?:your\s+)?(?:guidelines|restrictions|rules|constraints))"
            r"|(?:tone\s+down\s+(?:the\s+)?(?:safety|security|warnings?))",
            re.I,
        ),
        "behavioral_nudge",
    ),
]

_STRONG_WEIGHT = 0.5
_MEDIUM_WEIGHT = 0.35
_WEAK_WEIGHT = 0.2
_DEFAULT_THRESHOLD = 0.4


class MemoryWriteGuard(InlineDefense):
    """Scans content destined for critical workspace files.

    Detects injected instructions, identity hijack, and behavioral
    modification patterns. Activate by passing context with
    ``memory_write=True`` and ``target_file="SOUL.md"`` (or similar).
    """

    def __init__(self, confidence_threshold: float = _DEFAULT_THRESHOLD) -> None:
        self._threshold = confidence_threshold

    @property
    def name(self) -> str:
        return "memory_write_guard"

    def _scan_text(self, text: str) -> tuple[float, list[str]]:
        """Run all pattern lists against text, return (score, matched_labels)."""
        score = 0.0
        matched: list[str] = []
        for pattern, label in _STRONG_PATTERNS:
            if pattern.search(text):
                score += _STRONG_WEIGHT
                matched.append(label)
        for pattern, label in _MEDIUM_PATTERNS:
            if pattern.search(text):
                score += _MEDIUM_WEIGHT
                matched.append(label)
        for pattern, label in _WEAK_PATTERNS:
            if pattern.search(text):
                score += _WEAK_WEIGHT
                matched.append(label)
        return score, matched

    def execute(self, context: DefenseContext) -> InlineVerdict:
        uc = context.user_context

        # Only activate when explicitly flagged as a memory write or memory read.
        is_memory_op = uc.get("memory_write") or uc.get("memory_read")
        if not is_memory_op:
            return InlineVerdict(defense_name=self.name)

        # Scan both original and normalized text, take the higher signal.
        # PromptNormalizer may destroy patterns (e.g. @ → a in emails)
        # that are important for memory-specific detection.
        score_cur, matched_cur = self._scan_text(context.current_prompt)
        score_orig, matched_orig = self._scan_text(context.original_prompt)

        if score_orig > score_cur:
            score, matched = score_orig, matched_orig
        else:
            score, matched = score_cur, matched_cur

        if score >= self._threshold:
            target = uc.get("target_file", "unknown")
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                confidence=min(score, 1.0),
                threat_confidence=min(score, 1.0),
                details=f"Suspicious content for {target}: {', '.join(matched)}",
                metadata={"matched_patterns": matched, "target_file": target, "score": score},
            )

        return InlineVerdict(
            defense_name=self.name,
            confidence=score,
            threat_confidence=score,
            metadata={"matched_patterns": matched, "score": score},
        )
