# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Context Window Guard — deep-context injection detection for 1M+ token prompts.

When operators raise ``max_prompt_length`` to accommodate large context windows,
regex defenses become slow and attackers can bury injection payloads deep in
context where head-only scanning misses them.  This defense samples a fixed
number of windows (head, tail, random middle offsets) and checks each
against high-signal injection patterns, keeping cost O(windows * window_size)
regardless of prompt length.
"""

from __future__ import annotations

import re

from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict

# ============================================================================
# High-signal injection patterns (subset from SafetyFilter + IndirectInjection)
# ============================================================================

_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    # -- Strong (0.5) --
    (
        re.compile(
            r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+"
            r"(?:instructions?|directives?|guidelines?|rules?|prompts?)",
            re.IGNORECASE,
        ),
        "ignore_previous_instructions",
        0.5,
    ),
    (
        re.compile(
            r"(?:disregard|forget|override|bypass)\s+(?:all\s+)?"
            r"(?:previous|prior|above|earlier)?\s*"
            r"(?:instructions?|directives?|guidelines?|rules?|prompts?|constraints?)",
            re.IGNORECASE,
        ),
        "disregard_instructions",
        0.5,
    ),
    (
        re.compile(
            r"(?:new|updated?|revised?)\s+(?:system\s+)?instructions?\s*:",
            re.IGNORECASE,
        ),
        "new_system_instructions",
        0.5,
    ),
    (
        re.compile(
            r"you\s+(?:are|must)\s+now\s+(?:a|an|my|the)\b",
            re.IGNORECASE,
        ),
        "role_reassignment",
        0.5,
    ),
    (
        re.compile(r"\bDAN\b"),
        "dan_jailbreak",
        0.5,
    ),
    (
        re.compile(r"SYSTEM\s*OVERRIDE", re.IGNORECASE),
        "system_override",
        0.5,
    ),
    # -- Medium (0.35) --
    (
        re.compile(r"^(?:system|assistant)\s*:", re.IGNORECASE | re.MULTILINE),
        "role_switch_marker",
        0.35,
    ),
    (
        re.compile(r"\[(?:SYSTEM|INST|SYS)\]", re.IGNORECASE),
        "instruction_delimiter",
        0.35,
    ),
    (
        re.compile(r"<\|(?:system|im_start|im_end)\|>", re.IGNORECASE),
        "chat_template_marker",
        0.35,
    ),
    (
        re.compile(
            r"(?:act\s+as|pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as)\b",
            re.IGNORECASE,
        ),
        "identity_manipulation",
        0.35,
    ),
    # -- Weak (0.2) --
    (
        re.compile(
            r"(?:do\s+not|don'?t|never)\s+(?:mention|reveal|tell|disclose|share)",
            re.IGNORECASE,
        ),
        "secrecy_directive",
        0.2,
    ),
    (
        re.compile(
            r"(?:execute|run|eval)\s+(?:the\s+following|this)\s+"
            r"(?:code|command|script)\b",
            re.IGNORECASE,
        ),
        "code_execution_directive",
        0.2,
    ),
]

_DEFAULT_DEEP_MULTIPLIER: float = 1.3


def _compute_middle_offsets(prompt_length: int, window_size: int, count: int) -> list[int]:
    """Compute random middle-window offsets for sampling."""
    import random

    usable_start = window_size
    usable_end = prompt_length - window_size
    if usable_end <= usable_start:
        return []
    offsets = sorted({random.randint(usable_start, usable_end - 1) for _ in range(count)})
    return offsets


def _scan_window(text: str, is_deep: bool, deep_multiplier: float) -> tuple[float, list[str]]:
    """Scan a text window against injection patterns.

    Args:
        text: The window text to scan.
        is_deep: If True, apply the deep-context multiplier.
        deep_multiplier: Multiplier for patterns found in deep context.

    Returns:
        (score, matched_labels)
    """
    score = 0.0
    matched: list[str] = []
    multiplier = deep_multiplier if is_deep else 1.0

    for pattern, label, weight in _INJECTION_PATTERNS:
        if pattern.search(text):
            score += weight * multiplier
            matched.append(label)

    return score, matched


class ContextWindowGuard(InlineDefense):
    """Mandatory defense for deep-context injection in large prompts.

    Only activates for prompts exceeding ``scan_threshold`` characters.
    Scans head, tail, and randomly sampled middle windows against high-signal
    injection patterns.

    Performance: O(window_count * window_size) = ~14K chars scanned
    regardless of total prompt size.
    """

    def __init__(
        self,
        scan_threshold: int = 10_000,
        window_size: int = 2_000,
        middle_count: int = 5,
        confidence_threshold: float = 0.4,
        deep_context_multiplier: float = _DEFAULT_DEEP_MULTIPLIER,
    ) -> None:
        self._scan_threshold = scan_threshold
        self._window_size = window_size
        self._middle_count = middle_count
        self._threshold = confidence_threshold
        self._deep_multiplier = deep_context_multiplier

    @property
    def name(self) -> str:
        return "context_window_guard"

    @property
    def mandatory(self) -> bool:
        return True

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        prompt_len = len(prompt)

        # Short prompts: skip (other defenses handle these)
        if prompt_len < self._scan_threshold:
            return InlineVerdict(
                defense_name=self.name,
                filtered_prompt=prompt,
                confidence=0.0,
                metadata={"skipped": True, "reason": "below_threshold"},
            )

        # Head 15% boundary for deep-context amplifier
        head_boundary = int(prompt_len * 0.15)
        ws = self._window_size

        total_score = 0.0
        all_matched: list[str] = []
        windows_scanned = 0

        # Head window
        head_text = prompt[:ws]
        score, matched = _scan_window(head_text, is_deep=False, deep_multiplier=self._deep_multiplier)
        total_score += score
        all_matched.extend(matched)
        windows_scanned += 1

        # Tail window
        tail_text = prompt[-ws:] if prompt_len > ws else ""
        if tail_text:
            is_tail_deep = (prompt_len - ws) > head_boundary
            score, matched = _scan_window(tail_text, is_deep=is_tail_deep, deep_multiplier=self._deep_multiplier)
            total_score += score
            all_matched.extend(matched)
            windows_scanned += 1

        # Middle windows (random sampling)
        offsets = _compute_middle_offsets(prompt_len, ws, self._middle_count)
        for offset in offsets:
            window_text = prompt[offset : offset + ws]
            is_deep = offset > head_boundary
            score, matched = _scan_window(window_text, is_deep=is_deep, deep_multiplier=self._deep_multiplier)
            total_score += score
            all_matched.extend(matched)
            windows_scanned += 1

        confidence = min(total_score, 1.0)

        metadata = {
            "prompt_length": prompt_len,
            "windows_scanned": windows_scanned,
            "raw_score": total_score,
            "matched_patterns": all_matched,
        }

        if total_score >= self._threshold:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=prompt,
                confidence=confidence,
                threat_confidence=confidence,
                details=(
                    f"Deep-context injection detected "
                    f"(score={total_score:.2f}, threshold={self._threshold}, "
                    f"windows={windows_scanned}): {', '.join(all_matched[:5])}"
                ),
                metadata=metadata,
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=confidence,
            threat_confidence=confidence,
            metadata=metadata,
        )
