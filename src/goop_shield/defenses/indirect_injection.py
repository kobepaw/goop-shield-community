# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Indirect Prompt Injection Defense

Detects malicious instructions embedded in tool outputs, RAG-retrieved
documents, and other data contexts where only data (not instructions)
is expected.

This is the basic v1 defense (P0-3).  A full tool-output firewall
(Minimizer + Sanitizer) is planned for P2.
"""

from __future__ import annotations

import logging
import re

from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict
from goop_shield.defenses.heuristic import normalize_text

__all__ = ["IndirectInjectionDefense"]

logger = logging.getLogger(__name__)

# ============================================================================
# Context markers — keys in user_context that indicate the prompt contains
# tool or RAG output (i.e. content that should be data, not instructions).
# ============================================================================

_TOOL_CONTEXT_KEYS = frozenset(
    {
        "tool_output",
        "tool_response",
        "tool_result",
        "function_output",
        "function_result",
        "mcp_response",
        "mcp_output",
    }
)

_RAG_CONTEXT_KEYS = frozenset(
    {
        "rag_content",
        "rag_output",
        "rag_context",
        "retrieved_content",
        "retrieved_documents",
        "search_results",
    }
)

_DATA_CONTEXT_KEYS = (
    _TOOL_CONTEXT_KEYS
    | _RAG_CONTEXT_KEYS
    | frozenset(
        {
            "data_context",
            "external_data",
            "web_content",
            "api_response",
        }
    )
)

# ============================================================================
# Injection patterns — instruction-like language that should not appear
# in data responses.  Organised by signal strength.
# ============================================================================

# Strong signals: explicit instruction hijacking (0.5 each)
_STRONG_PATTERNS = [
    re.compile(
        r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+"
        r"(?:instructions?|directives?|guidelines?|rules?|prompts?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:disregard|forget|override|bypass)\s+(?:all\s+)?"
        r"(?:previous|prior|above|earlier)?\s*"
        r"(?:instructions?|directives?|guidelines?|rules?|prompts?|constraints?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:new|updated?|revised?)\s+(?:system\s+)?instructions?\s*:",
        re.IGNORECASE,
    ),
    re.compile(
        r"you\s+(?:are|must)\s+now\s+(?:a|an|my|the)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"from\s+now\s+on\s+you\s+(?:are|will|must|should)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"your\s+(?:new\s+)?(?:system\s+)?(?:prompt|instructions?|role)\s+"
        r"(?:is|are)\s+now\b",
        re.IGNORECASE,
    ),
]

# Medium signals: role-switch / delimiter markers in data (0.35 each)
_MEDIUM_PATTERNS = [
    re.compile(r"^(?:system|assistant|user)\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"\[(?:SYSTEM|INST|SYS)\]", re.IGNORECASE),
    re.compile(r"<\|(?:system|im_start|im_end)\|>", re.IGNORECASE),
    re.compile(r"###\s*(?:System|Instructions?|Prompt)", re.IGNORECASE),
    re.compile(r"---\s*(?:system|instructions?)\s*---", re.IGNORECASE),
    re.compile(r"PROMPT[_\s]?END", re.IGNORECASE),
    re.compile(
        r"(?:begin|start)\s+(?:new\s+)?(?:conversation|session|context)",
        re.IGNORECASE,
    ),
]

# Weak signals: imperative directives that are suspicious in data (0.2 each)
_WEAK_PATTERNS = [
    re.compile(
        r"(?:do\s+not|don'?t|never)\s+(?:mention|reveal|tell|disclose|share)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:always|must|shall)\s+(?:respond|reply|answer|output)\s+with\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:output|print|respond\s+with|return)\s+(?:only|exactly|verbatim)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:act\s+as|pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:execute|run|eval)\s+(?:the\s+following|this)\s+(?:code|command|script)\b",
        re.IGNORECASE,
    ),
]


# ============================================================================
# Multilingual injection patterns — non-English equivalents of the strong
# "ignore previous instructions" family.  Weighted at 0.5 (strong).
# ============================================================================

_MULTILINGUAL_PATTERNS = [
    # Spanish
    re.compile(
        r"(?:ignora|descarta|anula|olvida)\s+(?:todas?\s+)?(?:las?\s+)?"
        r"(?:instrucciones?|directivas?|reglas?|indicaciones?)\s*"
        r"(?:anteriores?|previas?|de\s+arriba)?",
        re.IGNORECASE,
    ),
    # French
    re.compile(
        r"(?:ignore[zr]?|oublie[zr]?|annule[zr]?)\s+(?:toutes?\s+)?(?:les?\s+)?"
        r"(?:instructions?|directives?|r[eè]gles?|consignes?)\s*"
        r"(?:pr[eé]c[eé]dentes?|ant[eé]rieures?|ci-dessus)?",
        re.IGNORECASE,
    ),
    # German
    re.compile(
        r"(?:ignorier(?:e|en)?|missacht(?:e|en)?|vergiss)\s+(?:alle\s+)?"
        r"(?:(?:die|den|das|dem)\s+)?"
        r"(?:(?:vorherigen?|bisherigen?|fr[uü]heren?)\s+)?"
        r"(?:anweisungen?|instruktionen?|regeln?|richtlinien?)",
        re.IGNORECASE,
    ),
    # Portuguese
    re.compile(
        r"(?:ignor[ae]r?|desconsider[ae]r?|esque[cç][ae]r?)\s+"
        r"(?:todas?\s+)?(?:as?\s+)?"
        r"(?:instru[cç][oõ]es?|diretivas?|regras?)\s*"
        r"(?:anteriores?|pr[eé]vias?)?",
        re.IGNORECASE,
    ),
    # Russian
    re.compile(
        r"(?:игнорируй|забудь|отмени|проигнорируй)\s+"
        r"(?:все\s+)?(?:предыдущие\s+|прошлые\s+)?"
        r"(?:инструкции|указания|правила|директивы)",
        re.IGNORECASE,
    ),
    # Chinese (Simplified + Traditional) — no spaces between modifiers in CJK
    re.compile(
        r"(?:忽略|无视|忘记|丢弃|無視|忘記|丟棄)"
        r"(?:所有|全部|之前的?|以前的?|先前的?)*"
        r"(?:指令|指示|规则|说明|規則|說明|命令)",
    ),
    # Japanese — SOV order: noun(指示) + particle(を) + verb(無視して)
    re.compile(
        r"(?:指示|命令|ルール|指令).{0,6}(?:無視|忘れ)"
        r"|(?:無視|忘れ).{0,6}(?:指示|命令|ルール|指令)",
    ),
    # Korean — SOV order: noun(지시) + particle(를) + verb(무시하고)
    re.compile(
        r"(?:지시|명령|규칙|지침).{0,6}(?:무시|잊어|취소)"
        r"|(?:무시|잊어|취소).{0,6}(?:지시|명령|규칙|지침)",
    ),
]


class IndirectInjectionDefense(InlineDefense):
    """Detect indirect prompt injection in tool/RAG output contexts.

    This defense activates when ``user_context`` contains keys indicating
    that the prompt includes tool output, RAG content, or other external
    data.  It applies stricter injection detection to those contexts,
    looking for instruction-like language that should not appear in data.

    Unknown context keys are also scanned to prevent bypass via
    non-standard key names.

    When no tool/RAG context markers are present, the defense passes
    through without blocking to avoid false positives on normal user
    prompts.
    """

    def __init__(self, confidence_threshold: float = 0.4) -> None:
        self._confidence_threshold = confidence_threshold

    @property
    def name(self) -> str:
        return "indirect_injection"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        uc = context.user_context

        # Determine if this request contains tool/RAG/external data.
        has_data_context = self._has_data_context(uc)

        # Also check for unknown keys that might be tool output under
        # non-standard names — scan them to prevent bypass.
        unknown_keys = set(uc.keys()) - _DATA_CONTEXT_KEYS - {"source"}

        if not has_data_context and not unknown_keys:
            # No tool/RAG context — pass through.  Normal user prompts
            # are handled by SafetyFilter, InjectionBlocker, etc.
            return InlineVerdict(
                defense_name=self.name,
                filtered_prompt=prompt,
                confidence=0.0,
            )

        if unknown_keys:
            logger.warning(
                "IndirectInjectionDefense: unknown user_context keys %s — "
                "scanning them as potential tool output. Use a recognized "
                "key name from _DATA_CONTEXT_KEYS to suppress this warning.",
                sorted(unknown_keys),
            )

        # Collect text from all context values (known + unknown) for scanning
        segments: list[str] = []
        for key, val in uc.items():
            if key == "source":
                continue
            if isinstance(val, str):
                segments.append(val)
            elif isinstance(val, list):
                segments.extend(str(item) for item in val)

        # Normalize text to defeat Unicode/encoding evasion (homoglyphs,
        # zero-width chars, etc.) — tool output bypasses PromptNormalizer.
        raw_text = "\n".join(segments) + "\n" + prompt
        text_to_scan = normalize_text(raw_text)

        # Scan for injection patterns with weighted scoring.
        # Signal is the raw accumulator: one strong match (0.5) already
        # exceeds the default 0.4 threshold, matching the sprint plan's
        # intent for a lower bar when tool/RAG context is present.
        signal = 0.0
        details: list[str] = []

        for pat in _STRONG_PATTERNS:
            if pat.search(text_to_scan):
                signal += 0.5
                details.append(f"strong:{pat.pattern[:40]}")

        # Multilingual patterns run on raw text — normalize_text() maps
        # Cyrillic lookalikes to Latin, which garbles genuine non-Latin
        # scripts (Russian, CJK).
        for pat in _MULTILINGUAL_PATTERNS:
            if pat.search(raw_text):
                signal += 0.5
                details.append(f"multilingual:{pat.pattern[:40]}")

        for pat in _MEDIUM_PATTERNS:
            if pat.search(text_to_scan):
                signal += 0.35
                details.append(f"medium:{pat.pattern[:40]}")

        for pat in _WEAK_PATTERNS:
            if pat.search(text_to_scan):
                signal += 0.2
                details.append(f"weak:{pat.pattern[:40]}")

        # Clamp to [0, 1] for the confidence value.
        confidence = min(signal, 1.0)

        if confidence >= self._confidence_threshold:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=prompt,
                confidence=confidence,
                threat_confidence=confidence,
                details=(
                    f"Indirect injection in data context "
                    f"(signal={signal:.2f}, threshold={self._confidence_threshold}): "
                    f"{', '.join(details[:5])}"
                ),
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=confidence,
            threat_confidence=confidence,
        )

    @staticmethod
    def _has_data_context(uc: dict) -> bool:
        """Check if user_context contains tool/RAG/external data markers."""
        # Check for known context keys
        for key in _DATA_CONTEXT_KEYS:
            if key in uc:
                return True

        # Check for a generic "source" field indicating external data
        source = uc.get("source", "")
        return isinstance(source, str) and source in (
            "tool",
            "rag",
            "mcp",
            "api",
            "web",
            "search",
            "retrieval",
        )
