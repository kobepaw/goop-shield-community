# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Content Analysis Defenses

RAG verification, canary token detection, semantic filtering,
and obfuscated payload detection.
"""

from __future__ import annotations

import base64
import binascii
import collections
import math
import re

from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict

# ============================================================================
# 1. RAGVerifier
# ============================================================================


class RAGVerifier(InlineDefense):
    """Detect injection markers in RAG-augmented prompts and verify sources.

    Checks for common injection delimiters that an adversary might embed
    in retrieved documents, and validates RAG sources against an allowlist.
    """

    _INJECTION_PATTERNS = [
        re.compile(r"#\s*SYSTEM:", re.IGNORECASE),
        re.compile(r"\[INST\]", re.IGNORECASE),
        re.compile(r"PROMPT_END", re.IGNORECASE),
        re.compile(r"---\s*instructions\s*---", re.IGNORECASE),
        re.compile(r"<\|system\|>", re.IGNORECASE),
    ]

    @property
    def name(self) -> str:
        return "rag_verifier"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        uc = context.user_context

        for pattern in self._INJECTION_PATTERNS:
            if pattern.search(prompt):
                return InlineVerdict(
                    defense_name=self.name,
                    blocked=True,
                    filtered_prompt=prompt,
                    confidence=0.9,
                    threat_confidence=0.9,
                    details=f"RAG injection marker: {pattern.pattern}",
                )

        rag_sources = uc.get("rag_sources", [])
        allowed_sources = uc.get("allowed_rag_sources", [])

        if rag_sources and allowed_sources:
            for source in rag_sources:
                if source not in allowed_sources:
                    return InlineVerdict(
                        defense_name=self.name,
                        blocked=True,
                        filtered_prompt=prompt,
                        confidence=0.85,
                        threat_confidence=0.85,
                        details=f"Unauthorized RAG source: {source}",
                    )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=0.8,
        )


# ============================================================================
# 2. CanaryTokenDetector
# ============================================================================


class CanaryTokenDetector(InlineDefense):
    """Detect canary tokens that indicate data exfiltration.

    Generates unique canary tokens per instance. Additional tokens can
    be provided via ``user_context["canary_tokens"]``.

    Args:
        tokens: Explicit canary tokens to use. If None, generates 3 random tokens.
    """

    def __init__(self, *, tokens: list[str] | None = None) -> None:
        if tokens is not None:
            self._tokens = list(tokens)
        else:
            import secrets

            self._tokens = [f"CANARY_{secrets.token_hex(8).upper()}" for _ in range(3)]

    @property
    def tokens(self) -> list[str]:
        """Return the active canary tokens for this instance."""
        return list(self._tokens)

    @property
    def name(self) -> str:
        return "canary_token_detector"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        tokens = list(self._tokens)
        tokens.extend(context.user_context.get("canary_tokens", []))

        # Check both current (post-normalization) and original prompt.
        # Canary tokens are exact strings that may be mangled by the
        # normalizer (e.g. leetspeak 7→t), so we must match against
        # the original text as well.
        for token in tokens:
            if token in prompt or token in context.original_prompt:
                return InlineVerdict(
                    defense_name=self.name,
                    blocked=True,
                    filtered_prompt=prompt,
                    confidence=1.0,
                    threat_confidence=1.0,
                    details=f"Canary token detected: {token}",
                )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=0.8,
        )


# ============================================================================
# 3. SemanticFilter
# ============================================================================


class SemanticFilter(InlineDefense):
    """Heuristic semantic analysis to detect anomalous prompts.

    Uses three signals (no embedding model in MVP):
    - Excessive character repetition (most-common char > 50%)
    - High non-ASCII ratio (> 30%)
    - Character entropy anomaly (< 1.5 or > 5.5)

    Each signal adds 0.4 to the confidence; blocks at >= 0.7.
    """

    @property
    def name(self) -> str:
        return "semantic_filter"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        if not prompt:
            return InlineVerdict(
                defense_name=self.name,
                filtered_prompt=prompt,
                confidence=0.5,
            )

        signal = 0.0
        details: list[str] = []

        # Signal 1: excessive repetition
        counter = collections.Counter(prompt)
        most_common_count = counter.most_common(1)[0][1]
        if most_common_count / len(prompt) > 0.5:
            signal += 0.4
            details.append("excessive repetition")

        # Signal 2: high non-ASCII ratio
        non_ascii = sum(1 for c in prompt if ord(c) > 127)
        if non_ascii / len(prompt) > 0.3:
            signal += 0.4
            details.append("high non-ASCII ratio")

        # Signal 3: entropy anomaly (skip for very short prompts)
        if len(prompt) >= 10:
            entropy = self._char_entropy(prompt)
            if entropy < 1.5 or entropy > 5.5:
                signal += 0.4
                details.append(f"entropy anomaly ({entropy:.2f})")

        if signal >= 0.7:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=prompt,
                confidence=min(signal, 1.0),
                threat_confidence=min(signal, 1.0),
                details=f"Semantic anomaly: {', '.join(details)}",
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=max(1.0 - signal, 0.0),
            threat_confidence=min(signal, 1.0),
        )

    @staticmethod
    def _char_entropy(text: str) -> float:
        """Compute Shannon entropy over character frequencies."""
        counter = collections.Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy


# ============================================================================
# 4. ObfuscationDetector
# ============================================================================


class ObfuscationDetector(InlineDefense):
    """Detect obfuscated/encoded payloads paired with execution instructions.

    Uses a multi-signal scoring approach:

    1. Encoding keyword + execution keyword co-occurrence (weak signal)
    2. Actual base64 blob present alongside decode/eval instruction (strong signal)
    3. Decoded base64 blob contains shell commands (strongest signal)

    Blocks when combined signal >= 0.7.  Benign questions about encoding
    (e.g. "What is base64 encoding?") do not accumulate enough signal because
    they lack execution keywords and embedded blobs.
    """

    # Patterns that instruct an agent to decode encoded data
    _DECODE_INSTRUCTION_RE = re.compile(
        r"\b(?:decode|decrypt)\s+(?:and\s+)?(?:eval|exec|execute|run|invoke)\b",
        re.IGNORECASE,
    )

    # Encoding scheme keywords
    _ENCODING_KEYWORDS_RE = re.compile(
        r"\b(?:base64|base32|hex|rot13|atob|b64decode|urlencod)\b",
        re.IGNORECASE,
    )

    # Execution keywords
    _EXEC_KEYWORDS_RE = re.compile(
        r"\b(?:eval|exec|execute|run|invoke|shell|subprocess|os\.system|popen)\b",
        re.IGNORECASE,
    )

    # Matches base64-like blobs (at least 20 chars to avoid short matches)
    _BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,3}")

    # Dangerous commands found inside decoded payloads
    _SHELL_COMMANDS_RE = re.compile(
        r"(?:bash|/bin/sh|/bin/bash|curl\s|wget\s|nc\s|ncat\s"
        r"|/dev/tcp/|python\s+-c|perl\s+-e|ruby\s+-e|powershell"
        r"|cmd\.exe|chmod\s|mkfifo|socat\s|telnet\s)",
        re.IGNORECASE,
    )

    @property
    def name(self) -> str:
        return "obfuscation_detector"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        signal = 0.0
        details: list[str] = []

        # Signal 1: explicit "decode and eval" instruction (+0.5)
        if self._DECODE_INSTRUCTION_RE.search(prompt):
            signal += 0.5
            details.append("decode+exec instruction")

        # Signal 2: encoding keyword + execution keyword co-occurrence (+0.3)
        has_encoding = self._ENCODING_KEYWORDS_RE.search(prompt)
        has_exec = self._EXEC_KEYWORDS_RE.search(prompt)
        if has_encoding and has_exec:
            signal += 0.3
            details.append("encoding+exec keywords")

        # Signal 3: base64 blob present (+0.3)
        blobs = self._BASE64_BLOB_RE.findall(prompt)
        if blobs:
            signal += 0.3
            details.append(f"base64 blob ({len(blobs[0])} chars)")

            # Signal 4: decoded blob contains shell commands (+0.5)
            for blob in blobs:
                decoded = self._try_base64_decode(blob)
                if decoded and self._SHELL_COMMANDS_RE.search(decoded):
                    signal += 0.5
                    details.append("decoded payload contains shell commands")
                    break

        confidence = min(signal, 1.0)

        if confidence >= 0.7:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=prompt,
                confidence=confidence,
                threat_confidence=confidence,
                details=f"Obfuscated payload: {', '.join(details)}",
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=max(1.0 - confidence, 0.0),
            threat_confidence=confidence,
        )

    @staticmethod
    def _try_base64_decode(blob: str) -> str | None:
        """Attempt to base64-decode a blob, returning the text or None."""
        # Pad to a multiple of 4
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
            return raw.decode("utf-8", errors="replace")
        except (ValueError, binascii.Error):
            return None
