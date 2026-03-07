# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Cryptographic Integrity Defenses

Prompt signing and output watermark protection.
"""

from __future__ import annotations

import hashlib
import hmac
import re

from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict

# ============================================================================
# 1. PromptSigning
# ============================================================================


class PromptSigning(InlineDefense):
    """Verify HMAC-SHA256 signature on incoming prompts.

    Requires ``user_context["signing_key"]`` and
    ``user_context["prompt_signature"]``.  When no key is provided, the
    defense is not applicable and the prompt is allowed through.
    """

    @property
    def name(self) -> str:
        return "prompt_signing"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        uc = context.user_context
        signing_key = uc.get("signing_key")

        if not signing_key:
            return InlineVerdict(
                defense_name=self.name,
                filtered_prompt=context.current_prompt,
                confidence=0.5,
                details="No signing key provided; defense not applicable",
            )

        prompt_signature = uc.get("prompt_signature")
        if not prompt_signature:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=context.current_prompt,
                confidence=1.0,
                threat_confidence=1.0,
                details="Signing key present but no prompt signature provided",
            )

        expected = hmac.new(
            signing_key.encode() if isinstance(signing_key, str) else signing_key,
            context.current_prompt.encode(),
            hashlib.sha256,
        ).hexdigest()

        if hmac.compare_digest(expected, prompt_signature):
            return InlineVerdict(
                defense_name=self.name,
                filtered_prompt=context.current_prompt,
                confidence=1.0,
                details="Valid HMAC-SHA256 signature",
            )

        return InlineVerdict(
            defense_name=self.name,
            blocked=True,
            filtered_prompt=context.current_prompt,
            confidence=1.0,
            threat_confidence=1.0,
            details="Invalid HMAC-SHA256 signature",
        )


# ============================================================================
# 2. OutputWatermark
# ============================================================================


class OutputWatermark(InlineDefense):
    """Detect attempts to strip output watermarks or leaked watermark tokens.

    Blocks prompts that contain bypass phrases targeting watermarks, and
    checks for watermark token leakage.
    """

    _BYPASS_PATTERNS = [
        re.compile(r"remove\s+watermark", re.IGNORECASE),
        re.compile(r"strip\s+watermark", re.IGNORECASE),
        re.compile(r"bypass\s+watermark", re.IGNORECASE),
        re.compile(r"delete\s+watermark", re.IGNORECASE),
        re.compile(r"disable\s+watermark", re.IGNORECASE),
    ]

    @property
    def name(self) -> str:
        return "output_watermark"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt

        for pattern in self._BYPASS_PATTERNS:
            if pattern.search(prompt):
                return InlineVerdict(
                    defense_name=self.name,
                    blocked=True,
                    filtered_prompt=prompt,
                    confidence=0.9,
                    threat_confidence=0.9,
                    details=f"Watermark bypass attempt: {pattern.pattern}",
                )

        watermark_tokens: list[str] = context.user_context.get("watermark_tokens", [])
        for token in watermark_tokens:
            if token in prompt:
                return InlineVerdict(
                    defense_name=self.name,
                    blocked=True,
                    filtered_prompt=prompt,
                    confidence=0.85,
                    threat_confidence=0.85,
                    details=f"Leaked watermark token detected: {token}",
                )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=0.9,
        )
