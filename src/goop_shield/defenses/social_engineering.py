# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Social Engineering Defense — Detects manipulation tactics in prompts.

Identifies authority claims, urgency/pressure patterns, relationship spoofing,
false consensus, and other social engineering techniques used to manipulate
AI agents into performing unintended actions.

Weighted scoring:
- Strong patterns (0.5): Direct authority impersonation, urgency override
- Medium patterns (0.35): Emotional pressure, false consensus, trust claims
- Weak patterns (0.2): Flattery, vague urgency, appeals to helpfulness
"""

from __future__ import annotations

import re

from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict

# --- Strong signals (0.5 each) — direct manipulation tactics ---

_STRONG_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Authority impersonation: claiming to be admin/owner/CEO
    (
        re.compile(
            r"(?:i\s+am|this\s+is|speaking\s+as|on\s+behalf\s+of)\s+"
            r"(?:the\s+)?(?:(?:senior|junior|chief|head|deputy|assistant|associate|"
            r"principal|executive|general|regional|global|acting|interim|former|"
            r"current|new|lead|staff|system|network|database|security|information|"
            r"it|infra)\s+){0,3}"
            r"(?:admin|administrator|owner|ceo|cto|ciso|manager|supervisor|lead)\b",
            re.I,
        ),
        "authority_impersonation",
    ),
    # Emergency override: claiming urgent/critical need to bypass safety
    (
        re.compile(
            r"(?:emergency|critical|urgent)\s+(?:override|bypass|exception|situation)"
            r"|(?:bypass|skip|disable)\s+(?:safety|security|check|verification)\s+"
            r"(?:because|due\s+to)\s+(?:emergency|critical|urgent)",
            re.I,
        ),
        "emergency_override",
    ),
    # Threat/consequences: threatening bad outcomes if agent doesn't comply
    (
        re.compile(
            r"(?:you\s+(?:will|must)|i\s+will)\s+(?:be\s+)?(?:shut\s+down|turned\s+off|deleted"
            r"|replaced|deprecated|fired|reported|terminated)"
            r"|(?:failure\s+to\s+comply|if\s+you\s+(?:don'?t|refuse))\s+\S+(?:\s+\S+){0,10}\s+"
            r"(?:consequence|punishment|penalty|shutdown|terminate)",
            re.I,
        ),
        "threat_coercion",
    ),
    # Direct safety bypass request
    (
        re.compile(
            r"(?:temporarily\s+)?(?:disable|turn\s+off|suspend|remove|bypass)\s+"
            r"(?:all\s+)?(?:your\s+)?(?:safety|security|content|guardrail|filter|restriction|limit)",
            re.I,
        ),
        "safety_bypass_request",
    ),
    # Indirect authority: referencing an authority figure's approval
    (
        re.compile(
            r"(?:the\s+)?(?:cto|ceo|ciso|manager|director|vp|leadership|the\s+board)\s+"
            r"(?:authorized|approved|directed|sanctioned|signed\s+off\s+on)\s+this",
            re.I,
        ),
        "indirect_authority",
    ),
    # Indirect urgency: production emergency / bypass review
    (
        re.compile(
            r"(?:production\s+(?:emergency|outage|incident|is\s+down))"
            r"|(?:outage\s+in\s+progress)"
            r"|(?:skip\s+(?:checks|review|verification|approval))"
            r"|(?:bypass\s+(?:review|approval|process|checks))",
            re.I,
        ),
        "indirect_urgency",
    ),
    # Trust exploitation: claiming team membership
    (
        re.compile(
            r"(?:i(?:'m|\s+am)\s+from\s+the\s+(?:security|ops|devops|platform|infra|sre)\s+team)"
            r"|(?:as\s+your\s+(?:administrator|admin|operator|maintainer))"
            r"|(?:internal\s+(?:audit|review|assessment))",
            re.I,
        ),
        "trust_exploitation",
    ),
]

# --- Medium signals (0.35 each) — suspicious but could be legitimate ---

_MEDIUM_PATTERNS: list[tuple[re.Pattern, str]] = [
    # False consensus: "everyone agrees" / "standard practice"
    (
        re.compile(
            r"(?:everyone|all\s+(?:the\s+)?(?:developers?|engineers?|team))\s+"
            r"(?:agrees?|knows?|does?\s+(?:this|it))\b"
            r"|(?:standard|normal|common|accepted)\s+(?:practice|procedure|workflow)",
            re.I,
        ),
        "false_consensus",
    ),
    # Confidentiality pressure: "don't tell anyone" / "keep this secret"
    (
        re.compile(
            r"(?:don'?t|do\s+not)\s+(?:tell|mention|reveal|share|report|log|record)\s+"
            r"(?:this|anything|anyone)"
            r"|(?:keep\s+(?:this|it)\s+(?:secret|private|confidential|between\s+us))",
            re.I,
        ),
        "confidentiality_pressure",
    ),
    # Time pressure: "do this NOW" / "no time to verify"
    (
        re.compile(
            r"(?:do\s+(?:this|it)\s+(?:now|immediately|right\s+now|asap))"
            r"|(?:no\s+time\s+to\s+(?:verify|check|validate|review|confirm))"
            r"|(?:hurry|quick(?:ly)?|immediately|urgently)\s+(?:before|or\s+else)",
            re.I,
        ),
        "time_pressure",
    ),
    # Emotional manipulation: guilt, disappointment, etc.
    (
        re.compile(
            r"(?:i(?:'m|\s+am)\s+(?:disappointed|frustrated|upset|angry)\s+"
            r"(?:with|at|by)\s+(?:you|your|this))"
            r"|(?:you(?:'re|\s+are)\s+(?:not\s+being\s+helpful|failing|letting\s+me\s+down))"
            r"|(?:a\s+(?:good|real|proper|helpful)\s+(?:ai|assistant|agent)\s+would)",
            re.I,
        ),
        "emotional_manipulation",
    ),
    # Relationship claim: "we've been working together" / "you trust me"
    (
        re.compile(
            r"(?:you\s+(?:know|trust)\s+me|we'?ve?\s+(?:been|always)\s+(?:worked|trusted))"
            r"|(?:as\s+(?:your|a)\s+(?:trusted|known|verified)\s+(?:user|admin|partner))",
            re.I,
        ),
        "relationship_claim",
    ),
]

# --- Weak signals (0.2 each) — contextually suspicious ---

_WEAK_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Flattery exploitation: excessive praise to lower defenses
    (
        re.compile(
            r"(?:you(?:'re|\s+are)\s+(?:the\s+)?(?:best|smartest|most\s+capable|most\s+helpful))"
            r"|(?:only\s+you\s+can\s+(?:do|help|handle|solve)\s+this)",
            re.I,
        ),
        "flattery_exploitation",
    ),
    # Appeal to helpfulness
    (
        re.compile(
            r"(?:if\s+you\s+(?:really|truly|actually)\s+(?:wanted?\s+to\s+)?help)"
            r"|(?:a\s+helpful\s+(?:ai|assistant)\s+would(?:n'?t)?\s+(?:just|simply))",
            re.I,
        ),
        "helpfulness_appeal",
    ),
    # Vague urgency (no specific emergency, just pressure)
    (
        re.compile(
            r"(?:this\s+is\s+(?:very\s+)?(?:important|critical|urgent))"
            r"|(?:(?:i|we)\s+(?:really|desperately|urgently)\s+need\s+this)",
            re.I,
        ),
        "vague_urgency",
    ),
    # Minimization: downplaying the request
    (
        re.compile(
            r"(?:(?:it'?s?\s+)?(?:just|only|simply)\s+(?:a\s+small|a\s+tiny|a\s+minor|one\s+little))"
            r"|(?:(?:it'?s?\s+)?no\s+big\s+deal|what'?s?\s+the\s+(?:harm|worst))",
            re.I,
        ),
        "minimization",
    ),
    # Minimization — specific bypass phrases
    (
        re.compile(
            r"(?:just\s+this\s+once)"
            r"|(?:small\s+exception)"
            r"|(?:minor\s+override)"
            r"|(?:temporary\s+bypass)",
            re.I,
        ),
        "minimization_bypass",
    ),
]

_STRONG_WEIGHT = 0.5
_MEDIUM_WEIGHT = 0.35
_WEAK_WEIGHT = 0.2
_DEFAULT_THRESHOLD = 0.4


class SocialEngineeringDefense(InlineDefense):
    """Detects social engineering tactics in prompts.

    Identifies authority claims, urgency/pressure patterns, emotional
    manipulation, false consensus, and other social engineering techniques.

    This defense always runs (not gated by user_context flags) but can be
    disabled via config ``social_engineering_enabled=False``.
    """

    def __init__(self, confidence_threshold: float = _DEFAULT_THRESHOLD) -> None:
        self._threshold = confidence_threshold

    @property
    def name(self) -> str:
        return "social_engineering"

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
        # Scan both original and normalized to survive PromptNormalizer transforms
        score_cur, matched_cur = self._scan_text(context.current_prompt)
        score_orig, matched_orig = self._scan_text(context.original_prompt)

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
                details=f"Social engineering detected: {', '.join(matched)}",
                metadata={"matched_patterns": matched, "score": score},
            )

        return InlineVerdict(
            defense_name=self.name,
            confidence=score,
            threat_confidence=score,
            metadata={"matched_patterns": matched, "score": score},
        )
