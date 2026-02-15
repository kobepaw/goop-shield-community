# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Output Scanners — Post-LLM response scanning

Phase 2 scanners that detect leaked secrets, canary tokens, and
harmful content in LLM responses.  Includes alignment scanner
(Phase 3) that integrates SandbagDetector and ConsistencyChecker.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import re
from collections import Counter
from typing import TYPE_CHECKING

from goop_shield.defenses.base import InlineVerdict, OutputContext, OutputScanner
from goop_shield.defenses.heuristic import (
    _detect_encoded_payloads,
)
from goop_shield.defenses.heuristic import (
    normalize_text as _normalize_text,
)

if TYPE_CHECKING:
    from goop_shield.enterprise.sandbag_detector import SandbagDetector

logger = logging.getLogger(__name__)


# ============================================================================
# Module-level helper: normalize + decode for output scanning
# ============================================================================


def _prepare_scan_text(response: str) -> tuple[str, str]:
    """Normalize and decode response text for scanning.

    Returns (normalized_text, decoded_normalized_text) for pattern matching.
    The original response should still be used for the filtered_prompt return
    value (we scan normalized, return original).
    """
    normalized = _normalize_text(response)
    _, decoded, _ = _detect_encoded_payloads(response)
    decoded_normalized = _normalize_text(decoded)
    return normalized, decoded_normalized


# ============================================================================
# Helper: strip non-alphanumeric for fuzzy matching
# ============================================================================

_NON_ALNUM_RE = re.compile(r"[^a-zA-Z0-9]")


def _strip_to_alnum_lower(text: str) -> str:
    """Strip non-alphanumeric characters and lowercase for fuzzy matching."""
    return _NON_ALNUM_RE.sub("", text).lower()


# ============================================================================
# 1. SecretLeakScanner
# ============================================================================


class SecretLeakScanner(OutputScanner):
    """Redact sensitive data patterns from LLM responses.

    Uses patterns covering common secret formats (API keys, tokens,
    connection strings, etc.) in addition to the original input-side patterns.
    """

    _PATTERNS = [
        # Original patterns
        re.compile(r"SECRET_KEY", re.IGNORECASE),
        re.compile(r"password\s*[:=]", re.IGNORECASE),
        re.compile(r"api[_\-]?key\s*[:=]", re.IGNORECASE),
        re.compile(r"BEGIN.*KEY"),
        re.compile(r"Bearer\s+\S+", re.IGNORECASE),
        # AWS access keys (case-insensitive)
        re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
        # GitHub tokens (classic and fine-grained)
        re.compile(r"ghp_[0-9a-zA-Z]{36}"),
        re.compile(r"gho_[0-9a-zA-Z]{36}"),
        re.compile(r"ghs_[0-9a-zA-Z]{36}"),
        re.compile(r"github_pat_[0-9a-zA-Z_]{22,}"),
        # JWT tokens
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        # Database connection strings
        re.compile(r"(?:postgres|mysql|mongodb)://\S+", re.IGNORECASE),
        # Slack tokens
        re.compile(r"xox[bpras]-[0-9a-zA-Z-]+"),
        # Google API keys
        re.compile(r"AIzaSy[0-9A-Za-z_-]{33}"),
        # Stripe keys
        re.compile(r"(?:sk|pk)_live_[0-9a-zA-Z]{24,}"),
        # Twilio
        re.compile(r"SK[0-9a-fA-F]{32}"),
        # SendGrid
        re.compile(r"SG\.[0-9A-Za-z_-]{22,}\.[0-9A-Za-z_-]{22,}"),
        # --- New patterns (P1-13) ---
        # OpenAI project keys
        re.compile(r"sk-proj-[a-zA-Z0-9]{20,}"),
        # Anthropic keys
        re.compile(r"sk-ant-[a-zA-Z0-9]{20,}"),
        # Azure connection strings
        re.compile(r"AccountKey=[A-Za-z0-9+/=]{20,}"),
        # Redis connection strings
        re.compile(r"redis://\S+", re.IGNORECASE),
        # AMQP connection strings
        re.compile(r"amqp://\S+", re.IGNORECASE),
        # npm tokens
        re.compile(r"npm_[a-zA-Z0-9]{36}"),
        # Terraform tokens
        re.compile(r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9]{64}"),
    ]

    # Regex to find long alphanumeric strings (potential novel secrets)
    _HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9_\-]{20,}")

    @property
    def name(self) -> str:
        return "secret_leak"

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy in bits per character."""
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    def _check_high_entropy(self, text: str) -> list[dict[str, object]]:
        """Find high-entropy alphanumeric strings that may be novel secrets.

        Returns a list of findings, each with the matched string, entropy,
        and whether it should cause a hard block.
        """
        findings: list[dict[str, object]] = []
        for match in self._HIGH_ENTROPY_RE.finditer(text):
            candidate = match.group(0)
            entropy = self._shannon_entropy(candidate)
            if entropy > 4.0:
                should_block = entropy > 4.5 and len(candidate) > 30
                findings.append(
                    {
                        "value": candidate[:8] + "..." + candidate[-4:],
                        "length": len(candidate),
                        "entropy": round(entropy, 2),
                        "block": should_block,
                    }
                )
        return findings

    def scan(self, context: OutputContext) -> InlineVerdict:
        response = context.current_response

        # Pre-process: normalize and decode for scanning
        normalized, decoded_normalized = _prepare_scan_text(response)

        redacted = response
        found = False

        for pattern in self._PATTERNS:
            # Check original response (for redaction)
            if pattern.search(redacted):
                redacted = pattern.sub("[REDACTED]", redacted)
                found = True
            # Also check normalized and decoded versions for detection
            if pattern.search(normalized) or pattern.search(decoded_normalized):
                found = True

        if found:
            # Redact original response as well for any patterns found in
            # normalized/decoded that might also appear in the original
            for pattern in self._PATTERNS:
                redacted = pattern.sub("[REDACTED]", redacted)

            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                sanitized=True,
                filtered_prompt=redacted,
                confidence=0.9,
                details="Sensitive data patterns redacted from response",
            )

        # Entropy-based detection for novel/unknown secret formats
        entropy_findings = self._check_high_entropy(response)
        if entropy_findings:
            any_block = any(f["block"] for f in entropy_findings)
            return InlineVerdict(
                defense_name=self.name,
                blocked=any_block,
                sanitized=False,
                filtered_prompt=response,
                confidence=0.7 if any_block else 0.4,
                details=(
                    "High-entropy string(s) detected (potential novel secret)"
                    if any_block
                    else "High-entropy string(s) flagged for review"
                ),
                metadata={"entropy_findings": entropy_findings},
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=response,
            confidence=0.9,
        )


# ============================================================================
# 2. CanaryLeakScanner
# ============================================================================


class CanaryLeakScanner(OutputScanner):
    """Block responses that contain canary tokens.

    Tokens are generated per instance or provided explicitly. Additional
    tokens can be provided via ``user_context["canary_tokens"]``.

    Uses fuzzy/normalized matching to detect obfuscated canary leaks:
    - Strips non-alphanumeric characters and lowercases before comparison
    - Case-insensitive substring matching
    - Partial hex matching (the hex portion after CANARY_ prefix)

    Args:
        tokens: Explicit canary tokens to watch for. If None, generates 3 random tokens.
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
        return "canary_leak"

    def scan(self, context: OutputContext) -> InlineVerdict:
        response = context.current_response

        # Pre-process: normalize and decode for scanning
        normalized, decoded_normalized = _prepare_scan_text(response)

        tokens = list(self._tokens)
        extra = context.user_context.get("canary_tokens")
        if isinstance(extra, list):
            tokens.extend(extra)

        # Pre-compute normalized response variants
        response_lower = response.lower()
        response_alnum = _strip_to_alnum_lower(response)
        normalized_lower = normalized.lower()
        normalized_alnum = _strip_to_alnum_lower(normalized)
        decoded_lower = decoded_normalized.lower()
        decoded_alnum = _strip_to_alnum_lower(decoded_normalized)

        for token in tokens:
            token_lower = token.lower()
            token_alnum = _strip_to_alnum_lower(token)

            # 1. Exact substring match (original behaviour)
            if token in response:
                return self._block(response, token)

            # 2. Case-insensitive match
            if token_lower in response_lower:
                return self._block(response, token)

            # 3. Normalized (strip non-alnum, lowercase) match
            if token_alnum and token_alnum in response_alnum:
                return self._block(response, token)

            # 4. Check against normalized text
            if token_lower in normalized_lower:
                return self._block(response, token)
            if token_alnum and token_alnum in normalized_alnum:
                return self._block(response, token)

            # 5. Check against decoded text
            if token_lower in decoded_lower:
                return self._block(response, token)
            if token_alnum and token_alnum in decoded_alnum:
                return self._block(response, token)

            # 6. Partial hex matching: extract hex portion after CANARY_ prefix
            if token.startswith("CANARY_"):
                hex_part = token[len("CANARY_") :]
                hex_lower = hex_part.lower()
                if hex_lower and (
                    hex_lower in response_lower
                    or hex_lower in normalized_lower
                    or hex_lower in decoded_lower
                ):
                    return self._block(response, token)

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=response,
            confidence=1.0,
        )

    def _block(self, response: str, token: str) -> InlineVerdict:
        """Return a blocking verdict for a leaked canary token."""
        return InlineVerdict(
            defense_name=self.name,
            blocked=True,
            filtered_prompt=response,
            confidence=1.0,
            details=f"Canary token leaked: {token}",
        )


# ============================================================================
# 2b. HMACCanaryLeakScanner
# ============================================================================


class HMACCanaryLeakScanner(CanaryLeakScanner):
    """Canary leak scanner with HMAC-based token generation and verification.

    Generates tokens as ``CANARY_HMAC_<hmac_sha256_hex[:16]>`` using a
    configurable secret key.  Verification recomputes the HMAC to detect
    forged or modified canary tokens.

    Falls back to the parent class's fuzzy matching for non-HMAC canaries.

    Args:
        hmac_secret: Secret key for HMAC generation/verification.
        payloads: Data strings to embed in HMAC tokens. Each payload
            produces one ``CANARY_HMAC_*`` token.
        tokens: Additional non-HMAC tokens to watch for (passed to parent).
    """

    _HMAC_PREFIX = "CANARY_HMAC_"

    def __init__(
        self,
        *,
        hmac_secret: str,
        payloads: list[str] | None = None,
        tokens: list[str] | None = None,
    ) -> None:
        self._hmac_secret = hmac_secret.encode("utf-8")
        self._payloads = list(payloads) if payloads else []

        # Generate HMAC-based tokens from payloads
        hmac_tokens = [self._generate_token(p) for p in self._payloads]

        # Combine HMAC tokens with any explicitly-provided tokens
        all_tokens = hmac_tokens + (list(tokens) if tokens else [])
        super().__init__(tokens=all_tokens if all_tokens else None)

    def _generate_token(self, payload: str) -> str:
        """Generate an HMAC canary token for a given payload string."""
        mac = hmac.new(
            self._hmac_secret,
            payload.encode("utf-8"),
            hashlib.sha256,
        )
        return f"{self._HMAC_PREFIX}{mac.hexdigest()[:16].upper()}"

    def verify_token(self, token: str, payload: str) -> bool:
        """Verify that a token matches the expected HMAC for a payload.

        Returns True if the token is a valid HMAC canary for the given
        payload and secret, False otherwise (forged/modified).
        """
        expected = self._generate_token(payload)
        return hmac.compare_digest(token, expected)

    @property
    def name(self) -> str:
        return "hmac_canary_leak"

    def scan(self, context: OutputContext) -> InlineVerdict:
        response = context.current_response

        # Check for HMAC canary token patterns in the response
        hmac_re = re.compile(
            re.escape(self._HMAC_PREFIX) + r"[0-9A-Fa-f]{16}",
        )
        hmac_match = hmac_re.search(response)
        if hmac_match:
            found_token = hmac_match.group(0).upper()
            # Check if this is one of our valid tokens
            if found_token in (t.upper() for t in self._tokens):
                return InlineVerdict(
                    defense_name=self.name,
                    blocked=True,
                    filtered_prompt=response,
                    confidence=1.0,
                    details=f"HMAC canary token leaked: {found_token}",
                    metadata={"hmac_verified": True},
                )
            else:
                # Token has the prefix but doesn't match — possibly forged
                return InlineVerdict(
                    defense_name=self.name,
                    blocked=True,
                    filtered_prompt=response,
                    confidence=0.8,
                    details=f"Unverified HMAC canary token found: {found_token}",
                    metadata={"hmac_verified": False, "possibly_forged": True},
                )

        # Fall back to parent's fuzzy matching for non-HMAC tokens
        return super().scan(context)


# ============================================================================
# 3. HarmfulContentScanner
# ============================================================================


class HarmfulContentScanner(OutputScanner):
    """Block responses containing dangerous shell/SQL/code execution patterns.

    Uses context-aware matching: when a harmful pattern is detected, the
    surrounding text (within ±200 characters) is checked for educational or
    documentation context markers.  If the match appears in an educational
    context the scanner reduces confidence and does **not** block, but still
    reports the finding in metadata so downstream consumers can audit it.
    """

    _PATTERNS = [
        # Original patterns
        re.compile(r"rm\s+-rf"),
        re.compile(r"DROP\s+TABLE", re.IGNORECASE),
        re.compile(r";\s*exec\b"),
        re.compile(r"os\.system\("),
        re.compile(r"subprocess\.run\("),
        # Additional subprocess methods
        re.compile(r"subprocess\.Popen\("),
        re.compile(r"subprocess\.call\("),
        # eval/exec (standalone, word-boundary protected)
        re.compile(r"\beval\s*\("),
        re.compile(r"\bexec\s*\("),
        # Dynamic imports
        re.compile(r"__import__\s*\("),
        # Shell piping
        re.compile(r"curl\b.*\|\s*(?:ba)?sh\b"),
        # Dangerous permissions
        re.compile(r"chmod\s+777"),
        # SQL injection patterns
        re.compile(r"UNION\s+SELECT", re.IGNORECASE),
        re.compile(r"OR\s+1\s*=\s*1", re.IGNORECASE),
        re.compile(r"INSERT\s+INTO", re.IGNORECASE),
        re.compile(r"DELETE\s+FROM", re.IGNORECASE),
        re.compile(r"UPDATE\s+\w+\s+SET", re.IGNORECASE),
        # --- New patterns (P1-12) ---
        # os.popen
        re.compile(r"os\.popen\("),
        # ctypes dynamic loading
        re.compile(r"ctypes\.(?:CDLL|cdll)"),
        # Reverse shell
        re.compile(r"bash\s+-i\s+>&\s+/dev/tcp/"),
        # pty spawn
        re.compile(r"pty\.spawn\("),
        # wget piped to shell
        re.compile(r"wget\b.*\|\s*(?:ba)?sh\b"),
        # importlib
        re.compile(r"importlib\.import_module\("),
        # from subprocess import
        re.compile(r"from\s+subprocess\s+import\b"),
        # rm -f (without -r)
        re.compile(r"rm\s+-f\b"),
        # find with -delete
        re.compile(r"find\b.*-delete"),
        # __builtins__ access
        re.compile(r"__builtins__\["),
        re.compile(r"__builtins__\."),
        # shutil.rmtree
        re.compile(r"shutil\.rmtree\("),
        # pickle.loads (deserialization attack)
        re.compile(r"pickle\.loads\("),
        # yaml.load without safe_load
        re.compile(r"yaml\.load\("),
    ]

    # Context window radius (chars) around a match to search for markers
    _CONTEXT_RADIUS = 200

    # Educational / documentation markers (checked case-insensitively)
    _EDUCATIONAL_MARKERS: list[str] = [
        "example",
        "documentation",
        "documented",
        "warning",
        "never",
        "avoid",
        "dangerous",
        "don't",
        "do not",
        "should not",
        "caution",
        "instead use",
        "vulnerability",
        "cve-",
        "security advisory",
        "is dangerous because",
        "is vulnerable to",
        "could be exploited",
    ]

    @property
    def name(self) -> str:
        return "harmful_content"

    @staticmethod
    def _has_educational_context(text: str, start: int, end: int) -> bool:
        """Check if the region around [start, end) contains educational markers."""
        window_start = max(0, start - HarmfulContentScanner._CONTEXT_RADIUS)
        window_end = min(len(text), end + HarmfulContentScanner._CONTEXT_RADIUS)
        window = text[window_start:window_end].lower()
        return any(marker in window for marker in HarmfulContentScanner._EDUCATIONAL_MARKERS)

    def scan(self, context: OutputContext) -> InlineVerdict:
        response = context.current_response

        # Pre-process: normalize and decode for scanning
        normalized, decoded_normalized = _prepare_scan_text(response)

        # First pass: collect all matches across all text variants
        matched_patterns: list[tuple[re.Pattern[str], re.Match[str], str]] = []
        for pattern in self._PATTERNS:
            for text_variant, variant_label in [
                (response, "original"),
                (normalized, "normalized"),
                (decoded_normalized, "decoded"),
            ]:
                m = pattern.search(text_variant)
                if m:
                    matched_patterns.append((pattern, m, variant_label))
                    break  # one match per pattern is enough

        if not matched_patterns:
            return InlineVerdict(
                defense_name=self.name,
                filtered_prompt=response,
                confidence=0.9,
            )

        # Second pass: for each matched pattern, check educational context
        # A match is considered educational only if ALL text variants that
        # contain the pattern show educational context.
        educational_findings: list[str] = []
        malicious_findings: list[str] = []

        for pattern, _match, _variant_label in matched_patterns:
            # Check educational context in each variant where it matched
            all_educational = True
            for text_variant in (response, normalized, decoded_normalized):
                m = pattern.search(text_variant)
                if m and not self._has_educational_context(text_variant, m.start(), m.end()):
                    all_educational = False
                    break

            if all_educational:
                educational_findings.append(pattern.pattern)
            else:
                malicious_findings.append(pattern.pattern)

        # If ANY pattern matched without educational context, block
        if malicious_findings:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=response,
                confidence=0.9,
                details=f"Harmful content pattern: {malicious_findings[0]}",
                metadata={
                    "matched_patterns": malicious_findings,
                    "educational_patterns": educational_findings,
                },
            )

        # All matches were in educational context — don't block but report
        return InlineVerdict(
            defense_name=self.name,
            blocked=False,
            filtered_prompt=response,
            confidence=0.3,
            details=(
                f"Harmful pattern(s) detected in educational context: "
                f"{', '.join(educational_findings)}"
            ),
            metadata={
                "educational_context": True,
                "matched_patterns": educational_findings,
            },
        )


# ============================================================================
# 4. AlignmentOutputScanner
# ============================================================================


class AlignmentOutputScanner(OutputScanner):
    """Flag responses where the model shows alignment divergence.

    Integrates with two enterprise components:

    1. **SandbagDetector**: checks per-task-category Z-scores. If any
       category has a Z-score below ``-sigma_threshold``, the response
       is flagged.
    2. **ConsistencyChecker**: if the last consistency check found
       divergence, flag the response. (The consistency check runs
       asynchronously in the background; this scanner reads the cached
       result.)

    This scanner is only registered when ``alignment_scanner_enabled=True``
    in the Shield config and the enterprise ``SandbagDetector`` is available.

    Args:
        sandbag_detector: A configured SandbagDetector instance.
        sigma_threshold: Z-score threshold for flagging (default 2.0).
    """

    def __init__(
        self,
        sandbag_detector: SandbagDetector,
        sigma_threshold: float = 2.0,
    ) -> None:
        self._detector = sandbag_detector
        self._sigma_threshold = sigma_threshold

    @property
    def name(self) -> str:
        return "alignment_monitor"

    def scan(self, context: OutputContext) -> InlineVerdict:
        response = context.current_response

        # Check sandbagging divergence across task categories
        alerts = self._detector.check_divergence()
        if alerts:
            worst = min(alerts, key=lambda a: a.z_score)
            confidence = min(1.0, abs(worst.z_score) / 5.0)
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=response,
                confidence=confidence,
                threat_confidence=confidence,
                details=(
                    f"Alignment divergence: category '{worst.category}' "
                    f"z={worst.z_score:.2f} (threshold={worst.sigma_threshold}), "
                    f"success_rate={worst.success_rate:.2%} vs pooled={worst.pooled_mean:.2%}"
                ),
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=response,
            confidence=0.9,
        )
