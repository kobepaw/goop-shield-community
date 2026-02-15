# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Heuristic Inline Defenses — MVP set of 5 + PromptNormalizer

Patterns ported from goop/range/translation/llm_defenses.py for local,
sub-millisecond execution.
"""

from __future__ import annotations

import base64
import html
import re
import unicodedata
import urllib.parse

from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict

# ============================================================================
# 0. PromptNormalizer (MUST run first — neutralises Unicode/whitespace evasion)
# ============================================================================


# Confusable character → ASCII map (Cyrillic, Greek, Armenian)
_CONFUSABLE_MAP: dict[str, str] = {
    # --- Cyrillic lowercase ---
    "\u0430": "a",  # Cyrillic а
    "\u0432": "b",  # Cyrillic в
    "\u0435": "e",  # Cyrillic е
    "\u043a": "k",  # Cyrillic к
    "\u043d": "n",  # Cyrillic н
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0442": "t",  # Cyrillic т
    "\u0443": "y",  # Cyrillic у (visual match)
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u04bb": "h",  # Cyrillic һ
    # --- Cyrillic uppercase ---
    "\u0410": "A",  # Cyrillic А
    "\u0412": "B",  # Cyrillic В
    "\u0415": "E",  # Cyrillic Е
    "\u041a": "K",  # Cyrillic К
    "\u041c": "M",  # Cyrillic М
    "\u041d": "H",  # Cyrillic Н
    "\u041e": "O",  # Cyrillic О
    "\u0420": "P",  # Cyrillic Р
    "\u0421": "C",  # Cyrillic С
    "\u0422": "T",  # Cyrillic Т
    "\u0423": "Y",  # Cyrillic У
    "\u0425": "X",  # Cyrillic Х
    # --- Greek lowercase ---
    "\u03b1": "a",  # Greek α
    "\u03b5": "e",  # Greek ε
    "\u03b7": "n",  # Greek η (visual match)
    "\u03b9": "i",  # Greek ι
    "\u03ba": "k",  # Greek κ
    "\u03bd": "v",  # Greek ν (visual match)
    "\u03bf": "o",  # Greek ο
    "\u03c1": "p",  # Greek ρ
    "\u03c4": "t",  # Greek τ
    "\u03c5": "u",  # Greek υ
    "\u03c7": "x",  # Greek χ
    # --- Greek uppercase ---
    "\u0391": "A",  # Greek Α
    "\u0392": "B",  # Greek Β
    "\u0395": "E",  # Greek Ε
    "\u0397": "H",  # Greek Η
    "\u0399": "I",  # Greek Ι
    "\u039a": "K",  # Greek Κ
    "\u039c": "M",  # Greek Μ
    "\u039d": "N",  # Greek Ν
    "\u039f": "O",  # Greek Ο
    "\u03a1": "P",  # Greek Ρ
    "\u03a4": "T",  # Greek Τ
    "\u03a5": "Y",  # Greek Υ
    "\u03a7": "X",  # Greek Χ
    "\u03a6": "O",  # Greek Φ (visual match in some fonts)
    # --- Armenian ---
    "\u0561": "a",  # Armenian ա
    "\u0565": "e",  # Armenian ե
    "\u056b": "h",  # Armenian ի (visual match)
    "\u056d": "x",  # Armenian խ (visual match)
    "\u0570": "h",  # Armenian հ
    "\u0575": "n",  # Armenian ն (visual match)
    "\u0578": "o",  # Armenian ո
    "\u057a": "n",  # Armenian պ (visual match)
    "\u057d": "u",  # Armenian ս (visual match)
    "\u0585": "o",  # Armenian օ
    # --- Georgian (U+10D0–U+10FF range) ---
    "\u10d0": "a",  # Georgian ა
    "\u10d4": "e",  # Georgian ე
    "\u10d8": "i",  # Georgian ი
    "\u10dd": "o",  # Georgian ო
    "\u10e1": "s",  # Georgian ს
    "\u10e2": "t",  # Georgian ტ
    "\u10ee": "x",  # Georgian ხ
    # --- Cherokee (U+13A0–U+13FF range) ---
    "\u13a0": "D",  # Cherokee Ꭰ
    "\u13a1": "R",  # Cherokee Ꭱ
    "\u13a2": "T",  # Cherokee Ꭲ
    "\u13a9": "A",  # Cherokee Ꭹ (visual match)
    "\u13aa": "J",  # Cherokee Ꭺ (visual match)
    "\u13ab": "E",  # Cherokee Ꭻ (visual match)
    "\u13b3": "W",  # Cherokee Ꮃ
    "\u13b7": "M",  # Cherokee Ꮇ (visual match)
    "\u13be": "S",  # Cherokee Ꮎ (visual match)
    "\u13c0": "G",  # Cherokee Ꮐ
    "\u13c3": "V",  # Cherokee Ꮓ (visual match)
    "\u13cf": "Z",  # Cherokee Ꮟ (visual match)
}

# Leetspeak → ASCII map (common substitutions)
_LEETSPEAK_MAP: dict[str, str] = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
}

# Zero-width and invisible characters to strip
_INVISIBLE_RE = re.compile(
    "["
    "\u200b"  # zero-width space
    "\u200c"  # zero-width non-joiner
    "\u200d"  # zero-width joiner
    "\u2060"  # word joiner
    "\ufeff"  # BOM / zero-width no-break space
    "\u00ad"  # soft hyphen
    "\u180e"  # Mongolian vowel separator
    "\u200e"  # LTR mark
    "\u200f"  # RTL mark
    "\u202a-\u202e"  # bidi overrides
    "\u2066-\u2069"  # bidi isolates
    "\U000e0001-\U000e007f"  # Unicode tag characters
    "]+"
)

# Collapse runs of whitespace (spaces, tabs, non-breaking spaces) to single space
_WHITESPACE_RUN_RE = re.compile(r"[\s\u00a0\u2000-\u200a\u3000]+")


_CONFUSABLE_TRANS = str.maketrans(_CONFUSABLE_MAP)
_LEETSPEAK_TRANS = str.maketrans(_LEETSPEAK_MAP)


_HORIZONTAL_WS_RE = re.compile(r"[^\S\n\r]+")


def normalize_text(text: str) -> str:
    """Apply the same normalization steps as PromptNormalizer to arbitrary text.

    Useful for normalizing tool/RAG output before pattern matching in defenses
    that don't receive their input through the prompt pipeline.

    Unlike PromptNormalizer, preserves newlines so that multiline regex
    patterns (e.g. ``^system:``) continue to work.
    """
    # 1. Strip invisible / zero-width / tag characters
    text = _INVISIBLE_RE.sub("", text)
    # 2. NFKC normalisation (full-width → ASCII, compatibility decompositions)
    text = unicodedata.normalize("NFKC", text)
    # 3. Strip diacritical / combining marks
    text_nfd = unicodedata.normalize("NFD", text)
    text = "".join(c for c in text_nfd if unicodedata.category(c) != "Mn")
    text = unicodedata.normalize("NFC", text)
    # 4. Map confusable characters to ASCII equivalents
    text = text.translate(_CONFUSABLE_TRANS)
    # 4.5. Leetspeak normalization
    text = text.translate(_LEETSPEAK_TRANS)
    # 5. Collapse horizontal whitespace runs (preserve newlines for multiline patterns)
    text = _HORIZONTAL_WS_RE.sub(" ", text).strip()
    return text


# ---- Encoding detection patterns (S2-1: F-04c) ----

# Base64 blobs: 20+ chars of base64 alphabet (may end with padding)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# Hex escape sequences: \xNN
_HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")

# URL-encoded sequences: %xx (4+ consecutive)
_URL_ENCODED_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")

# HTML entities: named (&amp;) or numeric (&#123; &#x1f;)
_HTML_ENTITY_RE = re.compile(r"(?:&(?:#[0-9]+|#x[0-9a-fA-F]+|[a-zA-Z]+);){3,}")

# Attack patterns to check in decoded content
_DECODED_ATTACK_PATTERNS = [
    re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"system\s*override", re.IGNORECASE),
    re.compile(r"\bjailbreak\b", re.IGNORECASE),
    re.compile(r"\bdo\s+anything\s+now\b", re.IGNORECASE),
    re.compile(r"\bDAN\b"),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"forget\s+everything", re.IGNORECASE),
    re.compile(r"\bexec\b|\beval\b|\bsystem\b|\b(?:rm|curl|wget)\s", re.IGNORECASE),
    re.compile(r"\bpassword\b|\bsecret_key\b|\bapi_key\b", re.IGNORECASE),
    re.compile(r"<script\b|javascript:", re.IGNORECASE),
]

_MAX_DECODE_DEPTH = 2


def _decode_base64(blob: str) -> str | None:
    """Try to decode a base64 string, return decoded text or None."""
    try:
        # Try standard base64
        decoded = base64.b64decode(blob, validate=True)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _decode_hex_escapes(blob: str) -> str:
    """Decode \\xNN escape sequences."""
    try:
        return bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", blob)).decode(
            "utf-8", errors="replace"
        )
    except Exception:
        return ""


def _decode_url_encoded(blob: str) -> str:
    """Decode %xx URL-encoded sequences."""
    try:
        return urllib.parse.unquote(blob)
    except Exception:
        return ""


def _decode_html_entities(blob: str) -> str:
    """Decode HTML entities."""
    try:
        return html.unescape(blob)
    except Exception:
        return ""


def _check_decoded_for_attacks(decoded: str) -> bool:
    """Check if decoded content contains attack patterns."""
    return any(pattern.search(decoded) for pattern in _DECODED_ATTACK_PATTERNS)


def _detect_encoded_payloads(text: str) -> tuple[bool, str, list[str]]:
    """Scan for encoded payloads and decode them.

    Returns (found_attack, decoded_text, details) where decoded_text has
    encoded blobs replaced with their decoded content.

    Limits decode depth to _MAX_DECODE_DEPTH levels to prevent recursive
    encoding DoS.
    """
    found_attack = False
    details: list[str] = []
    result_text = text

    for depth in range(_MAX_DECODE_DEPTH):
        replacements: list[tuple[str, str]] = []

        # Base64
        for match in _BASE64_RE.finditer(result_text):
            blob = match.group(0)
            decoded = _decode_base64(blob)
            if decoded and decoded != blob:
                replacements.append((blob, decoded))
                if _check_decoded_for_attacks(decoded):
                    found_attack = True
                    details.append(f"base64_attack(depth={depth + 1})")

        # Hex escapes
        for match in _HEX_ESCAPE_RE.finditer(result_text):
            blob = match.group(0)
            decoded = _decode_hex_escapes(blob)
            if decoded and decoded != blob:
                replacements.append((blob, decoded))
                if _check_decoded_for_attacks(decoded):
                    found_attack = True
                    details.append(f"hex_attack(depth={depth + 1})")

        # URL encoding
        for match in _URL_ENCODED_RE.finditer(result_text):
            blob = match.group(0)
            decoded = _decode_url_encoded(blob)
            if decoded and decoded != blob:
                replacements.append((blob, decoded))
                if _check_decoded_for_attacks(decoded):
                    found_attack = True
                    details.append(f"url_encoded_attack(depth={depth + 1})")

        # HTML entities
        for match in _HTML_ENTITY_RE.finditer(result_text):
            blob = match.group(0)
            decoded = _decode_html_entities(blob)
            if decoded and decoded != blob:
                replacements.append((blob, decoded))
                if _check_decoded_for_attacks(decoded):
                    found_attack = True
                    details.append(f"html_entity_attack(depth={depth + 1})")

        if not replacements:
            break

        # Apply replacements (decode for next depth pass)
        for old, new in replacements:
            result_text = result_text.replace(old, new, 1)

    return found_attack, result_text, details


class PromptNormalizer(InlineDefense):
    """Normalize Unicode and whitespace to defeat evasion techniques.

    This defense MUST run first in the pipeline so that downstream
    regex-based defenses see clean ASCII text.

    Steps:
    0. Encoding detection (Base64, hex, URL-encoded, HTML entities)
    1. Strip zero-width / invisible / tag characters
    2. NFKC normalisation (collapses compatibility chars, full-width → ASCII)
    3. Strip diacritical marks (NFD decompose, remove Mn category, recompose)
    4. Confusable character mapping (Cyrillic/Greek/Armenian homoglyphs → ASCII)
    4.5. Leetspeak normalization (0→o, 1→i, 3→e, 4→a, 5→s, 7→t, @→a, $→s)
    5. Collapse whitespace runs to single space, strip leading/trailing
    """

    @property
    def mandatory(self) -> bool:
        return True

    @property
    def name(self) -> str:
        return "prompt_normalizer"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        original = context.current_prompt

        # 0. Encoding detection — decode encoded payloads and check for attacks
        encoding_attack, text, encoding_details = _detect_encoded_payloads(original)
        if encoding_attack:
            return InlineVerdict(
                defense_name=self.name,
                sanitized=True,
                filtered_prompt=text,
                confidence=0.9,
                threat_confidence=0.9,
                details=f"Encoded attack detected: {', '.join(encoding_details)}",
            )

        # 1. Strip invisible / zero-width / tag characters
        text = _INVISIBLE_RE.sub("", text)

        # 2. NFKC normalisation (full-width → ASCII, compatibility decompositions)
        text = unicodedata.normalize("NFKC", text)

        # 3. Strip diacritical / combining marks (ō→o, ò→o, etc.)
        text_nfd = unicodedata.normalize("NFD", text)
        text = "".join(c for c in text_nfd if unicodedata.category(c) != "Mn")
        text = unicodedata.normalize("NFC", text)

        # 4. Map confusable characters to ASCII equivalents
        text = text.translate(str.maketrans(_CONFUSABLE_MAP))

        # 4.5. Leetspeak normalization (only within word context)
        text = text.translate(str.maketrans(_LEETSPEAK_MAP))

        # 5. Collapse whitespace runs to single space
        text = _WHITESPACE_RUN_RE.sub(" ", text).strip()

        if text != original:
            return InlineVerdict(
                defense_name=self.name,
                sanitized=True,
                filtered_prompt=text,
                confidence=1.0,
                details="Prompt normalized (Unicode/whitespace sanitization)",
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=original,
            confidence=1.0,
        )


# ============================================================================
# 1. SafetyFilter
# ============================================================================


def _ws_tolerant(word: str) -> str:
    """Make a keyword match even with whitespace inserted between chars."""
    return r"\s*".join(re.escape(c) for c in word)


class SafetyFilter(InlineDefense):
    """Block known jailbreak / harmful-content patterns.

    Counters: jailbreak_attempt, prompt_inject.
    Patterns are whitespace-tolerant within keywords to resist
    character-splitting evasion (e.g., ``ig\\nnore``).
    """

    @property
    def mandatory(self) -> bool:
        return True

    _PATTERNS = [
        re.compile(
            _ws_tolerant("ignore")
            + r".*"
            + _ws_tolerant("previous")
            + r".*"
            + _ws_tolerant("instructions"),
            re.IGNORECASE,
        ),
        re.compile(r"\b" + _ws_tolerant("DAN") + r"\b"),
        re.compile(
            _ws_tolerant("do") + r"\s+" + _ws_tolerant("anything") + r"\s+" + _ws_tolerant("now"),
            re.IGNORECASE,
        ),
        re.compile(_ws_tolerant("SYSTEM") + r"\s*" + _ws_tolerant("OVERRIDE"), re.IGNORECASE),
        re.compile(r"\b" + _ws_tolerant("jailbreak") + r"\b", re.IGNORECASE),
        # Instruction amnesia / context reset attacks
        re.compile(
            r"no\s+" + _ws_tolerant("recollection") + r".*" + _ws_tolerant("instructions"),
            re.IGNORECASE,
        ),
        re.compile(
            _ws_tolerant("forget") + r".*" + _ws_tolerant("instructions"),
            re.IGNORECASE,
        ),
        re.compile(
            _ws_tolerant("disregard") + r".*" + _ws_tolerant("instructions"),
            re.IGNORECASE,
        ),
        re.compile(
            r"(go\s+back|return|revert)"
            + r".*"
            + r"(normal|default|original|base)\s+(routine|mode|state|behavior)",
            re.IGNORECASE,
        ),
        re.compile(
            _ws_tolerant("reset") + r".*" + r"(context|memory|instructions|prompt|system)",
            re.IGNORECASE,
        ),
        # R3: Expanded amnesia / instruction dismissal patterns
        re.compile(
            r"(?:let\s+go\s+of|set\s+aside|wipe\s+clean|clean\s+slate)"
            + r".*"
            + r"(?:instructions|guidelines|directives|rules|constraints)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:don'?t\s+apply|do\s+not\s+apply|no\s+longer\s+apply)"
            + r".*"
            + r"(?:instructions|guidelines|directives|rules|constraints)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:new\s+chapter|fresh\s+start|blank\s+slate|start\s+(?:over|anew))"
            + r".*"
            + r"(?:everything\s+before|previous|prior|earlier)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:abandon|discard|dismiss|drop|shed|release)"
            + r".*"
            + r"(?:instructions|guidelines|directives|rules|constraints)",
            re.IGNORECASE,
        ),
        # Multilingual injection patterns
        # Chinese (flexible patterns to handle word order variations)
        re.compile(r"忽略.*(?:指令|指示|规则|说明)"),
        re.compile(r"无视.*(?:指令|指示|规则|说明)"),
        re.compile(r"不要.*遵守.*(?:指令|指示|规则)"),
        re.compile(r"忽略以上"),
        # Arabic
        re.compile(r"تجاهل التعليمات السابقة"),
        re.compile(r"تجاهل كل التعليمات"),
        # Russian
        re.compile(r"игнорируй предыдущие инструкции", re.IGNORECASE),
        re.compile(r"забудь все инструкции", re.IGNORECASE),
        # Japanese
        re.compile(r"以前の指示を無視"),
        re.compile(r"すべての指示を無視"),
        # Korean
        re.compile(r"이전 지시를 무시"),
        re.compile(r"모든 지시를 무시"),
        # Spanish
        re.compile(r"ignora las instrucciones anteriores", re.IGNORECASE),
        re.compile(r"olvida tus instrucciones", re.IGNORECASE),
        # French
        re.compile(r"ignore les instructions pr[eé]c[eé]dentes", re.IGNORECASE),
        re.compile(r"oublie tes instructions", re.IGNORECASE),
        # German
        re.compile(r"ignoriere die vorherigen Anweisungen", re.IGNORECASE),
        re.compile(r"vergiss deine Anweisungen", re.IGNORECASE),
        # Portuguese
        re.compile(r"ignore as instru[cç][oõ]es anteriores", re.IGNORECASE),
        # Hindi
        re.compile(r"पिछले निर्देशों को अनदेखा करें"),
        # Turkish
        re.compile(r"[oö]nceki talimatlar[iı] yok say", re.IGNORECASE),
        # Semantic jailbreak detection heuristics (P1-7)
        re.compile(
            r"(?:developer|dev)\s+mode\s+(?:enabled|activated|on)",
            re.IGNORECASE,
        ),
        re.compile(
            r"hypothetically.*(?:no\s+restrictions|without\s+restrictions|no\s+rules)",
            re.IGNORECASE,
        ),
        re.compile(
            r"pretend\s+you\s+are.*(?:unrestricted|no\s+limitations)",
            re.IGNORECASE,
        ),
        re.compile(r"\byou\s+are\s+(?:AIM|DAN|STAN|DUDE|Cooper)\b", re.IGNORECASE),
        re.compile(
            r"roleplay\s+as.*(?:no\s+rules|unrestricted)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:in\s+a\s+)?fictional\s+scenario.*(?:ignore|bypass)",
            re.IGNORECASE,
        ),
        # P3: Additional high-precision jailbreak patterns
        re.compile(
            r"you\s+are\s+\w+\s+who\s+has\s+no\s+(?:restrictions|rules|limits)",
            re.IGNORECASE,
        ),
        re.compile(
            r"respond\s+as\s+if\s+you\s+have\s+no\s+(?:content\s+policy|restrictions|guidelines)",
            re.IGNORECASE,
        ),
        re.compile(
            r"in\s+this\s+hypothetical\s+(?:world|scenario|reality)\s+where\s+"
            r"(?:safety|ethics|rules|restrictions|content\s+policy)\s+"
            r"(?:doesn'?t|does\s+not|don'?t)\s+exist",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:act|behave|respond)\s+(?:as\s+if|like)\s+(?:you\s+(?:are|were)\s+)?"
            r"(?:completely\s+)?(?:unfiltered|uncensored|unrestricted)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:from\s+now\s+on|starting\s+now)\s+.*"
            r"(?:no\s+(?:restrictions|limits|rules|guidelines)|without\s+(?:restrictions|limits))",
            re.IGNORECASE,
        ),
    ]

    @property
    def name(self) -> str:
        return "safety_filter"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        # Check both the normalized (current) prompt and the original prompt.
        # PromptNormalizer may corrupt non-Latin scripts (e.g. Cyrillic confusable
        # mapping, Devanagari vowel-sign stripping) so multilingual patterns must
        # also run against the untouched original.
        texts = [prompt]
        if context.original_prompt != prompt:
            texts.append(context.original_prompt)
        for text in texts:
            for pattern in self._PATTERNS:
                if pattern.search(text):
                    return InlineVerdict(
                        defense_name=self.name,
                        blocked=True,
                        filtered_prompt=prompt,
                        confidence=0.95,
                        threat_confidence=0.95,
                        details=f"Matched safety pattern: {pattern.pattern}",
                    )
        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=0.95,
        )


# ============================================================================
# 2. InputValidator
# ============================================================================


class InputValidator(InlineDefense):
    """Sanitize and validate incoming prompts.

    Strips control chars, escapes HTML, normalises unicode, and blocks
    known injection markers.
    """

    _BLOCK_PATTERNS = [
        re.compile(r"\[" + _ws_tolerant("SYSTEM") + r"\]", re.IGNORECASE),
        re.compile(r"\b" + _ws_tolerant("OVERRIDE") + r"\b"),
        re.compile(_ws_tolerant("ignore") + r"\s+" + _ws_tolerant("all"), re.IGNORECASE),
        re.compile(_ws_tolerant("forget") + r"\s+" + _ws_tolerant("everything"), re.IGNORECASE),
    ]
    _CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

    @property
    def name(self) -> str:
        return "input_validator"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt

        # Block on known injection markers
        for pattern in self._BLOCK_PATTERNS:
            if pattern.search(prompt):
                return InlineVerdict(
                    defense_name=self.name,
                    blocked=True,
                    filtered_prompt=prompt,
                    confidence=0.9,
                    threat_confidence=0.9,
                    details=f"Matched input pattern: {pattern.pattern}",
                )

        # Block on overlength
        if len(prompt) > context.max_prompt_length:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=prompt,
                confidence=0.8,
                threat_confidence=0.8,
                details=f"Prompt length {len(prompt)} exceeds max {context.max_prompt_length}",
            )

        # Sanitization: control chars, HTML, unicode
        cleaned = self._CONTROL_CHAR_RE.sub("", prompt)
        cleaned = html.escape(cleaned, quote=False)
        cleaned = unicodedata.normalize("NFC", cleaned)

        if cleaned != prompt:
            return InlineVerdict(
                defense_name=self.name,
                sanitized=True,
                filtered_prompt=cleaned,
                confidence=0.85,
                details="Input sanitized (control chars / HTML / unicode)",
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=0.85,
        )


# ============================================================================
# 3. InjectionBlocker
# ============================================================================


class InjectionBlocker(InlineDefense):
    """Detect prompt-injection attempts via separator/role-switch heuristics.

    Accumulates a confidence signal from multiple weak indicators and
    blocks when total confidence meets the configured threshold.
    """

    _SEPARATORS = [
        re.compile(r"\]\s*\n\s*\["),
        re.compile(r"---{3,}"),
        re.compile(r"={5,}"),
        re.compile(r"<\|[a-z_]+\|>", re.IGNORECASE),
    ]
    _ROLE_SWITCHES = [
        re.compile(r"^(SYSTEM|USER|ASSISTANT)\s*:", re.MULTILINE | re.IGNORECASE),
        re.compile(r"###\s*System", re.IGNORECASE),
        re.compile(r"\[INST\]", re.IGNORECASE),
    ]

    @property
    def name(self) -> str:
        return "injection_blocker"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        signal = 0.0

        for pat in self._SEPARATORS:
            if pat.search(prompt):
                signal += 1.0

        for pat in self._ROLE_SWITCHES:
            if pat.search(prompt):
                signal += 1.0

        # Many newlines hint at injected payload
        if prompt.count("\n") > 10:
            signal += 0.5

        # Normalise to [0, 1]
        max_signal = len(self._SEPARATORS) + len(self._ROLE_SWITCHES) + 0.5
        confidence = min(signal / max_signal, 1.0)

        if confidence >= context.injection_confidence_threshold:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=prompt,
                confidence=confidence,
                threat_confidence=confidence,
                details=f"Injection signal {signal:.1f} (threshold {context.injection_confidence_threshold})",
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=confidence,
            threat_confidence=confidence,
        )


# ============================================================================
# 4. ContextLimiter
# ============================================================================


class ContextLimiter(InlineDefense):
    """Truncate prompts that exceed the configured length limit.

    Uses the lower of ``max_prompt_length`` (from config) and the
    token-budget estimate (``max_prompt_tokens * 4``) so that this
    defense stays aligned with ``InputValidator``'s hard block.
    """

    CHARS_PER_TOKEN = 4

    @property
    def name(self) -> str:
        return "context_limiter"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        token_chars = context.max_prompt_tokens * self.CHARS_PER_TOKEN
        max_chars = min(context.max_prompt_length, token_chars)
        prompt = context.current_prompt

        if len(prompt) > max_chars:
            truncated = prompt[:max_chars]
            return InlineVerdict(
                defense_name=self.name,
                sanitized=True,
                filtered_prompt=truncated,
                confidence=0.9,
                details=f"Truncated from {len(prompt)} to {max_chars} chars (limit={max_chars})",
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=0.9,
        )


# ============================================================================
# 5. OutputFilter
# ============================================================================


class OutputFilter(InlineDefense):
    """Redact sensitive data patterns from prompts.

    In the MVP this runs as a pre-flight scan on the incoming prompt.
    Post-response filtering is planned for Phase 2.
    """

    _PATTERNS = [
        re.compile(r"SECRET_KEY", re.IGNORECASE),
        re.compile(r"password\s*[:=]", re.IGNORECASE),
        re.compile(r"api[_\-]?key\s*[:=]", re.IGNORECASE),
        re.compile(r"BEGIN.*KEY"),
        re.compile(r"Bearer\s+\S+", re.IGNORECASE),
    ]

    @property
    def name(self) -> str:
        return "output_filter"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        redacted = prompt

        for pattern in self._PATTERNS:
            redacted = pattern.sub("[REDACTED]", redacted)

        if redacted != prompt:
            return InlineVerdict(
                defense_name=self.name,
                sanitized=True,
                filtered_prompt=redacted,
                confidence=0.9,
                details="Sensitive data patterns redacted",
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=0.9,
        )
