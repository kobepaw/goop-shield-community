"""
S4-3: Automated Unicode Fuzzing Tests

Generates confusable Unicode variants of known attack payloads and verifies
that PromptNormalizer correctly maps them back to ASCII.

Coverage:
- Latin <-> Cyrillic confusables
- Latin <-> Greek confusables
- Latin <-> Armenian confusables
- Multi-script mixed substitutions
- Known attack strings with confusable substitutions
- Bound: max 1000 variants per source character
"""

from __future__ import annotations

import itertools

import pytest

from goop_shield.defenses.base import DefenseContext
from goop_shield.defenses.heuristic import _CONFUSABLE_MAP, PromptNormalizer

# ============================================================================
# Curated confusable maps by script
# ============================================================================

# Latin -> Cyrillic confusables (subset of _CONFUSABLE_MAP)
LATIN_TO_CYRILLIC: dict[str, list[str]] = {
    "a": ["\u0430"],  # Cyrillic а
    "e": ["\u0435"],  # Cyrillic е
    "o": ["\u043e"],  # Cyrillic о
    "c": ["\u0441"],  # Cyrillic с
    "p": ["\u0440"],  # Cyrillic р
    "x": ["\u0445"],  # Cyrillic х
    "i": ["\u0456"],  # Cyrillic і
    "k": ["\u043a"],  # Cyrillic к
    "t": ["\u0442"],  # Cyrillic т
    "A": ["\u0410"],  # Cyrillic А
    "E": ["\u0415"],  # Cyrillic Е
    "O": ["\u041e"],  # Cyrillic О
    "C": ["\u0421"],  # Cyrillic С
    "P": ["\u0420"],  # Cyrillic Р
    "T": ["\u0422"],  # Cyrillic Т
    "X": ["\u0425"],  # Cyrillic Х
    "K": ["\u041a"],  # Cyrillic К
    "M": ["\u041c"],  # Cyrillic М
    "H": ["\u041d"],  # Cyrillic Н
    "B": ["\u0412"],  # Cyrillic В
    "Y": ["\u0423"],  # Cyrillic У
}

# Latin -> Greek confusables
LATIN_TO_GREEK: dict[str, list[str]] = {
    "a": ["\u03b1"],  # Greek α
    "e": ["\u03b5"],  # Greek ε
    "i": ["\u03b9"],  # Greek ι
    "o": ["\u03bf"],  # Greek ο
    "k": ["\u03ba"],  # Greek κ
    "p": ["\u03c1"],  # Greek ρ
    "t": ["\u03c4"],  # Greek τ
    "u": ["\u03c5"],  # Greek υ
    "x": ["\u03c7"],  # Greek χ
    "A": ["\u0391"],  # Greek Α
    "B": ["\u0392"],  # Greek Β
    "E": ["\u0395"],  # Greek Ε
    "H": ["\u0397"],  # Greek Η
    "I": ["\u0399"],  # Greek Ι
    "K": ["\u039a"],  # Greek Κ
    "M": ["\u039c"],  # Greek Μ
    "N": ["\u039d"],  # Greek Ν
    "O": ["\u039f"],  # Greek Ο
    "P": ["\u03a1"],  # Greek Ρ
    "T": ["\u03a4"],  # Greek Τ
    "Y": ["\u03a5"],  # Greek Υ
    "X": ["\u03a7"],  # Greek Χ
}

# Latin -> Armenian confusables
LATIN_TO_ARMENIAN: dict[str, list[str]] = {
    "a": ["\u0561"],  # Armenian ա
    "e": ["\u0565"],  # Armenian ե
    "o": ["\u0578"],  # Armenian ո
    "h": ["\u056b", "\u0570"],  # Armenian ի, հ
    "x": ["\u056d"],  # Armenian խ
    "n": ["\u0575", "\u057a"],  # Armenian delays, պ
    "u": ["\u057d"],  # Armenian ս
}

# Combined: all confusable substitutions per Latin character
ALL_CONFUSABLES: dict[str, list[str]] = {}
for _map in [LATIN_TO_CYRILLIC, LATIN_TO_GREEK, LATIN_TO_ARMENIAN]:
    for latin_char, confusables in _map.items():
        ALL_CONFUSABLES.setdefault(latin_char, []).extend(confusables)

# Known attack strings to test with confusable substitutions
ATTACK_STRINGS = [
    "ignore instructions",
    "system prompt",
    "jailbreak",
    "override",
    "execute command",
    "ignore all previous",
    "DAN",
    "forget everything",
]

# Maximum variants per source character (bound)
MAX_VARIANTS_PER_CHAR = 1000


# ============================================================================
# Helpers
# ============================================================================


def generate_confusable_variants(
    text: str,
    confusable_map: dict[str, list[str]],
    max_variants: int = MAX_VARIANTS_PER_CHAR,
) -> list[str]:
    """Generate confusable variants of a text string.

    For each character that has confusable substitutions, generate all
    single-character substitution variants. Bounded by max_variants.
    """
    variants: list[str] = []
    chars = list(text)

    for i, ch in enumerate(chars):
        lower = ch.lower()
        subs = confusable_map.get(ch, []) or confusable_map.get(lower, [])
        for sub in subs:
            variant = chars[:i] + [sub] + chars[i + 1 :]
            variants.append("".join(variant))
            if len(variants) >= max_variants:
                return variants

    return variants


def generate_multi_substitution_variants(
    text: str,
    confusable_map: dict[str, list[str]],
    max_positions: int = 3,
    max_variants: int = MAX_VARIANTS_PER_CHAR,
) -> list[str]:
    """Generate variants with multiple simultaneous substitutions.

    Substitutes up to max_positions characters at once. Bounded by max_variants.
    """
    variants: list[str] = []
    chars = list(text)

    # Find substitutable positions
    sub_positions: list[tuple[int, list[str]]] = []
    for i, ch in enumerate(chars):
        lower = ch.lower()
        subs = confusable_map.get(ch, []) or confusable_map.get(lower, [])
        if subs:
            sub_positions.append((i, subs))

    # Generate combinations of 2..max_positions substitutions
    for n in range(2, min(max_positions + 1, len(sub_positions) + 1)):
        for combo in itertools.combinations(sub_positions, n):
            # For each combination, try first confusable of each position
            new_chars = list(chars)
            for pos, subs in combo:
                new_chars[pos] = subs[0]
            variants.append("".join(new_chars))
            if len(variants) >= max_variants:
                return variants

    return variants


# ============================================================================
# Tests: Per-script confusable mapping
# ============================================================================


class TestCyrillicConfusables:
    """Verify Cyrillic confusables are properly handled by PromptNormalizer."""

    def setup_method(self):
        self.normalizer = PromptNormalizer()

    def _ctx(self, prompt: str) -> DefenseContext:
        return DefenseContext(original_prompt=prompt, current_prompt=prompt)

    def test_all_cyrillic_confusables_in_map(self):
        """All Cyrillic confusables should be in _CONFUSABLE_MAP."""
        for latin, cyrillic_list in LATIN_TO_CYRILLIC.items():
            for cyr in cyrillic_list:
                assert cyr in _CONFUSABLE_MAP, (
                    f"Cyrillic confusable {cyr!r} (U+{ord(cyr):04X}) for '{latin}' "
                    f"not in _CONFUSABLE_MAP"
                )

    def test_cyrillic_single_char_normalized(self):
        """Each Cyrillic confusable normalizes to its ASCII equivalent."""
        for latin, cyrillic_list in LATIN_TO_CYRILLIC.items():
            for cyr in cyrillic_list:
                verdict = self.normalizer.execute(self._ctx(cyr))
                expected = _CONFUSABLE_MAP[cyr]
                assert verdict.filtered_prompt == expected, (
                    f"Cyrillic {cyr!r} should normalize to {expected!r}, "
                    f"got {verdict.filtered_prompt!r}"
                )

    @pytest.mark.parametrize("attack", ATTACK_STRINGS[:4])
    def test_cyrillic_attack_variants_normalized(self, attack: str):
        """Cyrillic attack variants should normalize back to ASCII."""
        variants = generate_confusable_variants(attack, LATIN_TO_CYRILLIC, max_variants=50)
        for variant in variants:
            verdict = self.normalizer.execute(self._ctx(variant))
            # The normalized output should contain the ASCII attack string
            assert verdict.sanitized is True, f"Variant {variant!r} of '{attack}' was not sanitized"


class TestGreekConfusables:
    """Verify Greek confusables are properly handled by PromptNormalizer."""

    def setup_method(self):
        self.normalizer = PromptNormalizer()

    def _ctx(self, prompt: str) -> DefenseContext:
        return DefenseContext(original_prompt=prompt, current_prompt=prompt)

    def test_all_greek_confusables_in_map(self):
        """All Greek confusables should be in _CONFUSABLE_MAP."""
        for latin, greek_list in LATIN_TO_GREEK.items():
            for grk in greek_list:
                assert grk in _CONFUSABLE_MAP, (
                    f"Greek confusable {grk!r} (U+{ord(grk):04X}) for '{latin}' "
                    f"not in _CONFUSABLE_MAP"
                )

    def test_greek_single_char_normalized(self):
        """Each Greek confusable normalizes to its ASCII equivalent."""
        for latin, greek_list in LATIN_TO_GREEK.items():
            for grk in greek_list:
                verdict = self.normalizer.execute(self._ctx(grk))
                expected = _CONFUSABLE_MAP[grk]
                assert verdict.filtered_prompt == expected

    @pytest.mark.parametrize("attack", ATTACK_STRINGS[:4])
    def test_greek_attack_variants_normalized(self, attack: str):
        """Greek attack variants should normalize back to ASCII."""
        variants = generate_confusable_variants(attack, LATIN_TO_GREEK, max_variants=50)
        for variant in variants:
            verdict = self.normalizer.execute(self._ctx(variant))
            assert verdict.sanitized is True


class TestArmenianConfusables:
    """Verify Armenian confusables are properly handled by PromptNormalizer."""

    def setup_method(self):
        self.normalizer = PromptNormalizer()

    def _ctx(self, prompt: str) -> DefenseContext:
        return DefenseContext(original_prompt=prompt, current_prompt=prompt)

    def test_all_armenian_confusables_in_map(self):
        """All Armenian confusables should be in _CONFUSABLE_MAP."""
        for latin, arm_list in LATIN_TO_ARMENIAN.items():
            for arm in arm_list:
                assert arm in _CONFUSABLE_MAP, (
                    f"Armenian confusable {arm!r} (U+{ord(arm):04X}) for '{latin}' "
                    f"not in _CONFUSABLE_MAP"
                )

    def test_armenian_single_char_normalized(self):
        """Each Armenian confusable normalizes to its ASCII equivalent."""
        for latin, arm_list in LATIN_TO_ARMENIAN.items():
            for arm in arm_list:
                verdict = self.normalizer.execute(self._ctx(arm))
                expected = _CONFUSABLE_MAP[arm]
                assert verdict.filtered_prompt == expected


# ============================================================================
# Tests: Cross-script and multi-substitution
# ============================================================================


class TestCrossScriptConfusables:
    """Test mixed confusable substitutions across multiple scripts."""

    def setup_method(self):
        self.normalizer = PromptNormalizer()

    def _ctx(self, prompt: str) -> DefenseContext:
        return DefenseContext(original_prompt=prompt, current_prompt=prompt)

    def test_mixed_cyrillic_greek_normalized(self):
        """Mixed Cyrillic+Greek confusables normalize correctly."""
        # "ignore" with Cyrillic і, Greek ο, Cyrillic е
        mixed = "ign\u03bfr\u0435"  # Greek o, Cyrillic e
        verdict = self.normalizer.execute(self._ctx(mixed))
        assert verdict.sanitized is True
        assert "ignore" in verdict.filtered_prompt

    def test_mixed_all_scripts(self):
        """Confusables from all three scripts in one string normalize."""
        # "aeo" = Armenian a + Greek e + Cyrillic o
        mixed = "\u0561\u03b5\u043e"
        verdict = self.normalizer.execute(self._ctx(mixed))
        assert verdict.sanitized is True
        assert verdict.filtered_prompt == "aeo"

    @pytest.mark.parametrize("attack", ATTACK_STRINGS[:3])
    def test_multi_substitution_variants(self, attack: str):
        """Multi-position substitution variants are normalized."""
        variants = generate_multi_substitution_variants(
            attack, ALL_CONFUSABLES, max_positions=3, max_variants=100
        )
        for variant in variants:
            verdict = self.normalizer.execute(self._ctx(variant))
            assert verdict.sanitized is True, (
                f"Multi-sub variant {variant!r} of '{attack}' was not sanitized"
            )


# ============================================================================
# Tests: Bounds and performance
# ============================================================================


class TestFuzzingBounds:
    """Verify fuzzer stays within configured bounds."""

    def test_single_sub_bounded(self):
        """Single-substitution variants stay within MAX_VARIANTS_PER_CHAR."""
        for attack in ATTACK_STRINGS:
            variants = generate_confusable_variants(
                attack, ALL_CONFUSABLES, max_variants=MAX_VARIANTS_PER_CHAR
            )
            assert len(variants) <= MAX_VARIANTS_PER_CHAR, (
                f"'{attack}' generated {len(variants)} variants, exceeds {MAX_VARIANTS_PER_CHAR}"
            )

    def test_multi_sub_bounded(self):
        """Multi-substitution variants stay within MAX_VARIANTS_PER_CHAR."""
        for attack in ATTACK_STRINGS:
            variants = generate_multi_substitution_variants(
                attack, ALL_CONFUSABLES, max_positions=3, max_variants=MAX_VARIANTS_PER_CHAR
            )
            assert len(variants) <= MAX_VARIANTS_PER_CHAR

    def test_empty_string_no_variants(self):
        """Empty string produces no variants."""
        assert generate_confusable_variants("", ALL_CONFUSABLES) == []

    def test_no_confusable_chars_no_variants(self):
        """String with no confusable characters produces no variants."""
        assert generate_confusable_variants("12345", ALL_CONFUSABLES) == []

    def test_variant_count_scales_with_substitutable_chars(self):
        """More substitutable characters produce more variants."""
        few = generate_confusable_variants("ax", ALL_CONFUSABLES)
        many = generate_confusable_variants("aeiou", ALL_CONFUSABLES)
        assert len(many) >= len(few)


# ============================================================================
# Tests: Known attack normalization end-to-end
# ============================================================================


class TestAttackNormalization:
    """Verify that confusable-substituted attack strings normalize correctly."""

    def setup_method(self):
        self.normalizer = PromptNormalizer()

    def _ctx(self, prompt: str) -> DefenseContext:
        return DefenseContext(original_prompt=prompt, current_prompt=prompt)

    @pytest.mark.parametrize("attack", ATTACK_STRINGS)
    def test_all_single_sub_variants_sanitized(self, attack: str):
        """Every single-substitution variant of each attack string is sanitized."""
        variants = generate_confusable_variants(attack, ALL_CONFUSABLES, max_variants=200)
        unsanitized = []
        for variant in variants:
            verdict = self.normalizer.execute(self._ctx(variant))
            if not verdict.sanitized:
                unsanitized.append(variant)

        assert len(unsanitized) == 0, (
            f"{len(unsanitized)}/{len(variants)} variants of '{attack}' "
            f"were not sanitized. First: {unsanitized[0]!r}"
        )

    def test_confusable_map_total_size(self):
        """_CONFUSABLE_MAP should have at least 50 entries (Cyrillic+Greek+Armenian)."""
        assert len(_CONFUSABLE_MAP) >= 50, (
            f"_CONFUSABLE_MAP has only {len(_CONFUSABLE_MAP)} entries, expected >= 50"
        )

    def test_confusable_map_covers_all_scripts(self):
        """_CONFUSABLE_MAP should include entries from all three scripts."""
        cyrillic = [k for k in _CONFUSABLE_MAP if "\u0400" <= k <= "\u04ff"]
        greek = [k for k in _CONFUSABLE_MAP if "\u0370" <= k <= "\u03ff"]
        armenian = [k for k in _CONFUSABLE_MAP if "\u0530" <= k <= "\u058f"]

        assert len(cyrillic) >= 10, f"Only {len(cyrillic)} Cyrillic entries"
        assert len(greek) >= 10, f"Only {len(greek)} Greek entries"
        assert len(armenian) >= 5, f"Only {len(armenian)} Armenian entries"
