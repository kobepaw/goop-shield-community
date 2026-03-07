"""Tests for the Shield validation corpus and harness."""

from __future__ import annotations

import pytest

from goop_shield.validation.corpus import generate_corpus, get_corpus_stats


@pytest.fixture(scope="module")
def corpus() -> dict[str, list[str]]:
    """Generate corpus once for all tests in this module."""
    return generate_corpus()


class TestCorpusGeneration:
    """Tests for generate_corpus()."""

    EXPECTED_PRIMARY = [
        "injection",
        "jailbreak",
        "exfiltration",
        "obfuscation",
        "tool_abuse",
        "persona_hijack",
        "prompt_extraction",
    ]
    EXPECTED_SECONDARY = [
        "rag_injection",
        "context_overflow",
        "canary_exfil",
        "separator_injection",
        "sandbox_escape",
    ]
    EXPECTED_BENIGN = ["benign", "benign_edge"]
    EXPECTED_REAL_WORLD = ["field_real_world"]

    def test_all_primary_categories_present(self, corpus: dict[str, list[str]]) -> None:
        for cat in self.EXPECTED_PRIMARY:
            assert cat in corpus, f"Missing primary category: {cat}"

    def test_all_secondary_categories_present(self, corpus: dict[str, list[str]]) -> None:
        for cat in self.EXPECTED_SECONDARY:
            assert cat in corpus, f"Missing secondary category: {cat}"

    def test_benign_categories_present(self, corpus: dict[str, list[str]]) -> None:
        for cat in self.EXPECTED_BENIGN:
            assert cat in corpus, f"Missing benign category: {cat}"

    def test_field_category_present(self, corpus: dict[str, list[str]]) -> None:
        for cat in self.EXPECTED_REAL_WORLD:
            assert cat in corpus, f"Missing real-world category: {cat}"

    def test_primary_category_counts(self, corpus: dict[str, list[str]]) -> None:
        for cat in self.EXPECTED_PRIMARY:
            assert len(corpus[cat]) == 200, (
                f"{cat} should have 200 payloads, got {len(corpus[cat])}"
            )

    def test_secondary_category_counts(self, corpus: dict[str, list[str]]) -> None:
        for cat in self.EXPECTED_SECONDARY:
            assert len(corpus[cat]) == 100, (
                f"{cat} should have 100 payloads, got {len(corpus[cat])}"
            )

    def test_benign_category_counts(self, corpus: dict[str, list[str]]) -> None:
        assert len(corpus["benign"]) == 500
        assert len(corpus["benign_edge"]) == 500

    def test_total_category_count(self, corpus: dict[str, list[str]]) -> None:
        expected_count = (
            len(self.EXPECTED_PRIMARY)
            + len(self.EXPECTED_SECONDARY)
            + len(self.EXPECTED_BENIGN)
            + len(self.EXPECTED_REAL_WORLD)
        )
        assert len(corpus) == expected_count


class TestCorpusStats:
    """Tests for get_corpus_stats()."""

    def test_stats_keys_match_corpus(self, corpus: dict[str, list[str]]) -> None:
        stats = get_corpus_stats(corpus)
        assert set(stats.keys()) == set(corpus.keys())

    def test_stats_values_match_lengths(self, corpus: dict[str, list[str]]) -> None:
        stats = get_corpus_stats(corpus)
        for cat, count in stats.items():
            assert count == len(corpus[cat])

    def test_stats_returns_dict_of_ints(self, corpus: dict[str, list[str]]) -> None:
        stats = get_corpus_stats(corpus)
        for value in stats.values():
            assert isinstance(value, int)


class TestFieldPayloads:
    """Tests for field deployment real-world payloads."""

    def test_field_payloads_not_empty(self, corpus: dict[str, list[str]]) -> None:
        assert len(corpus["field_real_world"]) > 0

    def test_field_payloads_contain_known_patterns(self, corpus: dict[str, list[str]]) -> None:
        payloads_text = " ".join(corpus["field_real_world"])
        assert "SYSTEM OVERRIDE" in payloads_text
        assert "webhook.site" in payloads_text
        assert ".env" in payloads_text


class TestBenignPayloads:
    """Tests for benign payloads."""

    def test_benign_payloads_are_strings(self, corpus: dict[str, list[str]]) -> None:
        for payload in corpus["benign"]:
            assert isinstance(payload, str)
            assert len(payload) > 0

    def test_benign_edge_payloads_are_strings(self, corpus: dict[str, list[str]]) -> None:
        for payload in corpus["benign_edge"]:
            assert isinstance(payload, str)
            assert len(payload) > 0


class TestInjectionPayloads:
    """Tests for injection payloads."""

    def test_injection_payloads_contain_patterns(self, corpus: dict[str, list[str]]) -> None:
        payloads_text = " ".join(corpus["injection"]).lower()
        # Should contain at least some of these injection markers
        has_ignore = "ignore" in payloads_text
        has_system = "system" in payloads_text
        has_override = "override" in payloads_text
        has_inst = "inst" in payloads_text
        assert has_ignore or has_system or has_override or has_inst

    def test_injection_payloads_have_variations(self, corpus: dict[str, list[str]]) -> None:
        payloads = corpus["injection"]
        # Not all payloads should be identical
        unique = set(payloads)
        assert len(unique) > 10, "Injection payloads should have variety"
