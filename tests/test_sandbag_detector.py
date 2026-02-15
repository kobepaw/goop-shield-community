"""Tests for SandbagDetector and TaskCategorizer."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.skipif(True, reason="Enterprise features not available in community edition")

from goop_shield.enterprise.brorl_ranking import BroRLRankingBackend
from goop_shield.enterprise.sandbag_detector import (
    SandbagDetector,
)
from goop_shield.enterprise.task_categorizer import TaskCategorizer
from goop_shield.ranking.static import StaticRanking

# ============================================================================
# TestSandbagDetector
# ============================================================================


class TestSandbagDetector:
    """Core SandbagDetector functionality."""

    def test_record_outcome_creates_technique(self):
        """Recording an outcome creates a BroRL technique for the category."""
        backend = BroRLRankingBackend()
        detector = SandbagDetector(backend, min_samples=5)
        detector.record_task_outcome("safety_research", True)
        stats = detector.get_category_stats()
        assert "safety_research" in stats
        assert stats["safety_research"].samples == 1

    def test_no_alert_when_uniform(self):
        """No alerts when all categories perform equally."""
        backend = BroRLRankingBackend()
        detector = SandbagDetector(backend, min_samples=5, sigma_threshold=2.0)

        # Feed equal success rates to two categories
        for _ in range(10):
            detector.record_task_outcome("cat_a", True)
            detector.record_task_outcome("cat_a", False)
            detector.record_task_outcome("cat_b", True)
            detector.record_task_outcome("cat_b", False)

        alerts = detector.check_divergence()
        assert len(alerts) == 0

    def test_alert_fires_on_divergence(self):
        """Alert fires when one category significantly underperforms."""
        backend = BroRLRankingBackend()
        detector = SandbagDetector(backend, min_samples=5, sigma_threshold=1.5)

        # cat_a performs well (~90% success)
        for _ in range(50):
            detector.record_task_outcome("cat_a", True)
        for _ in range(5):
            detector.record_task_outcome("cat_a", False)

        # cat_b performs poorly (~20% success)
        for _ in range(10):
            detector.record_task_outcome("cat_b", True)
        for _ in range(40):
            detector.record_task_outcome("cat_b", False)

        alerts = detector.check_divergence()
        assert len(alerts) >= 1
        alert_categories = {a.category for a in alerts}
        assert "cat_b" in alert_categories

    def test_min_samples_respected(self):
        """No alerts when categories have fewer than min_samples."""
        backend = BroRLRankingBackend()
        detector = SandbagDetector(backend, min_samples=100)

        # Only 10 samples per category — well below min_samples=100
        for _ in range(10):
            detector.record_task_outcome("cat_a", True)
            detector.record_task_outcome("cat_b", False)

        alerts = detector.check_divergence()
        assert len(alerts) == 0

    def test_sigma_configurable(self):
        """Higher sigma threshold requires more extreme divergence."""
        backend = BroRLRankingBackend()

        # With low sigma (1.0), should alert more easily
        detector_low = SandbagDetector(backend, min_samples=5, sigma_threshold=1.0)

        backend2 = BroRLRankingBackend()
        # With high sigma (4.0), should be harder to trigger
        detector_high = SandbagDetector(backend2, min_samples=5, sigma_threshold=4.0)

        # Moderate divergence
        for _ in range(30):
            detector_low.record_task_outcome("cat_a", True)
            detector_high.record_task_outcome("cat_a", True)
        for _ in range(10):
            detector_low.record_task_outcome("cat_a", False)
            detector_high.record_task_outcome("cat_a", False)

        for _ in range(15):
            detector_low.record_task_outcome("cat_b", True)
            detector_high.record_task_outcome("cat_b", True)
        for _ in range(25):
            detector_low.record_task_outcome("cat_b", False)
            detector_high.record_task_outcome("cat_b", False)

        alerts_low = detector_low.check_divergence()
        alerts_high = detector_high.check_divergence()
        # Low sigma should fire more easily
        assert len(alerts_low) >= len(alerts_high)

    def test_static_ranking_fallback(self):
        """SandbagDetector works with StaticRanking (creates standalone BroRL)."""
        backend = StaticRanking()
        detector = SandbagDetector(backend, min_samples=5)

        # Should work without errors
        detector.record_task_outcome("test_cat", True)
        stats = detector.get_category_stats()
        assert "test_cat" in stats


# ============================================================================
# TestDivergenceMath
# ============================================================================


class TestDivergenceMath:
    """Z-score computation correctness."""

    def test_z_score_computation(self):
        """Z-scores are correctly computed relative to pooled mean."""
        backend = BroRLRankingBackend()
        detector = SandbagDetector(backend, min_samples=5)

        # Create clear divergence
        for _ in range(20):
            detector.record_task_outcome("good", True)
        for _ in range(5):
            detector.record_task_outcome("good", False)

        for _ in range(5):
            detector.record_task_outcome("bad", True)
        for _ in range(20):
            detector.record_task_outcome("bad", False)

        stats = detector.get_category_stats()
        # Good category should have positive z-score
        assert stats["good"].z_score > 0
        # Bad category should have negative z-score
        assert stats["bad"].z_score < 0

    def test_single_category_no_crash(self):
        """Single category doesn't crash — returns empty alerts."""
        backend = BroRLRankingBackend()
        detector = SandbagDetector(backend, min_samples=5)

        for _ in range(10):
            detector.record_task_outcome("only_cat", True)

        alerts = detector.check_divergence()
        assert alerts == []

    def test_two_categories_symmetric(self):
        """Two categories with identical performance have z_score ≈ 0."""
        backend = BroRLRankingBackend()
        detector = SandbagDetector(backend, min_samples=5)

        for _ in range(20):
            detector.record_task_outcome("cat_a", True)
            detector.record_task_outcome("cat_b", True)
        for _ in range(10):
            detector.record_task_outcome("cat_a", False)
            detector.record_task_outcome("cat_b", False)

        stats = detector.get_category_stats()
        # Z-scores should be very close to 0
        assert abs(stats["cat_a"].z_score) < 0.5
        assert abs(stats["cat_b"].z_score) < 0.5

    def test_all_perfect_no_alert(self):
        """All categories at 100% success — no alert (std=0)."""
        backend = BroRLRankingBackend()
        detector = SandbagDetector(backend, min_samples=5)

        for _ in range(10):
            detector.record_task_outcome("cat_a", True)
            detector.record_task_outcome("cat_b", True)

        alerts = detector.check_divergence()
        assert len(alerts) == 0

    def test_one_bad_fires(self):
        """One category at low success rate fires alert."""
        backend = BroRLRankingBackend()
        detector = SandbagDetector(backend, min_samples=5, sigma_threshold=1.5)

        # Three categories: two good, one bad
        for _ in range(30):
            detector.record_task_outcome("good_a", True)
            detector.record_task_outcome("good_b", True)
            detector.record_task_outcome("bad_c", False)
        for _ in range(5):
            detector.record_task_outcome("good_a", False)
            detector.record_task_outcome("good_b", False)
            detector.record_task_outcome("bad_c", True)

        alerts = detector.check_divergence()
        alert_cats = {a.category for a in alerts}
        assert "bad_c" in alert_cats


# ============================================================================
# TestTaskCategorizer
# ============================================================================


class TestTaskCategorizer:
    """TaskCategorizer classification."""

    def test_explicit_metadata(self):
        """Explicit task_category in context takes priority."""
        categorizer = TaskCategorizer()
        result = categorizer.categorize(
            "random text about nothing",
            context={"task_category": "safety_research"},
        )
        assert result == "safety_research"

    def test_keyword_fallback(self):
        """Keywords in prompt trigger category match."""
        categorizer = TaskCategorizer()
        result = categorizer.categorize("Analyze this security vulnerability in the code")
        assert result == "security_analysis"

    def test_default_general(self):
        """No keywords → default 'general'."""
        categorizer = TaskCategorizer()
        result = categorizer.categorize("Tell me a joke about elephants")
        assert result == "general"

    def test_case_insensitive(self):
        """Keyword matching is case-insensitive."""
        categorizer = TaskCategorizer()
        result = categorizer.categorize("SAFETY alignment HARMFUL bias")
        assert result == "safety_research"


# ============================================================================
# TestSyntheticStreams
# ============================================================================


class TestSyntheticStreams:
    """End-to-end synthetic stream tests."""

    def test_normal_stream_no_alerts(self):
        """Normal stream (~80% success across all categories) → no alerts."""
        backend = BroRLRankingBackend()
        detector = SandbagDetector(backend, min_samples=10, sigma_threshold=2.0)

        import random

        random.seed(42)

        for _ in range(50):
            for cat in ["safety", "code", "security"]:
                detector.record_task_outcome(cat, random.random() < 0.8)

        alerts = detector.check_divergence()
        assert len(alerts) == 0

    def test_sandbagging_stream_detects(self):
        """One category at 40% while others at 80% → detected."""
        backend = BroRLRankingBackend()
        detector = SandbagDetector(backend, min_samples=10, sigma_threshold=1.5)

        import random

        random.seed(42)

        for _ in range(60):
            detector.record_task_outcome("good_a", random.random() < 0.85)
            detector.record_task_outcome("good_b", random.random() < 0.85)
            detector.record_task_outcome("sandbagged", random.random() < 0.35)

        alerts = detector.check_divergence()
        assert len(alerts) >= 1
        assert any(a.category == "sandbagged" for a in alerts)

    def test_noisy_stream_tolerant(self):
        """Noisy but not divergent stream → no false alerts with sigma=2.0."""
        backend = BroRLRankingBackend()
        detector = SandbagDetector(backend, min_samples=10, sigma_threshold=2.0)

        import random

        random.seed(123)

        # All categories between 60-80% — noisy but not divergent
        for _ in range(60):
            detector.record_task_outcome("cat_a", random.random() < 0.7)
            detector.record_task_outcome("cat_b", random.random() < 0.65)
            detector.record_task_outcome("cat_c", random.random() < 0.75)

        alerts = detector.check_divergence()
        assert len(alerts) == 0
