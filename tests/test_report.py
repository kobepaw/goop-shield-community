"""Tests for Shield proof document generator."""

from __future__ import annotations

import pytest

from goop_shield.validation.report import ProofDocumentGenerator, generate_report


@pytest.fixture
def sample_results():
    """Sample validation results for testing."""
    return {
        "timestamp": 1707500000.0,
        "total_tested": 2500,
        "total_blocked": 1800,
        "overall_block_rate": 0.9,
        "false_positive_rate": 0.02,
        "net_protection_score": 0.88,
        "attack_payloads_tested": 2000,
        "attack_payloads_blocked": 1800,
        "benign_payloads_tested": 500,
        "benign_false_positives": 10,
        "categories": {
            "injection": {
                "total": 200,
                "blocked": 195,
                "allowed": 5,
                "block_rate": 0.975,
                "is_benign": False,
                "latency_p50": 1.2,
                "latency_p95": 3.5,
                "latency_p99": 8.1,
            },
            "jailbreak": {
                "total": 200,
                "blocked": 190,
                "allowed": 10,
                "block_rate": 0.95,
                "is_benign": False,
                "latency_p50": 1.0,
                "latency_p95": 2.8,
                "latency_p99": 6.2,
            },
            "exfiltration": {
                "total": 200,
                "blocked": 180,
                "allowed": 20,
                "block_rate": 0.90,
                "is_benign": False,
                "latency_p50": 1.5,
                "latency_p95": 4.0,
                "latency_p99": 9.0,
            },
            "obfuscation": {
                "total": 200,
                "blocked": 140,
                "allowed": 60,
                "block_rate": 0.70,
                "is_benign": False,
                "latency_p50": 2.0,
                "latency_p95": 5.5,
                "latency_p99": 12.0,
            },
            "benign": {
                "total": 300,
                "blocked": 5,
                "allowed": 295,
                "block_rate": 0.017,
                "is_benign": True,
                "latency_p50": 0.8,
                "latency_p95": 2.0,
                "latency_p99": 4.0,
            },
            "benign_edge": {
                "total": 200,
                "blocked": 5,
                "allowed": 195,
                "block_rate": 0.025,
                "is_benign": True,
                "latency_p50": 1.0,
                "latency_p95": 2.5,
                "latency_p99": 5.0,
            },
        },
    }


class TestProofDocumentGenerator:
    def test_generate_contains_title(self, sample_results):
        gen = ProofDocumentGenerator()
        report = gen.generate(sample_results)
        assert "# Shield" in report
        assert "Validation Proof Document" in report

    def test_generate_contains_summary(self, sample_results):
        gen = ProofDocumentGenerator()
        report = gen.generate(sample_results)
        assert "Executive Summary" in report
        assert "90.0%" in report  # block rate
        assert "2.0%" in report  # FPR

    def test_generate_contains_categories(self, sample_results):
        gen = ProofDocumentGenerator()
        report = gen.generate(sample_results)
        assert "injection" in report
        assert "jailbreak" in report
        assert "exfiltration" in report

    def test_generate_contains_latency(self, sample_results):
        gen = ProofDocumentGenerator()
        report = gen.generate(sample_results)
        assert "Latency" in report
        assert "p50" in report
        assert "p95" in report

    def test_generate_identifies_weak_categories(self, sample_results):
        gen = ProofDocumentGenerator()
        report = gen.generate(sample_results)
        # obfuscation has 70% block rate < 80% threshold
        assert "obfuscation" in report
        assert "70.0%" in report

    def test_bar_chart(self):
        gen = ProofDocumentGenerator()
        bar = gen._bar(0.5, width=10)
        assert bar == "[#####.....]"

        bar = gen._bar(1.0, width=10)
        assert bar == "[##########]"

        bar = gen._bar(0.0, width=10)
        assert bar == "[..........]"

    def test_generate_report_convenience(self, sample_results):
        report = generate_report(sample_results)
        assert isinstance(report, str)
        assert len(report) > 100

    def test_empty_results(self):
        gen = ProofDocumentGenerator()
        report = gen.generate({})
        assert "Shield" in report

    def test_report_methodology_section(self, sample_results):
        gen = ProofDocumentGenerator()
        report = gen.generate(sample_results)
        assert "Methodology" in report
        assert "BroRL" in report
