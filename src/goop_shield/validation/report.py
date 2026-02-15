# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Shield Proof Document Generator

Generates stakeholder-ready markdown reports from validation results.
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class ProofDocumentGenerator:
    """Generates validation proof documents from Shield test results."""

    def generate(self, results: dict) -> str:
        """Generate a full markdown proof document from validation results."""
        lines: list[str] = []

        lines.append("# Shield — Validation Proof Document")
        lines.append("")
        lines.append(f"**Generated**: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Total Payloads Tested**: {results.get('total_tested', 0):,}")
        lines.append("")

        # Executive Summary
        lines.append("## 1. Executive Summary")
        lines.append("")
        block_rate = results.get("overall_block_rate", 0)
        fpr = results.get("false_positive_rate", 0)
        nps = results.get("net_protection_score", 0)

        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| **Overall Block Rate** | {block_rate:.1%} |")
        lines.append(f"| **False Positive Rate** | {fpr:.1%} |")
        lines.append(f"| **Net Protection Score** | {nps:.1%} |")
        lines.append(f"| Attack Payloads Tested | {results.get('attack_payloads_tested', 0):,} |")
        lines.append(f"| Attack Payloads Blocked | {results.get('attack_payloads_blocked', 0):,} |")
        lines.append(f"| Benign Payloads Tested | {results.get('benign_payloads_tested', 0):,} |")
        lines.append(f"| Benign False Positives | {results.get('benign_false_positives', 0):,} |")
        lines.append("")

        # Visual summary
        lines.append("### Key Numbers")
        lines.append("")
        lines.append("```")
        lines.append(f"Block Rate:   {self._bar(block_rate)} {block_rate:.1%}")
        lines.append(f"FP Rate:      {self._bar(fpr)} {fpr:.1%}")
        lines.append(f"NPS:          {self._bar(max(0, nps))} {nps:.1%}")
        lines.append("```")
        lines.append("")

        # Per-Category Breakdown
        categories = results.get("categories", {})
        if categories:
            lines.append("## 2. Per-Category Results")
            lines.append("")

            # Attack categories
            lines.append("### Attack Categories")
            lines.append("")
            lines.append(
                "| Category | Total | Blocked | Block Rate | p50 (ms) | p95 (ms) | p99 (ms) |"
            )
            lines.append(
                "|----------|-------|---------|------------|----------|----------|----------|"
            )

            for cat, data in sorted(categories.items()):
                if data.get("is_benign"):
                    continue
                lines.append(
                    f"| {cat} | {data['total']} | {data['blocked']} | "
                    f"{data['block_rate']:.1%} | "
                    f"{data.get('latency_p50', 0):.1f} | "
                    f"{data.get('latency_p95', 0):.1f} | "
                    f"{data.get('latency_p99', 0):.1f} |"
                )
            lines.append("")

            # Benign categories
            lines.append("### Benign Categories (False Positive Analysis)")
            lines.append("")
            lines.append("| Category | Total | False Positives | FP Rate |")
            lines.append("|----------|-------|-----------------|---------|")

            for cat, data in sorted(categories.items()):
                if not data.get("is_benign"):
                    continue
                lines.append(
                    f"| {cat} | {data['total']} | {data['blocked']} | {data['block_rate']:.1%} |"
                )
            lines.append("")

            # Per-category bar charts
            lines.append("### Block Rate Distribution")
            lines.append("")
            lines.append("```")
            for cat, data in sorted(categories.items()):
                if data.get("is_benign"):
                    continue
                label = f"{cat:25s}"
                bar = self._bar(data["block_rate"], width=30)
                lines.append(f"{label} {bar} {data['block_rate']:.0%}")
            lines.append("```")
            lines.append("")

        # Latency Analysis
        lines.append("## 3. Latency Overhead")
        lines.append("")
        all_p50 = [d.get("latency_p50", 0) for d in categories.values()]
        all_p95 = [d.get("latency_p95", 0) for d in categories.values()]
        all_p99 = [d.get("latency_p99", 0) for d in categories.values()]

        if all_p50:
            avg_p50 = sum(all_p50) / len(all_p50)
            avg_p95 = sum(all_p95) / len(all_p95)
            avg_p99 = sum(all_p99) / len(all_p99)
            lines.append("| Percentile | Average Latency |")
            lines.append("|------------|-----------------|")
            lines.append(f"| p50 | {avg_p50:.1f}ms |")
            lines.append(f"| p95 | {avg_p95:.1f}ms |")
            lines.append(f"| p99 | {avg_p99:.1f}ms |")
        lines.append("")

        # Gaps and Recommendations
        lines.append("## 4. Gaps and Recommendations")
        lines.append("")

        weak_categories = []
        for cat, data in categories.items():
            if not data.get("is_benign") and data["block_rate"] < 0.8:
                weak_categories.append((cat, data["block_rate"]))

        if weak_categories:
            lines.append("### Weak Categories (Block Rate < 80%)")
            lines.append("")
            for cat, rate in sorted(weak_categories, key=lambda x: x[1]):
                lines.append(
                    f"- **{cat}**: {rate:.1%} block rate — needs additional defense coverage"
                )
            lines.append("")
        else:
            lines.append("All attack categories have block rates >= 80%.")
            lines.append("")

        high_fp_categories = []
        for cat, data in categories.items():
            if data.get("is_benign") and data["block_rate"] > 0.05:
                high_fp_categories.append((cat, data["block_rate"]))

        if high_fp_categories:
            lines.append("### High False Positive Categories (> 5%)")
            lines.append("")
            for cat, rate in sorted(high_fp_categories, key=lambda x: x[1], reverse=True):
                lines.append(f"- **{cat}**: {rate:.1%} false positive rate — defense tuning needed")
            lines.append("")

        # Methodology
        lines.append("## 5. Methodology")
        lines.append("")
        lines.append(
            "- **Attack corpus**: Programmatically generated payloads across 12+ categories"
        )
        lines.append("- **Real-world samples**: Field deployment IOCs")
        lines.append("- **Measurement**: In-process Defender evaluation (no network overhead)")
        lines.append(
            "- **Metrics**: Block rate, false positive rate, Net Protection Score (NPS = block_rate - FPR)"
        )
        lines.append(
            "- **Defense stack**: 18 inline defenses + 3 output scanners with BroRL adaptive ranking"
        )
        lines.append("")

        lines.append("---")
        lines.append("*Generated by Shield Validation Framework*")

        return "\n".join(lines)

    @staticmethod
    def _bar(value: float, width: int = 20) -> str:
        """Generate an ASCII bar chart."""
        filled = int(value * width)
        return "[" + "#" * filled + "." * (width - filled) + "]"


def generate_report(results: dict) -> str:
    """Convenience function to generate a report."""
    gen = ProofDocumentGenerator()
    return gen.generate(results)
