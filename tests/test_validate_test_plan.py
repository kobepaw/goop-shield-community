"""Tests for the PR test plan validation script."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# Import the module under test
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".github" / "scripts"))
from validate_test_plan import (
    parse_test_plan,
    validate_command,
    validate_test_plan,
)

# ---------------------------------------------------------------------------
# Fixtures — reusable PR bodies
# ---------------------------------------------------------------------------

WELL_FORMED_BODY = """\
## Summary

Add a new defense for XSS detection.

## Type of change

- [x] New feature (non-breaking change that adds functionality)
- [ ] Bug fix (non-breaking change that fixes an issue)

## Test Plan

### Automated Tests
- [ ] `pytest tests/test_app.py -v` — Validates API endpoints
- [x] `pytest tests/test_defender.py -v -k "test_pipeline"` — Validates defense pipeline

### Manual Verification (optional)
- [ ] Verified locally that the new defense catches XSS payloads

## Checklist

- [x] Tests pass locally
"""

DOC_ONLY_BODY = """\
## Summary

Update README.

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [x] Documentation update

## Test Plan

### Automated Tests

### Manual Verification (optional)
- [x] Verified docs render correctly

## Checklist

- [x] Documentation updated
"""

NO_TEST_PLAN_BODY = """\
## Summary

Random change.

## Type of change

- [x] Bug fix (non-breaking change that fixes an issue)

## Test Plan

### Automated Tests

### Manual Verification (optional)

## Checklist

- [ ] Tests pass locally
"""

MISSING_SECTION_BODY = """\
## Summary

No test plan section at all.

## Type of change

- [x] Bug fix (non-breaking change that fixes an issue)

## Checklist

- [ ] Tests pass locally
"""


# ---------------------------------------------------------------------------
# parse_test_plan
# ---------------------------------------------------------------------------


class TestParseTestPlan:
    def test_extracts_automated_commands(self):
        plan = parse_test_plan(WELL_FORMED_BODY)
        assert len(plan["automated"]) == 2
        assert plan["automated"][0]["command"] == "pytest tests/test_app.py -v"
        assert (
            plan["automated"][1]["command"] == 'pytest tests/test_defender.py -v -k "test_pipeline"'
        )

    def test_extracts_descriptions(self):
        plan = parse_test_plan(WELL_FORMED_BODY)
        assert plan["automated"][0]["description"] == "Validates API endpoints"

    def test_extracts_manual_items(self):
        plan = parse_test_plan(WELL_FORMED_BODY)
        assert len(plan["manual"]) == 1
        assert "XSS payloads" in plan["manual"][0]

    def test_detects_doc_only(self):
        plan = parse_test_plan(DOC_ONLY_BODY)
        assert plan["is_doc_only"] is True

    def test_not_doc_only_when_other_types(self):
        plan = parse_test_plan(WELL_FORMED_BODY)
        assert plan["is_doc_only"] is False

    def test_empty_body(self):
        plan = parse_test_plan("")
        assert plan["automated"] == []
        assert plan["manual"] == []
        assert plan["is_doc_only"] is False

    def test_none_like_body(self):
        plan = parse_test_plan("   \n\n  ")
        assert plan["automated"] == []

    def test_missing_test_plan_section(self):
        plan = parse_test_plan(MISSING_SECTION_BODY)
        assert plan["automated"] == []
        assert plan["manual"] == []

    def test_no_automated_items(self):
        plan = parse_test_plan(NO_TEST_PLAN_BODY)
        assert plan["automated"] == []

    def test_doc_plus_feature_not_doc_only(self):
        body = DOC_ONLY_BODY.replace("- [ ] Bug fix", "- [x] Bug fix")
        plan = parse_test_plan(body)
        assert plan["is_doc_only"] is False


# ---------------------------------------------------------------------------
# validate_command
# ---------------------------------------------------------------------------


class TestValidateCommand:
    def test_valid_pytest(self):
        errors = validate_command("pytest tests/test_app.py -v")
        assert errors == []

    def test_rejects_non_pytest(self):
        errors = validate_command("bash run_tests.sh")
        assert any("Only pytest" in e for e in errors)

    def test_rejects_rm(self):
        errors = validate_command("rm -rf /")
        assert any("Only pytest" in e for e in errors)

    def test_rejects_curl(self):
        errors = validate_command("curl http://evil.com")
        assert any("Only pytest" in e for e in errors)

    def test_rejects_disallowed_flags(self):
        errors = validate_command("pytest tests/test_app.py --no-header")
        assert any("--no-header" in e for e in errors)

    def test_rejects_collect_only(self):
        errors = validate_command("pytest tests/test_app.py --collect-only")
        assert any("--collect-only" in e for e in errors)

    def test_nonexistent_file(self):
        errors = validate_command("pytest tests/test_does_not_exist_xyz.py -v")
        assert any("not found" in e for e in errors)

    def test_existing_file(self):
        # This file exists (it's the file you're reading!)
        errors = validate_command("pytest tests/test_validate_test_plan.py -v")
        assert errors == []

    def test_empty_command(self):
        errors = validate_command("")
        assert any("Empty" in e for e in errors)

    def test_pytest_with_flags_only(self):
        errors = validate_command("pytest -v --tb=short")
        assert errors == []

    def test_node_id_syntax(self):
        errors = validate_command("pytest tests/test_validate_test_plan.py::TestValidateCommand -v")
        assert errors == []


# ---------------------------------------------------------------------------
# validate_test_plan (integration, dry-run mode)
# ---------------------------------------------------------------------------


class TestValidateTestPlan:
    def test_well_formed_dry_run(self):
        report = validate_test_plan(WELL_FORMED_BODY, run_tests=False)
        assert report["failed"] == 0
        # 2 automated (skipped in dry run) + 1 manual
        assert report["skipped"] == 3
        assert len(report["items"]) == 3

    def test_doc_only_skips(self):
        report = validate_test_plan(DOC_ONLY_BODY, run_tests=False)
        assert report["failed"] == 0
        assert report["skipped"] == 1
        assert "doc-only" in report["items"][0]["command"]

    def test_missing_test_plan_fails(self):
        report = validate_test_plan(NO_TEST_PLAN_BODY, run_tests=False)
        assert report["failed"] == 1
        assert "missing test plan" in report["items"][0]["command"]

    def test_empty_body_fails(self):
        report = validate_test_plan("", run_tests=False)
        assert report["failed"] == 1

    def test_no_section_at_all_fails(self):
        report = validate_test_plan(MISSING_SECTION_BODY, run_tests=False)
        assert report["failed"] == 1

    def test_invalid_command_reported(self):
        body = WELL_FORMED_BODY.replace(
            "pytest tests/test_app.py -v",
            "bash evil.sh",
        )
        report = validate_test_plan(body, run_tests=False)
        assert report["failed"] == 1
        assert "Only pytest" in report["items"][0]["output"]

    def test_manual_items_are_skipped(self):
        report = validate_test_plan(WELL_FORMED_BODY, run_tests=False)
        manual_items = [i for i in report["items"] if "(manual)" in i["command"]]
        assert len(manual_items) == 1
        assert manual_items[0]["status"] == "skipped"

    def test_run_tests_actually_runs(self):
        body = """\
## Type of change

- [x] New feature (non-breaking change that adds functionality)

## Test Plan

### Automated Tests
- [ ] `pytest tests/test_validate_test_plan.py::TestParseTestPlan::test_empty_body -v` — Smoke test
"""
        report = validate_test_plan(body, run_tests=True)
        assert report["passed"] == 1
        assert report["failed"] == 0
        assert report["items"][0]["duration_ms"] > 0

    def test_report_json_serialisable(self):
        report = validate_test_plan(WELL_FORMED_BODY, run_tests=False)
        # Should not raise
        json.dumps(report)


# ---------------------------------------------------------------------------
# CLI (via subprocess)
# ---------------------------------------------------------------------------


class TestCLI:
    def test_dry_run_flag(self, tmp_path):
        body_file = tmp_path / "body.md"
        body_file.write_text(WELL_FORMED_BODY)
        output_file = tmp_path / "report.json"

        result = subprocess.run(
            [
                sys.executable,
                str(
                    Path(__file__).resolve().parents[1]
                    / ".github"
                    / "scripts"
                    / "validate_test_plan.py"
                ),
                "--body-file",
                str(body_file),
                "--output",
                str(output_file),
                "--dry-run",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        report = json.loads(output_file.read_text())
        assert report["failed"] == 0

    def test_missing_body_exits_2(self):
        result = subprocess.run(
            [
                sys.executable,
                str(
                    Path(__file__).resolve().parents[1]
                    / ".github"
                    / "scripts"
                    / "validate_test_plan.py"
                ),
            ],
            capture_output=True,
            text=True,
            env={k: v for k, v in __import__("os").environ.items() if k != "PR_BODY"},
        )
        assert result.returncode == 2

    def test_failing_plan_exits_1(self, tmp_path):
        body_file = tmp_path / "body.md"
        body_file.write_text(NO_TEST_PLAN_BODY)
        output_file = tmp_path / "report.json"

        result = subprocess.run(
            [
                sys.executable,
                str(
                    Path(__file__).resolve().parents[1]
                    / ".github"
                    / "scripts"
                    / "validate_test_plan.py"
                ),
                "--body-file",
                str(body_file),
                "--output",
                str(output_file),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
