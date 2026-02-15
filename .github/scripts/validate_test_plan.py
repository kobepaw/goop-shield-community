#!/usr/bin/env python3
"""Parse, validate, and run test plans extracted from PR body markdown.

CI calls this script to enforce structured test plans on pull requests.
Only pytest commands are allowed — no arbitrary shell execution.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# --- Parsing ---


def parse_test_plan(body: str) -> dict:
    """Extract test plan items from a PR body written in markdown.

    Returns a dict with keys:
      - automated: list of {"command": str, "description": str}
      - manual: list of str
      - is_doc_only: bool
    """
    result: dict = {
        "automated": [],
        "manual": [],
        "is_doc_only": False,
    }

    if not body or not body.strip():
        return result

    # Detect doc-only PRs: "Documentation update" checked, nothing else checked.
    doc_checked = bool(re.search(r"- \[x\] Documentation update", body, re.IGNORECASE))
    other_types = [
        r"- \[x\] Bug fix",
        r"- \[x\] New feature",
        r"- \[x\] Breaking change",
        r"- \[x\] Refactoring",
    ]
    has_other = any(re.search(p, body, re.IGNORECASE) for p in other_types)
    if doc_checked and not has_other:
        result["is_doc_only"] = True

    in_automated = False
    in_manual = False
    in_comment = False

    for line in body.splitlines():
        stripped = line.strip()

        # Track HTML comment blocks
        if "<!--" in stripped and "-->" not in stripped:
            in_comment = True
            continue
        if "-->" in stripped:
            in_comment = False
            continue
        if in_comment or stripped.startswith("<!--"):
            continue

        # Section transitions
        if stripped.startswith("### Automated Tests"):
            in_automated = True
            in_manual = False
            continue
        elif stripped.startswith("### Manual Verification"):
            in_automated = False
            in_manual = True
            continue
        elif stripped.startswith("## ") or stripped.startswith("### "):
            in_automated = False
            in_manual = False
            continue

        if in_automated:
            match = re.match(r"- \[[ x]\]\s+`([^`]+)`(?:\s*[—\-]\s*(.*))?", stripped)
            if match:
                result["automated"].append(
                    {
                        "command": match.group(1).strip(),
                        "description": (match.group(2) or "").strip(),
                    }
                )

        if in_manual:
            match = re.match(r"- \[[ x]\]\s+(.*)", stripped)
            if match:
                result["manual"].append(match.group(1).strip())

    return result


# --- Validation ---

ALLOWED_COMMANDS = ("pytest",)
DISALLOWED_FLAGS = ("--no-header", "--co", "--collect-only")


def validate_command(command: str) -> list[str]:
    """Validate a single test command. Returns a list of error messages (empty = ok)."""
    errors: list[str] = []

    parts = command.split()
    if not parts:
        errors.append("Empty command")
        return errors

    if parts[0] not in ALLOWED_COMMANDS:
        errors.append(f"Only pytest commands are allowed, got: {parts[0]}")
        return errors

    for flag in DISALLOWED_FLAGS:
        if flag in parts:
            errors.append(f"Disallowed flag: {flag}")

    # Verify referenced test files exist
    for part in parts[1:]:
        if part.startswith("-"):
            continue
        # Handle test node ids like tests/test_foo.py::test_bar
        path_str = part.split("::")[0]
        if not path_str or path_str.startswith("-"):
            continue
        p = Path(path_str)
        if p.suffix == ".py" and not p.exists():
            errors.append(f"Test file not found: {path_str}")

    return errors


# --- Execution ---

DEFAULT_TIMEOUT = 300  # 5 minutes per command


def run_command(command: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Run a pytest command in a subprocess and return a result dict."""
    start = time.monotonic()
    try:
        parts = command.split()
        if parts and parts[0] == "pytest":
            parts = [sys.executable, "-m", "pytest"] + parts[1:]
        proc = subprocess.run(
            parts,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        # Trim output to last 4000 chars to keep reports manageable
        output = (proc.stdout[-2000:] + "\n" + proc.stderr[-2000:]).strip()
        return {
            "command": command,
            "status": "passed" if proc.returncode == 0 else "failed",
            "output": output,
            "duration_ms": duration_ms,
        }
    except subprocess.TimeoutExpired:
        duration_ms = int((time.monotonic() - start) * 1000)
        return {
            "command": command,
            "status": "failed",
            "output": f"Command timed out after {timeout}s",
            "duration_ms": duration_ms,
        }


# --- Orchestration ---


def validate_test_plan(body: str, *, run_tests: bool = True) -> dict:
    """Parse, validate, and optionally run the test plan from a PR body.

    Returns a JSON-serialisable report dict.
    """
    plan = parse_test_plan(body)

    report: dict = {
        "items": [],
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "errors": [],
    }

    # Doc-only PRs may skip automated tests
    if plan["is_doc_only"] and not plan["automated"]:
        report["items"].append(
            {
                "command": "(doc-only PR — no automated tests required)",
                "status": "skipped",
                "output": "",
                "duration_ms": 0,
            }
        )
        report["skipped"] = 1
        return report

    # Non-doc PRs need at least one automated test
    if not plan["automated"]:
        msg = (
            "No automated test items found in Test Plan. "
            "Non-documentation PRs require at least one pytest command."
        )
        report["errors"].append(msg)
        report["failed"] = 1
        report["items"].append(
            {
                "command": "(missing test plan)",
                "status": "failed",
                "output": msg,
                "duration_ms": 0,
            }
        )
        return report

    # Validate and (optionally) run each command
    for item in plan["automated"]:
        cmd = item["command"]
        validation_errors = validate_command(cmd)

        if validation_errors:
            report["items"].append(
                {
                    "command": cmd,
                    "status": "failed",
                    "output": "Validation errors: " + "; ".join(validation_errors),
                    "duration_ms": 0,
                }
            )
            report["failed"] += 1
            continue

        if run_tests:
            result = run_command(cmd)
            report["items"].append(result)
            if result["status"] == "passed":
                report["passed"] += 1
            else:
                report["failed"] += 1
        else:
            report["items"].append(
                {
                    "command": cmd,
                    "status": "skipped",
                    "output": "Dry run — not executed",
                    "duration_ms": 0,
                }
            )
            report["skipped"] += 1

    # Manual items are informational only
    for manual_item in plan["manual"]:
        report["items"].append(
            {
                "command": f"(manual) {manual_item}",
                "status": "skipped",
                "output": "Manual verification — not auto-run",
                "duration_ms": 0,
            }
        )
        report["skipped"] += 1

    return report


# --- CLI ---


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate PR test plan")
    parser.add_argument("--body-file", help="Path to file containing PR body markdown")
    parser.add_argument("--output", help="Path to write JSON report")
    parser.add_argument(
        "--dry-run", action="store_true", help="Validate commands without running them"
    )
    args = parser.parse_args()

    # Read PR body from file or env
    if args.body_file:
        body = Path(args.body_file).read_text()
    elif "PR_BODY" in os.environ:
        body = os.environ["PR_BODY"]
    else:
        print("Error: Provide --body-file or set PR_BODY env var", file=sys.stderr)
        sys.exit(2)

    report = validate_test_plan(body, run_tests=not args.dry_run)

    # Write JSON report
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2))

    # Print human-readable summary
    print(
        f"\nTest Plan Results: {report['passed']} passed, "
        f"{report['failed']} failed, {report['skipped']} skipped"
    )
    for item in report["items"]:
        icon = {"passed": "✓", "skipped": "⏭", "failed": "✗"}.get(item["status"], "?")
        print(f"  {icon} {item['command']}")

    if report["errors"]:
        for err in report["errors"]:
            print(f"\nError: {err}", file=sys.stderr)

    sys.exit(1 if report["failed"] > 0 else 0)


if __name__ == "__main__":
    main()
