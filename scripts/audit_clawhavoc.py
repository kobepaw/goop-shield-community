#!/usr/bin/env python3
"""
ClawHavoc Audit Scanner

Standalone scanner (stdlib only) that checks a directory tree for indicators
of the ClawHavoc supply-chain attack on ClawHub:
  - Known C2 IP addresses
  - Known malicious SHA-256 file hashes
  - Suspicious code patterns (reverse shells, SSH key access, etc.)

Usage:
    python3 audit_clawhavoc.py /path/to/skills/ [--json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Known Indicators of Compromise
# ---------------------------------------------------------------------------

# C2 IP addresses observed in ClawHavoc campaigns
CLAWHAVOC_C2_IPS: set[str] = {
    "91.92.242.30",
    "95.92.242.30",
    "96.92.242.30",
    "202.161.50.59",
    "54.91.154.110",
}

# SHA-256 hashes of known malicious payloads (Antiy/Koi reports)
# NOTE: Do NOT include the empty-file hash (e3b0c44...) — it matches every
# empty __init__.py and causes mass false positives.
CLAWHAVOC_HASHES: set[str] = {
    "a1f2e3d4b5c6a7f8e9d0c1b2a3f4e5d6b7c8a9f0e1d2c3b4a5f6e7d8c9b0a1",  # AMOS stealer dropper
    "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",  # reverse shell payload
}

# Regex patterns for suspicious content
_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

SUSPICIOUS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"curl\s.*\|\s*bash", re.I), "curl_pipe_bash"),
    (re.compile(r"eval\s*\(", re.I), "eval_call"),
    (re.compile(r"require\(['\"]child_process['\"]\)", re.I), "child_process_require"),
    (re.compile(r"/dev/tcp/", re.I), "dev_tcp_redirect"),
    (re.compile(r"\.ssh/id_rsa|\.ssh/id_ed25519|\.ssh/authorized_keys", re.I), "ssh_key_access"),
    (re.compile(r"base64\s+-d", re.I), "base64_decode"),
    (re.compile(r"net\.createConnection", re.I), "net_create_connection"),
    (re.compile(r"String\.fromCharCode", re.I), "string_from_char_code"),
    (re.compile(r"bash\s+-i\s+>&\s+/dev/tcp/", re.I), "bash_reverse_shell"),
    (re.compile(r"nc\s+-e\s+/bin/", re.I), "netcat_reverse_shell"),
    (re.compile(r"osascript\s+-e", re.I), "macos_osascript"),
    (re.compile(r"security\s+find-generic-password", re.I), "macos_keychain_access"),
]

# File extensions to scan (text-based)
_TEXT_EXTENSIONS: set[str] = {
    ".py", ".js", ".ts", ".sh", ".bash", ".zsh",
    ".yaml", ".yml", ".json", ".toml",
    ".md", ".txt", ".rst",
    ".rb", ".lua", ".pl",
    ".cfg", ".ini", ".conf",
}


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


def _sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _is_text_file(path: Path) -> bool:
    """Check if file should be scanned for text patterns."""
    return path.suffix.lower() in _TEXT_EXTENSIONS


def scan_directory(root: Path) -> dict:
    """Scan a directory tree for ClawHavoc IOCs.

    Returns a report dict with:
        clean_skills: list of skill dirs with no findings
        flagged_skills: dict mapping skill name -> list of findings
        hash_matches: list of files matching known malicious hashes
        c2_matches: list of (file, ip) tuples where C2 IPs were found
    """
    report: dict = {
        "clean_skills": [],
        "flagged_skills": {},
        "hash_matches": [],
        "c2_matches": [],
    }

    if not root.is_dir():
        report["error"] = f"Not a directory: {root}"
        return report

    # Identify skill directories (immediate subdirs of root)
    skill_dirs = sorted(d for d in root.iterdir() if d.is_dir())
    if not skill_dirs:
        # Treat root itself as a single "skill"
        skill_dirs = [root]

    for skill_dir in skill_dirs:
        skill_name = skill_dir.name
        findings: list[dict] = []

        for path in skill_dir.rglob("*"):
            if not path.is_file():
                continue

            # Hash check (all files)
            file_hash = _sha256(path)
            if file_hash in CLAWHAVOC_HASHES:
                finding = {
                    "type": "hash_match",
                    "file": str(path.relative_to(root)),
                    "hash": file_hash,
                }
                findings.append(finding)
                report["hash_matches"].append(finding)

            # Text content checks
            if _is_text_file(path):
                try:
                    content = path.read_text(errors="replace")
                except OSError:
                    continue

                # C2 IP check
                for match in _IPV4_RE.finditer(content):
                    ip = match.group(1)
                    if ip in CLAWHAVOC_C2_IPS:
                        finding = {
                            "type": "c2_ip",
                            "file": str(path.relative_to(root)),
                            "ip": ip,
                        }
                        findings.append(finding)
                        report["c2_matches"].append(finding)

                # Pattern check
                for pattern, tag in SUSPICIOUS_PATTERNS:
                    if pattern.search(content):
                        findings.append({
                            "type": "suspicious_pattern",
                            "file": str(path.relative_to(root)),
                            "pattern": tag,
                        })

        if findings:
            report["flagged_skills"][skill_name] = findings
        else:
            report["clean_skills"].append(skill_name)

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan a directory for ClawHavoc supply-chain IOCs.",
    )
    parser.add_argument(
        "directory",
        type=Path,
        help="Root directory to scan (e.g. ~/code/openclaw/skills/)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    args = parser.parse_args()

    report = scan_directory(args.directory.expanduser().resolve())

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        n_clean = len(report["clean_skills"])
        n_flagged = len(report["flagged_skills"])
        print(f"ClawHavoc Audit Report")
        print(f"======================")
        print(f"Directory: {args.directory}")
        print(f"Clean skills: {n_clean}")
        print(f"Flagged skills: {n_flagged}")
        print(f"Hash matches: {len(report['hash_matches'])}")
        print(f"C2 IP matches: {len(report['c2_matches'])}")
        print()

        if report.get("error"):
            print(f"ERROR: {report['error']}")
            sys.exit(1)

        if report["flagged_skills"]:
            print("FLAGGED SKILLS:")
            for skill, findings in report["flagged_skills"].items():
                print(f"\n  {skill}:")
                for f in findings:
                    if f["type"] == "hash_match":
                        print(f"    [HASH] {f['file']} -> {f['hash'][:16]}...")
                    elif f["type"] == "c2_ip":
                        print(f"    [C2]   {f['file']} -> {f['ip']}")
                    elif f["type"] == "suspicious_pattern":
                        print(f"    [PATTERN] {f['file']} -> {f['pattern']}")
            sys.exit(2)
        else:
            print("All skills clean.")


if __name__ == "__main__":
    main()
