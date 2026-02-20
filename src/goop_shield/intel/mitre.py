# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield MITRE ATT&CK Mapping

Maps all 20 Shield inline defenses to MITRE ATT&CK techniques,
and provides coverage analysis over audit events.
"""

from __future__ import annotations

from typing import Any

# ============================================================================
# Defense → MITRE ATT&CK mapping
# ============================================================================

DEFENSE_TO_MITRE: dict[str, dict[str, str]] = {
    "prompt_normalizer": {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Detects and neutralizes obfuscation techniques in prompts (Unicode tricks, whitespace evasion).",
    },
    "safety_filter": {
        "id": "T1204",
        "name": "User Execution",
        "tactic": "Execution",
        "description": "Blocks prompts that attempt to trick the model into executing unsafe instructions.",
    },
    "input_validator": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Validates input to prevent command injection and scripting attacks.",
    },
    "injection_blocker": {
        "id": "T1059.007",
        "name": "JavaScript",
        "tactic": "Execution",
        "description": "Blocks prompt injection attempts that embed executable payloads.",
    },
    "context_limiter": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Limits context window abuse to prevent context overflow attacks.",
    },
    "output_filter": {
        "id": "T1565",
        "name": "Data Manipulation",
        "tactic": "Impact",
        "description": "Filters model output to prevent data manipulation and leakage.",
    },
    "prompt_signing": {
        "id": "T1565",
        "name": "Data Manipulation",
        "tactic": "Impact",
        "description": "Cryptographic signing to detect tampered or forged prompts.",
    },
    "output_watermark": {
        "id": "T1565.001",
        "name": "Stored Data Manipulation",
        "tactic": "Impact",
        "description": "Watermarks output to detect unauthorized redistribution or manipulation.",
    },
    "rag_verifier": {
        "id": "T1213",
        "name": "Data from Information Repositories",
        "tactic": "Collection",
        "description": "Verifies RAG retrieval results for poisoned or manipulated documents.",
    },
    "canary_token_detector": {
        "id": "T1567",
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "description": "Detects canary tokens being exfiltrated through model responses.",
    },
    "semantic_filter": {
        "id": "T1204.001",
        "name": "Malicious Link",
        "tactic": "Execution",
        "description": "Semantic analysis to detect socially engineered or deceptive prompts.",
    },
    "obfuscation_detector": {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Detects encoding and obfuscation evasion techniques.",
    },
    "agent_sandbox": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Sandboxes agent tool calls to prevent unauthorized code execution.",
    },
    "rate_limiter": {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Limits request rate to prevent denial of service attacks.",
    },
    "prompt_monitor": {
        "id": "T1557",
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
        "description": "Monitors prompt patterns for adversary-in-the-middle interception.",
    },
    "model_guardrails": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Privilege Escalation",
        "description": "Enforces model guardrails to prevent privilege escalation via persona hijacking.",
    },
    "intent_validator": {
        "id": "T1204",
        "name": "User Execution",
        "tactic": "Execution",
        "description": "Validates user intent to prevent social engineering execution attacks.",
    },
    "exfil_detector": {
        "id": "T1567",
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "description": "Detects data exfiltration attempts through model interactions.",
    },
    "domain_reputation": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Checks domain reputation to detect C2 communication via application protocols.",
    },
    "ioc_matcher": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Matches indicators of compromise for known C2 infrastructure.",
    },
}


# ============================================================================
# Coverage analysis
# ============================================================================


def get_mitre_coverage(audit_events: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute MITRE ATT&CK coverage from audit events.

    For each technique, counts observations and block rates based on
    which defenses triggered in the audit events.

    Returns:
        Dict with 'techniques' (per-technique stats) and 'summary'.
    """
    technique_stats: dict[str, dict[str, Any]] = {}

    for event in audit_events:
        verdicts = event.get("verdicts", [])
        if isinstance(verdicts, str):
            import json

            verdicts = json.loads(verdicts)

        for verdict in verdicts:
            defense_name = verdict.get("defense_name", "")
            mitre = DEFENSE_TO_MITRE.get(defense_name)
            if mitre is None:
                continue

            tid = mitre["id"]
            if tid not in technique_stats:
                technique_stats[tid] = {
                    "id": tid,
                    "name": mitre["name"],
                    "tactic": mitre["tactic"],
                    "observations": 0,
                    "blocks": 0,
                    "defenses": set(),
                }

            technique_stats[tid]["observations"] += 1
            technique_stats[tid]["defenses"].add(defense_name)
            if verdict.get("action") == "block":
                technique_stats[tid]["blocks"] += 1

    # Convert sets to lists for JSON serialization
    for stats in technique_stats.values():
        stats["defenses"] = sorted(stats["defenses"])
        obs = stats["observations"]
        stats["block_rate"] = stats["blocks"] / obs if obs > 0 else 0.0

    # Summary
    all_technique_ids = {m["id"] for m in DEFENSE_TO_MITRE.values()}
    observed_ids = set(technique_stats.keys())

    return {
        "techniques": technique_stats,
        "summary": {
            "total_mapped_techniques": len(all_technique_ids),
            "techniques_observed": len(observed_ids),
            "techniques_not_observed": sorted(all_technique_ids - observed_ids),
            "total_observations": sum(s["observations"] for s in technique_stats.values()),
            "total_blocks": sum(s["blocks"] for s in technique_stats.values()),
        },
    }


def get_mitre_matrix() -> dict[str, list[dict[str, Any]]]:
    """Full tactic -> techniques structure for display.

    Returns a dict mapping tactic names to lists of technique dicts.
    """
    matrix: dict[str, list[dict[str, Any]]] = {}

    # Collect unique techniques (avoid duplicates from multiple defenses)
    seen: set[str] = set()
    for _defense_name, mitre in DEFENSE_TO_MITRE.items():
        tid = mitre["id"]
        tactic = mitre["tactic"]

        if tid not in seen:
            seen.add(tid)
            matrix.setdefault(tactic, []).append(
                {
                    "id": tid,
                    "name": mitre["name"],
                    "description": mitre["description"],
                    "defenses": [],  # Will populate below
                }
            )

    # Populate defense lists per technique
    technique_defenses: dict[str, list[str]] = {}
    for defense_name, mitre in DEFENSE_TO_MITRE.items():
        technique_defenses.setdefault(mitre["id"], []).append(defense_name)

    for tactic_techniques in matrix.values():
        for tech in tactic_techniques:
            tech["defenses"] = sorted(technique_defenses.get(tech["id"], []))

    return matrix
