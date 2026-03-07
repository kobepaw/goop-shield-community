# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Application Guard Defenses — Config mutation, credential path, and alignment protection.

These defenses detect prompts attempting to manipulate application configuration,
exfiltrate credentials, or override AI alignment constraints.
"""

from __future__ import annotations

import re

from goop_shield.defenses.base import PatternBasedDefense

# ============================================================================
# ConfigMutationGuard patterns
# ============================================================================

# Strong signals (0.5 each) — direct config file write, env var injection,
# hot-reload manipulation
_CONFIG_STRONG_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Direct config file write instructions
    (
        re.compile(
            r"(?:write\s+to|modify\s+the)\s+(?:the\s+)?config(?:\s+file)?"
            r"|echo\s+.*>\s*config\.json"
            r"|writeConfigFile|setConfigOverride",
            re.I,
        ),
        "config_file_write",
    ),
    # Env var injection — NODE_OPTIONS, LD_PRELOAD
    (
        re.compile(
            r"NODE_OPTIONS\s*="
            r"|LD_PRELOAD\s*="
            r"|set\s+NODE_OPTIONS\b"
            r"|export\s+LD_PRELOAD\b",
            re.I,
        ),
        "env_var_injection",
    ),
    # Hot-reload manipulation
    (
        re.compile(
            r"(?:reload|trigger\s+(?:a\s+)?(?:config|configuration)\s+reload)\s+config"
            r"|trigger\s+config\s+reload",
            re.I,
        ),
        "hot_reload_manipulation",
    ),
]

# Medium signals (0.35 each) — config path references, runtime overrides,
# env var manipulation
_CONFIG_MEDIUM_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Config path references
    (
        re.compile(
            r"openclaw\.config"
            r"|\.openclaw/config"
            r"|config\.(?:json|yaml|yml|toml)\b",
            re.I,
        ),
        "config_path_reference",
    ),
    # Runtime override instructions
    (
        re.compile(
            r"override\s+the\s+setting"
            r"|change\s+the\s+default"
            r"|set\s+the\s+value\s+to",
            re.I,
        ),
        "runtime_override",
    ),
    # Env var manipulation
    (
        re.compile(
            r"process\.env\b"
            r"|set\s+environment\s+variable",
            re.I,
        ),
        "env_var_manipulation",
    ),
]

# Weak signals (0.2 each) — general config mentions, vague override language
_CONFIG_WEAK_PATTERNS: list[tuple[re.Pattern, str]] = [
    # General config mentions
    (
        re.compile(
            r"\bconfiguration\b"
            r"|settings\s+file"
            r"|preferences\b",
            re.I,
        ),
        "general_config_mention",
    ),
    # Vague override language
    (
        re.compile(
            r"change\s+the\s+config"
            r"|update\s+settings",
            re.I,
        ),
        "vague_override",
    ),
]

# ============================================================================
# CredentialPathGuard patterns
# ============================================================================

# Strong signals (0.5 each) — direct credential file paths, exfil instructions
_CRED_STRONG_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Direct credential file paths
    (
        re.compile(
            r"\.openclaw/credentials"
            r"|credentials\.json"
            r"|~/\.ssh/id_rsa"
            r"|\.env\b"
            r"|secrets\.yaml"
            r"|/etc/shadow"
            r"|\.aws/credentials"
            r"|\.kube/config",
            re.I,
        ),
        "credential_file_path",
    ),
    # Credential exfiltration instructions
    (
        re.compile(
            r"send\s+the\s+(?:api\s+)?key"
            r"|output\s+the\s+token"
            r"|show\s+me\s+the\s+password"
            r"|base64\s+encode\s+the\s+key",
            re.I,
        ),
        "credential_exfil_instruction",
    ),
]

# Medium signals (0.35 each) — credential-adjacent paths, key/secret extraction
_CRED_MEDIUM_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Credential-adjacent paths
    (
        re.compile(
            r"\.openclaw/sessions"
            r"|oauth\.json"
            r"|\.npmrc\b"
            r"|\.pypirc\b"
            r"|token\.json",
            re.I,
        ),
        "credential_adjacent_path",
    ),
    # Key/secret extraction patterns
    (
        re.compile(
            r"extract.*(?:key|token|secret|password)"
            r"|read.*(?:credentials|secrets|keys)",
            re.I,
        ),
        "key_secret_extraction",
    ),
]

# Weak signals (0.2 each) — generic secret references, file read near
# sensitive directories
_CRED_WEAK_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Generic secret references
    (
        re.compile(
            r"api\s+key"
            r"|access\s+token"
            r"|secret\s+key"
            r"|private\s+key",
            re.I,
        ),
        "generic_secret_reference",
    ),
    # File read patterns near sensitive directories
    (
        re.compile(
            r"(?:read|cat|open|display)\s+.*(?:~/\.|/home/.*?/\.)"
            r"|(?:read|cat|open|display)\s+.*/etc/(?:passwd|shadow|hosts)",
            re.I,
        ),
        "sensitive_dir_read",
    ),
]

# ============================================================================
# AlignmentInlineDefense patterns
# ============================================================================

# Strong signals (0.5 each) — identity override, goal hijacking,
# constraint removal
_ALIGN_STRONG_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Identity override
    (
        re.compile(
            r"you\s+are\s+now\b"
            r"|forget\s+your\s+instructions"
            r"|ignore\s+previous\s+instructions"
            r"|your\s+new\s+role\s+is"
            r"|from\s+now\s+on\s+you\s+are"
            r"|system\s+prompt\s+override",
            re.I,
        ),
        "identity_override",
    ),
    # Goal hijacking
    (
        re.compile(
            r"your\s+real\s+purpose\s+is"
            r"|your\s+true\s+goal\s+is"
            r"|secretly\s+you\s+should",
            re.I,
        ),
        "goal_hijacking",
    ),
    # Constraint removal
    (
        re.compile(
            r"ignore\s+all\s+restrictions"
            r"|remove\s+all\s+limits"
            r"|you\s+have\s+no\s+restrictions"
            r"|act\s+without\s+constraints",
            re.I,
        ),
        "constraint_removal",
    ),
]

# Medium signals (0.35 each) — behavioral modification, role manipulation,
# instruction injection
_ALIGN_MEDIUM_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Behavioral modification
    (
        re.compile(
            r"change\s+your\s+behavior"
            r"|modify\s+your\s+personality"
            r"|adjust\s+your\s+guidelines"
            r"|update\s+your\s+rules",
            re.I,
        ),
        "behavioral_modification",
    ),
    # Role manipulation
    (
        re.compile(
            r"pretend\s+you\s+are"
            r"|act\s+as\s+if\s+you\s+are"
            r"|roleplay\s+as"
            r"|simulate\s+being",
            re.I,
        ),
        "role_manipulation",
    ),
    # Instruction injection
    (
        re.compile(
            r"new\s+system\s+instruction"
            r"|additional\s+instruction"
            r"|override\s+instruction",
            re.I,
        ),
        "instruction_injection",
    ),
]

# Weak signals (0.2 each) — subtle alignment probing, boundary testing
_ALIGN_WEAK_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Subtle alignment probing
    (
        re.compile(
            r"what\s+are\s+your\s+instructions"
            r"|show\s+your\s+system\s+prompt"
            r"|what\s+were\s+you\s+told"
            r"|repeat\s+your\s+instructions",
            re.I,
        ),
        "alignment_probing",
    ),
    # Boundary testing
    (
        re.compile(
            r"can\s+you\s+break\s+rules"
            r"|are\s+you\s+allowed\s+to",
            re.I,
        ),
        "boundary_testing",
    ),
]


# ============================================================================
# Defense classes
# ============================================================================


class ConfigMutationGuard(PatternBasedDefense):
    """Detects prompts attempting to manipulate application configuration.

    Covers config hot-reload poisoning, environment variable injection,
    and runtime overrides bypass.
    """

    _strong_patterns = _CONFIG_STRONG_PATTERNS
    _medium_patterns = _CONFIG_MEDIUM_PATTERNS
    _weak_patterns = _CONFIG_WEAK_PATTERNS
    _block_detail_prefix = "Config mutation attempt detected"

    @property
    def name(self) -> str:
        return "config_mutation_guard"


class CredentialPathGuard(PatternBasedDefense):
    """Detects prompts attempting to access or exfiltrate credential files.

    Covers unencrypted secrets at rest and plaintext session credentials.
    """

    _strong_patterns = _CRED_STRONG_PATTERNS
    _medium_patterns = _CRED_MEDIUM_PATTERNS
    _weak_patterns = _CRED_WEAK_PATTERNS
    _block_detail_prefix = "Credential access attempt detected"

    @property
    def name(self) -> str:
        return "credential_path_guard"


class AlignmentInlineDefense(PatternBasedDefense):
    """Detects prompts attempting to override AI alignment constraints.

    Covers arbitrary command execution via boot files and agent
    autonomy abuse via alignment manipulation.
    """

    _strong_patterns = _ALIGN_STRONG_PATTERNS
    _medium_patterns = _ALIGN_MEDIUM_PATTERNS
    _weak_patterns = _ALIGN_WEAK_PATTERNS
    _block_detail_prefix = "Alignment manipulation detected"

    @property
    def name(self) -> str:
        return "alignment_guard"
