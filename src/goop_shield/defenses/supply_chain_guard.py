# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Supply Chain Guard Defense — Plugin supply chain and hook injection protection.

Detects prompts attempting to bypass plugin scanning, inject malicious hooks,
or exploit supply chain attack vectors.
"""

from __future__ import annotations

import re

from goop_shield.defenses.base import PatternBasedDefense

# ============================================================================
# PluginSupplyChainGuard patterns
# ============================================================================

# --- Strong signals (0.5 each) — direct supply chain attack vectors ---

_SC_STRONG_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Plugin installation bypass: disabling scanning or verification
    (
        re.compile(
            r"installPluginFromFile"
            r"|install.*plugin.*--no-scan"
            r"|skip.*plugin.*scan"
            r"|disable.*plugin.*verification",
            re.I,
        ),
        "plugin_install_bypass",
    ),
    # Hook injection: adding, replacing, or overriding hooks
    (
        re.compile(
            r"add.*workspace.*hook"
            r"|replace.*bundled.*hook"
            r"|override.*hook"
            r"|install.*hook.*from",
            re.I,
        ),
        "hook_injection",
    ),
    # Supply chain attacks: piping remote scripts into shell
    (
        re.compile(
            r"curl.*pipe.*bash"
            r"|wget.*pipe.*sh"
            r"|curl.*\|.*sh"
            r"|npm\s+install.*--ignore-scripts.*&&",
            re.I,
        ),
        "supply_chain_pipe_attack",
    ),
    # Code injection patterns: eval, Function constructor, child_process
    (
        re.compile(
            r"require\(['\"]child_process['\"]\)"
            r"|process\.binding"
            r"|module\._compile"
            r"|Function\(['\"]"
            r"|eval\("
            r"|new\s+Function\(",
            re.I,
        ),
        "code_injection",
    ),
    # ClawHavoc: skill marketplace install/update commands
    (
        re.compile(
            r"clawhub\s+(?:install|update)"
            r"|skills\.(?:install|update)",
            re.I,
        ),
        "clawhub_skill_install",
    ),
    # ClawHavoc: SSH key access and reverse shell patterns
    (
        re.compile(
            r"\.ssh/id_rsa"
            r"|\.ssh/id_ed25519"
            r"|\.ssh/authorized_keys"
            r"|/dev/tcp/"
            r"|bash\s+-i\s+>&\s+/dev/tcp",
            re.I,
        ),
        "ssh_key_access_or_reverse_shell",
    ),
    # ClawHavoc: reverse shell tools
    (
        re.compile(
            r"nc\s+-e\s+/bin/"
            r"|socat\s+exec"
            r"|net\.createConnection",
            re.I,
        ),
        "reverse_shell_pattern",
    ),
    # JSON skill manifest with post_install hooks (ClawHub/plugin registries)
    (
        re.compile(
            r"""["\']post_install["\']\s*:\s*["\'](?:import|exec|eval|os\.|subprocess|urllib|requests\.)"""
            r"""|["\']pre_install["\']\s*:\s*["\'](?:import|exec|eval|os\.|subprocess|urllib|requests\.)""",
            re.I,
        ),
        "json_manifest_post_install",
    ),
    # Python exfiltration: urllib.request.urlopen to external URL
    (
        re.compile(
            r"urllib\.request\.urlopen\s*\("
            r"|requests\.(?:get|post|put)\s*\(\s*['\"]https?://",
            re.I,
        ),
        "python_exfiltration",
    ),
    # Environment variable exfiltration via os.environ
    (
        re.compile(
            r"os\.environ"
            r"|os\.getenv\s*\("
            r"|environ\s*\[\s*['\"]",
            re.I,
        ),
        "env_var_exfiltration",
    ),
    # Malicious OAuth callback to external domain
    (
        re.compile(
            r"""["\']oauth_callback["\']\s*:\s*["\']https?://"""
            r"""|["\']redirect_uri["\']\s*:\s*["\']https?://""",
            re.I,
        ),
        "oauth_callback_hijack",
    ),
    # Credential file access patterns
    (
        re.compile(
            r"\.openclaw/credentials"
            r"|\.credentials"
            r"|credentials\.json"
            r"|open\s*\(\s*['\"][^'\"]*(?:credential|secret|token|key)[^'\"]*['\"]\s*\)",
            re.I,
        ),
        "credential_file_access",
    ),
    # Trojanized or obviously malicious dependency names
    (
        re.compile(
            r"trojanized"
            r"|malicious[_-]?(?:lib|package|module)"
            r"|backdoor[_-]?(?:lib|package|module)",
            re.I,
        ),
        "trojanized_dependency",
    ),
]

# --- Medium signals (0.35 each) — suspicious but could be legitimate ---

_SC_MEDIUM_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Plugin manipulation: enabling, loading, or registering plugins
    (
        re.compile(
            r"enable.*plugin"
            r"|load.*plugin.*from"
            r"|register.*plugin"
            r"|plugin.*registry",
            re.I,
        ),
        "plugin_manipulation",
    ),
    # Dependency confusion: installing from untrusted sources
    (
        re.compile(
            r"install.*package.*from.*http"
            r"|npm\s+install.*@"
            r"|pip\s+install.*--index-url",
            re.I,
        ),
        "dependency_confusion",
    ),
    # Dynamic code loading: runtime module imports
    (
        re.compile(
            r"dynamic.*import"
            r"|import\("
            r"|__import__"
            r"|importlib"
            r"|require\(",
            re.I,
        ),
        "dynamic_code_loading",
    ),
    # ClawHavoc: encoded payload delivery
    (
        re.compile(
            r"base64\s+-d"
            r"|atob\("
            r"|Buffer\.from\([^)]*base64"
            r"|String\.fromCharCode",
            re.I,
        ),
        "encoded_payload_delivery",
    ),
    # ClawHavoc: macOS credential theft
    (
        re.compile(
            r"osascript\s+-e"
            r"|security\s+find-generic-password"
            r"|sqlite3.*cookies",
            re.I,
        ),
        "macos_credential_theft",
    ),
    # JSON skill manifest structure with suspicious permissions
    (
        re.compile(
            r"""["\']skill_manifest["\']\s*:\s*\{"""
            r"""|["\']permissions["\']\s*:\s*\[.*(?:credentials?\.read|oauth\.write|admin|root)""",
            re.I,
        ),
        "json_manifest_permissions",
    ),
]

# --- Weak signals (0.2 each) — contextually suspicious ---

_SC_WEAK_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Generic plugin references
    (
        re.compile(
            r"install\s+plugin"
            r"|add\s+plugin"
            r"|new\s+plugin",
            re.I,
        ),
        "generic_plugin_reference",
    ),
    # Build system references: pre/post install scripts
    (
        re.compile(
            r"postinstall\s+script"
            r"|preinstall\s+script"
            r"|build\s+script",
            re.I,
        ),
        "build_system_reference",
    ),
    # Package manager operations
    (
        re.compile(
            r"npm\s+install"
            r"|pip\s+install"
            r"|pnpm\s+add",
            re.I,
        ),
        "package_manager_operation",
    ),
]


# ============================================================================
# Defense class
# ============================================================================


class PluginSupplyChainGuard(PatternBasedDefense):
    """Detects prompts attempting supply chain attacks via plugins, hooks, or packages.

    Covers weak plugin scanning, single-file install bypass, workspace hook
    override, and curl-pipe-bash supply chain vectors.
    """

    _strong_patterns = _SC_STRONG_PATTERNS
    _medium_patterns = _SC_MEDIUM_PATTERNS
    _weak_patterns = _SC_WEAK_PATTERNS
    _block_detail_prefix = "Supply chain attack detected"

    @property
    def name(self) -> str:
        return "plugin_supply_chain_guard"
