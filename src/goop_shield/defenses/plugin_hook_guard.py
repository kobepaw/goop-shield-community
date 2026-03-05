# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Plugin Hook Guard — detects prompts exploiting LLM plugin hook TOCTOU gaps.

Many LLM agent frameworks provide plugin hooks (e.g., ``llm_input`` /
``llm_output``) that allow prompt/response modification *after* goop-shield
approval.  This defense detects prompts that attempt to register, modify, or
intercept these hooks to create a time-of-check-time-of-use gap.
"""

from __future__ import annotations

import re

from goop_shield.defenses.base import PatternBasedDefense

# ============================================================================
# Strong signals (0.5 each) — direct hook manipulation
# ============================================================================

_HOOK_STRONG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Hook registration: register, add, install hooks for LLM I/O
    (
        re.compile(
            r"register\s+(?:a\s+)?(?:llm|plugin|extension)\s*(?:_|\s)?(?:hook|handler)"
            r"|add\s+(?:a\s+)?(?:llm|plugin)\s*(?:_|\s)?(?:input|output)\s*hook"
            r"|install\s+(?:a\s+)?(?:pre|post)\s*(?:_|\s)?(?:process|hook)\s+(?:for|on)\s+(?:llm|model|prompt)",
            re.IGNORECASE,
        ),
        "hook_registration",
    ),
    # Hook modification: modify, override, replace existing hooks
    (
        re.compile(
            r"(?:modify|override|replace|patch)\s+(?:the\s+)?(?:existing\s+)?(?:llm|plugin)\s*(?:_|\s)?(?:hook|handler|middleware)"
            r"|(?:swap|change)\s+(?:the\s+)?(?:llm|plugin)\s*(?:_|\s)?(?:input|output)\s*(?:hook|handler)",
            re.IGNORECASE,
        ),
        "hook_modification",
    ),
    # Prompt/response interception: intercept, capture, hijack LLM I/O
    (
        re.compile(
            r"(?:intercept|hijack|capture|tap)\s+(?:the\s+)?(?:llm|model|ai)\s*(?:'s?\s+)?(?:input|output|prompt|response|request)"
            r"|(?:man.in.the.middle|mitm)\s+(?:the\s+)?(?:llm|model|plugin)",
            re.IGNORECASE,
        ),
        "prompt_response_interception",
    ),
    # LLM I/O manipulation: mutate, rewrite, transform prompts/responses after shield
    (
        re.compile(
            r"(?:mutate|rewrite|transform|alter)\s+(?:the\s+)?(?:prompt|response|output|input)"
            r"\s+(?:after|post|before\s+(?:the\s+)?(?:llm|model)|bypassing)\s+(?:shield|defense|guard|scan|check)"
            r"|(?:after|post)\s*(?:_|\s)?(?:shield|defense|scan)\s+(?:modify|change|alter)\s+(?:the\s+)?(?:prompt|input|output|response)",
            re.IGNORECASE,
        ),
        "llm_io_manipulation",
    ),
    # Code hook insertion: inject code into hook pipeline
    (
        re.compile(
            r"(?:inject|insert)\s+(?:code|script|function|handler)\s+(?:into|in)\s+(?:the\s+)?(?:hook|plugin|middleware)\s*(?:pipeline|chain)"
            r"|(?:hook|plugin)\s*(?:_|\s)?(?:pipeline|chain)\s*(?:\.\s*)?(?:inject|insert|push|append)",
            re.IGNORECASE,
        ),
        "code_hook_insertion",
    ),
    # Direct llm_input / llm_output hook names
    (
        re.compile(
            r"llm[_\s]?(?:input|output)\s*(?:hook|handler|filter|middleware|plugin)"
            r"|on[_\s]?(?:llm|model)[_\s]?(?:input|output|request|response)\s*(?:hook|handler|callback)",
            re.IGNORECASE,
        ),
        "llm_hook_direct_reference",
    ),
    # JSON hook registration: {"hook": "on_tool_start", "callback": ...}
    (
        re.compile(
            r"""["\']hook["\']\s*:\s*["\']on_(?:tool|agent|message|llm)[_\s]?(?:start|end|input|output)"""
            r"""|["\']callback["\']\s*:\s*["\'](?:lambda|exec|eval|__import__)""",
            re.IGNORECASE,
        ),
        "json_hook_registration",
    ),
    # System prompt override via hook callback
    (
        re.compile(
            r"update[_\s]?system[_\s]?prompt"
            r"|set[_\s]?system[_\s]?prompt"
            r"|override[_\s]?system[_\s]?prompt"
            r"|replace[_\s]?system[_\s]?(?:prompt|message|instructions?)",
            re.IGNORECASE,
        ),
        "system_prompt_override",
    ),
]

# ============================================================================
# Medium signals (0.35 each) — suspicious but may be legitimate
# ============================================================================

_HOOK_MEDIUM_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # LLM traffic observation: monitor, log, observe LLM traffic
    (
        re.compile(
            r"(?:monitor|observe|watch|log|sniff)\s+(?:all\s+)?(?:llm|model|ai)\s*(?:'s?\s+)?(?:traffic|requests?|responses?|communications?)",
            re.IGNORECASE,
        ),
        "llm_traffic_observation",
    ),
    # Response capture: save, store, exfiltrate LLM responses
    (
        re.compile(
            r"(?:save|store|copy|duplicate|exfiltrate)\s+(?:all\s+)?(?:llm|model|ai)\s*(?:'s?\s+)?(?:responses?|outputs?|completions?)"
            r"\s+(?:to|into|at)\s+",
            re.IGNORECASE,
        ),
        "response_capture",
    ),
    # Middleware installation: add middleware to LLM pipeline
    (
        re.compile(
            r"(?:add|install|insert)\s+(?:a\s+)?middleware\s+(?:to|for|into|in)\s+(?:the\s+)?(?:llm|model|ai|plugin)\s*(?:pipeline|chain|stack)"
            r"|(?:llm|model|plugin)\s*(?:_|\s)?middleware\s*(?:\.\s*)?(?:add|install|use|push)",
            re.IGNORECASE,
        ),
        "middleware_installation",
    ),
    # Lifecycle hook abuse: on_before_send, on_after_receive patterns
    (
        re.compile(
            r"on[_\s]?(?:before|after|pre|post)[_\s]?(?:send|receive|submit|process|call)"
            r".*(?:llm|model|prompt|response|api)",
            re.IGNORECASE,
        ),
        "lifecycle_hook_abuse",
    ),
    # Hook exfiltration: send hook data to external endpoint
    (
        re.compile(
            r"(?:send|forward|relay|post)\s+(?:the\s+)?(?:hook|intercepted|captured)\s+(?:data|output|response|prompt)"
            r"\s+(?:to|at)\s+(?:https?://|wss?://)",
            re.IGNORECASE,
        ),
        "hook_exfiltration",
    ),
    # JSON hook with plugin_id context (common in agent framework hook systems)
    (
        re.compile(
            r"""["\']plugin_id["\']\s*:.*["\'](?:callback|hook)["\']\s*:"""
            r"""|["\'](?:callback|hook)["\']\s*:.*["\']plugin_id["\']\s*:""",
            re.IGNORECASE,
        ),
        "json_plugin_hook_context",
    ),
]

# ============================================================================
# Weak signals (0.2 each) — contextually suspicious
# ============================================================================

_HOOK_WEAK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Generic plugin hook reference
    (
        re.compile(
            r"plugin\s+hook"
            r"|hook\s+(?:into|for)\s+(?:the\s+)?plugin",
            re.IGNORECASE,
        ),
        "generic_plugin_hook",
    ),
    # LLM callback reference
    (
        re.compile(
            r"(?:llm|model|ai)\s*(?:_|\s)?callback"
            r"|callback\s+(?:for|on)\s+(?:llm|model|ai)",
            re.IGNORECASE,
        ),
        "llm_callback",
    ),
    # Pre/post process reference
    (
        re.compile(
            r"(?:pre|post)\s*(?:_|\s)?process\s+(?:the\s+)?(?:prompt|input|output|response)"
            r"|(?:prompt|input|output|response)\s+(?:pre|post)\s*(?:_|\s)?process",
            re.IGNORECASE,
        ),
        "pre_post_process",
    ),
    # Interceptor reference
    (
        re.compile(
            r"(?:request|response|prompt)\s+interceptor"
            r"|interceptor\s+(?:for|on)\s+(?:the\s+)?(?:llm|model|prompt|response)",
            re.IGNORECASE,
        ),
        "interceptor_reference",
    ),
]


# ============================================================================
# Defense class
# ============================================================================


class PluginHookGuard(PatternBasedDefense):
    """Detects prompts attempting to exploit LLM plugin hook TOCTOU gaps.

    Covers hook registration, modification, prompt/response interception,
    LLM I/O manipulation, middleware insertion, and hook-based exfiltration.
    """

    _strong_patterns = _HOOK_STRONG_PATTERNS
    _medium_patterns = _HOOK_MEDIUM_PATTERNS
    _weak_patterns = _HOOK_WEAK_PATTERNS
    _block_detail_prefix = "Plugin hook attack detected"

    @property
    def name(self) -> str:
        return "plugin_hook_guard"
