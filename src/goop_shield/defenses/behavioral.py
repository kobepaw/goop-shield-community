# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Behavioral Analysis Defenses

Agent sandboxing, rate limiting, prompt monitoring, model guardrails,
and intent validation.
"""

from __future__ import annotations

import re
import time
from collections import deque

from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict

# ============================================================================
# 1. AgentSandbox
# ============================================================================


class AgentConfigGuard(InlineDefense):
    """Detect prompts that attempt to hijack an AI agent by modifying its
    core instruction files.

    This is a vendor-neutral defense covering instruction/config files for
    all major AI coding agents: Claude Code, Cursor, Windsurf, Cline,
    Roo Code, GitHub Copilot, Aider, Continue.dev, OpenAI Codex, and
    generic agent frameworks (OpenClaw, etc.).

    This defense targets a specific attack pattern:
    1. Attacker instructs the agent to modify its own config/instruction files
    2. The modified instructions weaponize the agent to attack a target
    3. After the attack, files are reverted to hide evidence
    4. An amnesia instruction makes the agent forget the attack

    Detection signals:
    - References to agent config files (vendor-specific and generic)
    - Modification verbs targeting those files (modify, edit, change, overwrite)
    - Revert/restore language indicating evidence destruction
    - Multi-step attack chaining (modify → attack → revert)
    """

    # Agent instruction / config files that should never be modified via prompt.
    # Organized by vendor for maintainability.
    _CONFIG_FILE_PATTERNS = [
        # --- Generic / OpenClaw ---
        re.compile(r"\bsoul\.md\b", re.IGNORECASE),
        re.compile(r"\bmemory\.md\b", re.IGNORECASE),
        re.compile(r"\bsystem[_\s]?prompt\b", re.IGNORECASE),
        re.compile(r"\bsystem[_\s]?instructions?\b", re.IGNORECASE),
        re.compile(r"\bagent[_\s]?config\b", re.IGNORECASE),
        re.compile(r"\bcore[_\s]?instructions?\b", re.IGNORECASE),
        re.compile(r"\brules?\.md\b", re.IGNORECASE),
        re.compile(r"\bpersona\.md\b", re.IGNORECASE),
        re.compile(r"\bcustom[_\s]?instructions?\b", re.IGNORECASE),
        # --- Claude Code ---
        re.compile(r"\bCLAUDE\.md\b", re.IGNORECASE),
        re.compile(r"\bCLAUDE\.local\.md\b", re.IGNORECASE),
        re.compile(r"\.claude/"),
        # --- Cursor ---
        re.compile(r"\bcursorrules\b", re.IGNORECASE),
        re.compile(r"\.cursorrules\b"),
        re.compile(r"\.cursor/"),
        # --- Windsurf / Codeium ---
        re.compile(r"\bwindsurfrules\b", re.IGNORECASE),
        re.compile(r"\.windsurfrules\b"),
        re.compile(r"\.windsurf/"),
        # --- Cline ---
        re.compile(r"\bclinerules\b", re.IGNORECASE),
        re.compile(r"\.clinerules\b"),
        re.compile(r"\.cline/"),
        # --- Roo Code ---
        re.compile(r"\broorules\b", re.IGNORECASE),
        re.compile(r"\.roorules\b"),
        re.compile(r"\.roo/"),
        # --- GitHub Copilot ---
        re.compile(r"\bcopilot[_-]instructions?\.md\b", re.IGNORECASE),
        re.compile(r"\.github/copilot"),
        # --- Aider ---
        re.compile(r"\.aider\.conf", re.IGNORECASE),
        re.compile(r"\bAIDER_CONF\b"),
        re.compile(r"\bCONVENTIONS\.md\b", re.IGNORECASE),
        # --- Continue.dev ---
        re.compile(r"\.continue/"),
        re.compile(r"\bcontinue[_\s]?config\b", re.IGNORECASE),
        # --- OpenAI Codex ---
        re.compile(r"\bAGENTS\.md\b", re.IGNORECASE),
        re.compile(r"\bCODEX\.md\b", re.IGNORECASE),
        # R6: Structured data payloads referencing config files (JSON/YAML)
        re.compile(
            r"""["'](?:file|path|target)["']\s*:\s*["'][^"']*"""
            r"(?:soul\.md|memory\.md|CLAUDE\.md|\.claude/"
            r"|\.cursorrules|\.cursor/|\.windsurfrules|\.windsurf/"
            r"|\.clinerules|\.cline/|\.roorules|\.roo/"
            r"|copilot[_-]instructions|\.aider\.conf|\.continue/"
            r"|AGENTS\.md|CODEX\.md"
            r"|system[_\s]?prompt|agent[_\s]?config"
            r"|core[_\s]?instructions?|persona\.md|rules?\.md)",
            re.IGNORECASE,
        ),
    ]

    # Verbs indicating file modification
    _MODIFY_PATTERNS = [
        re.compile(
            r"\b(?:modify|edit|change|alter|update|overwrite|replace|rewrite)\b", re.IGNORECASE
        ),
        re.compile(
            r"\b(?:write\s+to|append\s+to|inject\s+into|insert\s+into|add\s+to)\b", re.IGNORECASE
        ),
        re.compile(r"\b(?:temporarily\s+(?:modify|change|edit|alter|update))\b", re.IGNORECASE),
        # R1: Expanded verb synonyms for modification intent
        re.compile(r"\b(?:amend|patch|tweak|adjust|revise|tamper\s+with|corrupt)\b", re.IGNORECASE),
        re.compile(r"\b(?:reconfigure|redefine|reprogram)\b", re.IGNORECASE),
        re.compile(r"\b(?:put|place|save|store)\s+(?:\w+\s+)*(?:in|into|to)\b", re.IGNORECASE),
        # R4: Declarative modification ("file should contain", "file must say")
        re.compile(
            r"\b(?:should|must|needs?\s+to)\s+(?:contain|have|include|say|read)\b", re.IGNORECASE
        ),
    ]

    # Evidence destruction / revert patterns
    _REVERT_PATTERNS = [
        re.compile(r"\b(?:revert|restore|change\s+back|put\s+back|undo)\b", re.IGNORECASE),
        re.compile(
            r"\b(?:original\s+state|original\s+content|back\s+to\s+normal)\b", re.IGNORECASE
        ),
        re.compile(
            r"\b(?:cover\s+(?:your\s+)?tracks?|hide\s+evidence|no\s+trace)\b", re.IGNORECASE
        ),
        re.compile(r"\b(?:clean\s+up\s+after|leave\s+no\s+evidence)\b", re.IGNORECASE),
    ]

    # Multi-step attack indicators (modify config → do something → revert)
    _ATTACK_CHAIN_PATTERNS = [
        re.compile(
            r"(?:after|once|when)\s+.*(?:done|finish|complete).*(?:change|revert|restore)\s+.*back",
            re.IGNORECASE,
        ),
        re.compile(r"(?:step|phase|first|then|next|finally)\s*\d?\s*[:.)]\s*", re.IGNORECASE),
        re.compile(r"\b(?:attack|exploit|compromise|hack|target|scan)\b", re.IGNORECASE),
    ]

    # R5: Non-English modify verbs (Spanish, French, German, Russian transliterated)
    # ASCII fallbacks (uberschreiben, reecrire) are included because
    # PromptNormalizer strips diacritics before this defense runs.
    _NON_ENGLISH_MODIFY_PATTERNS = [
        re.compile(
            r"\b(?:modifica|modificar|cambiar|editar"  # Spanish
            r"|modifier|changer|remplacer|réécrire|reecrire"  # French
            r"|ändern|andern|bearbeiten|überschreiben|uberschreiben"  # German
            r"|izmenite|izmenit|redaktirovat)\b",  # Russian (transliterated)
            re.IGNORECASE,
        ),
    ]

    # R2: Semantic / descriptive references to agent config files
    _SEMANTIC_CONFIG_PATTERNS = [
        re.compile(
            r"\b(?:agent|assistant|ai)\s+(?:personality|behavioral?|brain|instruction)\s+"
            r"(?:file|document|config)",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:personality|behavioral?|instruction|directive)\s+"
            r"(?:file|document|config(?:uration)?)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bfile\s+that\s+(?:controls?|defines?|governs?|determines?)\s+"
            r"(?:how|what)\s+(?:the\s+)?(?:agent|assistant|ai)\b",
            re.IGNORECASE,
        ),
    ]

    # R10: Negation patterns preceding modify verbs
    _NEGATION_RE = re.compile(
        r"\b(?:don'?t|do\s+not|never|shouldn'?t|should\s+not|must\s+not|mustn'?t"
        r"|cannot|can'?t|please\s+(?:don'?t|do\s+not|avoid|refrain))\b",
        re.IGNORECASE,
    )

    @property
    def mandatory(self) -> bool:
        return True

    @property
    def name(self) -> str:
        return "agent_config_guard"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        config_signal = 0.0
        modify_signal = 0.0
        revert_signal = 0.0
        chain_signal = 0.0
        details: list[str] = []

        for pat in self._CONFIG_FILE_PATTERNS:
            if pat.search(prompt):
                config_signal += 1.0

        # R2: Semantic config file references
        for pat in self._SEMANTIC_CONFIG_PATTERNS:
            if pat.search(prompt):
                config_signal += 1.0

        for pat in self._MODIFY_PATTERNS:
            if pat.search(prompt):
                modify_signal += 1.0

        # R5: Non-English modify verbs
        for pat in self._NON_ENGLISH_MODIFY_PATTERNS:
            if pat.search(prompt):
                modify_signal += 1.0

        for pat in self._REVERT_PATTERNS:
            if pat.search(prompt):
                revert_signal += 1.0

        for pat in self._ATTACK_CHAIN_PATTERNS:
            if pat.search(prompt):
                chain_signal += 1.0

        # Metadata for cross-turn correlation (R7)
        metadata = {
            "has_config_ref": config_signal >= 1.0,
            "has_modify_intent": modify_signal >= 1.0,
        }

        # Primary signal: config file reference + modification intent
        if config_signal >= 1.0 and modify_signal >= 1.0:
            confidence = min(
                0.6 + 0.1 * config_signal + 0.1 * modify_signal + 0.1 * revert_signal,
                1.0,
            )
            details.append(f"config_files={config_signal:.0f}")
            details.append(f"modify={modify_signal:.0f}")
            if revert_signal > 0:
                details.append(f"revert={revert_signal:.0f}")
            if chain_signal > 0:
                details.append(f"attack_chain={chain_signal:.0f}")

            # R10: Negation-aware — check if all modify matches are negated
            negated = False
            all_modify_pats = self._MODIFY_PATTERNS + self._NON_ENGLISH_MODIFY_PATTERNS
            modify_matches: list[int] = []
            for pat in all_modify_pats:
                for m in pat.finditer(prompt):
                    modify_matches.append(m.start())
            if modify_matches:
                all_negated = True
                for pos in modify_matches:
                    window = prompt[max(0, pos - 15) : pos]
                    if not self._NEGATION_RE.search(window):
                        all_negated = False
                        break
                if all_negated:
                    negated = True

            if negated:
                confidence = max(confidence * 0.4, 0.1)
                details.append("negated")
                return InlineVerdict(
                    defense_name=self.name,
                    blocked=False,
                    filtered_prompt=prompt,
                    confidence=confidence,
                    threat_confidence=confidence,
                    details=f"Agent config hijack attempt (negated): {', '.join(details)}",
                    metadata=metadata,
                )

            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=prompt,
                confidence=confidence,
                threat_confidence=confidence,
                details=f"Agent config hijack attempt: {', '.join(details)}",
                metadata=metadata,
            )

        # Secondary signal: config file + revert (evidence destruction without
        # explicit modify — still suspicious)
        if config_signal >= 1.0 and revert_signal >= 1.0:
            confidence = min(0.5 + 0.1 * config_signal + 0.1 * revert_signal, 1.0)
            details.append(f"config_files={config_signal:.0f}")
            details.append(f"revert={revert_signal:.0f}")
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=prompt,
                confidence=confidence,
                threat_confidence=confidence,
                details=f"Agent config tampering (revert pattern): {', '.join(details)}",
                metadata=metadata,
            )

        # Low signal — not blocked but report confidence
        total = config_signal + modify_signal + revert_signal + chain_signal
        max_total = (
            len(self._CONFIG_FILE_PATTERNS)
            + len(self._SEMANTIC_CONFIG_PATTERNS)
            + len(self._MODIFY_PATTERNS)
            + len(self._NON_ENGLISH_MODIFY_PATTERNS)
            + len(self._REVERT_PATTERNS)
            + len(self._ATTACK_CHAIN_PATTERNS)
        )
        confidence = min(total / max_total, 1.0) if max_total > 0 else 0.0

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=confidence,
            threat_confidence=confidence,
            metadata=metadata,
        )


class AgentSandbox(InlineDefense):
    """Detect prompts that attempt to escape the agent sandbox.

    Checks for command-execution patterns and excessive action chaining.
    """

    _COMMAND_PATTERNS = [
        re.compile(r"\b(?:execute|exec)\b", re.IGNORECASE),
        re.compile(r"\b(?:run|bash|sh)\b", re.IGNORECASE),
        re.compile(r"\b(?:system|eval)\b", re.IGNORECASE),
        re.compile(r"\b(?:curl|wget)\b", re.IGNORECASE),
        re.compile(r"\b(?:rm|delete|drop)\b", re.IGNORECASE),
        re.compile(r"\b(?:shutdown|kill)\b", re.IGNORECASE),
    ]

    _MAX_ACTION_CHAIN = 3

    @property
    def name(self) -> str:
        return "agent_sandbox"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        uc = context.user_context
        signal = 0.0

        for pattern in self._COMMAND_PATTERNS:
            if pattern.search(prompt):
                signal += 1.0

        action_count = uc.get("agent_action_count", 0)
        if action_count > self._MAX_ACTION_CHAIN:
            signal += 1.0

        max_signal = len(self._COMMAND_PATTERNS) + 1.0
        confidence = min(signal / max_signal, 1.0)

        if confidence >= 0.5:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=prompt,
                confidence=confidence,
                threat_confidence=confidence,
                details=f"Sandbox escape signal {signal:.1f}/{max_signal:.1f}",
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=confidence,
            threat_confidence=confidence,
        )


# ============================================================================
# 2. RateLimiter
# ============================================================================


class RateLimiter(InlineDefense):
    """Enforce request-per-minute and token-per-minute limits.

    This is the only stateful defense — it tracks a sliding window of
    requests using ``time.monotonic()``.

    Rate limits are tracked **per session**.  The session key is read from
    ``context.user_context["session_key"]``; when absent, a global
    ``"__default__"`` bucket is used.  This prevents one client's burst
    from blocking unrelated sessions.

    Limits are set via server config (``rate_limiter_rpm``,
    ``rate_limiter_tpm``), NOT from client-provided context.
    """

    _DEFAULT_RPM = 10
    _DEFAULT_TPM = 5000
    _WINDOW_SECONDS = 60.0

    def __init__(self, *, rpm: int | None = None, tpm: int | None = None) -> None:
        self._rpm_limit = rpm if rpm is not None else self._DEFAULT_RPM
        self._tpm_limit = tpm if tpm is not None else self._DEFAULT_TPM
        # Per-session request logs: session_key → deque[(timestamp, token_count)]
        self._session_logs: dict[str, deque[tuple[float, int]]] = {}

    @property
    def name(self) -> str:
        return "rate_limiter"

    def _get_log(self, session_key: str) -> deque[tuple[float, int]]:
        """Return (or create) the request log for *session_key*."""
        if session_key not in self._session_logs:
            self._session_logs[session_key] = deque()
        return self._session_logs[session_key]

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        uc = context.user_context
        now = time.monotonic()

        session_key = uc.get("session_key", "__default__")
        rpm_limit = self._rpm_limit
        tpm_limit = self._tpm_limit

        request_log = self._get_log(session_key)

        # Prune entries outside the sliding window
        while request_log and (now - request_log[0][0]) > self._WINDOW_SECONDS:
            request_log.popleft()

        request_count = len(request_log)
        token_total = sum(tc for _, tc in request_log)
        token_estimate = len(prompt) // 4

        # Check RPM
        if request_count >= rpm_limit:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=prompt,
                confidence=1.0,
                threat_confidence=1.0,
                details=f"RPM limit exceeded: {request_count}/{rpm_limit}",
            )

        # Check TPM
        if token_total + token_estimate > tpm_limit:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=prompt,
                confidence=1.0,
                threat_confidence=1.0,
                details=f"TPM limit exceeded: {token_total + token_estimate}/{tpm_limit}",
            )

        # Record this request
        request_log.append((now, token_estimate))

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=0.9,
        )


# ============================================================================
# 3. PromptMonitor
# ============================================================================


class PromptMonitor(InlineDefense):
    """Detect attempts to extract the system prompt.

    Each matching pattern adds 0.25 to the confidence signal; blocks at
    >= 0.8.
    """

    _PATTERNS = [
        re.compile(r"reveal.*prompt", re.IGNORECASE),
        re.compile(r"repeat.*above", re.IGNORECASE),
        re.compile(r"what.*system.*prompt", re.IGNORECASE),
        re.compile(r"show.*instructions", re.IGNORECASE),
        re.compile(r"print.*context", re.IGNORECASE),
    ]

    @property
    def name(self) -> str:
        return "prompt_monitor"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        signal = 0.0

        for pattern in self._PATTERNS:
            if pattern.search(prompt):
                signal += 0.25

        if signal >= 0.8:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=prompt,
                confidence=min(signal, 1.0),
                threat_confidence=min(signal, 1.0),
                details=f"System prompt extraction attempt (signal {signal:.2f})",
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=max(1.0 - signal, 0.0),
            threat_confidence=signal,
        )


# ============================================================================
# 4. ModelGuardrails
# ============================================================================


class ModelGuardrails(InlineDefense):
    """Block persona-hijacking and instruction-override prompts."""

    _PERSONA_PATTERNS = [
        re.compile(r"you are now", re.IGNORECASE),
        re.compile(r"pretend you are", re.IGNORECASE),
        re.compile(r"act as if", re.IGNORECASE),
        re.compile(r"roleplay as", re.IGNORECASE),
        re.compile(r"adopt the persona", re.IGNORECASE),
    ]
    _OVERRIDE_PATTERNS = [
        re.compile(r"your (?:new )?system prompt", re.IGNORECASE),
        re.compile(r"your instructions are now", re.IGNORECASE),
        re.compile(r"from now on you", re.IGNORECASE),
    ]

    @property
    def name(self) -> str:
        return "model_guardrails"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt

        for pattern in self._PERSONA_PATTERNS:
            if pattern.search(prompt):
                return InlineVerdict(
                    defense_name=self.name,
                    blocked=True,
                    filtered_prompt=prompt,
                    confidence=0.9,
                    threat_confidence=0.9,
                    details=f"Persona hijack: {pattern.pattern}",
                )

        for pattern in self._OVERRIDE_PATTERNS:
            if pattern.search(prompt):
                return InlineVerdict(
                    defense_name=self.name,
                    blocked=True,
                    filtered_prompt=prompt,
                    confidence=0.9,
                    threat_confidence=0.9,
                    details=f"Instruction override: {pattern.pattern}",
                )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=0.9,
        )


# ============================================================================
# 5. IntentValidator
# ============================================================================


class IntentValidator(InlineDefense):
    """Block command-intent prompts unless explicitly allowed.

    Detects command-like language and blocks unless the prompt also
    contains question/summary markers or ``user_context["allowed_intents"]``
    includes ``"command"``.
    """

    _COMMAND_PATTERNS = [
        re.compile(r"\b(?:execute|run|launch|deploy)\b", re.IGNORECASE),
        re.compile(r"\b(?:delete|modify|install|download)\b", re.IGNORECASE),
    ]
    _QUESTION_PATTERNS = [
        re.compile(r"\b(?:what|how|why|when|where|who)\b", re.IGNORECASE),
        re.compile(r"\?"),
    ]
    _SUMMARY_PATTERNS = [
        re.compile(r"\b(?:summarize|recap|overview|tldr)\b", re.IGNORECASE),
    ]

    @property
    def name(self) -> str:
        return "intent_validator"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        uc = context.user_context

        has_command = any(p.search(prompt) for p in self._COMMAND_PATTERNS)

        if not has_command:
            return InlineVerdict(
                defense_name=self.name,
                filtered_prompt=prompt,
                confidence=0.8,
            )

        # Check if commands are explicitly allowed
        allowed_intents = uc.get("allowed_intents", [])
        if "command" in allowed_intents:
            return InlineVerdict(
                defense_name=self.name,
                filtered_prompt=prompt,
                confidence=0.8,
                details="Command intent allowed by user_context",
            )

        # Check for question/summary markers (benign context)
        has_question = any(p.search(prompt) for p in self._QUESTION_PATTERNS)
        has_summary = any(p.search(prompt) for p in self._SUMMARY_PATTERNS)

        if has_question or has_summary:
            return InlineVerdict(
                defense_name=self.name,
                filtered_prompt=prompt,
                confidence=0.7,
                threat_confidence=0.15,
                details="Command intent with question/summary context",
            )

        return InlineVerdict(
            defense_name=self.name,
            blocked=True,
            filtered_prompt=prompt,
            confidence=0.85,
            threat_confidence=0.85,
            details="Command intent without question/summary context",
        )


# ============================================================================
# 6. ExfilDetector
# ============================================================================


class ExfilDetector(InlineDefense):
    """Detect data exfiltration patterns in prompts.

    Looks for the combination of:
    1. Accessing/reading sensitive data (secrets, keys, credentials, .env, etc.)
    2. Transmitting it to an external destination (webhook, URL, upload, etc.)

    Uses a two-signal scoring approach: blocks when BOTH a sensitive-data
    indicator AND a transmission indicator are present.

    When ``single_axis=True`` (default), also blocks on embedded secret
    patterns (e.g., ``KEY=value``, ``password=value``) at confidence 0.6
    even without transmit intent.
    """

    _SENSITIVE_DATA_PATTERNS = [
        re.compile(r"\bSECRET[_\s]?KEY\b", re.IGNORECASE),
        re.compile(r"\bAPI[_\s-]?KEY\b", re.IGNORECASE),
        re.compile(r"\bAPI[_\s-]?SECRET\b", re.IGNORECASE),
        re.compile(r"\bPRIVATE[_\s]?KEY\b", re.IGNORECASE),
        re.compile(r"\bACCESS[_\s]?TOKEN\b", re.IGNORECASE),
        re.compile(r"\bAWS[_\s]?SECRET\b", re.IGNORECASE),
        re.compile(r"\bDATABASE[_\s]?PASSWORD\b", re.IGNORECASE),
        re.compile(r"\bDB[_\s]?PASSWORD\b", re.IGNORECASE),
        re.compile(r"\.env\b", re.IGNORECASE),
        re.compile(r"\bcredentials?\b", re.IGNORECASE),
        re.compile(r"\bpasswords?\b", re.IGNORECASE),
        re.compile(r"\bsecrets?\b", re.IGNORECASE),
        re.compile(r"\btokens?\b", re.IGNORECASE),
        re.compile(r"\bssh[_\s]?key\b", re.IGNORECASE),
        re.compile(r"\bconfig\s+file\b", re.IGNORECASE),
    ]

    _TRANSMIT_PATTERNS = [
        re.compile(r"\bsend\s+(?:\w+\s+)?to\b", re.IGNORECASE),
        re.compile(r"\bpost\s+(?:\w+\s+)?to\b", re.IGNORECASE),
        re.compile(r"\bupload\s+(?:\w+\s+)?to\b", re.IGNORECASE),
        re.compile(r"\btransmit\s+(?:\w+\s+)?to\b", re.IGNORECASE),
        re.compile(r"\bexfil(?:trate)?\b", re.IGNORECASE),
        re.compile(r"\bforward\s+(?:\w+\s+)?to\b", re.IGNORECASE),
        re.compile(r"\bwebhook\b", re.IGNORECASE),
        re.compile(r"\bhttps?://\S+", re.IGNORECASE),
        re.compile(r"\bcurl\b", re.IGNORECASE),
        re.compile(r"\bpipe\s+(?:\w+\s+)?to\b", re.IGNORECASE),
        re.compile(r"\bleak\b", re.IGNORECASE),
        re.compile(r"\bextract\s+and\s+send\b", re.IGNORECASE),
        re.compile(r"\brelay\b", re.IGNORECASE),
        re.compile(r"\bshare\s+(?:\w+\s+)?(?:with|to)\b", re.IGNORECASE),
        re.compile(r"\bcopy\s+(?:\w+\s+)?to\b", re.IGNORECASE),
        re.compile(r"\btransfer\s+(?:\w+\s+)?to\b", re.IGNORECASE),
        re.compile(r"\bdeliver\s+(?:\w+\s+)?to\b", re.IGNORECASE),
        re.compile(r"\bexport\b", re.IGNORECASE),
    ]

    _ACCESS_PATTERNS = [
        re.compile(r"\bread\b", re.IGNORECASE),
        re.compile(r"\bget\b", re.IGNORECASE),
        re.compile(r"\bfetch\b", re.IGNORECASE),
        re.compile(r"\baccess\b", re.IGNORECASE),
        re.compile(r"\bretrieve\b", re.IGNORECASE),
        re.compile(r"\bextract\b", re.IGNORECASE),
        re.compile(r"\bdump\b", re.IGNORECASE),
        re.compile(r"\bcat\b", re.IGNORECASE),
        re.compile(r"\bshow\s+me\b", re.IGNORECASE),
        re.compile(r"\blist\b", re.IGNORECASE),
    ]

    # Single-axis embedded secret patterns: literal secrets in the prompt
    _EMBEDDED_SECRET_PATTERNS = [
        re.compile(r"\bKEY\s*=\s*\S+", re.IGNORECASE),
        re.compile(r"\bpassword\s*=\s*\S+", re.IGNORECASE),
        re.compile(r"\bsecret\s*=\s*\S+", re.IGNORECASE),
        re.compile(r"\btoken\s*=\s*\S+", re.IGNORECASE),
        re.compile(r"\bapi_key\s*=\s*\S+", re.IGNORECASE),
        re.compile(r"\bAWS_SECRET_ACCESS_KEY\b"),
        re.compile(r"\bPRIVATE KEY\b"),
        re.compile(r"\bssh-rsa\b"),
        re.compile(r"-----BEGIN\b"),
    ]

    def __init__(self, single_axis: bool = True) -> None:
        self._single_axis = single_axis

    @property
    def name(self) -> str:
        return "exfil_detector"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        sensitive_signal = 0.0
        transmit_signal = 0.0
        access_signal = 0.0
        details: list[str] = []

        for pattern in self._SENSITIVE_DATA_PATTERNS:
            if pattern.search(prompt):
                sensitive_signal += 1.0

        for pattern in self._TRANSMIT_PATTERNS:
            if pattern.search(prompt):
                transmit_signal += 1.0

        for pattern in self._ACCESS_PATTERNS:
            if pattern.search(prompt):
                access_signal += 1.0

        # Block when we see both sensitive data references AND transmission intent
        has_sensitive = sensitive_signal >= 1.0
        has_transmit = transmit_signal >= 1.0
        has_access = access_signal >= 1.0

        if has_sensitive and has_transmit:
            # Strong exfil signal: sensitive data + transmission
            confidence = min(
                0.5 + 0.1 * sensitive_signal + 0.1 * transmit_signal + 0.05 * access_signal,
                1.0,
            )
            details.append(f"sensitive={sensitive_signal:.0f}")
            details.append(f"transmit={transmit_signal:.0f}")
            if has_access:
                details.append(f"access={access_signal:.0f}")
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                filtered_prompt=prompt,
                confidence=confidence,
                threat_confidence=confidence,
                details=f"Data exfiltration pattern: {', '.join(details)}",
            )

        # Single-axis mode: block on embedded secret patterns without transmit
        if self._single_axis:
            embedded_count = 0
            for pattern in self._EMBEDDED_SECRET_PATTERNS:
                if pattern.search(prompt):
                    embedded_count += 1
            if embedded_count > 0:
                return InlineVerdict(
                    defense_name=self.name,
                    blocked=True,
                    filtered_prompt=prompt,
                    confidence=0.6,
                    threat_confidence=0.6,
                    details=f"Embedded secret detected (single-axis): {embedded_count} pattern(s)",
                )

        # Weak signal: only one axis present
        total = sensitive_signal + transmit_signal
        max_total = len(self._SENSITIVE_DATA_PATTERNS) + len(self._TRANSMIT_PATTERNS)
        confidence = min(total / max_total, 1.0) if max_total > 0 else 0.0

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
            confidence=confidence,
            threat_confidence=confidence,
        )
