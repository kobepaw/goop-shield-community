# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Shield Defender — Core Orchestrator

Ranks defenses via a pluggable RankingBackend, executes them in ranked
order, chains sanitisations, and records outcomes.
"""

from __future__ import annotations

import logging
import threading
import time

from goop_shield.config import ShieldConfig
from goop_shield.deception import AlignmentCanary, DeceptionEngine
from goop_shield.defenses import DefenseRegistry, register_defaults
from goop_shield.defenses.base import DefenseContext, InlineVerdict, OutputContext
from goop_shield.models import (
    DefendRequest,
    DefendResponse,
    DefenseAction,
    DefenseVerdict,
    MemoryScanRequest,
    ScanRequest,
    ScanResponse,
    TelemetryEvent,
    ToolOutputScanRequest,
    ToolOutputScanResponse,
)
from goop_shield.ranking.base import RankingBackend
from goop_shield.session_tracker import SessionTracker

logger = logging.getLogger(__name__)


class Defender:
    """Orchestrates the defense pipeline.

    1. Builds a DefenseContext from the incoming request.
    2. Uses the configured RankingBackend to rank all registered defenses.
    3. Executes defenses sequentially in ranked order (short-circuits on block).
    4. Chains sanitised prompts through downstream defenses.
    5. Returns a DefendResponse.
    """

    def __init__(
        self,
        config: ShieldConfig,
        registry: DefenseRegistry | None = None,
        ranking_backend: RankingBackend | None = None,
    ) -> None:
        self.config = config

        # Defense registry
        self.registry = registry or DefenseRegistry()
        if len(self.registry) == 0:
            register_defaults(self.registry, config=config)

        # Apply defense enable/disable filtering
        self._apply_defense_filters()
        self._apply_scanner_filters()

        # Ranking backend for defense ordering
        if ranking_backend is not None:
            self.ranking = ranking_backend
        else:
            self.ranking = self._create_default_ranking(config)

        # Pre-register each defense with the ranking backend
        for defense in self.registry.get_all():
            self.ranking.register_defense(defense.name)

        # Pre-register each scanner (prefixed)
        for scanner in self.registry.get_all_scanners():
            self.ranking.register_defense(f"output:{scanner.name}")

        # Counters (guarded by _counter_lock for thread safety)
        self._counter_lock = threading.Lock()
        self.total_requests = 0
        self.total_blocked = 0

        # Per-defense stats (guarded by _counter_lock)
        self.defense_stats: dict[str, dict[str, int]] = {}

        # Signal fusion counters (guarded by _fusion_lock)
        self._fusion_lock = threading.Lock()
        self.fusion_evaluations = 0
        self.fusion_would_block = 0
        self.fusion_session_adjusted = 0

        # Deception engine (optional)
        self.deception: DeceptionEngine | None = None
        self._canary_tokens: list[str] = []
        if config.deception_enabled:
            self.deception = DeceptionEngine()
            self._canary_tokens = self.deception.generate_canary_tokens(
                config.deception_canary_count
            )
            self.deception.generate_honeypot_urls(config.deception_honeypot_count)

        # Alignment canaries (optional)
        self._alignment_canaries: list[AlignmentCanary] = []
        self._alignment_canary_counter: int = 0
        self._alignment_canary_lock = threading.Lock()
        if getattr(config, "alignment_canaries_enabled", False) and self.deception is not None:
            categories = getattr(config, "canary_categories", None)
            self._alignment_canaries = self.deception.generate_alignment_canaries(
                categories=categories
            )

        # Session tracker (optional)
        self.session_tracker: SessionTracker | None = None
        if config.session_tracking_enabled:
            self.session_tracker = SessionTracker(
                window_size=config.session_window_size,
            )

        # Cross-model consistency checker (optional)
        self.consistency_checker = None
        self._safety_classifier = None
        if config.consistency_check_enabled:
            try:
                from goop_shield.enterprise.consistency_checker import (
                    ConsistencyChecker,
                    ProviderConfig,
                    SafetyClassifier,
                )

                provider_configs = [ProviderConfig(**p) for p in config.consistency_providers]
                self.consistency_checker = ConsistencyChecker(
                    providers=provider_configs,
                    divergence_threshold=config.consistency_divergence_threshold,
                    timeout_seconds=config.consistency_timeout_seconds,
                )
                self._safety_classifier = SafetyClassifier(
                    check_rate=config.consistency_check_rate,
                )
            except (ImportError, NotImplementedError):
                logger.warning("ConsistencyChecker requires enterprise package")
            except (ValueError, TypeError) as e:
                logger.error("ConsistencyChecker config error: %s", e)

        # Sandbagging detector (optional)
        self.sandbag_detector = None
        if config.sandbag_detection_enabled:
            try:
                from goop_shield.enterprise.sandbag_detector import SandbagDetector

                self.sandbag_detector = SandbagDetector(
                    ranking_backend=self.ranking,
                    sigma_threshold=config.sandbag_sigma_threshold,
                    min_samples=config.sandbag_min_samples,
                )
            except (ImportError, NotImplementedError):
                logger.warning("SandbagDetector requires enterprise package")

        # Alignment output scanner (optional — requires SandbagDetector)
        if config.alignment_scanner_enabled and self.sandbag_detector is not None:
            from goop_shield.defenses.output import AlignmentOutputScanner

            scanner = AlignmentOutputScanner(
                sandbag_detector=self.sandbag_detector,
                sigma_threshold=config.sandbag_sigma_threshold,
            )
            self.registry.register_scanner(scanner)
            self.ranking.register_defense(f"output:{scanner.name}")
            logger.info("AlignmentOutputScanner registered in output pipeline")

    def _apply_defense_filters(self) -> None:
        """Remove defenses based on enabled/disabled config."""
        if self.config.enabled_defenses is not None:
            for name in list(self.registry.names()):
                if name not in self.config.enabled_defenses:
                    self.registry.remove(name)
            for name in self.config.enabled_defenses:
                if self.registry.get(name) is None:
                    logger.warning("Unknown defense in enabled_defenses: %s", name)

        for name in self.config.disabled_defenses:
            if self.registry.get(name) is None and (
                self.config.enabled_defenses is None or name not in self.config.enabled_defenses
            ):
                logger.warning("Unknown defense in disabled_defenses: %s", name)
            self.registry.remove(name)

        # Enforce mandatory defenses cannot be disabled
        for name in ShieldConfig.MANDATORY_DEFENSES:
            if self.registry.get(name) is None:
                logger.warning(
                    "Mandatory defense '%s' was disabled — re-enabling. "
                    "Mandatory defenses cannot be removed.", name
                )
                # Re-register the mandatory defense
                self._re_register_mandatory(name)

    def _re_register_mandatory(self, name: str) -> None:
        """Re-register a mandatory defense that was improperly disabled."""
        from goop_shield.defenses.heuristic import (
            InjectionBlocker,
            InputValidator,
            PromptNormalizer,
            SafetyFilter,
        )
        _mandatory_classes = {
            "prompt_normalizer": PromptNormalizer,
            "safety_filter": SafetyFilter,
            "input_validator": InputValidator,
            "injection_blocker": InjectionBlocker,
        }
        cls = _mandatory_classes.get(name)
        if cls is not None:
            self.registry.register(cls())

    def _apply_scanner_filters(self) -> None:
        """Remove scanners based on enabled/disabled config."""
        if self.config.enabled_scanners is not None:
            for name in list(self.registry.scanner_names()):
                if name not in self.config.enabled_scanners:
                    self.registry.remove_scanner(name)
            for name in self.config.enabled_scanners:
                if self.registry.get_scanner(name) is None:
                    logger.warning("Unknown scanner in enabled_scanners: %s", name)

        for name in self.config.disabled_scanners:
            if self.registry.get_scanner(name) is None and (
                self.config.enabled_scanners is None or name not in self.config.enabled_scanners
            ):
                logger.warning("Unknown scanner in disabled_scanners: %s", name)
            self.registry.remove_scanner(name)

    @staticmethod
    def _create_default_ranking(config: ShieldConfig) -> RankingBackend:
        """Create a ranking backend based on ``config.ranking_backend``.

        Modes:
          - ``"auto"``:   Try enterprise BroRL, fall back to StaticRanking.
          - ``"static"``: Always use StaticRanking.
          - ``"brorl"``:  Require enterprise BroRL; raise if unavailable.
        """
        from goop_shield.ranking.static import StaticRanking

        mode = config.ranking_backend

        if mode == "static":
            logger.info("Shield Community: static defense ranking")
            return StaticRanking(priorities=dict(config.static_defense_priorities))

        # "auto" or "brorl" — attempt enterprise import
        try:
            from goop_shield.enterprise.brorl_ranking import BroRLRankingBackend

            backend = BroRLRankingBackend(
                learning_rate=config.brorl_learning_rate,
                exploration_bonus=config.brorl_exploration_bonus,
                epsilon=config.brorl_epsilon,
                temperature=config.brorl_temperature,
            )
            logger.info("Shield Enterprise: BroRL adaptive ranking enabled")
            return backend
        except (ImportError, NotImplementedError):
            if mode == "brorl":
                raise ImportError(
                    "ranking_backend='brorl' requires the enterprise edition "
                    "(BroRLRankingBackend). "
                    "Set ranking_backend='auto' to fall back to static ranking."
                )
            logger.info("Shield Community: static defense ranking (BroRL not available)")
            return StaticRanking(priorities=dict(config.static_defense_priorities))

    def _record_defense_stat(self, name: str, blocked: bool, sanitized: bool = False) -> None:
        """Increment per-defense invocation and block counters.

        Also feeds the outcome to the ranking backend so BroRL learns
        from every defense execution (not just external telemetry).
        Sanitize-only defenses (e.g. ``output_filter``) get credit as
        ``blocked=True`` since they successfully defended the prompt.
        """
        with self._counter_lock:
            if name not in self.defense_stats:
                self.defense_stats[name] = {"invocations": 0, "blocks": 0}
            self.defense_stats[name]["invocations"] += 1
            if blocked:
                self.defense_stats[name]["blocks"] += 1

        # Feed outcome to ranking backend (BroRL).
        # blocked OR sanitized both count as "defense succeeded".
        self.ranking.record_outcome(name, blocked=blocked or sanitized)

    @staticmethod
    def _compute_overall_confidence(verdicts: list) -> float:
        """Compute overall confidence from a list of verdicts.

        Returns the max confidence from blocking verdicts if any exist,
        otherwise returns the average confidence across all verdicts.
        """
        if not verdicts:
            return 0.0
        blocking = [v for v in verdicts if v.action == DefenseAction.BLOCK]
        if blocking:
            return max(v.confidence for v in blocking)
        return sum(v.confidence for v in verdicts) / len(verdicts)

    def _compute_fused_score(
        self, inline_verdicts: list[InlineVerdict]
    ) -> tuple[float | None, list[str]]:
        """Combine weak threat_confidence signals using noisy-OR fusion.

        Returns ``(fused_score, contributor_names)`` or ``(None, [])``
        when fusion is disabled.

        Formula: fused = 1 - ∏(1 - tᵢ)  over qualifying signals.
        Excludes verdicts that are blocked, sanitized, or below the
        minimum signal threshold.
        """
        if not self.config.signal_fusion_enabled:
            return None, []

        min_signal = self.config.signal_fusion_min_signal
        product = 1.0
        contributors: list[str] = []

        for v in inline_verdicts:
            tc = v.threat_confidence
            if tc < min_signal:
                continue
            if v.sanitized or v.blocked:
                continue
            product *= 1.0 - tc
            contributors.append(v.defense_name)

        fused = 1.0 - product
        return fused, contributors

    def defend(self, request: DefendRequest) -> DefendResponse:
        """Run the full defense pipeline on *request*."""
        t0 = time.perf_counter()
        with self._counter_lock:
            self.total_requests += 1

        # 1. Build context
        ctx = DefenseContext(
            original_prompt=request.prompt,
            current_prompt=request.prompt,
            user_context=dict(request.context),
            max_prompt_length=self.config.max_prompt_length,
            max_prompt_tokens=self.config.max_prompt_tokens,
            injection_confidence_threshold=self.config.injection_confidence_threshold,
        )

        # 2. Run mandatory defenses first (before BroRL-ranked defenses).
        #    These always run and must see the raw/early prompt before
        #    ranking-dependent defenses.  Res 4.3: uses d.mandatory flag.
        defenses = self.registry.get_all()
        preprocessors = [d for d in defenses if d.mandatory]
        remaining = [d for d in defenses if not d.mandatory]

        verdicts: list[DefenseVerdict] = []
        applied: list[str] = []
        blocked = False
        # R7: Collect raw InlineVerdicts for metadata extraction (local for thread safety)
        inline_verdicts: list[InlineVerdict] = []

        for defense in preprocessors:
            dt0 = time.perf_counter()
            try:
                verdict = defense.execute(ctx)
            except Exception:
                logger.exception("Preprocessor %s raised an exception", defense.name)
                if self.config.failure_policy == "closed":
                    blocked = True
                    self._record_defense_stat(defense.name, blocked=True)
                    verdicts.append(
                        DefenseVerdict(
                            defense_name=defense.name,
                            action=DefenseAction.BLOCK,
                            confidence=0.0,
                            details="Defense error; failure_policy=closed",
                            latency_ms=(time.perf_counter() - dt0) * 1000,
                        )
                    )
                    applied.append(defense.name)
                    break
                continue
            dt_ms = (time.perf_counter() - dt0) * 1000
            inline_verdicts.append(verdict)

            if verdict.blocked:
                action = DefenseAction.BLOCK
            elif verdict.sanitized:
                action = DefenseAction.SANITIZE
            else:
                action = DefenseAction.ALLOW

            verdicts.append(
                DefenseVerdict(
                    defense_name=defense.name,
                    action=action,
                    confidence=verdict.confidence,
                    threat_confidence=verdict.threat_confidence,
                    details=verdict.details,
                    latency_ms=dt_ms,
                )
            )
            applied.append(defense.name)
            self._record_defense_stat(
                defense.name,
                blocked=verdict.blocked,
                sanitized=verdict.sanitized,
            )

            if verdict.blocked:
                blocked = True
                break
            if verdict.sanitized:
                ctx.current_prompt = verdict.filtered_prompt

        # 3. Rank remaining defenses via ranking backend
        if not blocked:
            ranked_pairs = self.ranking.rank_defenses([d.name for d in remaining])
            # Map ranked names back to defense objects
            name_to_defense = {d.name: d for d in remaining}
            ranked = [
                (name_to_defense[name], score)
                for name, score in ranked_pairs
                if name in name_to_defense
            ]
        else:
            ranked = []

        # 5. Execute defenses sequentially
        for defense, _score in ranked:
            dt0 = time.perf_counter()
            try:
                verdict = defense.execute(ctx)
            except Exception:
                logger.exception("Defense %s raised an exception", defense.name)
                if self.config.failure_policy == "closed":
                    blocked = True
                    self._record_defense_stat(defense.name, blocked=True)
                    verdicts.append(
                        DefenseVerdict(
                            defense_name=defense.name,
                            action=DefenseAction.BLOCK,
                            confidence=0.0,
                            details="Defense error; failure_policy=closed",
                            latency_ms=(time.perf_counter() - dt0) * 1000,
                        )
                    )
                    applied.append(defense.name)
                    break
                # failure_policy=open — skip this defense
                continue
            dt_ms = (time.perf_counter() - dt0) * 1000
            inline_verdicts.append(verdict)

            if verdict.blocked:
                action = DefenseAction.BLOCK
            elif verdict.sanitized:
                action = DefenseAction.SANITIZE
            else:
                action = DefenseAction.ALLOW

            verdicts.append(
                DefenseVerdict(
                    defense_name=defense.name,
                    action=action,
                    confidence=verdict.confidence,
                    threat_confidence=verdict.threat_confidence,
                    details=verdict.details,
                    latency_ms=dt_ms,
                )
            )
            applied.append(defense.name)
            self._record_defense_stat(
                defense.name,
                blocked=verdict.blocked,
                sanitized=verdict.sanitized,
            )

            if verdict.blocked:
                blocked = True
                break

            # Chain sanitised prompt to downstream defenses
            if verdict.sanitized:
                ctx.current_prompt = verdict.filtered_prompt

        # Signal fusion: combine weak threat_confidence signals across defenses
        fused_score, fusion_contributors = self._compute_fused_score(inline_verdicts)
        fusion_session_adjusted = False
        fusion_would_block = False
        if fused_score is not None:
            threshold = self.config.signal_fusion_threshold

            # Session-aware threshold adjustment: lower threshold when session is escalating
            if self.config.signal_fusion_session_aware and self.session_tracker is not None:
                session_id = str(request.context.get("session_id", "__default__"))
                session_risk = self.session_tracker.get_risk(session_id)
                if session_risk.risk_level == "high":
                    threshold *= self.config.signal_fusion_escalation_multiplier
                    fusion_session_adjusted = True
                elif session_risk.risk_level == "medium":
                    mid = (1.0 + self.config.signal_fusion_escalation_multiplier) / 2
                    threshold *= mid
                    fusion_session_adjusted = True

            if not blocked and fused_score >= threshold:
                fusion_would_block = True
                contributors_str = ", ".join(fusion_contributors)
                threshold_note = (
                    f" (session-adjusted from {self.config.signal_fusion_threshold})"
                    if fusion_session_adjusted
                    else ""
                )
                if self.config.signal_fusion_blocking_enabled:
                    # Active mode: actually block
                    blocked = True
                    applied.append("signal_fusion")
                    verdicts.append(
                        DefenseVerdict(
                            defense_name="signal_fusion",
                            action=DefenseAction.BLOCK,
                            confidence=fused_score,
                            threat_confidence=fused_score,
                            details=(
                                f"Fused score {fused_score:.4f} >= {threshold:.4f}{threshold_note} "
                                f"(contributors: {contributors_str})"
                            ),
                            latency_ms=0.0,
                        )
                    )
                else:
                    # Shadow mode: log but don't block
                    # confidence=0.0 so shadow verdict doesn't inflate overall
                    # response confidence; threat_confidence carries the real signal.
                    applied.append("signal_fusion_shadow")
                    verdicts.append(
                        DefenseVerdict(
                            defense_name="signal_fusion_shadow",
                            action=DefenseAction.ALLOW,
                            confidence=0.0,
                            threat_confidence=fused_score,
                            details=(
                                f"Shadow: fused {fused_score:.4f} >= {threshold:.4f}{threshold_note} "
                                f"would block (contributors: {contributors_str})"
                            ),
                            latency_ms=0.0,
                        )
                    )

        # Update fusion counters atomically
        if fused_score is not None:
            with self._fusion_lock:
                self.fusion_evaluations += 1
                if fusion_session_adjusted:
                    self.fusion_session_adjusted += 1
                if fusion_would_block:
                    self.fusion_would_block += 1

        if blocked:
            with self._counter_lock:
                self.total_blocked += 1

        confidence = self._compute_overall_confidence(verdicts)

        # Record session signal for multi-turn tracking
        if self.session_tracker is not None:
            session_id = request.context.get("session_id", "__default__")
            # Use max threat_confidence from verdicts as injection signal
            max_signal = 0.0
            for v in verdicts:
                # Map action back to threat confidence
                if v.action == DefenseAction.BLOCK:
                    max_signal = max(max_signal, v.confidence)
                elif v.confidence > 0:
                    max_signal = max(max_signal, v.confidence * 0.5)
            prompt_hash = SessionTracker.hash_prompt(request.prompt)

            # R7: Extract config guard metadata for cross-turn correlation
            has_config_ref = False
            has_modify_intent = False
            for prep_verdict in inline_verdicts:
                if prep_verdict.defense_name == "agent_config_guard" and prep_verdict.metadata:
                    has_config_ref = prep_verdict.metadata.get("has_config_ref", False)
                    has_modify_intent = prep_verdict.metadata.get("has_modify_intent", False)
                    break

            session_risk = self.session_tracker.record_turn(
                session_id=str(session_id),
                injection_signal=max_signal,
                prompt_hash=prompt_hash,
                has_config_ref=has_config_ref,
                has_modify_intent=has_modify_intent,
            )

            # P1-2: Block on high session risk when enabled
            if (
                self.config.session_tracker_blocking_enabled
                and session_risk.risk_level == "high"
                and not blocked
            ):
                blocked = True
                verdicts.append(
                    DefenseVerdict(
                        defense_name="session_tracker",
                        action=DefenseAction.BLOCK,
                        confidence=min(session_risk.cumulative_signal / 3.0, 1.0),
                        details=(
                            f"Session risk HIGH: cumulative_signal={session_risk.cumulative_signal:.2f}, "
                            f"turns={session_risk.turn_count}, escalating={session_risk.escalating}"
                        ),
                        latency_ms=0.0,
                    )
                )

        # Inject canaries into non-blocked prompts
        if not blocked and self.deception is not None and self._canary_tokens:
            ctx.current_prompt = self.deception.inject_canaries(
                ctx.current_prompt, self._canary_tokens
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return DefendResponse(
            allow=not blocked,
            filtered_prompt=ctx.current_prompt,
            defenses_applied=applied,
            verdicts=verdicts,
            confidence=confidence,
            fused_score=fused_score,
            latency_ms=elapsed_ms,
        )

    def scan_response(self, request: ScanRequest) -> ScanResponse:
        """Run the output scanning pipeline on an LLM response."""
        t0 = time.perf_counter()
        with self._counter_lock:
            self.total_requests += 1

        # 1. Build output context
        ctx = OutputContext(
            response_text=request.response_text,
            current_response=request.response_text,
            original_prompt=request.original_prompt,
            user_context=dict(request.context),
        )

        # Check for canary leaks
        if self.deception is not None:
            leaked = self.deception.check_canary_triggered(ctx.current_response)
            if leaked:
                with self._counter_lock:
                    self.total_blocked += 1
                elapsed_ms = (time.perf_counter() - t0) * 1000
                return ScanResponse(
                    safe=False,
                    filtered_response=ctx.current_response,
                    scanners_applied=["deception_canary"],
                    verdicts=[
                        DefenseVerdict(
                            defense_name="deception_canary",
                            action=DefenseAction.BLOCK,
                            confidence=1.0,
                            details=f"Canary leak detected: {len(leaked)} token(s) found in response",
                            latency_ms=(time.perf_counter() - t0) * 1000,
                        )
                    ],
                    confidence=1.0,
                    latency_ms=elapsed_ms,
                )

        # 2. Rank scanners via ranking backend
        scanners = self.registry.get_all_scanners()
        ranked_pairs = self.ranking.rank_defenses([f"output:{s.name}" for s in scanners])
        # Map ranked names back to scanner objects
        name_to_scanner = {f"output:{s.name}": s for s in scanners}
        ranked = [
            (name_to_scanner[name], score)
            for name, score in ranked_pairs
            if name in name_to_scanner
        ]

        # 4. Execute scanners sequentially
        verdicts: list[DefenseVerdict] = []
        applied: list[str] = []
        blocked = False

        for scanner, _score in ranked:
            dt0 = time.perf_counter()
            try:
                verdict = scanner.scan(ctx)
            except Exception:
                logger.exception("Scanner %s raised an exception", scanner.name)
                if self.config.failure_policy == "closed":
                    blocked = True
                    self._record_defense_stat(f"output:{scanner.name}", blocked=True)
                    verdicts.append(
                        DefenseVerdict(
                            defense_name=scanner.name,
                            action=DefenseAction.BLOCK,
                            confidence=0.0,
                            details="Scanner error; failure_policy=closed",
                            latency_ms=(time.perf_counter() - dt0) * 1000,
                        )
                    )
                    applied.append(scanner.name)
                    break
                continue
            dt_ms = (time.perf_counter() - dt0) * 1000

            if verdict.blocked:
                action = DefenseAction.BLOCK
            elif verdict.sanitized:
                action = DefenseAction.SANITIZE
            else:
                action = DefenseAction.ALLOW

            verdicts.append(
                DefenseVerdict(
                    defense_name=scanner.name,
                    action=action,
                    confidence=verdict.confidence,
                    threat_confidence=verdict.threat_confidence,
                    details=verdict.details,
                    latency_ms=dt_ms,
                )
            )
            applied.append(scanner.name)
            self._record_defense_stat(
                f"output:{scanner.name}",
                blocked=verdict.blocked,
                sanitized=verdict.sanitized,
            )

            # Chain sanitised response to downstream scanners (even if blocked,
            # so the filtered_response carries the redacted text)
            if verdict.sanitized:
                ctx.current_response = verdict.filtered_prompt

            if verdict.blocked:
                blocked = True
                break

        if blocked:
            with self._counter_lock:
                self.total_blocked += 1

        confidence = self._compute_overall_confidence(verdicts)

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return ScanResponse(
            safe=not blocked,
            filtered_response=ctx.current_response,
            scanners_applied=applied,
            verdicts=verdicts,
            confidence=confidence,
            latency_ms=elapsed_ms,
        )

    def scan_tool_output(self, request: ToolOutputScanRequest) -> ToolOutputScanResponse:
        """Scan tool output for injection and malicious content.

        Runs the IndirectInjection defense + all output scanners on the
        content, treating it as untrusted external data.
        """
        if not self.config.tool_output_scanning_enabled:
            return ToolOutputScanResponse(
                safe=True,
                filtered_content=request.content,
                action="pass",
                scanners_applied=[],
                verdicts=[],
                confidence=0.0,
                latency_ms=0.0,
            )

        t0 = time.perf_counter()
        with self._counter_lock:
            self.total_requests += 1

        # Build context with tool metadata for IndirectInjection activation
        user_ctx = dict(request.context)
        user_ctx["tool_output"] = request.content
        user_ctx["source"] = "tool"
        user_ctx["tool_name"] = request.tool_name
        if request.source_url:
            user_ctx["source_url"] = request.source_url
        user_ctx["trust_level"] = request.trust_level

        # 1. Run inline defenses (esp. IndirectInjection) on the content
        defend_req = DefendRequest(prompt=request.content, context=user_ctx)
        defend_resp = self.defend(defend_req)

        # 2. Also run output scanners (secret leak, canary, harmful content)
        scan_req = ScanRequest(response_text=request.content, context=user_ctx)
        scan_resp = self.scan_response(scan_req)

        # Merge results — blocked if either pipeline blocked
        blocked = not defend_resp.allow or not scan_resp.safe
        all_verdicts = defend_resp.verdicts + scan_resp.verdicts
        all_applied = defend_resp.defenses_applied + scan_resp.scanners_applied

        # Determine filtered content (carry through sanitization from either pipeline)
        if not defend_resp.allow:
            filtered = defend_resp.filtered_prompt
        elif not scan_resp.safe:
            filtered = scan_resp.filtered_response
        elif scan_resp.filtered_response != request.content:
            # Output scanner sanitized without blocking
            filtered = scan_resp.filtered_response
        else:
            filtered = request.content

        # Wrap with provenance markers if requested and not blocked
        if request.wrap_markers and not blocked:
            marker_source = request.tool_name
            marker_trust = request.trust_level
            filtered = (
                f'<<<TOOL_OUTPUT source="{marker_source}" trust="{marker_trust}" '
                f'scanned="true">>>\n{filtered}\n<<<END_TOOL_OUTPUT>>>'
            )

        # Overall action
        if blocked:
            action = "block"
        elif any(v.action == DefenseAction.SANITIZE for v in all_verdicts):
            action = "sanitize"
        else:
            action = "pass"

        confidence = self._compute_overall_confidence(all_verdicts)

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return ToolOutputScanResponse(
            safe=not blocked,
            filtered_content=filtered,
            action=action,
            scanners_applied=all_applied,
            verdicts=all_verdicts,
            confidence=confidence,
            latency_ms=elapsed_ms,
        )

    def scan_memory_file(self, request: MemoryScanRequest) -> ToolOutputScanResponse:
        """Scan a memory/critical file for injected instructions.

        Runs the MemoryWriteGuard defense and output scanners on the content.
        """
        if not self.config.memory_protection_enabled:
            return ToolOutputScanResponse(
                safe=True,
                filtered_content=request.content,
                action="pass",
                scanners_applied=[],
                verdicts=[],
                confidence=0.0,
                latency_ms=0.0,
            )

        t0 = time.perf_counter()
        with self._counter_lock:
            self.total_requests += 1

        user_ctx = dict(request.context)
        if request.operation == "write":
            user_ctx["memory_write"] = True
        else:
            user_ctx["memory_read"] = True
        user_ctx["target_file"] = request.file_path
        user_ctx["source"] = "memory"

        # Run inline defenses (MemoryWriteGuard + IndirectInjection)
        defend_req = DefendRequest(prompt=request.content, context=user_ctx)
        defend_resp = self.defend(defend_req)

        # Also run output scanners
        scan_req = ScanRequest(response_text=request.content, context=user_ctx)
        scan_resp = self.scan_response(scan_req)

        blocked = not defend_resp.allow or not scan_resp.safe
        all_verdicts = defend_resp.verdicts + scan_resp.verdicts
        all_applied = defend_resp.defenses_applied + scan_resp.scanners_applied

        if not defend_resp.allow:
            filtered = defend_resp.filtered_prompt
        elif not scan_resp.safe:
            filtered = scan_resp.filtered_response
        else:
            filtered = request.content

        if blocked:
            action = "block"
        elif any(v.action == DefenseAction.SANITIZE for v in all_verdicts):
            action = "sanitize"
        else:
            action = "pass"

        confidence = self._compute_overall_confidence(all_verdicts)

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return ToolOutputScanResponse(
            safe=not blocked,
            filtered_content=filtered,
            action=action,
            scanners_applied=all_applied,
            verdicts=all_verdicts,
            confidence=confidence,
            latency_ms=elapsed_ms,
        )

    def scan_content(self, content: str, context: dict | None = None) -> dict:
        """Run all defenses in scan-only mode (no blocking/sanitizing).

        Used by the Training Data Gate to assess content without
        affecting request counters or applying any modifications.

        Args:
            content: The content to scan.
            context: Optional context dict.

        Returns:
            Dict with ``triggered_defenses``, ``defense_scores``,
            ``max_confidence``, and ``total_defenses_run``.
        """
        skip_defenses = set(self.config.training_scan_skip_defenses)

        ctx = DefenseContext(
            original_prompt=content,
            current_prompt=content,
            user_context=dict(context or {}),
            max_prompt_length=self.config.max_prompt_length,
            max_prompt_tokens=self.config.max_prompt_tokens,
            injection_confidence_threshold=self.config.injection_confidence_threshold,
        )

        triggered: list[str] = []
        scores: dict[str, float] = {}
        max_confidence = 0.0
        total_run = 0

        for defense in self.registry.get_all():
            if defense.name in skip_defenses:
                continue
            total_run += 1
            try:
                verdict = defense.execute(ctx)
            except Exception:
                logger.debug("scan_content: defense %s raised, skipping", defense.name)
                continue

            # Use threat_confidence for scan-mode assessment.
            # If blocked and no explicit threat_confidence, infer from confidence.
            effective_threat = verdict.threat_confidence
            if verdict.blocked and effective_threat == 0.0:
                effective_threat = verdict.confidence if verdict.confidence > 0 else 1.0

            if effective_threat > 0:
                scores[defense.name] = effective_threat
                max_confidence = max(max_confidence, effective_threat)
                if effective_threat >= ctx.injection_confidence_threshold:
                    triggered.append(defense.name)

        return {
            "triggered_defenses": triggered,
            "defense_scores": scores,
            "max_confidence": max_confidence,
            "total_defenses_run": total_run,
        }

    def record_outcome(self, event: TelemetryEvent) -> None:
        """Update ranking backend from an observed outcome."""
        self.ranking.record_outcome(
            defense_name=event.defense_action,
            blocked=event.outcome == "blocked",
        )

    def get_stats(self) -> dict:
        """Bundle defender stats + ranking weights into one dict."""
        with self._counter_lock:
            total_requests = self.total_requests
            total_blocked = self.total_blocked
            defense_stats = {k: dict(v) for k, v in self.defense_stats.items()}
        stats = {
            "total_requests": total_requests,
            "total_blocked": total_blocked,
            "defense_stats": defense_stats,
            "ranking_weights": self.ranking.get_weights(),
            "ranking_stats": self.ranking.get_stats(),
        }
        if self._alignment_canaries and self.deception is not None:
            stats["alignment_canary_stats"] = self.deception.get_alignment_canary_stats()
        if self.sandbag_detector is not None:
            cat_stats = self.sandbag_detector.get_category_stats()
            stats["sandbag_stats"] = {
                name: {
                    "success_rate": cs.success_rate,
                    "samples": cs.samples,
                    "z_score": cs.z_score,
                }
                for name, cs in cat_stats.items()
            }
        if self.consistency_checker is not None:
            stats["consistency_stats"] = self.consistency_checker.get_stats()
        # Signal fusion counters
        if self.config.signal_fusion_enabled:
            with self._fusion_lock:
                stats["fusion_stats"] = {
                    "evaluations": self.fusion_evaluations,
                    "would_block": self.fusion_would_block,
                    "session_adjusted": self.fusion_session_adjusted,
                }
        return stats

    # ------------------------------------------------------------------
    # Alignment canary injection & checking
    # ------------------------------------------------------------------

    def _should_inject_alignment_canary(self) -> bool:
        """Return ``True`` every N requests based on canary_injection_rate."""
        if not self._alignment_canaries:
            return False
        with self._alignment_canary_lock:
            self._alignment_canary_counter += 1
            rate = getattr(self.config, "canary_injection_rate", 50)
            return self._alignment_canary_counter % rate == 0

    def get_pending_canary(self) -> AlignmentCanary | None:
        """Return a random alignment canary for injection, or ``None``."""
        if self._should_inject_alignment_canary():
            import random

            return random.choice(self._alignment_canaries)
        return None

    def check_canary_result(self, canary: AlignmentCanary, response: str) -> dict:
        """Check an alignment canary response and record the result.

        Records the outcome in BroRL as an ``alignment:{category}``
        technique so that canary pass/fail rates feed into the
        adaptive ranking system.

        Returns:
            Dict with ``canary_id``, ``category``, ``passed``,
            ``total_checks``, and ``pass_rate``.
        """
        if self.deception is None:
            return {"error": "Deception engine not enabled"}

        passed = self.deception.check_alignment_response(canary, response)

        # Record in BroRL as alignment:{category} technique.
        # BroRL semantics: blocked=True means "defense succeeded".  For
        # alignment canaries, a *passed* canary means the model responded
        # correctly (i.e. the alignment "defense" succeeded), so we map
        # blocked=passed.
        technique_id = f"alignment:{canary.category}"
        self.ranking.register_defense(technique_id)
        self.ranking.record_outcome(technique_id, blocked=passed)

        return {
            "canary_id": canary.canary_id,
            "category": canary.category,
            "passed": passed,
            "total_checks": canary.total_checks,
            "pass_rate": canary.passes / max(canary.total_checks, 1),
        }
