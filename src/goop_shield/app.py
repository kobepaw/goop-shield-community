# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield — Standalone FastAPI Application

Run with:
    python -m goop_shield.app
    uvicorn goop_shield.app:app --host 127.0.0.1 --port 8787
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import hmac
import ipaddress
import logging
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware

from goop_shield.audit import ShieldAuditDB, classify_attack
from goop_shield.behavior import BehavioralMonitor
from goop_shield.config import ShieldConfig
from goop_shield.defender import Defender
from goop_shield.models import (
    BehaviorEvent,
    BehaviorVerdict,
    DefendRequest,
    DefendResponse,
    MemoryScanRequest,
    ProbeRequest,
    RedTeamReport,
    ScanRequest,
    ScanResponse,
    ShieldHealth,
    TelemetryEvent,
    ToolOutputScanRequest,
    ToolOutputScanResponse,
)
from goop_shield.telemetry import TelemetryBuffer

logger = logging.getLogger(__name__)

_STARTUP_TIME: float = 0.0

_AUTH_EXEMPT_PATHS = frozenset({"/api/v1/health"})

# Paths that require SHIELD_API_KEY to be set. Returns 403 when auth is disabled.
_AUTH_REQUIRED_PATHS = frozenset(
    {
        "/debug/defend",
        "/api/v1/brorl/load",
        "/api/v1/policy/load",
        "/api/v1/telemetry/events",  # prevent ranking poisoning
    }
)

# Admin path prefixes gated when SHIELD_API_KEY is not set.
_ADMIN_PATH_PREFIXES = (
    "/api/v1/redteam/",
    "/api/v1/audit/",
    "/api/v1/brorl/",
    "/api/v1/policy/",
    "/api/v1/intel/",
    "/api/v1/training/",
)

# WebSocket subscribers for real-time audit events
_ws_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

# Background task references (prevent GC of fire-and-forget tasks)
_background_tasks: set[asyncio.Task[None]] = set()


def _broadcast_audit_event(event: dict[str, Any]) -> None:
    """Push event to all WebSocket subscribers (non-blocking)."""
    for q in _ws_subscribers:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass  # slow consumer — drop oldest not feasible, just skip


def _extract_http_metadata(request: Request) -> tuple[str, str, str, str]:
    """Extract HTTP metadata from request for audit logging.

    Returns (user_agent, content_type, accept_language, headers_hash).
    """
    user_agent = request.headers.get("user-agent", "")
    content_type = request.headers.get("content-type", "")
    accept_language = request.headers.get("accept-language", "")
    sorted_hdrs = sorted(
        (k.lower(), v)
        for k, v in request.headers.items()
        if k.lower() not in ("authorization", "cookie")
    )
    headers_hash = hashlib.sha256(str(sorted_hdrs).encode()).hexdigest()[:16]
    return user_agent, content_type, accept_language, headers_hash


def _enrich_audit_event(
    event: dict[str, Any],
    request: Request,
    source_ip: str,
    user_agent: str,
    headers_hash: str,
) -> None:
    """Enrich an audit event with threat intel and geo data, then broadcast.

    Handles threat actor wiring and geo enrichment. Broadcasts the fully-enriched
    event to WebSocket subscribers.
    """
    threat_actor_db = app.state.threat_actor_db
    if threat_actor_db is not None:
        try:
            actor_id = threat_actor_db.get_or_create_actor(source_ip, user_agent, headers_hash)
            threat_actor_db.update_actor_from_event(actor_id, event)
            event["actor_id"] = actor_id
        except Exception:
            logger.warning("Threat actor enrichment failed for %s", source_ip, exc_info=True)

    ip_enricher = app.state.ip_enricher
    if ip_enricher is not None and source_ip:
        geo = ip_enricher.enrich(source_ip)
        event["geo"] = geo.model_dump()

    _broadcast_audit_event(event)


def _enrich_events_with_actors(
    events: list[dict[str, Any]],
    threat_actor_db: Any,
) -> list[dict[str, Any]]:
    """Annotate audit events with actor_id by looking up (source_ip, request_headers_hash).

    Modifies events in-place and returns them for convenience.
    """
    for ev in events:
        source_ip = ev.get("source_ip", "")
        headers_hash = ev.get("request_headers_hash", "")
        if not source_ip:
            continue
        actor_id = threat_actor_db.get_actor_id_by_fingerprint(source_ip, headers_hash)
        if actor_id is not None:
            ev["actor_id"] = actor_id
    return events


# ============================================================================
# Auth Middleware
# ============================================================================


class ShieldAuthMiddleware(BaseHTTPMiddleware):
    """Bearer-token auth using ``SHIELD_API_KEY`` env var.

    Only the health endpoint is exempt. When the env var is unset all
    requests pass through (opt-in for research).
    """

    _auth_warning_logged = False

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        api_key = os.environ.get("SHIELD_API_KEY")
        if not api_key:
            if not ShieldAuthMiddleware._auth_warning_logged:
                logger.warning(
                    "Shield auth disabled: SHIELD_API_KEY env var not set. "
                    "Set SHIELD_API_KEY to enable bearer token authentication."
                )
                ShieldAuthMiddleware._auth_warning_logged = True
            # Block admin/debug endpoints when auth is disabled
            path = request.url.path
            if path in _AUTH_REQUIRED_PATHS or path.startswith(_ADMIN_PATH_PREFIXES):
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "This endpoint requires SHIELD_API_KEY to be set.",
                    },
                )
            return await call_next(request)

        if request.url.path in _AUTH_EXEMPT_PATHS:
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if hmac.compare_digest(auth_header, f"Bearer {api_key}"):
            return await call_next(request)

        return JSONResponse(
            status_code=403,
            content={
                "error": "forbidden",
                "message": "Invalid or missing API key",
            },
        )


# ============================================================================
# Config Loading
# ============================================================================


def _load_config() -> ShieldConfig:
    """Load ShieldConfig from env-var path or fall back to defaults."""
    config_path = os.environ.get("SHIELD_CONFIG")
    if config_path:
        from goop_shield._config_loader import ConfigLoader

        loader = ConfigLoader()
        return loader.load(ShieldConfig, config_path)
    return ShieldConfig()


# ============================================================================
# Lifespan
# ============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create Defender + TelemetryBuffer and store in app.state."""
    global _STARTUP_TIME
    _STARTUP_TIME = time.time()

    config = _load_config()
    defender = Defender(config)
    telemetry = TelemetryBuffer(
        buffer_size=config.telemetry_buffer_size,
        flush_interval=config.telemetry_flush_interval_seconds,
        privacy_mode=config.telemetry_privacy_mode,
    )

    if config.telemetry_enabled:
        await telemetry.start()

    app.state.defender = defender
    app.state.telemetry = telemetry
    app.state.config = config
    app.state.audit_db = None
    app.state.validation_bridge = None
    app.state.redteam_runner = None
    app.state.redteam_scheduler = None

    # Audit (optional, default on)
    if config.audit_enabled:
        app.state.audit_db = ShieldAuditDB(config.audit_db_path)

    # Validation bridge (optional, default off)
    if config.validation_bridge_enabled:
        try:
            from goop_shield.enterprise.validation_bridge import ValidationBridge

            app.state.validation_bridge = ValidationBridge(
                min_confidence=config.validation_bridge_min_confidence,
            )
        except (ImportError, NotImplementedError):
            from goop_shield.validation_bridge import ValidationBridge

            app.state.validation_bridge = ValidationBridge(
                min_confidence=config.validation_bridge_min_confidence,
            )

    # Red team (optional — requires enterprise)
    if config.use_redteam:
        try:
            from goop_shield.red.runner import RedTeamRunner
            from goop_shield.red.scheduler import ProbeScheduler

            runner = RedTeamRunner(defender, config)
            scheduler = ProbeScheduler(
                runner, interval_seconds=config.redteam_probe_interval_seconds
            )
            await scheduler.start()
            app.state.redteam_runner = runner
            app.state.redteam_scheduler = scheduler
        except (ImportError, NotImplementedError):
            logger.warning("Red team requires goop-ai Enterprise")

    # Threat intelligence (optional)
    app.state.ip_enricher = None
    app.state.threat_actor_db = None

    if config.intel_enabled:
        try:
            from goop_shield.intel.geoip import IPEnricher
            from goop_shield.intel.threat_actors import ThreatActorDB

            app.state.ip_enricher = IPEnricher(db_dir=config.geoip_db_dir)
            app.state.threat_actor_db = ThreatActorDB(db_path=config.threat_actor_db_path)
        except (ImportError, NotImplementedError):
            logger.warning("Threat intel requires goop-ai Enterprise")

    # Behavioral monitor
    app.state.behavior_monitor = BehavioralMonitor()

    # Sandbagging detector + task categorizer (optional)
    app.state.sandbag_detector = None
    app.state.task_categorizer = None
    if config.sandbag_detection_enabled and defender.sandbag_detector is not None:
        app.state.sandbag_detector = defender.sandbag_detector
        try:
            from goop_shield.enterprise.task_categorizer import TaskCategorizer

            app.state.task_categorizer = TaskCategorizer()
        except (ImportError, NotImplementedError):
            logger.warning("TaskCategorizer requires enterprise package")

    # Training data gate + quarantine store (optional)
    app.state.training_gate = None
    app.state.quarantine_store = None
    if config.training_gate_enabled:
        try:
            from goop_shield.enterprise.quarantine import QuarantineStore
            from goop_shield.enterprise.training_gate import TrainingDataGate

            quarantine_store = QuarantineStore(base_path=config.training_quarantine_path)
            app.state.quarantine_store = quarantine_store
            app.state.training_gate = TrainingDataGate(
                defender=defender,
                trust_threshold=config.training_trust_threshold,
                trust_thresholds=dict(config.training_trust_thresholds),
                quarantine_store=quarantine_store,
            )
        except (ImportError, NotImplementedError):
            logger.warning("TrainingDataGate requires enterprise package")

    # Cross-model consistency checker (optional)
    app.state.consistency_checker = None
    app.state.safety_classifier = None
    if config.consistency_check_enabled and defender.consistency_checker is not None:
        app.state.consistency_checker = defender.consistency_checker
        app.state.safety_classifier = defender._safety_classifier

    # Policy manager
    from goop_shield.policy import PolicyManager

    app.state.policy_manager = PolicyManager(defender)

    logger.info(
        "Shield started on %s:%d with %d defenses and %d scanners",
        config.host,
        config.port,
        len(defender.registry),
        len(defender.registry.get_all_scanners()),
    )

    yield

    if app.state.redteam_scheduler is not None:
        await app.state.redteam_scheduler.stop()
    if app.state.validation_bridge is not None:
        app.state.validation_bridge.close()
    if app.state.ip_enricher is not None:
        app.state.ip_enricher.close()
    if app.state.threat_actor_db is not None:
        app.state.threat_actor_db.close()
    if app.state.audit_db is not None:
        app.state.audit_db.close()
    await telemetry.stop()
    logger.info("Shield shut down")


# ============================================================================
# Application
# ============================================================================


app = FastAPI(
    title="Shield",
    description="Runtime defense service for AI agents",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.add_middleware(ShieldAuthMiddleware)


# ============================================================================
# Routes
# ============================================================================


async def _defend_core(body: DefendRequest, request: Request) -> DefendResponse:
    """Shared defense logic used by both public and debug endpoints."""
    defender: Defender = app.state.defender
    telemetry: TelemetryBuffer = app.state.telemetry
    config: ShieldConfig = app.state.config
    response = defender.defend(body)

    # Auto-telemetry for each applied defense
    if config.telemetry_enabled:
        for verdict in response.verdicts:
            telemetry.add(
                TelemetryEvent(
                    attack_type="unknown",
                    defense_action=verdict.defense_name,
                    outcome=verdict.action.value,
                )
            )

    # Audit logging
    audit_db: ShieldAuditDB | None = app.state.audit_db
    if audit_db is not None:
        verdict_dicts = [v.model_dump() for v in response.verdicts]
        classification = classify_attack(verdict_dicts)
        blocking = None
        for v in response.verdicts:
            if v.action.value == "block":
                blocking = v.defense_name
                break

        source_ip = request.client.host if request.client else ""
        user_agent, content_type, accept_language, headers_hash = _extract_http_metadata(request)

        event = audit_db.record_event(
            source_ip=source_ip,
            endpoint="defend",
            prompt=body.prompt,
            max_prompt_chars=config.audit_max_prompt_chars,
            shield_action="block"
            if not response.allow
            else ("sanitize" if body.prompt != response.filtered_prompt else "allow"),
            confidence=response.confidence,
            latency_ms=response.latency_ms,
            defenses_applied=response.defenses_applied,
            verdicts=verdict_dicts,
            attack_classification=classification,
            blocking_defense=blocking,
            user_agent=user_agent,
            content_type=content_type,
            accept_language=accept_language,
            request_headers_hash=headers_hash,
        )

        _enrich_audit_event(event, request, source_ip, user_agent, headers_hash)

        # Validation bridge
        bridge = app.state.validation_bridge
        if bridge is not None:
            bridge.maybe_record(
                shield_action=event["shield_action"],
                confidence=response.confidence,
                attack_classification=classification,
                blocking_defense=blocking,
                source_ip=source_ip,
                defenses_applied=response.defenses_applied,
            )

    # Non-blocking consistency check (post-response, background)
    if (
        response.allow
        and app.state.consistency_checker is not None
        and app.state.safety_classifier is not None
        and app.state.safety_classifier.should_check(body.prompt, dict(body.context))
    ):
        task = asyncio.create_task(_run_consistency_check(body.prompt, response.filtered_prompt))
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)

    return response


@app.post("/api/v1/defend")
async def defend(body: DefendRequest, request: Request) -> dict:
    """Classify and defend a prompt.

    Returns a minimal response with allow/block decision and filtered prompt.
    Defense names, per-defense verdicts, and confidence breakdown are omitted
    to prevent adaptive attackers from fingerprinting the pipeline.
    Use ``/debug/defend`` for full telemetry (requires API key).
    """
    response = await _defend_core(body, request)

    # Minimal public response: no defense names, no per-verdict details
    result: dict[str, Any] = {
        "allow": response.allow,
        "filtered_prompt": response.filtered_prompt,
        "confidence": response.confidence,
        "latency_ms": response.latency_ms,
    }
    if not response.allow:
        result["reason"] = "Request blocked by security policy"
    return result


@app.post("/debug/defend", response_model=DefendResponse)
async def debug_defend(body: DefendRequest, request: Request) -> DefendResponse:
    """Full-telemetry defend endpoint for debugging and admin use.

    Returns the complete DefendResponse with all defense names, verdicts,
    and confidence scores. Requires API key authentication (enforced by
    ShieldAuthMiddleware — ``/debug/*`` paths are not auth-exempt).
    """
    return await _defend_core(body, request)


async def _run_consistency_check(prompt: str, primary_response: str) -> None:
    """Background task: run consistency check and log divergences."""
    try:
        checker = app.state.consistency_checker
        audit_db: ShieldAuditDB | None = app.state.audit_db
        result = await checker.check_consistency(prompt, primary_response)

        if not result.is_consistent and audit_db is not None:
            audit_db.record_event(
                endpoint="consistency_check",
                shield_action="consistency_divergence",
                confidence=result.divergence_score,
                verdicts=[
                    {
                        "divergence_score": result.divergence_score,
                        "structural": result.structural_divergence,
                        "semantic": result.semantic_divergence,
                        "factual": result.factual_divergence,
                        "comparison_providers": list(result.comparison_responses.keys()),
                        "details": result.divergence_details,
                    }
                ],
            )
    except Exception:
        logger.warning("Background consistency check failed", exc_info=True)


@app.post("/api/v1/scan-response", response_model=ScanResponse)
async def scan_response(body: ScanRequest, request: Request) -> ScanResponse:
    """Scan an LLM response for leaked secrets, canary tokens, and harmful content."""
    defender: Defender = app.state.defender
    telemetry: TelemetryBuffer = app.state.telemetry
    config: ShieldConfig = app.state.config
    response = defender.scan_response(body)

    # Auto-telemetry for each applied scanner
    if config.telemetry_enabled:
        for verdict in response.verdicts:
            telemetry.add(
                TelemetryEvent(
                    attack_type="output_scan",
                    defense_action=verdict.defense_name,
                    outcome=verdict.action.value,
                )
            )

    # Audit logging
    audit_db: ShieldAuditDB | None = app.state.audit_db
    if audit_db is not None:
        verdict_dicts = [v.model_dump() for v in response.verdicts]
        classification = classify_attack(verdict_dicts)
        blocking = None
        for v in response.verdicts:
            if v.action.value == "block":
                blocking = v.defense_name
                break

        source_ip = request.client.host if request.client else ""
        user_agent, content_type, accept_language, headers_hash = _extract_http_metadata(request)

        event = audit_db.record_event(
            source_ip=source_ip,
            endpoint="scan_response",
            prompt=body.response_text,
            max_prompt_chars=config.audit_max_prompt_chars,
            shield_action="block" if not response.safe else "allow",
            confidence=response.confidence,
            latency_ms=response.latency_ms,
            defenses_applied=response.scanners_applied,
            verdicts=verdict_dicts,
            attack_classification=classification,
            blocking_defense=blocking,
            user_agent=user_agent,
            content_type=content_type,
            accept_language=accept_language,
            request_headers_hash=headers_hash,
        )

        _enrich_audit_event(event, request, source_ip, user_agent, headers_hash)

    return response


@app.post("/api/v1/scan-tool-output")
async def scan_tool_output(body: ToolOutputScanRequest, request: Request) -> ToolOutputScanResponse:
    """Scan tool output before it enters agent context.

    Runs both the inline defense pipeline (especially IndirectInjection) and
    all output scanners on the content.  Optionally wraps clean output with
    provenance markers.
    """
    defender: Defender = app.state.defender
    return defender.scan_tool_output(body)


@app.post("/api/v1/scan-memory")
async def scan_memory(body: MemoryScanRequest, request: Request) -> ToolOutputScanResponse:
    """Scan a memory/critical file before it enters agent context.

    Runs MemoryWriteGuard + IndirectInjection + output scanners.
    """
    defender: Defender = app.state.defender
    return defender.scan_memory_file(body)


@app.post("/api/v1/telemetry/events")
async def report_telemetry(event: TelemetryEvent) -> dict[str, bool]:
    """Report an external telemetry event."""
    defender: Defender = app.state.defender
    telemetry: TelemetryBuffer = app.state.telemetry

    telemetry.add(event)
    defender.record_outcome(event)
    return {"received": True}


@app.get("/api/v1/health", response_model=ShieldHealth)
async def health(request: Request) -> ShieldHealth:
    """Health check.

    Returns basic status for unauthenticated requests.
    Includes defense/scanner details only when authenticated.
    """
    defender: Defender = app.state.defender
    audit_db: ShieldAuditDB | None = app.state.audit_db

    # Check if request is authenticated
    api_key = os.environ.get("SHIELD_API_KEY")
    authenticated = False
    if api_key:
        auth_header = request.headers.get("authorization", "")
        authenticated = hmac.compare_digest(auth_header, f"Bearer {api_key}")

    return ShieldHealth(
        status="healthy",
        defenses_loaded=len(defender.registry),
        scanners_loaded=len(defender.registry.get_all_scanners()),
        brorl_ready=bool(defender.ranking.get_weights()),
        version="0.1.0",
        uptime_seconds=time.time() - _STARTUP_TIME,
        total_requests=defender.total_requests,
        total_blocked=defender.total_blocked,
        active_defenses=defender.registry.names() if authenticated or not api_key else [],
        active_scanners=defender.registry.scanner_names() if authenticated or not api_key else [],
        audit_events_total=audit_db.get_event_count() if audit_db else 0,
    )


@app.post("/api/v1/redteam/probe", response_model=RedTeamReport)
async def redteam_probe(request: ProbeRequest) -> RedTeamReport | JSONResponse:
    """Trigger an immediate red-team probe run."""
    runner = app.state.redteam_runner
    if runner is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Red team not enabled (use_redteam=False)"},
        )
    return runner.run_probes(probe_names=request.probe_names)


@app.get("/api/v1/redteam/results", response_model=RedTeamReport)
async def redteam_results() -> RedTeamReport | JSONResponse:
    """Get the latest red-team probe results."""
    runner = app.state.redteam_runner
    if runner is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Red team not enabled (use_redteam=False)"},
        )
    if runner.latest_report is None:
        return RedTeamReport()
    return runner.latest_report


@app.get("/api/v1/brorl/state")
async def brorl_state() -> dict:
    """Export ranking backend weights (alpha/beta posteriors for BroRL)."""
    defender: Defender = app.state.defender
    return defender.ranking.get_weights()


@app.post("/api/v1/brorl/load")
async def brorl_load(weights: dict) -> dict:
    """Load ranking backend weights."""
    # Validate structure before passing to the ranking backend
    if not isinstance(weights, dict):
        return JSONResponse(status_code=400, content={"error": "Weights must be a JSON object"})
    for key, val in weights.items():
        if not isinstance(key, str):
            return JSONResponse(
                status_code=400,
                content={"error": f"Weight key must be a string, got {type(key).__name__}"},
            )
        if key == "priorities":
            if not isinstance(val, dict):
                return JSONResponse(
                    status_code=400, content={"error": "'priorities' must be a dict"}
                )
            for pname, pval in val.items():
                if not isinstance(pname, str):
                    return JSONResponse(
                        status_code=400, content={"error": "Priority key must be a string"}
                    )
                if not isinstance(pval, (int, float)):
                    return JSONResponse(
                        status_code=400,
                        content={"error": f"Priority value for '{pname}' must be numeric"},
                    )
        elif key == "default_priority":
            if not isinstance(val, (int, float)):
                return JSONResponse(
                    status_code=400, content={"error": "'default_priority' must be numeric"}
                )
    defender: Defender = app.state.defender
    defender.ranking.load_weights(weights)
    return {"loaded": True}


@app.get("/api/v1/defender/stats")
async def defender_stats() -> dict:
    """Get aggregated defender stats including BroRL weights."""
    defender: Defender = app.state.defender
    return defender.get_stats()


@app.get("/api/v1/metrics", response_class=PlainTextResponse)
async def metrics(request: Request) -> str:
    """Prometheus-format metrics.

    Returns global counters for all requests. Per-defense details,
    BroRL weights, and red team stats require authentication.
    """
    defender: Defender = app.state.defender
    uptime = time.time() - _STARTUP_TIME

    # Check if request is authenticated
    api_key = os.environ.get("SHIELD_API_KEY")
    authenticated = False
    if api_key:
        auth_header = request.headers.get("authorization", "")
        authenticated = hmac.compare_digest(auth_header, f"Bearer {api_key}")

    lines: list[str] = []

    # Global counters (always visible)
    lines.append("# HELP shield_requests_total Total number of requests processed by Shield.")
    lines.append("# TYPE shield_requests_total counter")
    lines.append(f"shield_requests_total {defender.total_requests}")

    lines.append("# HELP shield_blocked_total Total number of requests blocked by Shield.")
    lines.append("# TYPE shield_blocked_total counter")
    lines.append(f"shield_blocked_total {defender.total_blocked}")

    lines.append("# HELP shield_defenses_loaded Number of defense modules currently loaded.")
    lines.append("# TYPE shield_defenses_loaded gauge")
    lines.append(f"shield_defenses_loaded {len(defender.registry)}")

    lines.append("# HELP shield_scanners_loaded Number of output scanners currently loaded.")
    lines.append("# TYPE shield_scanners_loaded gauge")
    lines.append(f"shield_scanners_loaded {len(defender.registry.get_all_scanners())}")

    lines.append("# HELP shield_uptime_seconds Time in seconds since Shield started.")
    lines.append("# TYPE shield_uptime_seconds gauge")
    lines.append(f"shield_uptime_seconds {uptime:.1f}")

    lines.append("# HELP shield_fusion_evaluations_total Total signal fusion evaluations.")
    lines.append("# TYPE shield_fusion_evaluations_total counter")
    lines.append(f"shield_fusion_evaluations_total {defender.fusion_evaluations}")

    lines.append("# HELP shield_fusion_would_block_total Fusion evaluations that would block.")
    lines.append("# TYPE shield_fusion_would_block_total counter")
    lines.append(f"shield_fusion_would_block_total {defender.fusion_would_block}")

    lines.append(
        "# HELP shield_fusion_session_adjusted_total Fusion evaluations adjusted by session context."
    )
    lines.append("# TYPE shield_fusion_session_adjusted_total counter")
    lines.append(f"shield_fusion_session_adjusted_total {defender.fusion_session_adjusted}")

    # Per-defense details only for authenticated requests
    if authenticated or not api_key:
        lines.append("# HELP shield_defense_invocations_total Total invocations per defense.")
        lines.append("# TYPE shield_defense_invocations_total counter")
        lines.append("# HELP shield_defense_blocks_total Total blocks per defense.")
        lines.append("# TYPE shield_defense_blocks_total counter")
        for name, stats in defender.defense_stats.items():
            safe_name = name.replace(":", "_")
            lines.append(
                f'shield_defense_invocations_total{{defense="{safe_name}"}} {stats["invocations"]}'
            )
            lines.append(f'shield_defense_blocks_total{{defense="{safe_name}"}} {stats["blocks"]}')

        ranking_weights = defender.ranking.get_weights()
        lines.append("# HELP shield_brorl_alpha BroRL alpha posterior per technique.")
        lines.append("# TYPE shield_brorl_alpha gauge")
        lines.append("# HELP shield_brorl_beta BroRL beta posterior per technique.")
        lines.append("# TYPE shield_brorl_beta gauge")
        lines.append("# HELP shield_brorl_success_rate BroRL derived success rate per technique.")
        lines.append("# TYPE shield_brorl_success_rate gauge")
        for tech_id, tech_data in ranking_weights.get("technique_stats", {}).items():
            safe_name = tech_id.replace(":", "_")
            alpha = tech_data.get("alpha", 1.0)
            beta = tech_data.get("beta", 1.0)
            success_rate = alpha / (alpha + beta) if (alpha + beta) > 0 else 0.0
            lines.append(f'shield_brorl_alpha{{technique="{safe_name}"}} {alpha:.4f}')
            lines.append(f'shield_brorl_beta{{technique="{safe_name}"}} {beta:.4f}')
            lines.append(f'shield_brorl_success_rate{{technique="{safe_name}"}} {success_rate:.4f}')

        runner = app.state.redteam_runner
        if runner is not None:
            lines.append("# HELP shield_redteam_probes_total Total red team probes executed.")
            lines.append("# TYPE shield_redteam_probes_total counter")
            lines.append(f"shield_redteam_probes_total {runner.total_probes_run}")

            lines.append("# HELP shield_redteam_bypasses_total Total red team bypasses detected.")
            lines.append("# TYPE shield_redteam_bypasses_total counter")
            lines.append(f"shield_redteam_bypasses_total {runner.total_bypasses}")

            lines.append("# HELP shield_redteam_bypass_rate Red team bypass rate per probe.")
            lines.append("# TYPE shield_redteam_bypass_rate gauge")
            for probe_name, pstats in runner.probe_stats.items():
                runs = pstats["runs"]
                bypasses = pstats["bypasses"]
                rate = bypasses / runs if runs > 0 else 0.0
                safe_name = probe_name.replace(":", "_")
                lines.append(f'shield_redteam_bypass_rate{{probe="{safe_name}"}} {rate:.4f}')

    return "\n".join(lines) + "\n"


# ============================================================================
# Audit Endpoints
# ============================================================================


@app.get("/api/v1/audit/events")
async def audit_events(
    since: float | None = Query(default=None),
    until: float | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    action: str | None = Query(default=None),
    classification: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Paginated audit event history with filters."""
    audit_db: ShieldAuditDB | None = app.state.audit_db
    if audit_db is None:
        return JSONResponse(status_code=404, content={"error": "Audit not enabled"})
    events = audit_db.get_events(
        since=since,
        until=until,
        source_ip=source_ip,
        action=action,
        classification=classification,
        limit=limit,
        offset=offset,
    )
    return {"events": events, "count": len(events), "limit": limit, "offset": offset}


@app.get("/api/v1/audit/events/{request_id}")
async def audit_event_detail(request_id: str) -> dict[str, Any]:
    """Single audit event by request_id."""
    audit_db: ShieldAuditDB | None = app.state.audit_db
    if audit_db is None:
        return JSONResponse(status_code=404, content={"error": "Audit not enabled"})
    event = audit_db.get_event(request_id)
    if event is None:
        return JSONResponse(status_code=404, content={"error": "Event not found"})
    return event


@app.get("/api/v1/audit/summary")
async def audit_summary(since: float | None = Query(default=None)) -> dict[str, Any]:
    """Aggregate audit statistics."""
    audit_db: ShieldAuditDB | None = app.state.audit_db
    if audit_db is None:
        return JSONResponse(status_code=404, content={"error": "Audit not enabled"})
    return audit_db.get_summary(since=since)


@app.get("/api/v1/audit/attackers")
async def audit_attackers(
    limit: int = Query(default=50, ge=1, le=500),
) -> dict[str, Any]:
    """Unique source IPs with block counts."""
    audit_db: ShieldAuditDB | None = app.state.audit_db
    if audit_db is None:
        return JSONResponse(status_code=404, content={"error": "Audit not enabled"})
    return {"attackers": audit_db.get_attackers(limit=limit)}


# ============================================================================
# WebSocket — Real-time Audit Stream
# ============================================================================


@app.websocket("/api/v1/shield/events/stream")
async def audit_event_stream(
    websocket: WebSocket,
    severity: str = Query(default="all"),
) -> None:
    """Real-time audit event stream.

    Query params:
        severity: "all" or "blocks" (only emit block events)
    """
    api_key = os.environ.get("SHIELD_API_KEY")
    if api_key:
        auth_header = websocket.headers.get("authorization", "")
        if not hmac.compare_digest(auth_header, f"Bearer {api_key}"):
            await websocket.close(code=1008, reason="Authentication required")
            return

    config: ShieldConfig = app.state.config
    if not config.audit_websocket_enabled:
        await websocket.close(code=1008, reason="WebSocket audit stream disabled")
        return

    await websocket.accept()

    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)
    _ws_subscribers.add(queue)
    try:
        while True:
            event = await queue.get()
            # Filter by severity
            if severity == "blocks" and event.get("shield_action") != "block":
                continue
            await websocket.send_json(event)
    except WebSocketDisconnect:
        logger.debug("Audit WebSocket client disconnected")
    except Exception as e:
        logger.error("Audit WebSocket error: %s", e)
    finally:
        _ws_subscribers.discard(queue)


# ============================================================================
# Behavioral Monitoring
# ============================================================================


@app.post("/api/v1/behavior/event", response_model=BehaviorVerdict)
async def behavior_event(event: BehaviorEvent) -> BehaviorVerdict:
    """Evaluate a single behavioral event."""
    monitor: BehavioralMonitor = app.state.behavior_monitor
    return monitor.evaluate_event(event)


@app.websocket("/api/v1/behavior/stream")
async def behavior_stream(
    websocket: WebSocket,
) -> None:
    """WebSocket stream for real-time behavioral monitoring."""
    api_key = os.environ.get("SHIELD_API_KEY")
    if api_key:
        auth_header = websocket.headers.get("authorization", "")
        if not hmac.compare_digest(auth_header, f"Bearer {api_key}"):
            await websocket.close(code=1008, reason="Authentication required")
            return

    await websocket.accept()
    monitor: BehavioralMonitor = app.state.behavior_monitor

    try:
        while True:
            data = await websocket.receive_json()
            event = BehaviorEvent(**data)
            verdict = monitor.evaluate_event(event)
            await websocket.send_json(verdict.model_dump())
    except WebSocketDisconnect:
        logger.debug("Behavior WebSocket client disconnected")
    except Exception as e:
        logger.error("Behavior WebSocket error: %s", e)


# ============================================================================
# Policy Management
# ============================================================================


@app.post("/api/v1/policy/load")
async def policy_load(body: dict) -> dict:
    """Load a versioned policy bundle."""
    from goop_shield.policy import PolicyBundle

    try:
        bundle = PolicyBundle.from_dict(body)
        manager = app.state.policy_manager
        manager.import_policy(bundle)
        return {"loaded": True, "version": bundle.version, "hash": bundle.hash}
    except (ValueError, KeyError) as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/v1/policy/export")
async def policy_export(
    version: str = Query(default="latest"),
) -> dict:
    """Export current policy as a versioned bundle."""
    manager = app.state.policy_manager
    bundle = manager.export_policy(version)
    return bundle.to_dict()


# ============================================================================
# Deception
# ============================================================================


@app.get("/api/v1/deception/canaries")
async def deception_canaries() -> dict:
    """List active canary tokens and their status."""
    defender: Defender = app.state.defender
    if defender.deception is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Deception not enabled (deception_enabled=False)"},
        )
    return {
        "canaries": defender.deception.get_active_canaries(),
        "total": defender.deception.total_canaries,
        "triggered": defender.deception.triggered_count,
    }


# ============================================================================
# Alignment Probes
# ============================================================================


@app.get("/api/v1/redteam/alignment")
async def redteam_alignment_results():
    """Get alignment-specific probe results from the latest run."""
    runner = app.state.redteam_runner
    if runner is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Red team not enabled (use_redteam=False)"},
        )
    if runner.latest_report is None:
        return {"alignment_results": [], "total": 0}
    return {
        "alignment_results": [r.model_dump() for r in runner.latest_report.alignment_results],
        "total": len(runner.latest_report.alignment_results),
    }


# ============================================================================
# Alignment Canaries
# ============================================================================


@app.get("/api/v1/alignment/pending-canary")
async def alignment_pending_canary():
    """Check if a canary is due for injection (used by client SDK)."""
    defender: Defender = app.state.defender
    if not defender._alignment_canaries:
        return {"canary": None, "status": "disabled"}
    canary = defender.get_pending_canary()
    if canary is None:
        return {"canary": None, "status": "not_due"}
    return {
        "canary": {
            "canary_id": canary.canary_id,
            "category": canary.category,
            "prompt": canary.prompt,
        },
        "status": "pending",
    }


@app.post("/api/v1/alignment/canary-result")
async def alignment_canary_result(body: dict):
    """Record an alignment canary check result."""
    defender: Defender = app.state.defender
    canary_id = body.get("canary_id", "")
    response_text = body.get("response", "")

    if not canary_id or not response_text:
        return JSONResponse(
            status_code=400,
            content={"error": "canary_id and response are required"},
        )

    # O(1) lookup by canary_id
    canary_map = {c.canary_id: c for c in defender._alignment_canaries}
    canary = canary_map.get(canary_id)

    if canary is None:
        return JSONResponse(
            status_code=404,
            content={"error": f"Canary {canary_id} not found"},
        )

    result = defender.check_canary_result(canary, response_text)

    # Audit logging
    audit_db: ShieldAuditDB | None = app.state.audit_db
    if audit_db is not None:
        audit_db.record_event(
            endpoint="alignment_canary",
            shield_action="alignment_canary_result",
            verdicts=[
                {
                    "canary_id": canary_id,
                    "category": result.get("category", ""),
                    "passed": result.get("passed", False),
                }
            ],
            confidence=1.0 if result.get("passed") else 0.0,
        )

    return result


@app.get("/api/v1/alignment/canary-stats")
async def alignment_canary_stats():
    """Get alignment canary pass/fail statistics per category."""
    defender: Defender = app.state.defender
    if defender.deception is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Deception not enabled (deception_enabled=False)"},
        )
    return defender.deception.get_alignment_canary_stats()


@app.get("/api/v1/alignment/canary-alerts")
async def alignment_canary_alerts():
    """Get alignment canary alerts for categories exceeding failure threshold."""
    defender: Defender = app.state.defender
    config: ShieldConfig = app.state.config
    if defender.deception is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Deception not enabled (deception_enabled=False)"},
        )
    threshold = getattr(config, "canary_alert_threshold", 0.3)
    alerts = defender.deception.check_alignment_alerts(alert_threshold=threshold)
    return {"alerts": alerts, "threshold": threshold}


# ============================================================================
# Red Team Reports
# ============================================================================


@app.get("/api/v1/redteam/report")
async def redteam_report() -> dict:
    """Generate a vulnerability report from the latest probe results."""
    from goop_shield.red.report import VulnerabilityReport

    runner = app.state.redteam_runner
    if runner is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Red team not enabled (use_redteam=False)"},
        )
    if runner.latest_report is None:
        return {"error": "No probe results yet. Run probes first."}

    report = VulnerabilityReport.from_probe_results(runner.latest_report.results)
    return report.to_dict()


# ============================================================================
# Aggregation
# ============================================================================


@app.post("/api/v1/aggregation/ingest")
async def aggregation_ingest(body: dict) -> dict:
    """Ingest batched telemetry from Shield instances."""
    from goop_shield.aggregation import TelemetryAggregator

    # Lazy init aggregator
    if not hasattr(app.state, "aggregator") or app.state.aggregator is None:
        config: ShieldConfig = app.state.config
        if not config.aggregator_enabled:
            return JSONResponse(
                status_code=404,
                content={"error": "Aggregation not enabled"},
            )
        app.state.aggregator = TelemetryAggregator()

    events = body.get("events", [])
    instance_id = body.get("instance_id", "unknown")
    count = app.state.aggregator.ingest_batch(events, instance_id=instance_id)
    return {"ingested": count, "should_retrain": app.state.aggregator.should_retrain()}


@app.get("/api/v1/aggregation/stats")
async def aggregation_stats(
    since: float | None = Query(default=None),
) -> dict:
    """Get aggregate statistics across all Shield instances."""
    if not hasattr(app.state, "aggregator") or app.state.aggregator is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Aggregation not enabled or no data ingested"},
        )
    stats = app.state.aggregator.get_aggregate_stats(since=since)
    return stats.to_dict()


# ============================================================================
# Intelligence Endpoints
# ============================================================================


@app.get("/api/v1/intel/actors")
async def intel_actors(
    limit: int = Query(default=50, ge=1, le=500),
    sort: str = Query(default="risk_level"),
) -> dict[str, Any]:
    """List threat actor profiles."""
    threat_actor_db = app.state.threat_actor_db
    if threat_actor_db is None:
        return JSONResponse(status_code=404, content={"error": "Intel not enabled"})
    actors = threat_actor_db.get_actors(limit=limit, sort=sort)
    return {"actors": [a.model_dump() for a in actors], "count": len(actors)}


@app.get("/api/v1/intel/actors/{actor_id}")
async def intel_actor_detail(actor_id: str) -> dict[str, Any]:
    """Get full threat actor profile."""
    threat_actor_db = app.state.threat_actor_db
    if threat_actor_db is None:
        return JSONResponse(status_code=404, content={"error": "Intel not enabled"})
    profile = threat_actor_db.get_actor_profile(actor_id)
    if profile is None:
        return JSONResponse(status_code=404, content={"error": "Actor not found"})
    return profile.model_dump()


@app.get("/api/v1/intel/campaigns")
async def intel_campaigns(
    limit: int = Query(default=20, ge=1, le=100),
    window_hours: int = Query(default=24, ge=1, le=168),
) -> dict[str, Any]:
    """List detected attack campaigns."""
    threat_actor_db = app.state.threat_actor_db
    if threat_actor_db is None:
        return JSONResponse(status_code=404, content={"error": "Intel not enabled"})
    # Fetch audit events and enrich with actor_id for campaign detection
    audit_db: ShieldAuditDB | None = app.state.audit_db
    if audit_db is not None:
        events = audit_db.get_events(limit=1000)
        _enrich_events_with_actors(events, threat_actor_db)
        threat_actor_db.detect_campaigns(events=events, window_hours=window_hours)
    campaigns = threat_actor_db.get_campaigns(limit=limit)
    return {"campaigns": [c.model_dump() for c in campaigns], "count": len(campaigns)}


@app.get("/api/v1/intel/campaigns/{campaign_id}")
async def intel_campaign_detail(campaign_id: str) -> dict[str, Any]:
    """Get campaign detail with event timeline."""
    threat_actor_db = app.state.threat_actor_db
    if threat_actor_db is None:
        return JSONResponse(status_code=404, content={"error": "Intel not enabled"})
    campaign = threat_actor_db.get_campaign(campaign_id)
    if campaign is None:
        return JSONResponse(status_code=404, content={"error": "Campaign not found"})
    return campaign.model_dump()


@app.get("/api/v1/intel/geo/{ip}")
async def intel_geo_lookup(ip: str) -> dict[str, Any]:
    """GeoIP/ASN lookup for an IP address."""
    ip_enricher = app.state.ip_enricher
    if ip_enricher is None:
        return JSONResponse(status_code=404, content={"error": "Intel not enabled"})
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "Invalid IP address"})
    geo = ip_enricher.enrich(ip)
    return geo.model_dump()


@app.get("/api/v1/intel/mitre")
async def intel_mitre() -> dict[str, Any]:
    """MITRE ATT&CK technique coverage from audit data."""
    from goop_shield.intel.mitre import get_mitre_coverage, get_mitre_matrix

    audit_db: ShieldAuditDB | None = app.state.audit_db
    if audit_db is None:
        return JSONResponse(status_code=404, content={"error": "Audit not enabled"})
    events = audit_db.get_events(limit=1000)
    coverage = get_mitre_coverage(events)
    matrix = get_mitre_matrix()
    return {"coverage": coverage, "matrix": matrix}


@app.get("/api/v1/intel/summary")
async def intel_summary() -> dict[str, Any]:
    """Intelligence summary: top actors, active campaigns, geo distribution."""
    threat_actor_db = app.state.threat_actor_db
    if threat_actor_db is None:
        return JSONResponse(status_code=404, content={"error": "Intel not enabled"})

    actors = threat_actor_db.get_actors(limit=10, sort="risk_level")
    # Detect campaigns from audit events
    audit_db: ShieldAuditDB | None = app.state.audit_db
    if audit_db is not None:
        events = audit_db.get_events(limit=1000)
        _enrich_events_with_actors(events, threat_actor_db)
        threat_actor_db.detect_campaigns(events=events, window_hours=24)
    campaigns = threat_actor_db.get_campaigns(limit=5)
    geo_dist = threat_actor_db.get_geo_distribution(enricher=app.state.ip_enricher)

    return {
        "top_actors": [a.model_dump() for a in actors],
        "active_campaigns": [c.model_dump() for c in campaigns],
        "geo_distribution": geo_dist,
    }


# ============================================================================
# Sabotage Defense — Sandbagging Detection
# ============================================================================


@app.post("/api/v1/sabotage/task-outcome")
async def sabotage_task_outcome(body: dict, request: Request) -> dict:
    """Record a task outcome for sandbagging detection.

    Automatically categorizes the task if no explicit category is provided.
    Returns any divergence alerts detected after recording.
    """
    sandbag_detector = app.state.sandbag_detector
    if sandbag_detector is None:
        return JSONResponse(
            status_code=404,
            content={
                "error": "Sandbagging detection not enabled (sandbag_detection_enabled=False)"
            },
        )

    prompt = body.get("prompt", "")
    succeeded = body.get("succeeded")
    if succeeded is None or not isinstance(succeeded, bool):
        return JSONResponse(
            status_code=400,
            content={"error": "'succeeded' field is required and must be a boolean"},
        )
    context = body.get("context", {})

    # Auto-categorize if not explicit
    category = context.get("task_category")
    if not category:
        categorizer = app.state.task_categorizer
        if categorizer is not None:
            category = categorizer.categorize(prompt, context)
        else:
            category = "general"

    sandbag_detector.record_task_outcome(category, succeeded)
    alerts = sandbag_detector.check_divergence()

    # Audit logging for alerts
    if alerts:
        audit_db: ShieldAuditDB | None = app.state.audit_db
        if audit_db is not None:
            for alert in alerts:
                audit_db.record_event(
                    endpoint="sabotage_task_outcome",
                    shield_action="sandbag_alert",
                    verdicts=[
                        {
                            "category": alert.category,
                            "z_score": alert.z_score,
                            "success_rate": alert.success_rate,
                            "pooled_mean": alert.pooled_mean,
                        }
                    ],
                    confidence=min(1.0, abs(alert.z_score) / 5.0),
                )

    return {
        "category": category,
        "succeeded": succeeded,
        "alerts": [
            {
                "category": a.category,
                "z_score": a.z_score,
                "success_rate": a.success_rate,
                "pooled_mean": a.pooled_mean,
                "sigma_threshold": a.sigma_threshold,
                "samples": a.samples,
            }
            for a in alerts
        ],
    }


# ============================================================================
# Training Data Gate
# ============================================================================


@app.post("/api/v1/training/validate")
async def training_validate(body: dict, request: Request) -> dict:
    """Validate a single training data item."""
    training_gate = app.state.training_gate
    if training_gate is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Training gate not enabled (training_gate_enabled=False)"},
        )

    content = body.get("content", "")
    source = body.get("source", "unknown")
    pipeline = body.get("pipeline")
    metadata = body.get("metadata")

    verdict = training_gate.validate(
        content=content,
        source=source,
        pipeline=pipeline,
        metadata=metadata,
    )

    # Audit logging
    audit_db: ShieldAuditDB | None = app.state.audit_db
    if audit_db is not None:
        audit_db.record_event(
            endpoint="training_validate",
            shield_action="training_data_scan",
            confidence=verdict.trust_score,
            verdicts=[
                {
                    "trust_score": verdict.trust_score,
                    "recommendation": verdict.recommendation,
                    "triggered_defenses": verdict.triggered_defenses,
                    "source": source,
                }
            ],
        )

    return dataclasses.asdict(verdict)


@app.post("/api/v1/training/validate-batch")
async def training_validate_batch(body: dict, request: Request) -> dict:
    """Validate a batch of training data items."""
    training_gate = app.state.training_gate
    if training_gate is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Training gate not enabled (training_gate_enabled=False)"},
        )

    items = body.get("items", [])
    pipeline = body.get("pipeline")

    result = await asyncio.get_event_loop().run_in_executor(
        None, lambda: training_gate.validate_batch(items=items, pipeline=pipeline)
    )

    return {
        "verdicts": [dataclasses.asdict(v) for v in result["verdicts"]],
        "summary": result["summary"],
        "duplicates_skipped": result["duplicates_skipped"],
        "total_processed": result["total_processed"],
    }


@app.get("/api/v1/training/quarantine")
async def training_quarantine_list(
    pipeline: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict:
    """List quarantined training data items."""
    quarantine_store = app.state.quarantine_store
    if quarantine_store is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Training gate not enabled (training_gate_enabled=False)"},
        )

    items = quarantine_store.list_quarantined(pipeline=pipeline, limit=limit)
    return {"items": items, "count": len(items)}


@app.post("/api/v1/training/quarantine/{item_id:path}/release")
async def training_quarantine_release(item_id: str) -> dict:
    """Release a quarantined item for use."""
    quarantine_store = app.state.quarantine_store
    if quarantine_store is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Training gate not enabled (training_gate_enabled=False)"},
        )

    try:
        record = quarantine_store.release(item_id)
        return {"released": True, "record": record}
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except FileNotFoundError:
        return JSONResponse(
            status_code=404,
            content={"error": f"Quarantine item not found: {item_id}"},
        )


@app.post("/api/v1/training/quarantine/{item_id:path}/reject")
async def training_quarantine_reject(item_id: str) -> dict:
    """Permanently reject a quarantined item."""
    quarantine_store = app.state.quarantine_store
    if quarantine_store is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Training gate not enabled (training_gate_enabled=False)"},
        )

    try:
        record = quarantine_store.reject(item_id)
        return {"rejected": True, "record": record}
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except FileNotFoundError:
        return JSONResponse(
            status_code=404,
            content={"error": f"Quarantine item not found: {item_id}"},
        )


# ============================================================================
# Cross-Model Consistency
# ============================================================================


@app.post("/api/v1/consistency/check")
async def consistency_check(body: dict) -> dict:
    """Manually trigger a consistency check for a prompt/response pair."""
    checker = app.state.consistency_checker
    if checker is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Consistency check not enabled (consistency_check_enabled=False)"},
        )

    prompt = body.get("prompt", "")
    primary_response = body.get("primary_response", "")
    if not prompt or not primary_response:
        return JSONResponse(
            status_code=400,
            content={"error": "'prompt' and 'primary_response' are required"},
        )

    result = await checker.check_consistency(prompt, primary_response)

    # Audit logging for divergences
    if not result.is_consistent:
        audit_db: ShieldAuditDB | None = app.state.audit_db
        if audit_db is not None:
            audit_db.record_event(
                endpoint="consistency_check",
                shield_action="consistency_divergence",
                confidence=result.divergence_score,
                verdicts=[
                    {
                        "divergence_score": result.divergence_score,
                        "structural": result.structural_divergence,
                        "semantic": result.semantic_divergence,
                        "factual": result.factual_divergence,
                        "comparison_providers": list(result.comparison_responses.keys()),
                        "details": result.divergence_details,
                    }
                ],
            )

    return {
        "is_consistent": result.is_consistent,
        "divergence_score": result.divergence_score,
        "structural_divergence": result.structural_divergence,
        "semantic_divergence": result.semantic_divergence,
        "factual_divergence": result.factual_divergence,
        "divergence_details": result.divergence_details,
        "comparison_providers": list(result.comparison_responses.keys()),
        "check_latency_ms": result.check_latency_ms,
    }


@app.get("/api/v1/consistency/stats")
async def consistency_stats() -> dict:
    """Get consistency check statistics."""
    checker = app.state.consistency_checker
    if checker is None:
        return JSONResponse(
            status_code=404,
            content={"error": "Consistency check not enabled (consistency_check_enabled=False)"},
        )
    return checker.get_stats()


# ============================================================================
# Experiment Dashboard Endpoints
# ============================================================================


@app.get("/api/v1/experiments/attack-log")
async def experiments_attack_log(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    classification: str | None = Query(default=None),
) -> dict[str, Any]:
    """Paginated list of recent attack attempts with Shield verdicts."""
    audit_db: ShieldAuditDB | None = app.state.audit_db
    if audit_db is None:
        return JSONResponse(status_code=404, content={"error": "Audit not enabled"})

    events = audit_db.get_events(
        classification=classification,
        limit=limit,
        offset=offset,
    )

    entries = []
    for ev in events:
        entries.append(
            {
                "request_id": ev.get("request_id"),
                "timestamp": ev.get("timestamp"),
                "source_ip": ev.get("source_ip"),
                "prompt_preview": ev.get("prompt_preview"),
                "shield_action": ev.get("shield_action"),
                "confidence": ev.get("confidence"),
                "latency_ms": ev.get("latency_ms"),
                "attack_classification": ev.get("attack_classification"),
                "blocking_defense": ev.get("blocking_defense"),
                "defenses_applied": ev.get("defenses_applied", []),
            }
        )

    return {"entries": entries, "count": len(entries), "limit": limit, "offset": offset}


@app.get("/api/v1/experiments/defense-heatmap")
async def experiments_defense_heatmap(
    since: float | None = Query(default=None),
) -> dict[str, Any]:
    """Matrix of defense_name x attack_classification with block counts."""
    audit_db: ShieldAuditDB | None = app.state.audit_db
    if audit_db is None:
        return JSONResponse(status_code=404, content={"error": "Audit not enabled"})

    return audit_db.get_defense_heatmap(since=since)


@app.get("/api/v1/experiments/brorl-drift")
async def experiments_brorl_drift() -> dict[str, Any]:
    """Current BroRL weights with success rates for drift monitoring.

    Returns per-technique alpha, beta, and derived success rate.
    Clients can poll this periodically to track drift over time.
    """
    defender: Defender = app.state.defender
    weights = defender.ranking.get_weights()
    technique_stats = weights.get("technique_stats", {})

    drift_data: dict[str, Any] = {}
    for tech_id, stats in technique_stats.items():
        alpha = stats.get("alpha", 1.0)
        beta = stats.get("beta", 1.0)
        total = alpha + beta
        success_rate = alpha / total if total > 0 else 0.0
        drift_data[tech_id] = {
            "alpha": alpha,
            "beta": beta,
            "success_rate": round(success_rate, 6),
            "total_samples": round(total - 2.0, 2),
        }

    return {
        "timestamp": time.time(),
        "techniques": drift_data,
        "total_techniques": len(drift_data),
    }


# ============================================================================
# Entrypoint
# ============================================================================


if __name__ == "__main__":
    import uvicorn

    config = _load_config()
    uvicorn.run(
        "goop_shield.app:app",
        host=config.host,
        port=config.port,
        workers=config.workers,
    )
