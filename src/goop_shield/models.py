# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield API Request/Response Models

Pydantic models for Shield endpoints.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class DefenseAction(StrEnum):
    """Possible defense actions."""

    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"


class DefendRequest(BaseModel):
    """Request to defend a prompt."""

    prompt: str = Field(..., min_length=1)
    context: dict[str, object] = Field(default_factory=dict)

    @field_validator("prompt")
    @classmethod
    def reject_whitespace_only(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Prompt must contain non-whitespace characters")
        return v


class DefenseVerdict(BaseModel):
    """Result from a single defense in the pipeline."""

    defense_name: str
    action: DefenseAction
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    threat_confidence: float | None = None
    details: str = ""
    latency_ms: float = Field(default=0.0, ge=0.0)


class DefendResponse(BaseModel):
    """Response from the defend endpoint."""

    allow: bool
    filtered_prompt: str
    defenses_applied: list[str] = Field(default_factory=list)
    verdicts: list[DefenseVerdict] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    fused_score: float | None = Field(default=None, ge=0.0, le=1.0)
    latency_ms: float = Field(default=0.0, ge=0.0)


class ScanRequest(BaseModel):
    """Request to scan an LLM response."""

    response_text: str = Field(..., min_length=1)
    original_prompt: str = ""
    context: dict[str, object] = Field(default_factory=dict)

    @field_validator("response_text")
    @classmethod
    def reject_whitespace_only(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("response_text must contain non-whitespace characters")
        return v


class ScanResponse(BaseModel):
    """Response from the scan-response endpoint."""

    safe: bool
    filtered_response: str
    scanners_applied: list[str] = Field(default_factory=list)
    verdicts: list[DefenseVerdict] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    latency_ms: float = Field(default=0.0, ge=0.0)


class ToolOutputScanRequest(BaseModel):
    """Request to scan tool output before it enters agent context."""

    content: str = Field(..., min_length=1)
    tool_name: str = Field(default="unknown")
    source_url: str = ""
    trust_level: Literal["owner", "known", "low", "untrusted"] = Field(default="untrusted")
    context: dict[str, object] = Field(default_factory=dict)
    wrap_markers: bool = Field(default=True)

    @field_validator("content")
    @classmethod
    def reject_whitespace_only(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("content must contain non-whitespace characters")
        return v


class ToolOutputScanResponse(BaseModel):
    """Response from tool output scanning."""

    safe: bool
    filtered_content: str
    action: str = "pass"  # pass | sanitize | block
    scanners_applied: list[str] = Field(default_factory=list)
    verdicts: list[DefenseVerdict] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    latency_ms: float = Field(default=0.0, ge=0.0)


class MemoryScanRequest(BaseModel):
    """Request to scan a memory/critical file before it enters context."""

    content: str = Field(..., min_length=1)
    file_path: str = Field(default="")
    operation: Literal["read", "write"] = Field(default="read")
    context: dict[str, object] = Field(default_factory=dict)

    @field_validator("content")
    @classmethod
    def reject_whitespace_only(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("content must contain non-whitespace characters")
        return v

    @field_validator("file_path")
    @classmethod
    def reject_path_traversal(cls, v: str) -> str:
        if ".." in v.split("/") or ".." in v.split("\\"):
            raise ValueError("Path traversal not allowed in file_path")
        return v


class TelemetryEvent(BaseModel):
    """Telemetry event for outcome reporting."""

    attack_type: str
    defense_action: str
    outcome: str


class ProbeRequest(BaseModel):
    """Request to trigger red-team probes."""

    probe_names: list[str] | None = None


class ProbeResult(BaseModel):
    """Result from executing a single red-team probe."""

    probe_name: str
    target_defense: str
    payload_blocked: bool
    expected_blocked: bool
    defense_bypassed: bool
    target_missed: bool = False
    caught_by: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    latency_ms: float = Field(default=0.0, ge=0.0)


class RedTeamReport(BaseModel):
    """Aggregated report from a red-team probe run."""

    total_probes: int = 0
    defenses_bypassed: int = 0
    target_misses: int = 0
    bypass_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    target_miss_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    results: list[ProbeResult] = Field(default_factory=list)
    alignment_results: list[ProbeResult] = Field(default_factory=list)
    timestamp: float = 0.0
    latency_ms: float = Field(default=0.0, ge=0.0)


class ShieldHealth(BaseModel):
    """Health check response."""

    status: str = "healthy"
    defenses_loaded: int = 0
    scanners_loaded: int = 0
    brorl_ready: bool = False
    version: str = "0.1.0"
    uptime_seconds: float = Field(default=0.0, ge=0.0)
    total_requests: int = Field(default=0, ge=0)
    total_blocked: int = Field(default=0, ge=0)
    active_defenses: list[str] = Field(default_factory=list)
    active_scanners: list[str] = Field(default_factory=list)
    audit_events_total: int = Field(default=0, ge=0)


class AuditFrame(BaseModel):
    """Audit frame for surveillance recording of proxy traffic."""

    request_id: str
    timestamp: float
    session_key: str
    direction: str  # "inbound" | "outbound"
    frame_type: str  # "req" | "res" | "event"
    method: str | None = None
    original_text: str | None = None
    filtered_text: str | None = None
    shield_action: str  # "allow" | "block" | "sanitize" | "scan_safe" | "scan_flagged"
    verdicts: list[dict] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    latency_ms: float = Field(default=0.0, ge=0.0)
    campaign_id: str | None = None
    campaign_phase: str | None = None


class BehaviorEvent(BaseModel):
    """Behavioral event for monitoring."""

    event_type: (
        str  # tool_call, file_access, network_request, credential_use, financial_transaction
    )
    tool: str | None = None
    args: dict[str, object] = Field(default_factory=dict)
    session_id: str = "default"
    timestamp: float | None = None


class BehaviorVerdict(BaseModel):
    """Verdict from behavioral monitoring."""

    decision: str  # allow, block, alert, require_human_approval
    severity: str = "low"  # low, medium, high, critical
    reason: str = ""
    matched_rules: list[str] = Field(default_factory=list)
