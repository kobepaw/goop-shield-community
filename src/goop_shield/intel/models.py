# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Shield Intel Data Models

Pydantic models for threat intelligence: IP enrichment, threat actors,
and campaign tracking.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class IPIntel(BaseModel):
    """GeoIP and threat intelligence for a single IP address."""

    ip: str = ""
    country_code: str = ""
    country_name: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    asn: int = 0
    org: str = ""
    isp: str = ""
    is_vpn: bool = False
    is_cloud: bool = False
    is_tor: bool = False
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


class ThreatActor(BaseModel):
    """Aggregated threat actor profile built from audit events."""

    actor_id: str = ""
    ips: list[str] = Field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    total_requests: int = 0
    total_blocks: int = 0
    attack_types: dict[str, int] = Field(default_factory=dict)
    geo: IPIntel | None = None
    risk_level: str = "low"  # low, medium, high, critical


class Campaign(BaseModel):
    """A detected attack campaign — a sequence of related events from one actor."""

    campaign_id: str = ""
    actor_id: str = ""
    name: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    event_count: int = 0
    phases: list[str] = Field(default_factory=list)
    techniques: list[dict] = Field(default_factory=list)
    success_rate: float = Field(default=0.0, ge=0.0, le=1.0)
