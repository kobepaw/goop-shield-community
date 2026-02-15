# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Shield Threat Actor Database — Enterprise Feature

Threat actor profiling and campaign detection requires goop-ai Enterprise.
This feature is not available in the community edition.
"""

from __future__ import annotations

from typing import Any

from goop_shield.intel.models import Campaign, ThreatActor


class ThreatActorDB:
    """SQLite-backed threat actor and campaign database.

    This module requires goop-ai Enterprise.
    Not available in the community edition.
    """

    def __init__(self, *args, **kwargs) -> None:
        raise ImportError(
            "Threat actor database requires goop-ai Enterprise. "
            "Not available in the community edition."
        )

    def get_or_create_actor(self, ip: str, user_agent: str = "", headers_hash: str = "") -> str:
        raise NotImplementedError

    def update_actor_from_event(self, actor_id: str, event: dict[str, Any]) -> None:
        raise NotImplementedError

    def get_actor_profile(self, actor_id: str) -> ThreatActor | None:
        raise NotImplementedError

    def detect_campaigns(self, events: list[dict[str, Any]], **kwargs) -> list[Campaign]:
        raise NotImplementedError

    def get_campaign(self, campaign_id: str) -> Campaign | None:
        raise NotImplementedError

    def get_campaigns(self, limit: int = 20) -> list[Campaign]:
        raise NotImplementedError

    def get_actors(self, limit: int = 50, sort: str = "risk_level") -> list[ThreatActor]:
        raise NotImplementedError

    def get_actor_id_by_fingerprint(self, source_ip: str, headers_hash: str) -> str | None:
        """Look up an actor_id by source_ip and headers_hash fingerprint.

        Returns the actor_id if found, or None.
        """
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError
