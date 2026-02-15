# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield Threat Intelligence Package

Provides MITRE ATT&CK mapping for Shield audit events.

GeoIP enrichment, threat actor tracking, and campaign detection
are not available in the community edition.
"""

from __future__ import annotations

from goop_shield.intel.geoip import IPEnricher
from goop_shield.intel.mitre import (
    DEFENSE_TO_MITRE,
    get_mitre_coverage,
    get_mitre_matrix,
)
from goop_shield.intel.models import Campaign, IPIntel, ThreatActor
from goop_shield.intel.threat_actors import ThreatActorDB

__all__ = [
    "Campaign",
    "DEFENSE_TO_MITRE",
    "IPEnricher",
    "IPIntel",
    "ThreatActor",
    "ThreatActorDB",
    "get_mitre_coverage",
    "get_mitre_matrix",
]
