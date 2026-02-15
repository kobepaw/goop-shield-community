# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield GeoIP Enrichment — Enterprise Feature

IP geolocation and network attribution requires goop-ai Enterprise.
This feature is not available in the community edition.
"""

from __future__ import annotations

from goop_shield.intel.models import IPIntel


class IPEnricher:
    """GeoIP enrichment with MaxMind and API fallback chain.

    This module requires goop-ai Enterprise.
    Not available in the community edition.
    """

    def __init__(self, *args, **kwargs) -> None:
        raise ImportError(
            "GeoIP enrichment requires goop-ai Enterprise. Not available in the community edition."
        )

    def enrich(self, ip: str) -> IPIntel:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError
