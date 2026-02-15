# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Shield Red Scheduler — Enterprise Feature

Periodic red team probe scheduling requires goop-ai Enterprise.
"""

from __future__ import annotations


class ProbeScheduler:
    """Periodically runs red-team probes in the background.

    This module requires goop-ai Enterprise.
    """

    def __init__(self, *args, **kwargs) -> None:
        raise ImportError(
            "Red team scheduler requires goop-ai Enterprise."
        )
