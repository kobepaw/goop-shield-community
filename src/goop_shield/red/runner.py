# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Shield Red Runner — Enterprise Feature

Red team probe execution requires goop-ai Enterprise.
The community edition does not include the RedTeamRunner.
"""

from __future__ import annotations


class RedTeamRunner:
    """Executes red-team probes against the defense pipeline.

    This module requires goop-ai Enterprise.
    """

    def __init__(self, *args, **kwargs) -> None:
        raise ImportError("Red team runner requires goop-ai Enterprise.")
