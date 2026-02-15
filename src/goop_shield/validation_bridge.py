# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield Validation Bridge (community stub).

The real implementation lives in the enterprise package.
This stub provides a no-op fallback for community-edition installs.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class ValidationBridge:
    """No-op stub — enterprise package required for real validation bridge."""

    def __init__(self, *args, **kwargs) -> None:
        logger.debug("ValidationBridge stub: enterprise package not available")
        self.records_created = 0
        self.records_skipped = 0

    def maybe_record(self, **kwargs) -> bool:
        return False

    def close(self) -> None:
        pass
