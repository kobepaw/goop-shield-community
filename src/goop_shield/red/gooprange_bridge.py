# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
GoopRange Bridge for Shield Red (compatibility stub).

The real implementation lives in :mod:`goop_shield.enterprise.gooprange_bridge`.
This stub re-exports it when available, or provides a no-op fallback for
community-edition installs.
"""

from __future__ import annotations

try:
    from goop_shield.enterprise.gooprange_bridge import (  # noqa: F401
        _PROBE_TO_GOOPRANGE,
        GoopRangeBridge,
        ValidationResult,
    )
except ImportError:
    import logging
    from dataclasses import dataclass

    logger = logging.getLogger(__name__)

    _PROBE_TO_GOOPRANGE: dict[str, str] = {}  # type: ignore[no-redef]

    @dataclass
    class ValidationResult:  # type: ignore[no-redef]
        """No-op stub result."""

        probe_name: str = ""
        gooprange_attack: str = ""
        real_world_success: bool = False
        real_world_success_rate: float = 0.0
        target_name: str = ""
        error: str | None = "enterprise package not available"

    class GoopRangeBridge:  # type: ignore[no-redef]
        """No-op stub when enterprise package is not installed."""

        def __init__(self, *args, **kwargs) -> None:
            logger.debug("GoopRangeBridge stub: enterprise package not available")
            self._results: list = []

        def validate_bypass(self, probe_result) -> ValidationResult:
            return ValidationResult(
                probe_name=getattr(probe_result, "probe_name", ""),
                gooprange_attack="unknown",
                error="enterprise package not available",
            )

        def validate_all_bypasses(self, probe_results) -> list[ValidationResult]:
            return []
