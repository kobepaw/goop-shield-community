# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Quarantine Store (Enterprise)

Directory-based quarantine storage for training data flagged by
TrainingDataGate. Supports listing, releasing, and rejecting items.
"""

from __future__ import annotations

from typing import Any


class QuarantineStore:
    """Directory-based quarantine storage for training data.

    Requires the enterprise edition.

    Args:
        base_path: Root directory for quarantine storage.
    """

    def __init__(self, base_path: str = "data/quarantine") -> None:
        raise ImportError(
            "QuarantineStore requires goop-ai Enterprise. Not available in the community edition."
        )

    def quarantine(
        self,
        content: str,
        verdict: Any,
        pipeline: str = "default",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        raise NotImplementedError

    def list_quarantined(
        self,
        pipeline: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        raise NotImplementedError

    def release(self, item_path: str) -> dict[str, Any]:
        raise NotImplementedError

    def reject(self, item_path: str) -> dict[str, Any]:
        raise NotImplementedError
