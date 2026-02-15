# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Shield Telemetry Buffer

Async event buffer with bounded deque, privacy-preserving hashing,
and periodic flush.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import deque
from typing import Any

from goop_shield.models import TelemetryEvent

logger = logging.getLogger(__name__)


class TelemetryBuffer:
    """Bounded async telemetry buffer.

    Events are accumulated in a deque and periodically flushed
    (MVP: logged as aggregate stats).
    """

    def __init__(
        self,
        buffer_size: int = 1000,
        flush_interval: float = 30.0,
        privacy_mode: bool = True,
    ) -> None:
        self._buffer: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self._flush_interval = flush_interval
        self._privacy_mode = privacy_mode
        self._flush_task: asyncio.Task[None] | None = None
        self._running = False

        # Aggregate counters
        self.total_events = 0
        self.total_blocked = 0
        self.total_allowed = 0

    def add(self, event: TelemetryEvent) -> None:
        """Add an event (sync, non-blocking)."""
        record: dict[str, Any] = {
            "attack_type": event.attack_type,
            "defense_action": event.defense_action,
            "outcome": event.outcome,
            "timestamp": time.time(),
        }

        if self._privacy_mode:
            meta = f"{event.attack_type}:{event.defense_action}:{event.outcome}"
            record["hash"] = hashlib.sha256(meta.encode()).hexdigest()[:16]

        self._buffer.append(record)
        self.total_events += 1
        if event.outcome == "blocked":
            self.total_blocked += 1
        else:
            self.total_allowed += 1

    async def start(self) -> None:
        """Start the periodic flush loop."""
        if self._running:
            return
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        """Drain remaining events and cancel the flush task."""
        self._running = False
        if self._flush_task is not None:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None
        # Final flush
        await self._flush()

    async def _flush_loop(self) -> None:
        """Background flush loop."""
        while self._running:
            await asyncio.sleep(self._flush_interval)
            await self._flush()

    async def _flush(self) -> None:
        """Flush aggregated stats (MVP: log them)."""
        if not self._buffer:
            return

        n = len(self._buffer)
        outcomes: dict[str, int] = {}
        for record in self._buffer:
            outcome = record.get("outcome", "unknown")
            outcomes[outcome] = outcomes.get(outcome, 0) + 1

        logger.info(
            "Telemetry flush: %d events — %s",
            n,
            ", ".join(f"{k}={v}" for k, v in sorted(outcomes.items())),
        )
        self._buffer.clear()

    def stats(self) -> dict[str, Any]:
        """Return aggregate telemetry statistics."""
        return {
            "total_events": self.total_events,
            "total_blocked": self.total_blocked,
            "total_allowed": self.total_allowed,
            "buffer_size": len(self._buffer),
            "privacy_mode": self._privacy_mode,
        }

    async def flush_to_aggregator(self, url: str) -> bool:
        """POST buffered events to central aggregator endpoint."""
        if not self._buffer:
            return True

        try:
            import httpx

            events = list(self._buffer)
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"{url}/api/v1/aggregation/ingest",
                    json={"events": events, "instance_id": "self"},
                )
                resp.raise_for_status()
                logger.info("Flushed %d events to aggregator at %s", len(events), url)
                return True
        except Exception as e:
            logger.warning("Failed to flush to aggregator: %s", e)
            return False
