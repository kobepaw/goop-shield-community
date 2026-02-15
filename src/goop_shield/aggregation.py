# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield Telemetry Aggregator

Central aggregation service for multi-Shield deployments.
Collects telemetry from multiple Shield instances, computes
cross-instance statistics, and triggers retraining when enough
new data accumulates.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class AggregateStats:
    """Cross-instance aggregation statistics."""

    total_events: int = 0
    total_blocked: int = 0
    total_allowed: int = 0
    block_rate: float = 0.0
    top_attacks: list[dict] = field(default_factory=list)
    top_defenses: list[dict] = field(default_factory=list)
    instance_count: int = 0
    time_range_start: float = 0.0
    time_range_end: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_events": self.total_events,
            "total_blocked": self.total_blocked,
            "total_allowed": self.total_allowed,
            "block_rate": self.block_rate,
            "top_attacks": self.top_attacks,
            "top_defenses": self.top_defenses,
            "instance_count": self.instance_count,
            "time_range_start": self.time_range_start,
            "time_range_end": self.time_range_end,
        }


class TelemetryAggregator:
    """SQLite-backed telemetry aggregation for multi-Shield deployments."""

    def __init__(self, db_path: str = "data/shield_aggregation.db") -> None:
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()
        self._events_since_retrain = 0

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS telemetry_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instance_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                event_type TEXT NOT NULL DEFAULT '',
                attack_type TEXT NOT NULL DEFAULT '',
                defense_action TEXT NOT NULL DEFAULT '',
                outcome TEXT NOT NULL DEFAULT '',
                confidence REAL NOT NULL DEFAULT 0.0,
                ingested_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp
                ON telemetry_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_telemetry_instance
                ON telemetry_events(instance_id);
            CREATE INDEX IF NOT EXISTS idx_telemetry_outcome
                ON telemetry_events(outcome);
        """)
        self._conn.commit()

    def ingest_batch(self, events: list[dict], instance_id: str = "default") -> int:
        """Accept batched telemetry from a Shield instance.

        Returns number of events ingested.
        """
        now = time.time()
        rows = []
        for event in events:
            rows.append(
                (
                    instance_id,
                    event.get("timestamp", now),
                    event.get("event_type", ""),
                    event.get("attack_type", ""),
                    event.get("defense_action", ""),
                    event.get("outcome", ""),
                    event.get("confidence", 0.0),
                    now,
                )
            )

        self._conn.executemany(
            "INSERT INTO telemetry_events "
            "(instance_id, timestamp, event_type, attack_type, defense_action, outcome, confidence, ingested_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        self._conn.commit()
        self._events_since_retrain += len(rows)
        logger.info("Ingested %d events from instance %s", len(rows), instance_id)
        return len(rows)

    def get_aggregate_stats(self, since: float | None = None) -> AggregateStats:
        """Compute cross-instance aggregation statistics."""
        where = ""
        params: list = []
        if since is not None:
            where = "WHERE timestamp >= ?"
            params.append(since)

        cursor = self._conn.execute(
            f"SELECT COUNT(*) as total, "
            f"SUM(CASE WHEN outcome = 'block' THEN 1 ELSE 0 END) as blocked, "
            f"SUM(CASE WHEN outcome != 'block' THEN 1 ELSE 0 END) as allowed, "
            f"MIN(timestamp) as t_start, MAX(timestamp) as t_end "
            f"FROM telemetry_events {where}",
            params,
        )
        row = cursor.fetchone()
        total = row[0] or 0
        blocked = row[1] or 0
        allowed = row[2] or 0
        t_start = row[3] or 0.0
        t_end = row[4] or 0.0

        # Top attacks
        cursor = self._conn.execute(
            f"SELECT attack_type, COUNT(*) as cnt "
            f"FROM telemetry_events {where} "
            f"GROUP BY attack_type ORDER BY cnt DESC LIMIT 10",
            params,
        )
        top_attacks = [{"attack_type": r[0], "count": r[1]} for r in cursor.fetchall()]

        # Top defenses
        if where:
            cursor = self._conn.execute(
                f"SELECT defense_action, COUNT(*) as cnt "
                f"FROM telemetry_events {where} AND outcome = 'block' "
                f"GROUP BY defense_action ORDER BY cnt DESC LIMIT 10",
                params,
            )
        else:
            cursor = self._conn.execute(
                "SELECT defense_action, COUNT(*) as cnt "
                "FROM telemetry_events WHERE outcome = 'block' "
                "GROUP BY defense_action ORDER BY cnt DESC LIMIT 10",
            )
        top_defenses = [{"defense": r[0], "count": r[1]} for r in cursor.fetchall()]

        # Instance count
        cursor = self._conn.execute(
            f"SELECT COUNT(DISTINCT instance_id) FROM telemetry_events {where}",
            params,
        )
        instance_count = cursor.fetchone()[0] or 0

        return AggregateStats(
            total_events=total,
            total_blocked=blocked,
            total_allowed=allowed,
            block_rate=blocked / total if total > 0 else 0.0,
            top_attacks=top_attacks,
            top_defenses=top_defenses,
            instance_count=instance_count,
            time_range_start=t_start,
            time_range_end=t_end,
        )

    def should_retrain(self, min_new_events: int = 1000) -> bool:
        """Check if enough new data has accumulated to justify retraining."""
        return self._events_since_retrain >= min_new_events

    def mark_retrained(self) -> None:
        """Reset the retrain counter after retraining."""
        self._events_since_retrain = 0

    def export_training_data(self, since: float | None = None, limit: int = 10000) -> list[dict]:
        """Export events for trainer consumption."""
        where = "WHERE timestamp >= ?" if since else ""
        params: list = [since] if since else []
        params.append(limit)

        cursor = self._conn.execute(
            f"SELECT instance_id, timestamp, attack_type, defense_action, outcome, confidence "
            f"FROM telemetry_events {where} "
            f"ORDER BY timestamp DESC LIMIT ?",
            params,
        )
        return [
            {
                "instance_id": r[0],
                "timestamp": r[1],
                "attack_type": r[2],
                "defense_action": r[3],
                "outcome": r[4],
                "confidence": r[5],
            }
            for r in cursor.fetchall()
        ]

    def close(self) -> None:
        """Close the SQLite connection."""
        self._conn.close()
