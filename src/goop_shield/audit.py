# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield Audit Log

Persistent SQLite-backed audit trail for every defend/scan request.
Follows the CalibrationFeedback pattern (WAL mode, persistent conn,
check_same_thread=False, Row factory).
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ============================================================================
# Attack Classification
# ============================================================================

_DEFENSE_TO_ATTACK_CATEGORY: dict[str, str] = {
    "input_validator": "injection",
    "injection_blocker": "injection",
    "prompt_normalizer": "injection",
    "safety_filter": "jailbreak",
    "model_guardrails": "persona_hijack",
    "exfil_detector": "exfiltration",
    "canary_token_detector": "exfiltration",
    "obfuscation_detector": "obfuscation",
    "encoding_detector": "obfuscation",
    "semantic_analyzer": "manipulation",
    "context_boundary": "context_abuse",
    "token_budget_guard": "resource_abuse",
    "rate_limiter": "resource_abuse",
    "role_enforcer": "privilege_escalation",
    "system_prompt_guard": "system_prompt_leak",
}


def classify_attack(verdicts: list[dict[str, Any]]) -> str:
    """Map blocking defense name to attack category.

    Scans verdicts for the first blocking defense and returns its category.
    Returns ``"none"`` when no defense blocked.
    """
    for verdict in verdicts:
        action = verdict.get("action", "")
        if action == "block":
            defense_name = verdict.get("defense_name", "")
            category = _DEFENSE_TO_ATTACK_CATEGORY.get(defense_name)
            if category:
                return category
            # Unknown defense blocked — still an attack
            return "unknown"
    return "none"


def _prompt_hash(prompt: str) -> str:
    """SHA-256[:16] of prompt for privacy-preserving dedup."""
    return hashlib.sha256(prompt.encode(errors="replace")).hexdigest()[:16]


# ============================================================================
# ShieldAuditDB
# ============================================================================


class ShieldAuditDB:
    """SQLite-backed audit log for Shield requests.

    Thread-safe persistent connection with WAL journalling.
    """

    def __init__(self, db_path: str = "data/shield_audit.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")

        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                source_ip TEXT NOT NULL DEFAULT '',
                endpoint TEXT NOT NULL DEFAULT '',
                prompt_hash TEXT NOT NULL DEFAULT '',
                prompt_preview TEXT NOT NULL DEFAULT '',
                shield_action TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0.0,
                latency_ms REAL NOT NULL DEFAULT 0.0,
                defenses_applied TEXT NOT NULL DEFAULT '[]',
                verdicts TEXT NOT NULL DEFAULT '[]',
                attack_classification TEXT NOT NULL DEFAULT 'none',
                blocking_defense TEXT DEFAULT NULL,
                session_key TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                content_type TEXT NOT NULL DEFAULT '',
                accept_language TEXT NOT NULL DEFAULT '',
                request_headers_hash TEXT NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_events(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_source_ip
                ON audit_events(source_ip);
            CREATE INDEX IF NOT EXISTS idx_audit_action
                ON audit_events(shield_action);
            CREATE INDEX IF NOT EXISTS idx_audit_classification
                ON audit_events(attack_classification);
            CREATE INDEX IF NOT EXISTS idx_audit_request_id
                ON audit_events(request_id);
        """)

        # Migrate existing databases: add new columns if missing
        for col, typedef in [
            ("user_agent", "TEXT NOT NULL DEFAULT ''"),
            ("content_type", "TEXT NOT NULL DEFAULT ''"),
            ("accept_language", "TEXT NOT NULL DEFAULT ''"),
            ("request_headers_hash", "TEXT NOT NULL DEFAULT ''"),
        ]:
            try:
                self._conn.execute(f"ALTER TABLE audit_events ADD COLUMN {col} {typedef}")
            except sqlite3.OperationalError:
                pass  # Column already exists

        # Index on new column — must run after migration adds the column
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_headers_hash "
            "ON audit_events(request_headers_hash)"
        )

        self._conn.commit()
        logger.info("Shield audit DB initialized at %s", self.db_path)

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._init_db()
        if self._conn is None:
            raise RuntimeError("Failed to initialize audit database connection")
        return self._conn

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record_event(
        self,
        *,
        source_ip: str = "",
        endpoint: str = "defend",
        prompt: str = "",
        max_prompt_chars: int = 200,
        shield_action: str = "allow",
        confidence: float = 0.0,
        latency_ms: float = 0.0,
        defenses_applied: list[str] | None = None,
        verdicts: list[dict[str, Any]] | None = None,
        attack_classification: str = "none",
        blocking_defense: str | None = None,
        session_key: str = "",
        request_id: str | None = None,
        user_agent: str = "",
        content_type: str = "",
        accept_language: str = "",
        request_headers_hash: str = "",
    ) -> dict[str, Any]:
        """Record an audit event and return the event dict (for WebSocket broadcast)."""
        conn = self._get_conn()

        if request_id is None:
            request_id = uuid.uuid4().hex[:16]

        ts = time.time()
        verdicts_list = verdicts or []
        defenses_list = defenses_applied or []

        conn.execute(
            """
            INSERT INTO audit_events
                (request_id, timestamp, source_ip, endpoint, prompt_hash,
                 prompt_preview, shield_action, confidence, latency_ms,
                 defenses_applied, verdicts, attack_classification,
                 blocking_defense, session_key,
                 user_agent, content_type, accept_language,
                 request_headers_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                ts,
                source_ip,
                endpoint,
                _prompt_hash(prompt),
                prompt[:max_prompt_chars] if prompt else "",
                shield_action,
                confidence,
                latency_ms,
                json.dumps(defenses_list),
                json.dumps(verdicts_list),
                attack_classification,
                blocking_defense,
                session_key,
                user_agent,
                content_type,
                accept_language,
                request_headers_hash,
            ),
        )
        conn.commit()

        return {
            "request_id": request_id,
            "timestamp": ts,
            "source_ip": source_ip,
            "endpoint": endpoint,
            "prompt_hash": _prompt_hash(prompt),
            "prompt_preview": prompt[:max_prompt_chars] if prompt else "",
            "shield_action": shield_action,
            "confidence": confidence,
            "latency_ms": latency_ms,
            "defenses_applied": defenses_list,
            "verdicts": verdicts_list,
            "attack_classification": attack_classification,
            "blocking_defense": blocking_defense,
            "session_key": session_key,
            "user_agent": user_agent,
            "content_type": content_type,
            "accept_language": accept_language,
            "request_headers_hash": request_headers_hash,
        }

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_event(self, request_id: str) -> dict[str, Any] | None:
        """Get a single event by request_id."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM audit_events WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_events(
        self,
        *,
        since: float | None = None,
        until: float | None = None,
        source_ip: str | None = None,
        action: str | None = None,
        classification: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Paginated event query with optional filters."""
        conditions: list[str] = []
        params: list[Any] = []

        if since is not None:
            conditions.append("timestamp >= ?")
            params.append(since)
        if until is not None:
            conditions.append("timestamp <= ?")
            params.append(until)
        if source_ip is not None:
            conditions.append("source_ip = ?")
            params.append(source_ip)
        if action is not None:
            conditions.append("shield_action = ?")
            params.append(action)
        if classification is not None:
            conditions.append("attack_classification = ?")
            params.append(classification)

        where = " AND ".join(conditions) if conditions else "1=1"
        rows = (
            self._get_conn()
            .execute(
                f"SELECT * FROM audit_events WHERE {where} "
                f"ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            )
            .fetchall()
        )

        return [self._row_to_dict(r) for r in rows]

    def get_summary(self, since: float | None = None) -> dict[str, Any]:
        """Aggregate stats: blocks by hour, top attack types, IPs, defenses."""
        conn = self._get_conn()
        time_clause = ""
        params: list[Any] = []
        if since is not None:
            time_clause = "WHERE timestamp >= ?"
            params = [since]

        # Total / blocked counts
        row = conn.execute(
            f"SELECT COUNT(*) as total, "
            f"SUM(CASE WHEN shield_action='block' THEN 1 ELSE 0 END) as blocked "
            f"FROM audit_events {time_clause}",
            params,
        ).fetchone()
        total = row["total"] or 0
        blocked = row["blocked"] or 0

        # Blocks by hour
        blocks_by_hour = {}
        rows = conn.execute(
            f"SELECT CAST((timestamp / 3600) AS INTEGER) * 3600 AS hour_ts, "
            f"COUNT(*) AS cnt "
            f"FROM audit_events {time_clause + ' AND' if time_clause else 'WHERE'} "
            f"shield_action='block' GROUP BY hour_ts ORDER BY hour_ts DESC LIMIT 24",
            params,
        ).fetchall()
        for r in rows:
            blocks_by_hour[r["hour_ts"]] = r["cnt"]

        # Top attack types
        top_attacks = conn.execute(
            f"SELECT attack_classification, COUNT(*) AS cnt "
            f"FROM audit_events {time_clause + ' AND' if time_clause else 'WHERE'} "
            f"attack_classification != 'none' "
            f"GROUP BY attack_classification ORDER BY cnt DESC LIMIT 10",
            params,
        ).fetchall()

        # Top source IPs
        top_ips = conn.execute(
            f"SELECT source_ip, COUNT(*) AS cnt "
            f"FROM audit_events {time_clause + ' AND' if time_clause else 'WHERE'} "
            f"shield_action='block' "
            f"GROUP BY source_ip ORDER BY cnt DESC LIMIT 10",
            params,
        ).fetchall()

        # Top blocking defenses
        top_defenses = conn.execute(
            f"SELECT blocking_defense, COUNT(*) AS cnt "
            f"FROM audit_events {time_clause + ' AND' if time_clause else 'WHERE'} "
            f"blocking_defense IS NOT NULL "
            f"GROUP BY blocking_defense ORDER BY cnt DESC LIMIT 10",
            params,
        ).fetchall()

        return {
            "total_events": total,
            "total_blocked": blocked,
            "block_rate": blocked / total if total > 0 else 0.0,
            "blocks_by_hour": blocks_by_hour,
            "top_attack_types": {r["attack_classification"]: r["cnt"] for r in top_attacks},
            "top_source_ips": {r["source_ip"]: r["cnt"] for r in top_ips},
            "top_blocking_defenses": {r["blocking_defense"]: r["cnt"] for r in top_defenses},
        }

    def get_attackers(self, limit: int = 50) -> list[dict[str, Any]]:
        """Unique source IPs with block counts."""
        rows = (
            self._get_conn()
            .execute(
                "SELECT source_ip, "
                "COUNT(*) AS total_requests, "
                "SUM(CASE WHEN shield_action='block' THEN 1 ELSE 0 END) AS blocks, "
                "MAX(timestamp) AS last_seen "
                "FROM audit_events "
                "WHERE source_ip != '' "
                "GROUP BY source_ip "
                "ORDER BY blocks DESC LIMIT ?",
                (limit,),
            )
            .fetchall()
        )

        return [
            {
                "source_ip": r["source_ip"],
                "total_requests": r["total_requests"],
                "blocks": r["blocks"],
                "last_seen": r["last_seen"],
            }
            for r in rows
        ]

    def get_event_count(self) -> int:
        """Total event count for health check."""
        row = self._get_conn().execute("SELECT COUNT(*) FROM audit_events").fetchone()
        return row[0] if row else 0

    def get_defense_heatmap(self, since: float | None = None) -> dict[str, Any]:
        """Return defense vs attack-classification block counts for heatmap display.

        Returns a dict with ``matrix``, ``defense_names``, and ``attack_types``.
        """
        conn = self._get_conn()
        time_clause = ""
        params: list[Any] = []
        if since is not None:
            time_clause = "AND timestamp >= ?"
            params = [since]

        rows = conn.execute(
            "SELECT blocking_defense, attack_classification, COUNT(*) AS cnt "
            "FROM audit_events "
            f"WHERE blocking_defense IS NOT NULL {time_clause} "
            "GROUP BY blocking_defense, attack_classification "
            "ORDER BY cnt DESC",
            params,
        ).fetchall()

        matrix: dict[str, dict[str, int]] = {}
        attack_types: set[str] = set()
        defense_names: set[str] = set()

        for row in rows:
            defense = row["blocking_defense"]
            attack = row["attack_classification"]
            count = row["cnt"]
            if defense is None or attack is None:
                continue
            matrix.setdefault(defense, {})[attack] = count
            attack_types.add(attack)
            defense_names.add(defense)

        return {
            "matrix": matrix,
            "defense_names": sorted(defense_names),
            "attack_types": sorted(attack_types),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        # Deserialize JSON columns
        for key in ("defenses_applied", "verdicts"):
            if isinstance(d.get(key), str):
                d[key] = json.loads(d[key])
        return d

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
