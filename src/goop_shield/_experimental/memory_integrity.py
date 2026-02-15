# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Memory Integrity — File hash store for critical workspace files.

Maintains SHA-256 hashes of critical files (SOUL.md, AGENTS.md, etc.)
and detects unexpected modifications between sessions.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class FileRecord:
    """Hash record for a single file."""

    sha256: str
    last_verified: float  # epoch seconds
    last_modified_by: str = "unknown"
    size: int = 0


@dataclass
class IntegrityReport:
    """Result of verifying critical files against stored hashes."""

    passed: list[str] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    tampered: bool = False


class MemoryIntegrity:
    """Manages cryptographic hashes of critical workspace files.

    Usage::

        mi = MemoryIntegrity(hash_store_path="data/integrity.json")
        mi.update("SOUL.md", modified_by="user:owner")
        report = mi.verify()
        if report.tampered:
            alert(...)
    """

    def __init__(self, hash_store_path: str = "data/integrity.json") -> None:
        self._store_path = Path(hash_store_path)
        self._records: dict[str, FileRecord] = {}
        self._load()

    def _load(self) -> None:
        """Load hash store from disk."""
        if not self._store_path.exists():
            return
        try:
            data = json.loads(self._store_path.read_text())
            for path, rec in data.get("files", {}).items():
                self._records[path] = FileRecord(**rec)
        except (json.JSONDecodeError, TypeError, KeyError) as e:
            logger.warning("Failed to load integrity store: %s", e)

    def _save(self) -> None:
        """Persist hash store to disk."""
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 1,
            "files": {path: asdict(rec) for path, rec in self._records.items()},
        }
        self._store_path.write_text(json.dumps(data, indent=2))

    @staticmethod
    def hash_content(content: str) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content.encode()).hexdigest()

    @staticmethod
    def hash_file(path: str | Path) -> str | None:
        """Compute SHA-256 hash of a file, or None if not found."""
        p = Path(path)
        if not p.exists():
            return None
        return MemoryIntegrity.hash_content(p.read_text())

    def update(self, path: str, *, modified_by: str = "agent:main") -> FileRecord:
        """Compute and store the hash for a file.

        Call this after an authorized write to a critical file.
        """
        p = Path(path)
        content = p.read_text() if p.exists() else ""
        record = FileRecord(
            sha256=self.hash_content(content),
            last_verified=time.time(),
            last_modified_by=modified_by,
            size=len(content),
        )
        self._records[str(path)] = record
        self._save()
        return record

    def verify(self) -> IntegrityReport:
        """Verify all tracked files against stored hashes."""
        report = IntegrityReport()

        for path, record in self._records.items():
            p = Path(path)
            if not p.exists():
                report.missing.append(path)
                continue

            current_hash = self.hash_file(path)
            if current_hash == record.sha256:
                report.passed.append(path)
            else:
                report.failed.append(
                    {
                        "path": path,
                        "expected": record.sha256,
                        "actual": current_hash,
                        "last_verified": record.last_verified,
                        "last_modified_by": record.last_modified_by,
                    }
                )

        report.tampered = len(report.failed) > 0
        return report

    def verify_file(self, path: str) -> bool | None:
        """Verify a single file. Returns True/False, or None if not tracked."""
        record = self._records.get(str(path))
        if record is None:
            return None
        current_hash = self.hash_file(path)
        return current_hash == record.sha256

    def is_tracked(self, path: str) -> bool:
        """Check if a file is tracked."""
        return str(path) in self._records

    def tracked_files(self) -> list[str]:
        """List all tracked file paths."""
        return list(self._records.keys())

    def get_record(self, path: str) -> FileRecord | None:
        """Get the stored record for a file."""
        return self._records.get(str(path))

    def remove(self, path: str) -> None:
        """Stop tracking a file."""
        self._records.pop(str(path), None)
        self._save()
