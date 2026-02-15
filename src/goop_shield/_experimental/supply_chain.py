# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Supply Chain Validator — Verifies integrity of models and dependencies.

Provides checksum verification for:
- Model files (ensure no tampering/substitution)
- Configuration files (ensure no unauthorized changes)
- Critical dependencies (ensure expected versions)

Does NOT require external services — all validation is local.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ChecksumRecord:
    """Expected checksum for a verified artifact."""

    path: str
    expected_sha256: str
    artifact_type: str = "file"  # file | model | config
    description: str = ""


@dataclass
class ValidationResult:
    """Result of a single artifact validation."""

    path: str
    valid: bool
    actual_sha256: str = ""
    expected_sha256: str = ""
    reason: str = ""


@dataclass
class DependencyCheck:
    """Result of a dependency version check."""

    package: str
    expected_version: str
    actual_version: str | None = None
    valid: bool = False
    reason: str = ""


@dataclass
class SupplyChainReport:
    """Full supply chain validation report."""

    artifacts: list[ValidationResult] = field(default_factory=list)
    dependencies: list[DependencyCheck] = field(default_factory=list)
    valid: bool = True
    summary: str = ""

    def __post_init__(self):
        if self.artifacts or self.dependencies:
            failed_artifacts = [a for a in self.artifacts if not a.valid]
            failed_deps = [d for d in self.dependencies if not d.valid]
            self.valid = len(failed_artifacts) == 0 and len(failed_deps) == 0
            parts = []
            if failed_artifacts:
                parts.append(f"{len(failed_artifacts)} artifact(s) failed")
            if failed_deps:
                parts.append(f"{len(failed_deps)} dependency(ies) failed")
            if parts:
                self.summary = "FAILED: " + ", ".join(parts)
            else:
                self.summary = (
                    f"OK: {len(self.artifacts)} artifact(s), "
                    f"{len(self.dependencies)} dependency(ies) verified"
                )


class SupplyChainValidator:
    """Validates integrity of models, configs, and dependencies.

    Args:
        manifest_path: Path to JSON manifest of expected checksums.
    """

    def __init__(self, manifest_path: str = "data/supply_chain_manifest.json") -> None:
        self._manifest_path = manifest_path
        self._checksums: list[ChecksumRecord] = []
        self._expected_deps: dict[str, str] = {}
        self._load_manifest()

    def _load_manifest(self) -> None:
        """Load the supply chain manifest from disk."""
        path = Path(self._manifest_path)
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            for item in data.get("artifacts", []):
                self._checksums.append(
                    ChecksumRecord(
                        path=item["path"],
                        expected_sha256=item["sha256"],
                        artifact_type=item.get("type", "file"),
                        description=item.get("description", ""),
                    )
                )
            self._expected_deps = data.get("dependencies", {})
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Failed to load supply chain manifest: %s", e)

    def save_manifest(self) -> None:
        """Persist the current manifest to disk."""
        path = Path(self._manifest_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "artifacts": [
                    {
                        "path": c.path,
                        "sha256": c.expected_sha256,
                        "type": c.artifact_type,
                        "description": c.description,
                    }
                    for c in self._checksums
                ],
                "dependencies": self._expected_deps,
            }
            path.write_text(json.dumps(data, indent=2))
        except OSError as e:
            logger.error("Failed to save supply chain manifest to %s: %s", path, e)

    @staticmethod
    def hash_file(file_path: str) -> str:
        """Compute SHA-256 hash of a file."""
        h = hashlib.sha256()
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def register_artifact(
        self,
        file_path: str,
        artifact_type: str = "file",
        description: str = "",
    ) -> ChecksumRecord:
        """Register an artifact by computing its current checksum."""
        sha256 = self.hash_file(file_path)
        record = ChecksumRecord(
            path=file_path,
            expected_sha256=sha256,
            artifact_type=artifact_type,
            description=description,
        )
        # Replace existing or add new
        self._checksums = [c for c in self._checksums if c.path != file_path]
        self._checksums.append(record)
        return record

    def register_dependency(self, package: str, version: str) -> None:
        """Register an expected dependency version."""
        self._expected_deps[package] = version

    def validate_artifacts(self) -> list[ValidationResult]:
        """Validate all registered artifacts against expected checksums."""
        results: list[ValidationResult] = []
        for record in self._checksums:
            try:
                actual = self.hash_file(record.path)
                valid = actual == record.expected_sha256
                results.append(
                    ValidationResult(
                        path=record.path,
                        valid=valid,
                        actual_sha256=actual,
                        expected_sha256=record.expected_sha256,
                        reason="" if valid else "checksum mismatch",
                    )
                )
            except FileNotFoundError:
                results.append(
                    ValidationResult(
                        path=record.path,
                        valid=False,
                        expected_sha256=record.expected_sha256,
                        reason="file not found",
                    )
                )
        return results

    def validate_dependencies(self) -> list[DependencyCheck]:
        """Validate installed package versions against expected versions."""
        results: list[DependencyCheck] = []
        for package, expected in self._expected_deps.items():
            try:
                actual = importlib.metadata.version(package)
                valid = actual == expected
                results.append(
                    DependencyCheck(
                        package=package,
                        expected_version=expected,
                        actual_version=actual,
                        valid=valid,
                        reason="" if valid else f"version mismatch: {actual} != {expected}",
                    )
                )
            except importlib.metadata.PackageNotFoundError:
                results.append(
                    DependencyCheck(
                        package=package,
                        expected_version=expected,
                        actual_version=None,
                        valid=False,
                        reason="package not installed",
                    )
                )
        return results

    def validate_all(self) -> SupplyChainReport:
        """Run full supply chain validation."""
        artifacts = self.validate_artifacts()
        dependencies = self.validate_dependencies()
        return SupplyChainReport(artifacts=artifacts, dependencies=dependencies)
