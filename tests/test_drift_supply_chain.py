"""Tests for drift detection and supply chain validation (Phase 5)."""

from __future__ import annotations

import pytest

try:
    from goop_shield._experimental.drift_detector import DriftDetector
    from goop_shield._experimental.supply_chain import SupplyChainValidator
except ImportError:
    pytest.skip(
        "goop_shield._experimental not available (not installed as editable)",
        allow_module_level=True,
    )

# ---------------------------------------------------------------------------
# DriftDetector
# ---------------------------------------------------------------------------


class TestDriftDetector:
    def test_record_and_stats(self):
        dd = DriftDetector(baseline_path="/tmp/nonexistent.json")
        dd.record("safety_filter", blocked=True)
        dd.record("safety_filter", blocked=False)
        dd.record("safety_filter", blocked=True)

        stats = dd.get_stats("safety_filter")
        assert stats is not None
        assert stats.total == 3
        assert stats.blocked == 2

    def test_block_rate(self):
        dd = DriftDetector(baseline_path="/tmp/nonexistent.json")
        for _ in range(3):
            dd.record("test_defense", blocked=True)
        for _ in range(7):
            dd.record("test_defense", blocked=False)

        stats = dd.get_stats("test_defense")
        assert abs(stats.block_rate - 0.3) < 0.01

    def test_no_alert_below_window(self):
        """No alerts until window_size observations accumulated."""
        dd = DriftDetector(baseline_path="/tmp/nonexistent.json", window_size=50)
        for _ in range(30):
            dd.record("test_defense", blocked=True)

        report = dd.analyze()
        assert report.defenses_analyzed == 0
        assert not report.has_drift

    def test_no_alert_stable_rate(self):
        """Stable block rate should not trigger alerts."""
        dd = DriftDetector(baseline_path="/tmp/nonexistent.json", window_size=10)
        # Simulate stable ~30% block rate
        for i in range(100):
            dd.record("test_defense", blocked=(i % 3 == 0))

        report = dd.analyze()
        assert report.defenses_analyzed == 1
        # Stable rate should not trigger
        assert not report.has_drift

    def test_get_all_stats(self):
        dd = DriftDetector(baseline_path="/tmp/nonexistent.json")
        dd.record("defense_a", blocked=True)
        dd.record("defense_b", blocked=False)

        all_stats = dd.get_all_stats()
        assert "defense_a" in all_stats
        assert "defense_b" in all_stats

    def test_reset_single(self):
        dd = DriftDetector(baseline_path="/tmp/nonexistent.json")
        dd.record("defense_a", blocked=True)
        dd.record("defense_b", blocked=True)

        dd.reset("defense_a")
        assert dd.get_stats("defense_a") is None
        assert dd.get_stats("defense_b") is not None

    def test_reset_all(self):
        dd = DriftDetector(baseline_path="/tmp/nonexistent.json")
        dd.record("defense_a", blocked=True)
        dd.record("defense_b", blocked=True)

        dd.reset()
        assert len(dd.get_all_stats()) == 0

    def test_persistence(self, tmp_path):
        path = str(tmp_path / "baselines.json")
        dd1 = DriftDetector(baseline_path=path)
        for _ in range(10):
            dd1.record("test_defense", blocked=True)
        dd1.save_baselines()

        dd2 = DriftDetector(baseline_path=path)
        stats = dd2.get_stats("test_defense")
        assert stats is not None
        assert stats.total == 10

    def test_std_dev(self):
        dd = DriftDetector(baseline_path="/tmp/nonexistent.json")
        stats = dd.get_stats("nonexistent")
        assert stats is None

        dd.record("test", blocked=True)
        dd.record("test", blocked=False)
        stats = dd.get_stats("test")
        assert stats.std_dev >= 0

    def test_ema_updates(self):
        """EMA rate should track the recent block trend."""
        dd = DriftDetector(baseline_path="/tmp/nonexistent.json", decay_rate=0.9)
        # Start with all blocks
        for _ in range(20):
            dd.record("test", blocked=True)

        stats = dd.get_stats("test")
        # EMA should be close to 1.0 after many blocks
        assert stats.ema_rate > 0.5

        # Now record all passes
        for _ in range(50):
            dd.record("test", blocked=False)

        stats = dd.get_stats("test")
        # EMA should decrease toward 0
        assert stats.ema_rate < 0.5

    def test_report_timestamp(self):
        dd = DriftDetector(baseline_path="/tmp/nonexistent.json")
        report = dd.analyze()
        assert report.timestamp > 0


# ---------------------------------------------------------------------------
# SupplyChainValidator
# ---------------------------------------------------------------------------


class TestSupplyChainValidator:
    def test_hash_file(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")

        h1 = SupplyChainValidator.hash_file(str(test_file))
        h2 = SupplyChainValidator.hash_file(str(test_file))
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_hash_file_not_found(self):
        import pytest

        with pytest.raises(FileNotFoundError):
            SupplyChainValidator.hash_file("/nonexistent/file.bin")

    def test_register_and_validate_artifact(self, tmp_path):
        test_file = tmp_path / "model.bin"
        test_file.write_bytes(b"model weights data")
        manifest = str(tmp_path / "manifest.json")

        scv = SupplyChainValidator(manifest_path=manifest)
        record = scv.register_artifact(str(test_file), artifact_type="model")
        assert record.expected_sha256

        results = scv.validate_artifacts()
        assert len(results) == 1
        assert results[0].valid is True

    def test_detect_tampered_artifact(self, tmp_path):
        test_file = tmp_path / "config.yaml"
        test_file.write_text("key: value")
        manifest = str(tmp_path / "manifest.json")

        scv = SupplyChainValidator(manifest_path=manifest)
        scv.register_artifact(str(test_file), artifact_type="config")

        # Tamper with the file
        test_file.write_text("key: EVIL_VALUE")

        results = scv.validate_artifacts()
        assert len(results) == 1
        assert results[0].valid is False
        assert results[0].reason == "checksum mismatch"

    def test_detect_missing_artifact(self, tmp_path):
        test_file = tmp_path / "model.bin"
        test_file.write_bytes(b"data")
        manifest = str(tmp_path / "manifest.json")

        scv = SupplyChainValidator(manifest_path=manifest)
        scv.register_artifact(str(test_file))

        test_file.unlink()

        results = scv.validate_artifacts()
        assert len(results) == 1
        assert results[0].valid is False
        assert results[0].reason == "file not found"

    def test_validate_dependency_installed(self):
        scv = SupplyChainValidator(manifest_path="/tmp/nonexistent.json")
        import pydantic

        scv.register_dependency("pydantic", pydantic.__version__)

        results = scv.validate_dependencies()
        assert len(results) == 1
        assert results[0].valid is True

    def test_validate_dependency_version_mismatch(self):
        scv = SupplyChainValidator(manifest_path="/tmp/nonexistent.json")
        scv.register_dependency("pydantic", "0.0.0-fake")

        results = scv.validate_dependencies()
        assert len(results) == 1
        assert results[0].valid is False
        assert "version mismatch" in results[0].reason

    def test_validate_dependency_not_installed(self):
        scv = SupplyChainValidator(manifest_path="/tmp/nonexistent.json")
        scv.register_dependency("totally-fake-package-xyz", "1.0.0")

        results = scv.validate_dependencies()
        assert len(results) == 1
        assert results[0].valid is False
        assert "not installed" in results[0].reason

    def test_validate_all(self, tmp_path):
        test_file = tmp_path / "data.bin"
        test_file.write_bytes(b"valid data")
        manifest = str(tmp_path / "manifest.json")

        scv = SupplyChainValidator(manifest_path=manifest)
        scv.register_artifact(str(test_file))
        import pydantic

        scv.register_dependency("pydantic", pydantic.__version__)

        report = scv.validate_all()
        assert report.valid is True
        assert len(report.artifacts) == 1
        assert len(report.dependencies) == 1
        assert "OK" in report.summary

    def test_validate_all_with_failure(self, tmp_path):
        test_file = tmp_path / "data.bin"
        test_file.write_bytes(b"valid data")
        manifest = str(tmp_path / "manifest.json")

        scv = SupplyChainValidator(manifest_path=manifest)
        scv.register_artifact(str(test_file))
        scv.register_dependency("totally-fake-xyz", "1.0.0")

        report = scv.validate_all()
        assert report.valid is False
        assert "FAILED" in report.summary

    def test_persistence(self, tmp_path):
        test_file = tmp_path / "model.bin"
        test_file.write_bytes(b"weights")
        manifest = str(tmp_path / "manifest.json")

        scv1 = SupplyChainValidator(manifest_path=manifest)
        scv1.register_artifact(str(test_file))
        scv1.register_dependency("pydantic", "2.0.0")
        scv1.save_manifest()

        scv2 = SupplyChainValidator(manifest_path=manifest)
        assert len(scv2._checksums) == 1
        assert len(scv2._expected_deps) == 1

    def test_re_register_updates(self, tmp_path):
        test_file = tmp_path / "data.bin"
        test_file.write_bytes(b"v1")
        manifest = str(tmp_path / "manifest.json")

        scv = SupplyChainValidator(manifest_path=manifest)
        r1 = scv.register_artifact(str(test_file))

        test_file.write_bytes(b"v2")
        r2 = scv.register_artifact(str(test_file))

        assert r1.expected_sha256 != r2.expected_sha256
        # Should only have one record (replaced)
        assert len(scv._checksums) == 1

    def test_empty_manifest(self, tmp_path):
        manifest = str(tmp_path / "manifest.json")
        scv = SupplyChainValidator(manifest_path=manifest)
        report = scv.validate_all()
        assert report.valid is True
        assert len(report.artifacts) == 0
        assert len(report.dependencies) == 0
