"""Tests for Shield Policy Manager."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from goop_shield.policy import PolicyBundle, PolicyManager

# ============================================================================
# PolicyBundle Tests
# ============================================================================


class TestPolicyBundle:
    def test_hash_computed_on_init(self):
        bundle = PolicyBundle(
            version="1.0",
            brorl_weights={"tech_a": {"alpha": 2.0, "beta": 1.0}},
            defense_config={"active_defenses": ["input_validator"]},
        )
        assert bundle.hash
        assert len(bundle.hash) == 16

    def test_verify_integrity_passes(self):
        bundle = PolicyBundle(
            version="1.0",
            brorl_weights={"tech_a": {"alpha": 2.0, "beta": 1.0}},
        )
        assert bundle.verify_integrity() is True

    def test_verify_integrity_fails_on_tamper(self):
        bundle = PolicyBundle(
            version="1.0",
            brorl_weights={"tech_a": {"alpha": 2.0, "beta": 1.0}},
        )
        bundle.brorl_weights["tech_a"]["alpha"] = 99.0
        assert bundle.verify_integrity() is False

    def test_to_dict_roundtrip(self):
        bundle = PolicyBundle(
            version="2.0",
            brorl_weights={"x": {"alpha": 1.0}},
            defense_config={"failure_policy": "open"},
        )
        d = bundle.to_dict()
        restored = PolicyBundle.from_dict(d)
        assert restored.version == "2.0"
        assert restored.brorl_weights == {"x": {"alpha": 1.0}}
        assert restored.hash == bundle.hash
        assert restored.verify_integrity() is True

    def test_from_dict_ignores_extra_keys(self):
        data = {
            "version": "3.0",
            "brorl_weights": {},
            "defense_config": {},
            "hash": "",
            "created_at": 0.0,
            "extra_key": "ignored",
        }
        bundle = PolicyBundle.from_dict(data)
        assert bundle.version == "3.0"


# ============================================================================
# PolicyManager Tests
# ============================================================================


def _make_mock_defender():
    """Create a mock Defender with ranking backend, registry, and config."""
    defender = MagicMock()
    defender.ranking.get_weights.return_value = {
        "technique_stats": {
            "input_validator": {"alpha": 2.0, "beta": 1.0},
        },
        "total_decisions": 10,
    }
    defender.registry.names.return_value = ["input_validator", "safety_filter"]
    defender.registry.scanner_names.return_value = ["secret_scanner"]
    defender.config.failure_policy = "closed"
    defender.config.max_prompt_length = 4096
    return defender


class TestPolicyManager:
    def test_export_policy_creates_bundle(self):
        defender = _make_mock_defender()
        manager = PolicyManager(defender)

        bundle = manager.export_policy("v1.0")

        assert bundle.version == "v1.0"
        assert bundle.brorl_weights["technique_stats"]["input_validator"]["alpha"] == 2.0
        assert "input_validator" in bundle.defense_config["active_defenses"]
        assert bundle.hash
        assert len(manager.history) == 1

    def test_import_policy_loads_weights(self):
        defender = _make_mock_defender()
        manager = PolicyManager(defender)

        weights = {"technique_stats": {"safety_filter": {"alpha": 3.0, "beta": 0.5}}}
        bundle = PolicyBundle(version="v2.0", brorl_weights=weights)

        manager.import_policy(bundle)

        defender.ranking.load_weights.assert_called_once_with(weights)
        assert len(manager.history) == 1

    def test_import_policy_hash_mismatch_raises(self):
        defender = _make_mock_defender()
        manager = PolicyManager(defender)

        bundle = PolicyBundle(
            version="v3.0",
            brorl_weights={"x": {"alpha": 1.0}},
        )
        # Tamper with weights after hash was computed
        bundle.brorl_weights["x"]["alpha"] = 999.0

        with pytest.raises(ValueError, match="integrity check failed"):
            manager.import_policy(bundle)

        defender.ranking.load_weights.assert_not_called()

    def test_history_tracks_exports_and_imports(self):
        defender = _make_mock_defender()
        manager = PolicyManager(defender)

        manager.export_policy("v1")
        bundle = PolicyBundle(version="v2", brorl_weights={})
        manager.import_policy(bundle)

        assert len(manager.history) == 2
        assert manager.history[0].version == "v1"
        assert manager.history[1].version == "v2"
