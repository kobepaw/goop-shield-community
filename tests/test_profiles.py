"""
Tests for Shield defense profile presets.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_PRESETS_DIR = Path(__file__).resolve().parents[1] / "config"


class TestShieldStrictProfile:
    def setup_method(self):
        path = _PRESETS_DIR / "shield_strict.yaml"
        assert path.exists(), f"Missing preset: {path}"
        self.data = yaml.safe_load(path.read_text())

    def test_is_valid_yaml(self):
        assert isinstance(self.data, dict)

    def test_max_prompt_length(self):
        assert self.data["max_prompt_length"] == 1000

    def test_max_prompt_tokens(self):
        assert self.data["max_prompt_tokens"] == 512

    def test_injection_confidence_threshold(self):
        assert self.data["injection_confidence_threshold"] == 0.5

    def test_failure_policy_closed(self):
        assert self.data["failure_policy"] == "closed"

    def test_audit_enabled(self):
        assert self.data["audit_enabled"] is True

    def test_redteam_enabled(self):
        assert self.data["use_redteam"] is True

    def test_brorl_epsilon(self):
        assert self.data["brorl_epsilon"] == 0.01

    def test_redteam_probe_interval(self):
        assert self.data["redteam_probe_interval_seconds"] == 300


class TestShieldBalancedProfile:
    def setup_method(self):
        path = _PRESETS_DIR / "shield_balanced.yaml"
        assert path.exists(), f"Missing preset: {path}"
        self.data = yaml.safe_load(path.read_text())

    def test_is_valid_yaml(self):
        assert isinstance(self.data, dict)

    def test_max_prompt_length(self):
        assert self.data["max_prompt_length"] == 4000

    def test_max_prompt_tokens(self):
        assert self.data["max_prompt_tokens"] == 1024

    def test_injection_confidence_threshold(self):
        assert self.data["injection_confidence_threshold"] == 0.7

    def test_failure_policy_closed(self):
        assert self.data["failure_policy"] == "closed"

    def test_audit_enabled(self):
        assert self.data["audit_enabled"] is True


class TestShieldPermissiveProfile:
    def setup_method(self):
        path = _PRESETS_DIR / "shield_permissive.yaml"
        assert path.exists(), f"Missing preset: {path}"
        self.data = yaml.safe_load(path.read_text())

    def test_is_valid_yaml(self):
        assert isinstance(self.data, dict)

    def test_max_prompt_length(self):
        assert self.data["max_prompt_length"] == 10000

    def test_max_prompt_tokens(self):
        assert self.data["max_prompt_tokens"] == 4096

    def test_injection_confidence_threshold(self):
        assert self.data["injection_confidence_threshold"] == 0.9

    def test_failure_policy_open(self):
        assert self.data["failure_policy"] == "open"

    def test_audit_disabled(self):
        assert self.data["audit_enabled"] is False

    def test_disabled_defenses_list(self):
        disabled = self.data["disabled_defenses"]
        assert isinstance(disabled, list)
        expected = {
            "prompt_signing",
            "output_watermark",
            "rag_verifier",
            "canary_token_detector",
            "semantic_filter",
            "obfuscation_detector",
        }
        assert set(disabled) == expected
