"""
Tests for ShieldConfig.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from goop_shield.config import ShieldConfig


class TestShieldConfigDefaults:
    """Verify default values."""

    def test_default_host(self):
        cfg = ShieldConfig()
        assert cfg.host == "127.0.0.1"

    def test_default_port(self):
        cfg = ShieldConfig()
        assert cfg.port == 8787

    def test_default_workers(self):
        cfg = ShieldConfig()
        assert cfg.workers == 1

    def test_default_max_prompt_length(self):
        cfg = ShieldConfig()
        assert cfg.max_prompt_length == 2000

    def test_default_injection_threshold(self):
        cfg = ShieldConfig()
        assert cfg.injection_confidence_threshold == 0.7

    def test_default_brorl_learning_rate(self):
        cfg = ShieldConfig()
        assert cfg.brorl_learning_rate == 0.1

    def test_default_telemetry_enabled(self):
        cfg = ShieldConfig()
        assert cfg.telemetry_enabled is True

    def test_default_failure_policy(self):
        cfg = ShieldConfig()
        assert cfg.failure_policy == "closed"


class TestShieldConfigValidation:
    """Boundary and invalid-value tests."""

    def test_port_too_low(self):
        with pytest.raises(ValidationError):
            ShieldConfig(port=0)

    def test_port_too_high(self):
        with pytest.raises(ValidationError):
            ShieldConfig(port=70000)

    def test_workers_zero(self):
        with pytest.raises(ValidationError):
            ShieldConfig(workers=0)

    def test_injection_threshold_above_one(self):
        with pytest.raises(ValidationError):
            ShieldConfig(injection_confidence_threshold=1.5)

    def test_injection_threshold_below_zero(self):
        with pytest.raises(ValidationError):
            ShieldConfig(injection_confidence_threshold=-0.1)

    def test_brorl_learning_rate_zero(self):
        with pytest.raises(ValidationError):
            ShieldConfig(brorl_learning_rate=0)

    def test_max_prompt_length_below_min(self):
        with pytest.raises(ValidationError):
            ShieldConfig(max_prompt_length=50)

    def test_telemetry_buffer_too_small(self):
        with pytest.raises(ValidationError):
            ShieldConfig(telemetry_buffer_size=5)

    def test_invalid_failure_policy(self):
        with pytest.raises(ValidationError):
            ShieldConfig(failure_policy="maybe")


class TestShieldConfigFrozenAndExtra:
    """Config is frozen and forbids extra fields."""

    def test_frozen(self):
        cfg = ShieldConfig()
        with pytest.raises(ValidationError):
            cfg.port = 9999  # type: ignore[misc]

    def test_extra_field_forbidden(self):
        with pytest.raises(ValidationError):
            ShieldConfig(nonexistent_field="bad")  # type: ignore[call-arg]

    def test_valid_custom_values(self):
        cfg = ShieldConfig(port=9000, workers=4, failure_policy="closed")
        assert cfg.port == 9000
        assert cfg.workers == 4
        assert cfg.failure_policy == "closed"
