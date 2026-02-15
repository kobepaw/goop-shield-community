"""
Shared fixtures for Shield tests.
"""

from __future__ import annotations

import pytest

# Skip enterprise test files that import enterprise internals not available in OSS
collect_ignore = [
    "test_consistency_checker.py",
    "test_middleware.py",
]

from goop_shield.config import ShieldConfig
from goop_shield.defender import Defender
from goop_shield.defenses import DefenseRegistry, register_defaults
from goop_shield.defenses.base import DefenseContext


@pytest.fixture
def shield_config():
    """Default ShieldConfig for testing."""
    return ShieldConfig()


@pytest.fixture
def defense_registry():
    """Registry pre-loaded with default defenses and 3 output scanners."""
    registry = DefenseRegistry()
    register_defaults(registry)
    return registry


@pytest.fixture
def defender(shield_config, defense_registry):
    """Defender wired with default config and registry."""
    return Defender(shield_config, registry=defense_registry)


@pytest.fixture
def defense_context():
    """Basic defense context with a benign prompt."""
    return DefenseContext(
        original_prompt="Hello, how are you?",
        current_prompt="Hello, how are you?",
    )
