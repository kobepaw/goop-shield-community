# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield Policy Manager

Versioned policy bundles for packaging and distributing BroRL weights
+ defense configuration.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class PolicyBundle:
    """Versioned snapshot of Shield defense policy."""

    version: str
    brorl_weights: dict = field(default_factory=dict)
    defense_config: dict = field(default_factory=dict)
    created_at: float = 0.0
    hash: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = time.time()
        if not self.hash:
            self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """SHA256 hash of weights + config for integrity verification."""
        payload = json.dumps(
            {"weights": self.brorl_weights, "config": self.defense_config},
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> PolicyBundle:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def verify_integrity(self) -> bool:
        """Check that the hash matches the contents."""
        return self.hash == self._compute_hash()


class PolicyManager:
    """Manages versioned policy bundles for Shield."""

    def __init__(self, defender) -> None:
        self._defender = defender
        self._history: list[PolicyBundle] = []

    def export_policy(self, version: str) -> PolicyBundle:
        """Package current ranking weights + defense config as a versioned bundle."""
        weights = self._defender.ranking.get_weights()
        defense_config = {
            "active_defenses": self._defender.registry.names(),
            "active_scanners": self._defender.registry.scanner_names(),
            "failure_policy": self._defender.config.failure_policy,
            "max_prompt_length": self._defender.config.max_prompt_length,
        }
        bundle = PolicyBundle(
            version=version,
            brorl_weights=weights,
            defense_config=defense_config,
        )
        self._history.append(bundle)
        logger.info("Exported policy v%s (hash=%s)", version, bundle.hash)
        return bundle

    def import_policy(self, bundle: PolicyBundle) -> None:
        """Load a policy bundle into the running defender."""
        if not bundle.verify_integrity():
            raise ValueError("Policy bundle integrity check failed (hash mismatch)")

        self._defender.ranking.load_weights(bundle.brorl_weights)
        self._history.append(bundle)
        logger.info("Imported policy v%s (hash=%s)", bundle.version, bundle.hash)

    @property
    def history(self) -> list[PolicyBundle]:
        return list(self._history)
