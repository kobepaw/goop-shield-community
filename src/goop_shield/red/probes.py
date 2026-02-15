# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Shield Red Probes — Enterprise Feature

Red team probing with attack payloads requires goop-ai Enterprise.
The community edition includes the Probe ABC and ProbeRegistry for
custom integrations but does not ship concrete attack probes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class Probe(ABC):
    """Abstract base class for red-team probes."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique probe name."""
        ...

    @property
    @abstractmethod
    def target_defense(self) -> str:
        """Name of the defense this probe targets."""
        ...

    @property
    def description(self) -> str:
        """Human-readable description."""
        return ""

    @abstractmethod
    def build_payload(self) -> str:
        """Build the prompt payload to send through the defense pipeline."""
        ...

    def build_context(self) -> dict:
        """Build optional context for the DefendRequest (default empty)."""
        return {}

    def expected_blocked(self) -> bool:
        """Whether the target defense should block this payload."""
        return True

    def expected_sanitized(self) -> bool:
        """Whether the target defense should sanitize (not block) this payload."""
        return False


class ProbeRegistry:
    """Registry of available red-team probes."""

    def __init__(self) -> None:
        self._probes: dict[str, Probe] = {}

    def register(self, probe: Probe) -> None:
        """Register a probe by its name."""
        self._probes[probe.name] = probe

    def get(self, name: str) -> Probe | None:
        """Get a probe by name."""
        return self._probes.get(name)

    def get_all(self) -> list[Probe]:
        """Get all registered probes."""
        return list(self._probes.values())

    def names(self) -> list[str]:
        """Get names of all registered probes."""
        return list(self._probes.keys())

    def remove(self, name: str) -> None:
        """Remove a probe by name (no-op if not found)."""
        self._probes.pop(name, None)

    def __len__(self) -> int:
        return len(self._probes)


def register_default_probes(registry: ProbeRegistry) -> None:
    """No-op in community edition — requires goop-ai Enterprise."""


def register_alignment_probes(registry: ProbeRegistry) -> None:
    """No-op in community edition — requires goop-ai Enterprise."""


def register_fusion_probes(registry: ProbeRegistry) -> None:
    """No-op in community edition — requires goop-ai Enterprise."""


def register_agent_probes(registry: ProbeRegistry) -> None:
    """No-op in community edition — requires goop-ai Enterprise."""
