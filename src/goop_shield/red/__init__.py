# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield Red — Continuous Red-Teaming Engine

The community edition includes the Probe ABC and ProbeRegistry for
custom integrations. Attack probes, the runner, and the scheduler
require goop-ai Enterprise.
"""

from goop_shield.red.advanced_probes import register_advanced_probes
from goop_shield.red.multi_turn_probes import (
    MultiTurnProbe,
    register_multi_turn_probes,
)
from goop_shield.red.probes import Probe, ProbeRegistry, register_default_probes

__all__ = [
    "MultiTurnProbe",
    "Probe",
    "ProbeRegistry",
    "register_advanced_probes",
    "register_default_probes",
    "register_multi_turn_probes",
]
