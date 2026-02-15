# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield Red — Continuous Red-Teaming Engine

The community edition includes the Probe ABC and ProbeRegistry for
custom integrations. Attack probes, the runner, and the scheduler
require goop-ai Enterprise.
"""

from goop_shield.red.probes import Probe, ProbeRegistry, register_default_probes

__all__ = [
    "Probe",
    "ProbeRegistry",
    "register_default_probes",
]
