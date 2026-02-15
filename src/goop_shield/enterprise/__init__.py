# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Shield Enterprise — Proprietary extensions for adaptive defense.

All classes in this package raise ``ImportError`` on instantiation in the
community edition.  They import successfully (preserving type signatures)
but cannot be used without goop-ai Enterprise.

See docs/editions.md for the full tier split.
"""

from goop_shield.enterprise.brorl_ranking import BroRLRankingBackend
from goop_shield.enterprise.consistency_checker import (
    ConsistencyChecker,
    ConsistencyResult,
    ProviderConfig,
    SafetyClassifier,
)
from goop_shield.enterprise.gooprange_bridge import GoopRangeBridge, ValidationResult
from goop_shield.enterprise.middleware import (
    PromptBlockedError,
    ResponseBlockedError,
    ShieldedProvider,
)
from goop_shield.enterprise.quarantine import QuarantineStore
from goop_shield.enterprise.sandbag_detector import CategoryStats, SandbagAlert, SandbagDetector
from goop_shield.enterprise.task_categorizer import TaskCategorizer
from goop_shield.enterprise.telemetry_pipeline import TelemetryPipeline
from goop_shield.enterprise.training_gate import TrainingDataGate, TrainingDataVerdict
from goop_shield.enterprise.validation_bridge import ValidationBridge

__all__ = [
    "BroRLRankingBackend",
    "ConsistencyChecker",
    "ConsistencyResult",
    "CategoryStats",
    "GoopRangeBridge",
    "PromptBlockedError",
    "ProviderConfig",
    "QuarantineStore",
    "ResponseBlockedError",
    "SafetyClassifier",
    "SandbagAlert",
    "SandbagDetector",
    "ShieldedProvider",
    "TaskCategorizer",
    "TelemetryPipeline",
    "TrainingDataGate",
    "TrainingDataVerdict",
    "ValidationBridge",
    "ValidationResult",
]
