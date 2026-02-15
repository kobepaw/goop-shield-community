# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Shield — Runtime Defense Service for AI Agents

Standalone FastAPI sidecar that intercepts prompts, classifies threats
via BroRL Thompson sampling, executes heuristic defenses, and returns
allow/block decisions.
"""

from goop_shield._version import __version__
from goop_shield.client import ShieldClient, ShieldClientError, ShieldUnavailableError
from goop_shield.config import ShieldConfig
from goop_shield.middleware import PromptBlockedError, ResponseBlockedError, ShieldedProvider
from goop_shield.models import DefendRequest, DefendResponse, ShieldHealth

__all__ = [
    "__version__",
    "ShieldClient",
    "ShieldClientError",
    "ShieldUnavailableError",
    "ShieldConfig",
    "ShieldedProvider",
    "PromptBlockedError",
    "ResponseBlockedError",
    "DefendRequest",
    "DefendResponse",
    "ShieldHealth",
]
