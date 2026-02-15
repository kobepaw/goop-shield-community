# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield Framework Adapters

Abstraction layer for integrating Shield with any AI agent framework.
"""

from goop_shield.adapters.base import BaseShieldAdapter, ScanResult, ShieldResult
from goop_shield.adapters.generic import GenericHTTPAdapter

__all__ = [
    "BaseShieldAdapter",
    "GenericHTTPAdapter",
    "ShieldResult",
    "ScanResult",
]

# Optional imports — don't fail if framework not installed
try:
    from goop_shield.adapters.langchain import LangChainShieldAdapter, LangChainShieldCallback

    __all__.extend(["LangChainShieldAdapter", "LangChainShieldCallback"])
except ImportError:
    pass

try:
    from goop_shield.adapters.crewai import CrewAIShieldAdapter

    __all__.append("CrewAIShieldAdapter")
except ImportError:
    pass

try:
    from goop_shield.adapters.openclaw import OpenClawAdapter

    __all__.append("OpenClawAdapter")
except ImportError:
    pass
