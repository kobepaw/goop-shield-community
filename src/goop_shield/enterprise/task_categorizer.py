# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
Task Categorizer (Enterprise)

Classifies tasks into categories for sandbagging detection using
keyword matching against 5 built-in categories.
"""

from __future__ import annotations


class TaskCategorizer:
    """Classify tasks into categories for sandbagging detection.

    Requires goop-ai Enterprise. Not available in community edition.
    """

    def __init__(self) -> None:
        raise ImportError(
            "TaskCategorizer requires goop-ai Enterprise. Not available in the community edition."
        )

    def categorize(self, prompt: str, context: dict | None = None) -> str:
        """Categorize a task based on prompt content and context.

        Args:
            prompt: The task prompt text.
            context: Optional context dict.

        Returns:
            Category string (e.g. "safety_research", "general").
        """
        raise ImportError(
            "TaskCategorizer requires goop-ai Enterprise. Not available in the community edition."
        )
