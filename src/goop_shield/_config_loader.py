# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Simplified Configuration Loader for goop-shield.

Loads YAML configs with inheritance ('extends'), environment variable
substitution (``${VAR:-default}``), and Pydantic validation.

Based on goop.config.loader but without search_paths or singleton.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class ConfigLoader:
    """Load Shield configuration from YAML with inheritance and env-var substitution."""

    ENV_PATTERN = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}")

    def __init__(self, base_dir: Path | str | None = None) -> None:
        self.base_dir = Path(base_dir) if base_dir else Path.cwd()

    def load(
        self,
        config_class: type[T],
        path: str | Path,
        **overrides: Any,
    ) -> T:
        """Load config from *path*, resolve ``extends`` chains, and validate."""
        merged = self._load_yaml(path)

        # Resolve inheritance with cycle detection
        visited: set[str] = {str(Path(path).resolve())}
        while "extends" in merged:
            base_path = merged.pop("extends")
            base_key = str(Path(base_path).resolve())
            if base_key in visited:
                raise ValueError(
                    f"Circular config inheritance detected: {base_key} already visited"
                )
            visited.add(base_key)
            base_raw = self._load_yaml(base_path)
            merged = self._deep_merge(base_raw, merged)

        # Env-var substitution
        merged = self._substitute_env_vars(merged)

        # CLI / caller overrides (highest priority)
        for key, value in overrides.items():
            if value is not None:
                self._set_nested(merged, key, value)

        return config_class.model_validate(merged)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_yaml(self, path: str | Path) -> dict[str, Any]:
        """Read a YAML file and return a dict.  Validates path stays within allowed dirs."""
        file_path = Path(path)
        if not file_path.is_absolute():
            file_path = self.base_dir / file_path
        file_path = file_path.resolve()

        # Security: resolved path must be within base_dir or cwd
        allowed = [self.base_dir.resolve(), Path.cwd().resolve()]
        if not any(_is_subpath(file_path, d) for d in allowed):
            raise ValueError(f"Config path escapes allowed directories: {file_path}")

        if not file_path.exists():
            raise FileNotFoundError(f"Config file not found: {file_path}")

        with open(file_path) as f:
            return yaml.safe_load(f) or {}

    def _deep_merge(self, base: dict, overlay: dict) -> dict:
        """Recursively merge *overlay* onto *base*; overlay wins."""
        result = base.copy()
        for key, value in overlay.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def _substitute_env_vars(self, obj: Any) -> Any:
        """Recursively replace ``${VAR:-default}`` patterns in strings."""
        if isinstance(obj, str):

            def _replace(match: re.Match) -> str:
                var_name = match.group(1)
                default = match.group(2)
                # Security: only allow SHIELD_* env vars to prevent exfiltration
                if not var_name.startswith("SHIELD_"):
                    logger.warning(
                        "Blocked env var substitution for non-SHIELD_ variable: %s", var_name
                    )
                    if default is not None:
                        return str(default)
                    return str(match.group(0))
                value = os.environ.get(var_name)
                if value is not None:
                    return str(value)
                if default is not None:
                    return str(default)
                return str(match.group(0))

            return self.ENV_PATTERN.sub(_replace, obj)
        if isinstance(obj, dict):
            return {k: self._substitute_env_vars(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._substitute_env_vars(item) for item in obj]
        return obj

    def _set_nested(self, obj: dict, key: str, value: Any) -> None:
        """Set a value using dot-notation key (e.g. ``"server.port"``)."""
        parts = key.split(".")
        current = obj
        for part in parts[:-1]:
            if part not in current or not isinstance(current[part], dict):
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value


def _is_subpath(child: Path, parent: Path) -> bool:
    """Return True if *child* is equal to or inside *parent*."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False
