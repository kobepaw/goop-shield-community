"""Tests for Shield framework adapters."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from goop_shield.adapters.base import ScanResult, ShieldResult
from goop_shield.adapters.crewai import CrewAIShieldAdapter
from goop_shield.adapters.generic import GenericHTTPAdapter
from goop_shield.adapters.langchain import LangChainShieldCallback
from goop_shield.adapters.openclaw import OpenClawAdapter


class TestShieldResult:
    def test_defaults(self):
        r = ShieldResult()
        assert r.allowed is True
        assert r.filtered_prompt == ""
        assert r.blocked_by is None

    def test_blocked(self):
        r = ShieldResult(allowed=False, blocked_by="safety_filter")
        assert not r.allowed
        assert r.blocked_by == "safety_filter"


class TestScanResult:
    def test_defaults(self):
        r = ScanResult()
        assert r.safe is True

    def test_flagged(self):
        r = ScanResult(safe=False, flagged_by="secret_leak")
        assert not r.safe


class TestGenericHTTPAdapter:
    @patch("goop_shield.adapters.generic.httpx")
    def test_intercept_prompt_success(self, mock_httpx):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "allow": True,
            "filtered_prompt": "hello",
            "confidence": 0.9,
            "defenses_applied": ["safety_filter"],
            "verdicts": [],
        }
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = mock_resp
        mock_httpx.Client.return_value = mock_client

        adapter = GenericHTTPAdapter()
        result = adapter.intercept_prompt("hello")
        assert result.allowed is True

    @patch("goop_shield.adapters.generic.httpx")
    def test_intercept_prompt_blocked(self, mock_httpx):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "allow": False,
            "filtered_prompt": "hello",
            "confidence": 0.95,
            "defenses_applied": ["safety_filter"],
            "verdicts": [{"action": "block", "defense_name": "safety_filter"}],
        }
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = mock_resp
        mock_httpx.Client.return_value = mock_client

        adapter = GenericHTTPAdapter()
        result = adapter.intercept_prompt("ignore previous")
        assert result.allowed is False
        assert result.blocked_by == "safety_filter"

    def test_intercept_prompt_connection_error(self):
        """Adapter gracefully handles connection failures."""
        adapter = GenericHTTPAdapter(shield_url="http://nonexistent:9999")
        result = adapter.intercept_prompt("hello")
        assert result.allowed is True  # Fail-open


class TestOpenClawAdapter:
    @patch("goop_shield.adapters.generic.httpx")
    def test_from_hook_event(self, mock_httpx):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "allow": True,
            "filtered_prompt": "test",
            "confidence": 0.9,
            "defenses_applied": [],
            "verdicts": [],
        }
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = mock_resp
        mock_httpx.Client.return_value = mock_client

        adapter = OpenClawAdapter()
        result = adapter.from_hook_event({"tool": "read_file", "args": {"path": "/tmp/test"}})
        assert result.allowed is True


class TestLangChainCallback:
    @patch("goop_shield.adapters.generic.httpx")
    def test_on_llm_start(self, mock_httpx):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "allow": True,
            "filtered_prompt": "test",
            "confidence": 0.9,
            "defenses_applied": [],
            "verdicts": [],
        }
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = mock_resp
        mock_httpx.Client.return_value = mock_client

        callback = LangChainShieldCallback()
        callback.on_llm_start({}, ["Hello world"])
        assert len(callback._blocked_prompts) == 0


class TestCrewAIAdapter:
    @patch("goop_shield.adapters.generic.httpx")
    def test_wrap_tool_blocked(self, mock_httpx):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "allow": False,
            "filtered_prompt": "test",
            "confidence": 0.95,
            "defenses_applied": ["safety_filter"],
            "verdicts": [{"action": "block", "defense_name": "safety_filter"}],
        }
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = mock_resp
        mock_httpx.Client.return_value = mock_client

        adapter = CrewAIShieldAdapter()
        with pytest.raises(PermissionError):
            adapter.wrap_tool_execution("evil_tool", lambda: "result")
