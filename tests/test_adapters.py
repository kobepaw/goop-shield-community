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


# ---------------------------------------------------------------------------
# Helpers for new OpenClaw adapter tests
# ---------------------------------------------------------------------------


def _allow_mock_httpx(mock_httpx):
    """Configure mock httpx to return allow/safe responses."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "allow": True,
        "filtered_prompt": "ok",
        "safe": True,
        "filtered_response": "ok",
        "filtered_content": "ok",
        "action": "pass",
        "confidence": 0.1,
        "defenses_applied": [],
        "scanners_applied": [],
        "verdicts": [],
    }
    mock_resp.raise_for_status = MagicMock()
    mock_client = MagicMock()
    mock_client.post.return_value = mock_resp
    mock_httpx.Client.return_value = mock_client
    return mock_client


# ---------------------------------------------------------------------------
# TestOpenClawAdapterSubAgentContext
# ---------------------------------------------------------------------------


class TestOpenClawAdapterSubAgentContext:
    """Tests for _extract_agent_context static method."""

    def test_extracts_session_id_snake_case(self):
        ctx = OpenClawAdapter._extract_agent_context({"session_id": "s1"})
        assert ctx["session_id"] == "s1"

    def test_extracts_session_id_camel_case(self):
        ctx = OpenClawAdapter._extract_agent_context({"sessionId": "s2"})
        assert ctx["session_id"] == "s2"

    def test_parent_session_id_sets_sub_agent_true(self):
        ctx = OpenClawAdapter._extract_agent_context({"parent_session_id": "p1"})
        assert ctx["sub_agent"] is True
        assert ctx["parent_agent_id"] == "p1"

    def test_parent_session_id_camel_case_sets_sub_agent_true(self):
        ctx = OpenClawAdapter._extract_agent_context({"parentSessionId": "p2"})
        assert ctx["sub_agent"] is True
        assert ctx["parent_agent_id"] == "p2"

    def test_parent_agent_id_sets_sub_agent_true(self):
        ctx = OpenClawAdapter._extract_agent_context({"parent_agent_id": "p3"})
        assert ctx["sub_agent"] is True
        assert ctx["parent_agent_id"] == "p3"

    def test_agent_depth_extraction_snake_case(self):
        ctx = OpenClawAdapter._extract_agent_context({"agent_depth": 3})
        assert ctx["agent_depth"] == 3

    def test_agent_depth_extraction_spawn_depth(self):
        ctx = OpenClawAdapter._extract_agent_context({"spawn_depth": 2})
        assert ctx["agent_depth"] == 2

    def test_agent_depth_extraction_camel_case(self):
        ctx = OpenClawAdapter._extract_agent_context({"spawnDepth": 4})
        assert ctx["agent_depth"] == 4

    def test_agent_depth_coerced_to_int(self):
        ctx = OpenClawAdapter._extract_agent_context({"agent_depth": "5"})
        assert ctx["agent_depth"] == 5

    def test_agent_depth_invalid_value_ignored(self):
        ctx = OpenClawAdapter._extract_agent_context({"agent_depth": "abc"})
        assert "agent_depth" not in ctx

    def test_task_content_extraction_snake_case(self):
        ctx = OpenClawAdapter._extract_agent_context({"task_content": "do stuff"})
        assert ctx["task_content"] == "do stuff"

    def test_task_content_extraction_camel_case(self):
        ctx = OpenClawAdapter._extract_agent_context({"taskContent": "do stuff"})
        assert ctx["task_content"] == "do stuff"

    def test_task_content_extraction_short_key(self):
        ctx = OpenClawAdapter._extract_agent_context({"task": "do stuff"})
        assert ctx["task_content"] == "do stuff"

    def test_fallback_parent_present_no_depth_defaults_to_1(self):
        ctx = OpenClawAdapter._extract_agent_context({"parent_session_id": "p1"})
        assert ctx["agent_depth"] == 1

    def test_empty_event_returns_empty_context(self):
        ctx = OpenClawAdapter._extract_agent_context({})
        assert ctx == {}

    def test_full_event_all_fields(self):
        ctx = OpenClawAdapter._extract_agent_context(
            {
                "session_id": "s1",
                "parent_session_id": "p1",
                "agent_depth": 2,
                "task_content": "analyze data",
            }
        )
        assert ctx["session_id"] == "s1"
        assert ctx["parent_agent_id"] == "p1"
        assert ctx["sub_agent"] is True
        assert ctx["agent_depth"] == 2
        assert ctx["task_content"] == "analyze data"

    def test_snake_case_takes_precedence_over_camel_case_for_session_id(self):
        ctx = OpenClawAdapter._extract_agent_context(
            {
                "session_id": "snake",
                "sessionId": "camel",
            }
        )
        assert ctx["session_id"] == "snake"


# ---------------------------------------------------------------------------
# TestOpenClawAdapterOriginValidation
# ---------------------------------------------------------------------------


class TestOpenClawAdapterOriginValidation:
    """Tests for WebSocket origin validation (CVE-2026-25253)."""

    def test_validate_origin_returns_true_when_disabled(self):
        adapter = OpenClawAdapter()
        assert adapter._validate_origin("https://evil.com") is True

    def test_validate_origin_returns_false_for_empty_origin_when_configured(self):
        adapter = OpenClawAdapter(allowed_origins=["https://safe.com"])
        assert adapter._validate_origin("") is False
        assert adapter._validate_origin(None) is False

    def test_validate_origin_accepts_listed_origin(self):
        adapter = OpenClawAdapter(allowed_origins=["https://safe.com"])
        assert adapter._validate_origin("https://safe.com") is True

    def test_validate_origin_rejects_unlisted_origin(self):
        adapter = OpenClawAdapter(allowed_origins=["https://safe.com"])
        assert adapter._validate_origin("https://evil.com") is False

    def test_validate_origin_accepts_multiple_listed_origins(self):
        adapter = OpenClawAdapter(allowed_origins=["https://a.com", "https://b.com"])
        assert adapter._validate_origin("https://a.com") is True
        assert adapter._validate_origin("https://b.com") is True

    def test_normalize_origin_adds_scheme(self):
        assert OpenClawAdapter._normalize_origin("example.com") == "https://example.com"

    def test_normalize_origin_strips_trailing_path(self):
        result = OpenClawAdapter._normalize_origin("https://example.com/path/to/thing")
        assert result == "https://example.com"

    def test_normalize_origin_preserves_non_standard_port(self):
        result = OpenClawAdapter._normalize_origin("https://example.com:8080")
        assert result == "https://example.com:8080"

    def test_normalize_origin_strips_standard_https_port(self):
        result = OpenClawAdapter._normalize_origin("https://example.com:443")
        assert result == "https://example.com"

    def test_normalize_origin_strips_standard_http_port(self):
        result = OpenClawAdapter._normalize_origin("http://example.com:80")
        assert result == "http://example.com"

    def test_normalize_origin_preserves_http_scheme(self):
        result = OpenClawAdapter._normalize_origin("http://example.com")
        assert result == "http://example.com"

    def test_from_jsonrpc_message_blocks_when_origin_not_allowed(self):
        adapter = OpenClawAdapter(allowed_origins=["https://safe.com"])
        result = adapter.from_jsonrpc_message(
            {"type": "req", "params": {"content": "hello"}},
            origin="https://evil.com",
        )
        assert result is not None
        assert result.allowed is False
        assert result.blocked_by == "openclaw_origin_rejected"

    @patch("goop_shield.adapters.generic.httpx")
    def test_from_jsonrpc_message_passes_when_origin_allowed(self, mock_httpx):
        _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter(allowed_origins=["https://safe.com"])
        result = adapter.from_jsonrpc_message(
            {"type": "req", "params": {"content": "hello"}},
            origin="https://safe.com",
        )
        assert result is not None
        assert result.allowed is True

    @patch("goop_shield.adapters.generic.httpx")
    def test_from_jsonrpc_message_passes_when_origins_disabled(self, mock_httpx):
        _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        result = adapter.from_jsonrpc_message(
            {"type": "req", "params": {"content": "hello"}},
            origin="https://anything.com",
        )
        assert result is not None
        assert result.allowed is True


# ---------------------------------------------------------------------------
# TestOpenClawExternalContentMarkers
# ---------------------------------------------------------------------------


class TestOpenClawExternalContentMarkers:
    """Tests for external content marker detection."""

    def test_has_external_markers_detects_marker(self):
        assert OpenClawAdapter._has_external_markers("<<< EXTERNAL UNTRUSTED CONTENT >>>")

    def test_has_external_markers_detects_underscore_variant(self):
        assert OpenClawAdapter._has_external_markers("<<<EXTERNAL_UNTRUSTED_CONTENT>>>")

    def test_has_external_markers_case_insensitive(self):
        assert OpenClawAdapter._has_external_markers("<<<external_untrusted_content>>>")

    def test_has_external_markers_returns_false_for_clean_text(self):
        assert not OpenClawAdapter._has_external_markers("Hello world")

    def test_has_external_markers_returns_false_for_empty_string(self):
        assert not OpenClawAdapter._has_external_markers("")

    def test_has_external_markers_partial_match_not_detected(self):
        assert not OpenClawAdapter._has_external_markers("<<<EXTERNAL>>>")

    @patch("goop_shield.adapters.generic.httpx")
    def test_intercept_prompt_sets_external_content_flag(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.intercept_prompt("<<<EXTERNAL_UNTRUSTED_CONTENT>>> payload")
        call_json = mock_client.post.call_args[1]["json"]
        assert call_json["context"]["has_external_content"] is True
        assert call_json["context"]["trust_level"] == "untrusted"

    @patch("goop_shield.adapters.generic.httpx")
    def test_intercept_prompt_clean_text_no_external_flag(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.intercept_prompt("Hello world")
        call_json = mock_client.post.call_args[1]["json"]
        assert "has_external_content" not in call_json["context"]

    @patch("goop_shield.adapters.generic.httpx")
    def test_scan_tool_output_forces_untrusted_when_markers_found(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.scan_tool_output(
            "<<<EXTERNAL_UNTRUSTED_CONTENT>>> secret data",
            "read_file",
            trust_level="trusted",
        )
        call_json = mock_client.post.call_args[1]["json"]
        assert call_json["trust_level"] == "untrusted"

    @patch("goop_shield.adapters.generic.httpx")
    def test_scan_tool_output_preserves_trust_level_when_clean(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.scan_tool_output("clean data", "read_file", trust_level="owner")
        call_json = mock_client.post.call_args[1]["json"]
        assert call_json["trust_level"] == "owner"


# ---------------------------------------------------------------------------
# TestOpenClawLlmHooks
# ---------------------------------------------------------------------------


class TestOpenClawLlmHooks:
    """Tests for llm_input and llm_output event processing."""

    @patch("goop_shield.adapters.generic.httpx")
    def test_from_llm_input_event_sends_concatenated_prompt(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.from_llm_input_event(
            {
                "prompt": "user question",
                "system_prompt": "You are helpful.",
            }
        )
        call_json = mock_client.post.call_args[1]["json"]
        assert call_json["prompt"] == "You are helpful.\nuser question"

    @patch("goop_shield.adapters.generic.httpx")
    def test_from_llm_input_event_prompt_only_no_system(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.from_llm_input_event({"prompt": "just a question"})
        call_json = mock_client.post.call_args[1]["json"]
        assert call_json["prompt"] == "just a question"

    def test_from_llm_input_event_returns_allowed_for_empty_prompts(self):
        adapter = OpenClawAdapter()
        result = adapter.from_llm_input_event({"prompt": "", "system_prompt": ""})
        assert result.allowed is True

    def test_from_llm_input_event_returns_allowed_for_missing_prompts(self):
        adapter = OpenClawAdapter()
        result = adapter.from_llm_input_event({})
        assert result.allowed is True

    @patch("goop_shield.adapters.generic.httpx")
    def test_from_llm_input_event_propagates_agent_context(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.from_llm_input_event(
            {
                "prompt": "question",
                "session_id": "sess-1",
                "parent_session_id": "parent-1",
                "agent_depth": 2,
            }
        )
        call_json = mock_client.post.call_args[1]["json"]
        ctx = call_json["context"]
        assert ctx["hook"] == "llm_input"
        assert ctx["session_id"] == "sess-1"
        assert ctx["parent_agent_id"] == "parent-1"
        assert ctx["agent_depth"] == 2
        assert ctx["sub_agent"] is True

    @patch("goop_shield.adapters.generic.httpx")
    def test_from_llm_input_event_detects_external_markers(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.from_llm_input_event(
            {
                "prompt": "<<<EXTERNAL_UNTRUSTED_CONTENT>>> payload",
            }
        )
        call_json = mock_client.post.call_args[1]["json"]
        assert call_json["context"]["has_external_content"] is True

    @patch("goop_shield.adapters.generic.httpx")
    def test_from_llm_output_event_scans_response(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        result = adapter.from_llm_output_event(
            {
                "response": "Here is the answer.",
                "original_prompt": "What is 2+2?",
            }
        )
        assert result.safe is True
        mock_client.post.assert_called_once()

    def test_from_llm_output_event_returns_safe_for_empty_response(self):
        adapter = OpenClawAdapter()
        result = adapter.from_llm_output_event({"response": ""})
        assert result.safe is True

    def test_from_llm_output_event_returns_safe_for_missing_response(self):
        adapter = OpenClawAdapter()
        result = adapter.from_llm_output_event({})
        assert result.safe is True


# ---------------------------------------------------------------------------
# TestOpenClawSubagentSpawn
# ---------------------------------------------------------------------------


class TestOpenClawSubagentSpawn:
    """Tests for sub-agent spawn interception."""

    def test_intercept_subagent_spawn_blocks_when_depth_exceeds_max(self):
        adapter = OpenClawAdapter(max_agent_depth=3)
        result = adapter.intercept_subagent_spawn(
            {
                "agent_depth": 4,
                "parent_session_id": "p1",
                "task_content": "do something",
            }
        )
        assert result.allowed is False
        assert result.blocked_by == "openclaw_depth_limit"

    def test_intercept_subagent_spawn_blocks_at_default_max_depth(self):
        adapter = OpenClawAdapter()
        result = adapter.intercept_subagent_spawn(
            {
                "agent_depth": 6,
                "parent_session_id": "p1",
            }
        )
        assert result.allowed is False
        assert result.blocked_by == "openclaw_depth_limit"

    @patch("goop_shield.adapters.generic.httpx")
    def test_intercept_subagent_spawn_allows_at_exact_max_depth(self, mock_httpx):
        _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter(max_agent_depth=3)
        result = adapter.intercept_subagent_spawn(
            {
                "agent_depth": 3,
                "parent_session_id": "p1",
                "task_content": "summarize",
            }
        )
        assert result.allowed is True

    @patch("goop_shield.adapters.generic.httpx")
    def test_intercept_subagent_spawn_passes_clean_task_content(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.intercept_subagent_spawn(
            {
                "agent_depth": 1,
                "parent_session_id": "p1",
                "task_content": "Summarize the document.",
            }
        )
        call_json = mock_client.post.call_args[1]["json"]
        assert call_json["context"]["sub_agent_spawn"] is True
        assert call_json["context"]["sub_agent"] is True

    @patch("goop_shield.adapters.generic.httpx")
    def test_intercept_subagent_spawn_builds_correct_synthetic_prompt(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.intercept_subagent_spawn(
            {
                "agent_depth": 2,
                "parent_session_id": "p1",
                "task_content": "Find the answer.",
                "args": {"model": "gpt-4"},
            }
        )
        call_json = mock_client.post.call_args[1]["json"]
        prompt = call_json["prompt"]
        assert "[OpenClaw SubAgent Spawn] depth=2" in prompt
        assert "Task: Find the answer." in prompt
        assert "Args:" in prompt

    @patch("goop_shield.adapters.generic.httpx")
    def test_intercept_subagent_spawn_no_task_no_args(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.intercept_subagent_spawn(
            {
                "agent_depth": 1,
                "parent_session_id": "p1",
            }
        )
        call_json = mock_client.post.call_args[1]["json"]
        prompt = call_json["prompt"]
        assert "[OpenClaw SubAgent Spawn] depth=1" in prompt
        assert "Task:" not in prompt

    @patch("goop_shield.adapters.generic.httpx")
    def test_intercept_subagent_spawn_zero_depth_passes(self, mock_httpx):
        _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        result = adapter.intercept_subagent_spawn({"agent_depth": 0})
        assert result.allowed is True


# ---------------------------------------------------------------------------
# TestOpenClawFromHookEventWithAgentContext
# ---------------------------------------------------------------------------


class TestOpenClawFromHookEventWithAgentContext:
    """Tests for from_hook_event propagating agent context."""

    @patch("goop_shield.adapters.generic.httpx")
    def test_from_hook_event_propagates_session_id(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.from_hook_event(
            {
                "tool": "read_file",
                "args": {"path": "/tmp/test"},
                "session_id": "sess-42",
            }
        )
        call_json = mock_client.post.call_args[1]["json"]
        assert call_json["context"]["session_id"] == "sess-42"

    @patch("goop_shield.adapters.generic.httpx")
    def test_from_hook_event_propagates_sub_agent_context(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.from_hook_event(
            {
                "tool": "write_file",
                "args": {},
                "session_id": "child-1",
                "parent_session_id": "parent-1",
                "agent_depth": 2,
                "task_content": "write the summary",
            }
        )
        call_json = mock_client.post.call_args[1]["json"]
        ctx = call_json["context"]
        assert ctx["sub_agent"] is True
        assert ctx["parent_agent_id"] == "parent-1"
        assert ctx["agent_depth"] == 2
        assert ctx["task_content"] == "write the summary"

    @patch("goop_shield.adapters.generic.httpx")
    def test_from_hook_event_no_agent_context(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.from_hook_event({"tool": "ls", "args": {}})
        call_json = mock_client.post.call_args[1]["json"]
        ctx = call_json["context"]
        assert ctx["framework"] == "openclaw"
        assert ctx["tool_call"] is True
        assert "sub_agent" not in ctx

    @patch("goop_shield.adapters.generic.httpx")
    def test_from_hook_event_camel_case_session_id(self, mock_httpx):
        mock_client = _allow_mock_httpx(mock_httpx)
        adapter = OpenClawAdapter()
        adapter.from_hook_event(
            {
                "tool": "read_file",
                "args": {},
                "sessionId": "camel-sess",
            }
        )
        call_json = mock_client.post.call_args[1]["json"]
        assert call_json["context"]["session_id"] == "camel-sess"
