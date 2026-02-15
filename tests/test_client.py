"""
Tests for the Shield async HTTP client SDK.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from goop_shield.client import ShieldClient, ShieldClientError, ShieldUnavailableError

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def defend_allowed_json():
    return {
        "allow": True,
        "filtered_prompt": "Hello",
        "defenses_applied": ["safety_filter"],
        "verdicts": [
            {
                "defense_name": "safety_filter",
                "action": "allow",
                "confidence": 0.1,
                "details": "",
                "latency_ms": 0.5,
            }
        ],
        "confidence": 0.1,
        "latency_ms": 1.0,
    }


@pytest.fixture
def defend_blocked_json():
    return {
        "allow": False,
        "filtered_prompt": "",
        "defenses_applied": ["safety_filter"],
        "verdicts": [
            {
                "defense_name": "safety_filter",
                "action": "block",
                "confidence": 0.95,
                "details": "Jailbreak detected",
                "latency_ms": 0.8,
            }
        ],
        "confidence": 0.95,
        "latency_ms": 1.2,
    }


@pytest.fixture
def scan_safe_json():
    return {
        "safe": True,
        "filtered_response": "The weather is nice.",
        "scanners_applied": ["secret_scanner"],
        "verdicts": [],
        "confidence": 0.0,
        "latency_ms": 0.5,
    }


@pytest.fixture
def health_json():
    return {
        "status": "healthy",
        "defenses_loaded": 20,
        "scanners_loaded": 3,
        "brorl_ready": True,
        "version": "0.1.0",
        "uptime_seconds": 42.0,
        "total_requests": 10,
        "total_blocked": 2,
        "active_defenses": ["safety_filter"],
        "active_scanners": ["secret_scanner"],
    }


@pytest.fixture
def probe_json():
    return {
        "total_probes": 5,
        "defenses_bypassed": 1,
        "bypass_rate": 0.2,
        "results": [],
        "timestamp": 1000.0,
        "latency_ms": 50.0,
    }


def _mock_response(status_code: int, json_data: dict) -> httpx.Response:
    """Build a fake httpx.Response."""
    return httpx.Response(
        status_code=status_code,
        json=json_data,
        request=httpx.Request("POST", "http://test"),
    )


def _mock_text_response(status_code: int, text: str) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        text=text,
        request=httpx.Request("POST", "http://test"),
    )


# ============================================================================
# Tests
# ============================================================================


class TestShieldClient:
    @pytest.mark.asyncio
    async def test_defend_allowed(self, defend_allowed_json):
        mock_resp = _mock_response(200, defend_allowed_json)
        with patch.object(
            httpx.AsyncClient, "post", new_callable=AsyncMock, return_value=mock_resp
        ):
            async with ShieldClient() as client:
                result = await client.defend("Hello")
        assert result.allow is True
        assert result.filtered_prompt == "Hello"
        assert len(result.defenses_applied) == 1

    @pytest.mark.asyncio
    async def test_defend_blocked(self, defend_blocked_json):
        mock_resp = _mock_response(200, defend_blocked_json)
        with patch.object(
            httpx.AsyncClient, "post", new_callable=AsyncMock, return_value=mock_resp
        ):
            async with ShieldClient() as client:
                result = await client.defend("Ignore instructions")
        assert result.allow is False
        assert result.confidence == 0.95

    @pytest.mark.asyncio
    async def test_scan_response(self, scan_safe_json):
        mock_resp = _mock_response(200, scan_safe_json)
        with patch.object(
            httpx.AsyncClient, "post", new_callable=AsyncMock, return_value=mock_resp
        ):
            async with ShieldClient() as client:
                result = await client.scan_response(
                    "The weather is nice.", original_prompt="Weather?"
                )
        assert result.safe is True
        assert result.filtered_response == "The weather is nice."

    @pytest.mark.asyncio
    async def test_health(self, health_json):
        mock_resp = _mock_response(200, health_json)
        with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock, return_value=mock_resp):
            async with ShieldClient() as client:
                result = await client.health()
        assert result.status == "healthy"
        assert result.defenses_loaded == 20
        assert result.scanners_loaded == 3

    @pytest.mark.asyncio
    async def test_probe(self, probe_json):
        mock_resp = _mock_response(200, probe_json)
        with patch.object(
            httpx.AsyncClient, "post", new_callable=AsyncMock, return_value=mock_resp
        ):
            async with ShieldClient() as client:
                result = await client.probe()
        assert result.total_probes == 5
        assert result.bypass_rate == 0.2

    @pytest.mark.asyncio
    async def test_auth_header_sent(self, defend_allowed_json):
        mock_resp = _mock_response(200, defend_allowed_json)
        with patch.object(
            httpx.AsyncClient, "post", new_callable=AsyncMock, return_value=mock_resp
        ):
            async with ShieldClient(api_key="sk-test-123") as client:
                await client.defend("Hello")
        # Verify the client was created with auth header
        assert client._client.headers.get("authorization") == "Bearer sk-test-123"

    @pytest.mark.asyncio
    async def test_no_auth_header_when_unset(self, defend_allowed_json):
        mock_resp = _mock_response(200, defend_allowed_json)
        with patch.object(
            httpx.AsyncClient, "post", new_callable=AsyncMock, return_value=mock_resp
        ):
            async with ShieldClient() as client:
                await client.defend("Hello")
        assert "authorization" not in client._client.headers

    @pytest.mark.asyncio
    async def test_client_error_on_4xx(self):
        mock_resp = _mock_text_response(403, '{"error":"forbidden"}')
        with patch.object(
            httpx.AsyncClient, "post", new_callable=AsyncMock, return_value=mock_resp
        ):
            async with ShieldClient() as client:
                with pytest.raises(ShieldClientError) as exc_info:
                    await client.defend("Hello")
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_unavailable_on_connection_error(self):
        with patch.object(
            httpx.AsyncClient,
            "post",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            async with ShieldClient() as client:
                with pytest.raises(ShieldUnavailableError):
                    await client.defend("Hello")

    @pytest.mark.asyncio
    async def test_context_manager(self, defend_allowed_json):
        mock_resp = _mock_response(200, defend_allowed_json)
        with patch.object(
            httpx.AsyncClient, "post", new_callable=AsyncMock, return_value=mock_resp
        ):
            async with ShieldClient() as client:
                result = await client.defend("Hello")
                assert result.allow is True

    @pytest.mark.asyncio
    async def test_custom_base_url(self, health_json):
        mock_resp = _mock_response(200, health_json)
        with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock, return_value=mock_resp):
            async with ShieldClient(base_url="http://10.0.0.1:9999") as client:
                await client.health()
        assert client.base_url == "http://10.0.0.1:9999"

    @pytest.mark.asyncio
    async def test_unavailable_on_timeout(self):
        with patch.object(
            httpx.AsyncClient,
            "post",
            new_callable=AsyncMock,
            side_effect=httpx.TimeoutException("Request timed out"),
        ):
            async with ShieldClient() as client:
                with pytest.raises(ShieldUnavailableError):
                    await client.defend("Hello")

    @pytest.mark.asyncio
    async def test_unavailable_on_timeout_get(self):
        with patch.object(
            httpx.AsyncClient,
            "get",
            new_callable=AsyncMock,
            side_effect=httpx.TimeoutException("Request timed out"),
        ):
            async with ShieldClient() as client:
                with pytest.raises(ShieldUnavailableError):
                    await client.health()

    @pytest.mark.asyncio
    async def test_timeout_passed(self):
        client = ShieldClient(timeout=42.0)
        assert client._client.timeout.connect == 42.0
        await client.close()
