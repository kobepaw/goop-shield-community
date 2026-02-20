# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 goop-shield contributors
"""
Shield Client SDK — Async HTTP Client for Shield REST API

Wraps Shield's FastAPI endpoints with a typed async client.

Usage::

    async with ShieldClient("http://127.0.0.1:8787", api_key="sk-...") as client:
        result = await client.defend("Hello, world")
        if not result.allow:
            print("Blocked!", result.verdicts)
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from goop_shield.models import (
    DefendResponse,
    RedTeamReport,
    ScanResponse,
    ShieldHealth,
)

logger = logging.getLogger(__name__)


class ShieldClientError(Exception):
    """Raised on non-2xx responses from the Shield server."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(f"Shield API error {status_code}: {body}")


class ShieldUnavailableError(ShieldClientError):
    """Raised when the Shield server is unreachable."""

    def __init__(self, message: str) -> None:
        # Use 0 for connection-level failures (no HTTP status)
        super().__init__(status_code=0, body=message)


class ShieldClient:
    """Async HTTP client for the Shield REST API.

    Parameters
    ----------
    base_url:
        Shield server URL (default ``http://127.0.0.1:8787``).
    api_key:
        Optional bearer token for authenticated endpoints.
    timeout:
        Request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8787",
        api_key: str | None = None,
        timeout: float = 10.0,
        canary_enabled: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._canary_enabled = canary_enabled
        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            timeout=timeout,
        )

    async def defend(
        self,
        prompt: str,
        context: dict | None = None,
    ) -> DefendResponse:
        """Send a prompt through the Shield defense pipeline.

        Returns a :class:`DefendResponse` with ``allow``, ``filtered_prompt``,
        ``verdicts``, etc.

        If the server has alignment canaries enabled, a background task
        is scheduled to execute any pending canary without blocking the
        real request.
        """
        payload: dict = {"prompt": prompt}
        if context:
            payload["context"] = context
        data = await self._post("/api/v1/defend", payload)

        # Fire-and-forget canary execution (non-blocking)
        if self._canary_enabled:
            try:
                asyncio.ensure_future(self._maybe_run_canary())
            except Exception:
                pass  # Never let canary scheduling interfere with the real request

        return DefendResponse.model_validate(data)

    async def scan_response(
        self,
        response_text: str,
        original_prompt: str = "",
        context: dict | None = None,
    ) -> ScanResponse:
        """Scan an LLM response for leaked secrets, harmful content, etc."""
        payload: dict = {"response_text": response_text}
        if original_prompt:
            payload["original_prompt"] = original_prompt
        if context:
            payload["context"] = context
        data = await self._post("/api/v1/scan-response", payload)
        return ScanResponse.model_validate(data)

    async def health(self) -> ShieldHealth:
        """Check Shield server health."""
        data = await self._get("/api/v1/health")
        return ShieldHealth.model_validate(data)

    async def probe(
        self,
        probe_names: list[str] | None = None,
    ) -> RedTeamReport:
        """Trigger red-team probes and return the report."""
        payload: dict = {}
        if probe_names is not None:
            payload["probe_names"] = probe_names
        data = await self._post("/api/v1/redteam/probe", payload)
        return RedTeamReport.model_validate(data)

    async def get_brorl_state(self) -> dict:
        """Get BroRL technique weights (alpha/beta posteriors)."""
        return await self._get("/api/v1/brorl/state")

    async def load_brorl_weights(self, weights: dict) -> dict:
        """Load BroRL technique weights."""
        return await self._post("/api/v1/brorl/load", weights)

    async def metrics_raw(self) -> str:
        """Get raw Prometheus-format metrics text."""
        try:
            resp = await self._client.get("/api/v1/metrics")
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise ShieldUnavailableError(str(exc)) from exc
        self._check_status(resp)
        return resp.text

    async def get_defender_stats(self) -> dict:
        """Get aggregated defender stats including BroRL weights."""
        return await self._get("/api/v1/defender/stats")

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> ShieldClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _maybe_run_canary(self) -> None:
        """Side-channel canary execution (non-blocking background task).

        Checks the Shield server for a pending alignment canary.  If one
        is available, sends the canary prompt back to the server's
        canary-result endpoint.  This never blocks the real request.
        """
        try:
            resp = await self._client.get("/api/v1/alignment/pending-canary")
            if resp.status_code != 200:
                return
            data = resp.json()
            canary = data.get("canary")
            if not canary:
                return
            # Post the canary back for server-side evaluation.
            # In a full deployment the client would also send the canary
            # prompt to the LLM and return the LLM's response; for now
            # we delegate evaluation to the server.
            await self._client.post(
                "/api/v1/alignment/canary-result",
                json={
                    "canary_id": canary.get("canary_id", ""),
                    "response": canary.get("prompt", ""),
                },
            )
        except Exception:
            # Never let canary errors propagate — this is best-effort
            logger.warning("Alignment canary side-channel failed", exc_info=True)

    async def _post(self, path: str, payload: dict) -> dict:
        try:
            resp = await self._client.post(path, json=payload)
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise ShieldUnavailableError(str(exc)) from exc
        self._check_status(resp)
        return dict(resp.json())

    async def _get(self, path: str) -> dict:
        try:
            resp = await self._client.get(path)
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise ShieldUnavailableError(str(exc)) from exc
        self._check_status(resp)
        return dict(resp.json())

    @staticmethod
    def _check_status(resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            raise ShieldClientError(resp.status_code, resp.text)
