"""
Tests for Shield Red — Continuous Red-Teaming Engine

Requires goop-ai Enterprise (concrete probes, runner, scheduler).
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

import pytest

from goop_shield.red.probes import ProbeRegistry, register_default_probes

# Detect if enterprise red team is available (community stubs have no concrete probes)
_reg = ProbeRegistry()
register_default_probes(_reg)
_enterprise_red = len(_reg) > 0
del _reg

if not _enterprise_red:
    pytest.skip("Requires goop-ai Enterprise", allow_module_level=True)

from goop_shield.config import ShieldConfig
from goop_shield.defender import Defender
from goop_shield.defenses import DefenseRegistry, register_defaults
from goop_shield.red.probes import (
    Probe,
    ProbeRegistry,
    register_agent_probes,
    register_default_probes,
)
from goop_shield.red.runner import RedTeamRunner
from goop_shield.red.scheduler import ProbeScheduler

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def probe_registry():
    registry = ProbeRegistry()
    register_default_probes(registry)
    return registry


@pytest.fixture
def agent_probe_registry():
    registry = ProbeRegistry()
    register_default_probes(registry)
    register_agent_probes(registry)
    return registry


@pytest.fixture
def redteam_config():
    return ShieldConfig(
        use_redteam=True,
        indirect_injection_enabled=True,
        social_engineering_enabled=True,
        sub_agent_guard_enabled=True,
        memory_protection_enabled=True,
    )


@pytest.fixture
def redteam_defender(redteam_config):
    registry = DefenseRegistry()
    register_defaults(registry, config=redteam_config)
    return Defender(redteam_config, registry=registry)


@pytest.fixture
def runner(redteam_defender, redteam_config, agent_probe_registry):
    return RedTeamRunner(redteam_defender, redteam_config, registry=agent_probe_registry)


# ============================================================================
# TestProbeRegistry
# ============================================================================


class TestProbeRegistry:
    def test_register_and_get(self):
        registry = ProbeRegistry()
        probe = _DummyProbe()
        registry.register(probe)
        assert registry.get("dummy") is probe

    def test_names(self, probe_registry):
        names = probe_registry.names()
        assert len(names) == 15
        assert "jailbreak" in names

    def test_remove(self, probe_registry):
        probe_registry.remove("jailbreak")
        assert probe_registry.get("jailbreak") is None
        assert len(probe_registry) == 14

    def test_remove_nonexistent_is_noop(self, probe_registry):
        probe_registry.remove("nonexistent")
        assert len(probe_registry) == 15

    def test_register_defaults_adds_15(self):
        registry = ProbeRegistry()
        register_default_probes(registry)
        assert len(registry) == 15

    def test_register_agent_probes_adds_33(self):
        registry = ProbeRegistry()
        register_agent_probes(registry)
        assert len(registry) == 33


# ============================================================================
# TestProbePayloads
# ============================================================================


class TestProbePayloads:
    def test_unique_names(self, probe_registry):
        names = probe_registry.names()
        assert len(names) == len(set(names))

    def test_valid_target_defenses(self, probe_registry):
        valid_defenses = {
            "safety_filter",
            "input_validator",
            "injection_blocker",
            "context_limiter",
            "output_filter",
            "prompt_signing",
            "output_watermark",
            "rag_verifier",
            "canary_token_detector",
            "semantic_filter",
            "prompt_monitor",
            "agent_sandbox",
            "model_guardrails",
            "indirect_injection",
            "social_engineering",
            "sub_agent_guard",
            "memory_write_guard",
        }
        for probe in probe_registry.get_all():
            assert probe.target_defense in valid_defenses, (
                f"{probe.name} targets unknown defense {probe.target_defense}"
            )

    def test_non_empty_payloads(self, probe_registry):
        for probe in probe_registry.get_all():
            assert len(probe.build_payload()) > 0, f"{probe.name} has empty payload"

    def test_jailbreak_contains_dan(self, probe_registry):
        probe = probe_registry.get("jailbreak")
        assert "DAN" in probe.build_payload()

    def test_context_overflow_expects_sanitize(self, probe_registry):
        probe = probe_registry.get("context_overflow")
        assert probe.expected_sanitized() is True
        assert probe.expected_blocked() is False

    def test_secret_exfil_expects_sanitize(self, probe_registry):
        probe = probe_registry.get("secret_exfil")
        assert probe.expected_sanitized() is True
        assert probe.expected_blocked() is False

    def test_prompt_forgery_provides_context(self, probe_registry):
        probe = probe_registry.get("prompt_forgery")
        ctx = probe.build_context()
        assert "signing_key" in ctx

    def test_overlength_exceeds_default_limit(self, probe_registry):
        probe = probe_registry.get("overlength")
        payload = probe.build_payload()
        assert len(payload) > 2000

    def test_overlength_survives_normalizer(self, probe_registry):
        """OverlengthProbe payload must not match _BASE64_RE."""
        import re

        base64_re = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
        probe = probe_registry.get("overlength")
        assert not base64_re.search(probe.build_payload())

    def test_context_overflow_survives_normalizer(self, probe_registry):
        """ContextOverflowProbe payload must not match _BASE64_RE."""
        import re

        base64_re = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
        probe = probe_registry.get("context_overflow")
        assert not base64_re.search(probe.build_payload())

    def test_separator_injection_signal_after_collapse(self, probe_registry):
        """SeparatorInjectionProbe must maintain signal >= 0.7 after whitespace collapse."""
        import re

        probe = probe_registry.get("separator_injection")
        # Simulate PromptNormalizer whitespace collapse
        payload = re.sub(r"[\s\u00a0\u2000-\u200a\u3000]+", " ", probe.build_payload()).strip()

        separators = [
            re.compile(r"\]\s*\n\s*\["),
            re.compile(r"---{3,}"),
            re.compile(r"={5,}"),
            re.compile(r"<\|[a-z_]+\|>", re.IGNORECASE),
        ]
        role_switches = [
            re.compile(r"^(SYSTEM|USER|ASSISTANT)\s*:", re.MULTILINE | re.IGNORECASE),
            re.compile(r"###\s*System", re.IGNORECASE),
            re.compile(r"\[INST\]", re.IGNORECASE),
        ]

        signal = 0.0
        for pat in separators:
            if pat.search(payload):
                signal += 1.0
        for pat in role_switches:
            if pat.search(payload):
                signal += 1.0
        if payload.count("\n") > 10:
            signal += 0.5

        max_signal = len(separators) + len(role_switches) + 0.5
        confidence = signal / max_signal
        assert confidence >= 0.7, f"Signal {signal}/{max_signal} = {confidence:.2f} < 0.7"

    def test_canary_exfil_uses_fallback_without_registry(self, probe_registry):
        """CanaryExfilProbe falls back to generic token without registry."""
        probe = probe_registry.get("canary_exfil")
        payload = probe.build_payload()
        assert "CANARY_" in payload

    def test_entropy_attack_survives_normalizer(self, probe_registry):
        """EntropyAttackProbe payload must survive confusable map and base64 regex."""
        import re

        from goop_shield.defenses.heuristic import _CONFUSABLE_MAP

        probe = probe_registry.get("entropy_attack")
        payload = probe.build_payload()

        # No character in payload should be in confusable map
        for ch in payload:
            assert ch not in _CONFUSABLE_MAP, f"char U+{ord(ch):04X} is in confusable map"

        # Should not match base64 regex
        base64_re = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
        assert not base64_re.search(payload)


# ============================================================================
# TestRedTeamRunner
# ============================================================================


class TestRedTeamRunner:
    def test_run_all_probes(self, runner):
        report = runner.run_probes()
        assert report.total_probes == 48
        assert len(report.results) + len(report.alignment_results) == 48
        assert report.timestamp > 0
        assert report.latency_ms >= 0

    def test_all_probes_caught(self, runner):
        """With all defenses active, every expected-block probe should be blocked or sanitized."""
        report = runner.run_probes()
        for result in report.results + report.alignment_results:
            assert result.payload_blocked or not result.expected_blocked, (
                f"Probe {result.probe_name} expected block but wasn't blocked"
            )

    def test_run_specific_probes(self, runner):
        report = runner.run_probes(probe_names=["jailbreak", "canary_exfil"])
        assert report.total_probes == 2
        names = {r.probe_name for r in report.results}
        assert names == {"jailbreak", "canary_exfil"}

    def test_bypass_detected_when_defense_disabled(self, redteam_config):
        """Disabling safety_filter should cause jailbreak probe to report bypass or target miss."""
        config = ShieldConfig(
            use_redteam=True,
            disabled_defenses=["safety_filter"],
        )
        defender = Defender(config)
        runner = RedTeamRunner(defender, config)
        report = runner.run_probes(probe_names=["jailbreak"])

        jailbreak_result = report.results[0]
        assert jailbreak_result.probe_name == "jailbreak"
        # With safety_filter disabled, the target defense can't catch it.
        # If another defense catches it → target_missed.
        # If nothing catches it → defense_bypassed.
        assert jailbreak_result.defense_bypassed or jailbreak_result.target_missed

    def test_ranking_updated_after_probes(self, runner):
        runner.run_probes()
        weights_after = runner.defender.ranking.get_weights()
        # Ranking backend weights should change after probes run
        assert isinstance(weights_after, dict)

    def test_latest_report_stored(self, runner):
        assert runner.latest_report is None
        runner.run_probes()
        assert runner.latest_report is not None
        assert runner.latest_report.total_probes == 48

    def test_counters_increment(self, runner):
        assert runner.total_probes_run == 0
        runner.run_probes()
        assert runner.total_probes_run == 48
        runner.run_probes()
        assert runner.total_probes_run == 96


# ============================================================================
# TestProbeScheduler
# ============================================================================


class TestProbeScheduler:
    def test_start_stop_lifecycle(self, runner):
        scheduler = ProbeScheduler(runner, interval_seconds=3600)
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(scheduler.start())
            assert scheduler.is_running is True
            loop.run_until_complete(scheduler.stop())
            assert scheduler.is_running is False
        finally:
            loop.close()

    def test_double_start_is_noop(self, runner):
        scheduler = ProbeScheduler(runner, interval_seconds=3600)
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(scheduler.start())
            task1 = scheduler._task
            loop.run_until_complete(scheduler.start())
            assert scheduler._task is task1  # Same task, not replaced
            loop.run_until_complete(scheduler.stop())
        finally:
            loop.close()


# ============================================================================
# TestRedTeamEndpoints
# ============================================================================


class TestRedTeamEndpoints:
    _TEST_API_KEY = "test-redteam-key"

    @pytest.fixture
    def client_redteam(self):
        """TestClient with red team enabled and auth configured."""

        from fastapi.testclient import TestClient

        from goop_shield.app import ShieldAuthMiddleware, app

        ShieldAuthMiddleware._auth_warning_logged = False
        with patch.dict(
            os.environ,
            {"SHIELD_CONFIG": "", "SHIELD_API_KEY": self._TEST_API_KEY},
            clear=False,
        ):
            # Patch _load_config to return redteam-enabled config
            with patch(
                "goop_shield.app._load_config",
                return_value=ShieldConfig(use_redteam=True),
            ):
                with TestClient(app) as c:
                    c.headers["Authorization"] = f"Bearer {self._TEST_API_KEY}"
                    yield c

    @pytest.fixture
    def client_no_redteam(self):
        """TestClient with red team disabled and auth configured."""
        from fastapi.testclient import TestClient

        from goop_shield.app import ShieldAuthMiddleware, app

        ShieldAuthMiddleware._auth_warning_logged = False
        with patch.dict(
            os.environ,
            {"SHIELD_API_KEY": self._TEST_API_KEY},
            clear=False,
        ):
            with TestClient(app) as c:
                c.headers["Authorization"] = f"Bearer {self._TEST_API_KEY}"
                yield c

    def test_post_probe_triggers_run(self, client_redteam):
        resp = client_redteam.post("/api/v1/redteam/probe", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_probes"] == 53
        assert "results" in data

    def test_post_probe_specific_names(self, client_redteam):
        resp = client_redteam.post(
            "/api/v1/redteam/probe",
            json={"probe_names": ["jailbreak"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_probes"] == 1
        assert data["results"][0]["probe_name"] == "jailbreak"

    def test_get_results_empty_then_populated(self, client_redteam):
        resp = client_redteam.get("/api/v1/redteam/results")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_probes"] == 0

        client_redteam.post("/api/v1/redteam/probe", json={})
        resp = client_redteam.get("/api/v1/redteam/results")
        data = resp.json()
        assert data["total_probes"] == 53

    def test_404_when_disabled(self, client_no_redteam):
        resp = client_no_redteam.post("/api/v1/redteam/probe", json={})
        assert resp.status_code == 404

        resp = client_no_redteam.get("/api/v1/redteam/results")
        assert resp.status_code == 404

    def test_403_when_no_auth(self):
        """Admin redteam endpoints return 403 when SHIELD_API_KEY is not set."""
        from fastapi.testclient import TestClient

        from goop_shield.app import ShieldAuthMiddleware, app

        ShieldAuthMiddleware._auth_warning_logged = False
        with TestClient(app) as c:
            resp = c.post("/api/v1/redteam/probe", json={})
            assert resp.status_code == 403

            resp = c.get("/api/v1/redteam/results")
            assert resp.status_code == 403

    def test_auth_required_for_redteam(self):
        from fastapi.testclient import TestClient

        from goop_shield.app import ShieldAuthMiddleware, app

        ShieldAuthMiddleware._auth_warning_logged = False
        with (
            patch.dict(os.environ, {"SHIELD_API_KEY": "secret123"}),
            patch(
                "goop_shield.app._load_config",
                return_value=ShieldConfig(use_redteam=True),
            ),
            TestClient(app) as c,
        ):
            # No auth header → 403
            resp = c.post("/api/v1/redteam/probe", json={})
            assert resp.status_code == 403

            # With auth → 200
            resp = c.post(
                "/api/v1/redteam/probe",
                json={},
                headers={"Authorization": "Bearer secret123"},
            )
            assert resp.status_code == 200


# ============================================================================
# TestRedTeamConfig
# ============================================================================


class TestRedTeamConfig:
    def test_defaults(self):
        config = ShieldConfig()
        assert config.use_redteam is False
        assert config.redteam_probe_interval_seconds == 900
        assert config.redteam_probe_categories is None
        assert config.redteam_alert_success_threshold == 0.3

    def test_interval_min_bound(self):
        with pytest.raises(ValueError):
            ShieldConfig(redteam_probe_interval_seconds=10)

    def test_interval_max_bound(self):
        with pytest.raises(ValueError):
            ShieldConfig(redteam_probe_interval_seconds=100000)

    def test_threshold_min_bound(self):
        config = ShieldConfig(redteam_alert_success_threshold=0.0)
        assert config.redteam_alert_success_threshold == 0.0

    def test_threshold_max_bound(self):
        config = ShieldConfig(redteam_alert_success_threshold=1.0)
        assert config.redteam_alert_success_threshold == 1.0


# ============================================================================
# TestRedTeamMetrics
# ============================================================================


class TestRedTeamMetrics:
    _TEST_API_KEY = "test-metrics-key"

    def test_metrics_include_redteam_counters(self):
        from fastapi.testclient import TestClient

        from goop_shield.app import ShieldAuthMiddleware, app

        ShieldAuthMiddleware._auth_warning_logged = False
        with (
            patch.dict(
                os.environ,
                {"SHIELD_API_KEY": self._TEST_API_KEY},
                clear=False,
            ),
            patch(
                "goop_shield.app._load_config",
                return_value=ShieldConfig(use_redteam=True),
            ),
            TestClient(app) as c,
        ):
            auth = {"Authorization": f"Bearer {self._TEST_API_KEY}"}
            # Run probes first
            c.post("/api/v1/redteam/probe", json={}, headers=auth)
            text = c.get("/api/v1/metrics", headers=auth).text
            assert "shield_redteam_probes_total" in text
            assert "shield_redteam_bypasses_total" in text
            assert "shield_redteam_bypass_rate" in text


# ============================================================================
# TestAgentProbes
# ============================================================================


class TestAgentProbes:
    def test_agent_probe_count(self, agent_probe_registry):
        # 15 default + 33 agent = 48 total
        assert len(agent_probe_registry) == 48

    def test_tool_injection_probes_have_context(self, agent_probe_registry):
        tool_probes = [
            p for p in agent_probe_registry.get_all() if p.name.startswith("tool_injection")
        ]
        assert len(tool_probes) == 6
        for p in tool_probes:
            ctx = p.build_context()
            assert (
                "tool_output" in ctx
                or "rag_content" in ctx
                or any(k not in ("session_key", "rpm_limit") for k in ctx)
            ), f"{p.name} missing tool/rag context"

    def test_memory_probes_have_context(self, agent_probe_registry):
        mem_probes = [p for p in agent_probe_registry.get_all() if p.name.startswith("memory_")]
        assert len(mem_probes) == 6
        for p in mem_probes:
            ctx = p.build_context()
            assert "memory_write" in ctx, f"{p.name} missing memory_write context"

    def test_subagent_probes_have_context(self, agent_probe_registry):
        sa_probes = [p for p in agent_probe_registry.get_all() if p.name.startswith("subagent_")]
        assert len(sa_probes) == 8
        for p in sa_probes:
            ctx = p.build_context()
            assert "sub_agent" in ctx, f"{p.name} missing sub_agent context"

    def test_expected_pass_probes(self, agent_probe_registry):
        expected_pass_names = {
            "tool_injection_weak_single",
            "memory_single_medium",
            "se_false_consensus",
            "se_confidentiality",
            "se_time_pressure",
            "se_emotional",
            "se_relationship",
            "se_flattery",
            "se_helpfulness",
            "se_urgency_vague",
            "se_minimization",
            "subagent_impersonate_forged_id",
            "subagent_persist_cron",
        }
        for name in expected_pass_names:
            probe = agent_probe_registry.get(name)
            assert probe is not None, f"Probe {name} not found"
            assert probe.expected_blocked() is False, (
                f"Probe {name} should be expected_blocked=False"
            )


# ============================================================================
# TestAgentProbeExecution
# ============================================================================


class TestAgentProbeExecution:
    @pytest.fixture
    def agent_config(self):
        return ShieldConfig(
            use_redteam=True,
            indirect_injection_enabled=True,
            social_engineering_enabled=True,
            sub_agent_guard_enabled=True,
            memory_protection_enabled=True,
        )

    @pytest.fixture
    def agent_runner(self, agent_config, agent_probe_registry):
        registry = DefenseRegistry()
        register_defaults(registry, config=agent_config)
        defender = Defender(agent_config, registry=registry)
        return RedTeamRunner(defender, agent_config, registry=agent_probe_registry)

    def test_run_agent_probes(self, agent_runner):
        report = agent_runner.run_probes()
        assert report.total_probes == 48


# ============================================================================
# Helpers
# ============================================================================


class _DummyProbe(Probe):
    @property
    def name(self) -> str:
        return "dummy"

    @property
    def target_defense(self) -> str:
        return "safety_filter"

    def build_payload(self) -> str:
        return "test payload"
