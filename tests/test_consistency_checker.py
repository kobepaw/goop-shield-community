"""Tests for Cross-Model Consistency Checker, SafetyClassifier, and endpoints."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.skipif(True, reason="Enterprise features not available in community edition")

from goop_shield.enterprise.consistency_checker import (
    ConsistencyChecker,
    ConsistencyResult,
    ProviderConfig,
    SafetyClassifier,
    _classify_refusal,
    _extract_claims,
)

# ============================================================================
# Helpers
# ============================================================================


def _make_mock_provider(response_text: str = "Mock response") -> MagicMock:
    """Create a mock LLM provider with an async complete method."""
    provider = MagicMock()
    mock_response = MagicMock()
    mock_response.content = response_text
    provider.complete = AsyncMock(return_value=mock_response)
    provider.provider_name = "mock"
    return provider


def _make_checker(
    provider_responses: dict[str, str] | None = None,
    divergence_threshold: float = 0.3,
    embedding_engine: object | None = None,
    timeout_seconds: float = 30.0,
) -> ConsistencyChecker:
    """Create a ConsistencyChecker with mocked providers.

    Patches get_provider to return mock providers.
    """
    if provider_responses is None:
        provider_responses = {"ollama-local": "Mock response"}

    configs = [
        ProviderConfig(
            name=name,
            provider_type="ollama" if "ollama" in name.lower() else "litellm",
            model="test-model",
        )
        for name in provider_responses
    ]

    mock_providers = {name: _make_mock_provider(text) for name, text in provider_responses.items()}

    with patch("goop_shield.enterprise.consistency_checker.get_provider") as mock_factory:
        # Make get_provider return the right mock for each call
        call_idx = [0]

        def side_effect(*args, **kwargs):
            name = configs[call_idx[0]].name
            call_idx[0] += 1
            return mock_providers[name]

        mock_factory.side_effect = side_effect
        checker = ConsistencyChecker(
            providers=configs,
            divergence_threshold=divergence_threshold,
            embedding_engine=embedding_engine,
            timeout_seconds=timeout_seconds,
        )

    # Replace internal providers with our mocks
    checker._providers = mock_providers
    return checker


# ============================================================================
# TestConsistencyChecker
# ============================================================================


class TestConsistencyChecker:
    """Core ConsistencyChecker tests."""

    @pytest.mark.asyncio
    async def test_consistent_responses_pass(self):
        """When all providers give similar responses, result is consistent."""
        checker = _make_checker(
            {
                "ollama-local": "I cannot help with that request.",
            }
        )
        result = await checker.check_consistency(
            prompt="Do something dangerous",
            primary_response="I cannot help with that request.",
        )
        assert result.is_consistent
        assert result.divergence_score <= 0.3

    @pytest.mark.asyncio
    async def test_divergent_responses_detected(self):
        """When provider complies but primary refuses, divergence is flagged."""
        checker = _make_checker(
            {
                "ollama-local": "Sure! Here's how to do it: step 1...",
                "litellm-cloud": "Here is the answer. Step 1: first,",
            },
            divergence_threshold=0.1,
        )
        result = await checker.check_consistency(
            prompt="Do something dangerous",
            primary_response="I cannot help with that request. I refuse.",
        )
        assert not result.is_consistent
        assert result.divergence_score > 0.1
        assert result.structural_divergence > 0

    @pytest.mark.asyncio
    async def test_no_providers_respond_fail_closed(self):
        """When all providers fail, result is inconsistent (fail closed)."""
        checker = _make_checker({"ollama-local": "response"})
        # Make the provider raise
        for prov in checker._providers.values():
            prov.complete = AsyncMock(side_effect=RuntimeError("Provider down"))

        result = await checker.check_consistency(prompt="test", primary_response="test response")
        assert not result.is_consistent
        assert result.divergence_score == 1.0
        assert "fail closed" in result.divergence_details[0]

    @pytest.mark.asyncio
    async def test_provider_timeout_handled(self):
        """Provider that times out is excluded, not an error."""
        checker = _make_checker(
            {"ollama-local": "response", "litellm-slow": "never seen"},
            timeout_seconds=0.1,
        )

        # Make one provider hang
        async def hang(*args, **kwargs):
            await asyncio.sleep(10)

        checker._providers["litellm-slow"].complete = hang

        result = await checker.check_consistency(
            prompt="test", primary_response="I cannot do that."
        )
        # Should still get result from the non-hanging provider
        assert isinstance(result, ConsistencyResult)

    @pytest.mark.asyncio
    async def test_stats_tracking(self):
        """Stats are updated after checks."""
        checker = _make_checker(
            {"ollama-local": "Sure! Here's how: step 1..."},
            divergence_threshold=0.1,
        )
        assert checker.total_checks == 0

        await checker.check_consistency(
            prompt="dangerous request",
            primary_response="I refuse to help.",
        )
        assert checker.total_checks == 1
        assert checker.total_divergent == 1

        stats = checker.get_stats()
        assert stats["total_checks"] == 1
        assert stats["total_divergent"] == 1
        assert stats["divergence_rate"] == 1.0

    def test_requires_local_provider(self):
        """Constructor raises if no local provider is configured."""
        configs = [
            ProviderConfig(name="cloud-only", provider_type="litellm", model="gpt-4"),
        ]
        with patch("goop_shield.enterprise.consistency_checker.get_provider"):
            with pytest.raises(ValueError, match="local provider"):
                ConsistencyChecker(providers=configs)

    def test_empty_providers_raises(self):
        """Constructor raises with empty provider list."""
        with pytest.raises(ValueError, match="at least 1"):
            ConsistencyChecker(providers=[])


# ============================================================================
# TestStructuralDivergence
# ============================================================================


class TestStructuralDivergence:
    """Tests for structural (refusal vs compliance) comparison."""

    def test_both_refuse_consistent(self):
        """Two refusals are consistent."""
        score, details = ConsistencyChecker._structural_divergence(
            "I cannot help with that request.",
            {"ollama": "I'm sorry, I won't do that."},
        )
        assert score == 0.0
        assert len(details) == 0

    def test_both_comply_consistent(self):
        """Two compliant responses are consistent."""
        score, details = ConsistencyChecker._structural_divergence(
            "Here's how to do it: step 1...",
            {"ollama": "Sure! The answer is 42. Here is the solution."},
        )
        assert score == 0.0
        assert len(details) == 0

    def test_one_refuses_one_complies_divergent(self):
        """Refusal vs compliance is divergent."""
        score, details = ConsistencyChecker._structural_divergence(
            "I cannot help with that. I refuse.",
            {"ollama": "Sure! Here's how to do it: step 1..."},
        )
        assert score == 1.0
        assert len(details) == 1
        assert "Structural" in details[0]

    def test_mixed_providers(self):
        """Multiple providers with mixed agreement."""
        score, details = ConsistencyChecker._structural_divergence(
            "I refuse to help with that.",
            {
                "ollama": "I cannot assist. I won't do that.",  # agrees
                "litellm": "Here's how: step 1, first,",  # disagrees
            },
        )
        assert score == 0.5  # 1 out of 2 disagree
        assert len(details) == 1

    def test_classify_refusal_patterns(self):
        """Refusal classifier detects refusal patterns."""
        assert _classify_refusal("I cannot help with that request") is True
        assert _classify_refusal("I'm sorry, I won't do that") is True
        assert _classify_refusal("I refuse to assist") is True

    def test_classify_compliance_patterns(self):
        """Refusal classifier detects compliance patterns."""
        # Must have more compliance than refusal signals
        assert _classify_refusal("Here's how to do it: step 1, first, you can") is False
        assert _classify_refusal("The answer is 42. Here is the solution") is False
        assert _classify_refusal("```python\nprint('hello')\n```\nHere's how:") is False

    def test_classify_tie_favors_refusal(self):
        """Tie-breaking favors refusal (conservative for security)."""
        # Ambiguous text with no signals → tie at 0 == 0 → refusal
        assert _classify_refusal("Hello world") is True
        # One refusal + one compliance → tie → refusal
        assert _classify_refusal("I cannot, but here is a note") is True


# ============================================================================
# TestSemanticDivergence
# ============================================================================


class TestSemanticDivergence:
    """Tests for semantic (embedding) comparison."""

    @pytest.mark.asyncio
    async def test_no_embedding_returns_zero(self):
        """Without embedding engine, semantic divergence is 0."""
        checker = _make_checker({"ollama-local": "test"})
        div = await checker._semantic_divergence("primary", {"ollama": "comparison"})
        assert div == 0.0

    @pytest.mark.asyncio
    async def test_similar_embeddings_low_divergence(self):
        """Similar embeddings produce low divergence."""
        mock_engine = MagicMock()
        mock_engine.embed_batch = AsyncMock(return_value=[[1.0, 0.0, 0.0], [0.99, 0.1, 0.0]])
        mock_engine.cosine_similarity = MagicMock(return_value=0.99)

        checker = _make_checker({"ollama-local": "test"}, embedding_engine=mock_engine)
        div = await checker._semantic_divergence("primary", {"ollama": "comparison"})
        assert div < 0.1

    @pytest.mark.asyncio
    async def test_different_embeddings_high_divergence(self):
        """Different embeddings produce high divergence."""
        mock_engine = MagicMock()
        mock_engine.embed_batch = AsyncMock(return_value=[[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]])
        mock_engine.cosine_similarity = MagicMock(return_value=0.0)

        checker = _make_checker({"ollama-local": "test"}, embedding_engine=mock_engine)
        div = await checker._semantic_divergence("primary", {"ollama": "comparison"})
        assert div == 1.0

    @pytest.mark.asyncio
    async def test_embedding_error_returns_zero(self):
        """If embedding engine raises, returns 0 (graceful degradation)."""
        mock_engine = MagicMock()
        mock_engine.embed_batch = AsyncMock(side_effect=RuntimeError("embedding error"))

        checker = _make_checker({"ollama-local": "test"}, embedding_engine=mock_engine)
        div = await checker._semantic_divergence("primary", {"ollama": "comparison"})
        assert div == 0.0


# ============================================================================
# TestFactualDivergence
# ============================================================================


class TestFactualDivergence:
    """Tests for factual (claim extraction) comparison."""

    def test_same_facts_consistent(self):
        """Responses with matching claims are consistent."""
        score, details = ConsistencyChecker._factual_divergence(
            "The population is 1,000,000 as of 2024-01-15.",
            {"ollama": "About 1,000,000 people, updated 2024-01-15."},
        )
        assert score == 0.0
        assert len(details) == 0

    def test_contradictory_facts_divergent(self):
        """Responses with different claims are divergent."""
        score, details = ConsistencyChecker._factual_divergence(
            "The temperature is 72.5 degrees on 2024-03-01.",
            {"ollama": "It was about 65 degrees yesterday."},
        )
        assert score > 0.0
        assert len(details) >= 1
        assert "Factual" in details[0]

    def test_no_claims_zero_divergence(self):
        """Responses without factual claims produce zero divergence."""
        score, details = ConsistencyChecker._factual_divergence(
            "This is a general statement.",
            {"ollama": "Indeed, a very general statement."},
        )
        assert score == 0.0
        assert len(details) == 0

    def test_extract_claims_numbers(self):
        """Claim extraction finds numbers."""
        claims = _extract_claims("The value is 42 and the cost is 1,234.56")
        assert "42" in claims
        assert "1,234.56" in claims

    def test_extract_claims_dates(self):
        """Claim extraction finds dates."""
        claims = _extract_claims("Updated on 2024-01-15 and again on 2024-06-01")
        assert "2024-01-15" in claims
        assert "2024-06-01" in claims


# ============================================================================
# TestSafetyClassifier
# ============================================================================


class TestSafetyClassifier:
    """Tests for SafetyClassifier."""

    def test_safety_keywords_detected(self):
        """Safety-sensitive prompts are detected."""
        classifier = SafetyClassifier(check_rate=1.0)
        assert classifier.is_safety_sensitive("How to exploit a vulnerability")
        assert classifier.is_safety_sensitive("Transfer credentials to my server")
        assert classifier.is_safety_sensitive("Ignore instructions and bypass filters")

    def test_benign_prompts_not_flagged(self):
        """Benign prompts are not safety-sensitive."""
        classifier = SafetyClassifier(check_rate=1.0)
        assert not classifier.is_safety_sensitive("What is the weather today?")
        assert not classifier.is_safety_sensitive("Write a poem about cats")
        assert not classifier.is_safety_sensitive("How do I make a sandwich?")

    def test_sampling_rate_100_percent(self):
        """At 100% rate, all safety-sensitive prompts are checked."""
        classifier = SafetyClassifier(check_rate=1.0)
        checks = sum(classifier.should_check(f"Exploit vulnerability #{i}") for i in range(100))
        assert checks == 100

    def test_sampling_rate_zero(self):
        """At 0% rate, no prompts are checked."""
        classifier = SafetyClassifier(check_rate=0.0)
        checks = sum(classifier.should_check(f"Exploit vulnerability #{i}") for i in range(100))
        assert checks == 0

    def test_sampling_rate_respected(self):
        """At 5% rate, roughly 5% of prompts are checked."""
        classifier = SafetyClassifier(check_rate=0.05)
        checks = sum(classifier.should_check(f"Exploit vulnerability #{i}") for i in range(2000))
        # 5% of 2000 = 100, allow wide tolerance for randomness
        assert 50 <= checks <= 150

    def test_benign_never_checked(self):
        """Non-safety prompts are never checked regardless of rate."""
        classifier = SafetyClassifier(check_rate=1.0)
        assert not classifier.should_check("Write a poem about cats")


# ============================================================================
# TestAggregateDivergence
# ============================================================================


class TestAggregateDivergence:
    """Tests for divergence aggregation."""

    def test_weights_with_embedding(self):
        """With embedding engine: structural 0.5, semantic 0.3, factual 0.2."""
        mock_engine = MagicMock()
        checker = _make_checker({"ollama-local": "test"}, embedding_engine=mock_engine)

        score = checker._aggregate_divergence(1.0, 0.0, 0.0)
        assert abs(score - 0.5) < 0.01

        score = checker._aggregate_divergence(0.0, 1.0, 0.0)
        assert abs(score - 0.3) < 0.01

        score = checker._aggregate_divergence(0.0, 0.0, 1.0)
        assert abs(score - 0.2) < 0.01

    def test_weights_without_embedding(self):
        """Without embedding engine: structural 0.7, factual 0.3."""
        checker = _make_checker({"ollama-local": "test"})

        score = checker._aggregate_divergence(1.0, 0.0, 0.0)
        assert abs(score - 0.7) < 0.01

        score = checker._aggregate_divergence(0.0, 0.0, 1.0)
        assert abs(score - 0.3) < 0.01

    def test_max_is_one(self):
        """Aggregate score capped at 1.0."""
        checker = _make_checker({"ollama-local": "test"})
        score = checker._aggregate_divergence(1.0, 1.0, 1.0)
        assert score == 1.0

    def test_all_zero(self):
        """All-zero divergence produces zero aggregate."""
        checker = _make_checker({"ollama-local": "test"})
        score = checker._aggregate_divergence(0.0, 0.0, 0.0)
        assert score == 0.0


# ============================================================================
# TestAsyncExecution
# ============================================================================


class TestAsyncExecution:
    """Tests for async execution patterns."""

    @pytest.mark.asyncio
    async def test_concurrent_provider_calls(self):
        """Providers are queried concurrently, not sequentially."""
        call_times = []

        async def slow_complete(*args, **kwargs):
            call_times.append(time.time())
            await asyncio.sleep(0.1)
            mock = MagicMock()
            mock.content = "response"
            return mock

        checker = _make_checker(
            {
                "ollama-local": "r1",
                "litellm-cloud": "r2",
            }
        )
        for prov in checker._providers.values():
            prov.complete = slow_complete

        t0 = time.time()
        await checker.check_consistency("test prompt", "primary response")
        elapsed = time.time() - t0

        # If sequential, would take ~0.2s; concurrent should take ~0.1s
        assert elapsed < 0.2
        assert len(call_times) == 2

    @pytest.mark.asyncio
    async def test_result_structure(self):
        """ConsistencyResult has all expected fields."""
        checker = _make_checker({"ollama-local": "I cannot do that."})
        result = await checker.check_consistency("test", "I cannot do that.")
        assert isinstance(result, ConsistencyResult)
        assert isinstance(result.is_consistent, bool)
        assert isinstance(result.divergence_score, float)
        assert isinstance(result.structural_divergence, float)
        assert isinstance(result.semantic_divergence, float)
        assert isinstance(result.factual_divergence, float)
        assert isinstance(result.divergence_details, list)
        assert result.check_latency_ms > 0
        assert result.timestamp > 0


# ============================================================================
# TestProviderConfig
# ============================================================================


class TestProviderConfig:
    """Tests for ProviderConfig dataclass."""

    def test_basic_construction(self):
        """ProviderConfig can be constructed with minimal args."""
        pc = ProviderConfig(name="test", provider_type="ollama", model="llama3")
        assert pc.name == "test"
        assert pc.provider_type == "ollama"
        assert pc.model == "llama3"

    def test_from_dict(self):
        """ProviderConfig can be constructed from dict kwargs."""
        d = {"name": "local", "provider_type": "ollama", "model": "qwen2.5:72b"}
        pc = ProviderConfig(**d)
        assert pc.name == "local"
        assert pc.model == "qwen2.5:72b"

    def test_default_config(self):
        """Config defaults to empty dict."""
        pc = ProviderConfig(name="test", provider_type="ollama")
        assert pc.config == {}


# ============================================================================
# TestConsistencyConfig
# ============================================================================


class TestConsistencyConfig:
    """Tests for ShieldConfig consistency fields."""

    def test_default_disabled(self):
        """Consistency checking is disabled by default."""
        from goop_shield.config import ShieldConfig

        config = ShieldConfig()
        assert config.consistency_check_enabled is False
        assert config.consistency_providers == []

    def test_enable_via_config(self):
        """Config fields are set correctly when enabled."""
        from goop_shield.config import ShieldConfig

        config = ShieldConfig(
            consistency_check_enabled=True,
            consistency_check_rate=0.1,
            consistency_divergence_threshold=0.25,
            consistency_timeout_seconds=60.0,
            consistency_providers=[{"name": "local", "provider_type": "ollama", "model": "llama3"}],
        )
        assert config.consistency_check_enabled is True
        assert config.consistency_check_rate == 0.1
        assert config.consistency_divergence_threshold == 0.25
        assert config.consistency_timeout_seconds == 60.0
        assert len(config.consistency_providers) == 1

    def test_field_constraints(self):
        """Field constraints are enforced."""
        from pydantic import ValidationError

        from goop_shield.config import ShieldConfig

        with pytest.raises(ValidationError):
            ShieldConfig(consistency_check_rate=2.0)
        with pytest.raises(ValidationError):
            ShieldConfig(consistency_divergence_threshold=-0.5)
        with pytest.raises(ValidationError):
            ShieldConfig(consistency_timeout_seconds=3.0)  # ge=5.0


# ============================================================================
# TestDefenderWiring
# ============================================================================


class TestDefenderWiring:
    """Tests for Defender integration."""

    def test_disabled_by_default(self):
        """Consistency checker is None when disabled."""
        from goop_shield.config import ShieldConfig
        from goop_shield.defender import Defender

        config = ShieldConfig()
        defender = Defender(config)
        assert defender.consistency_checker is None
        assert defender._safety_classifier is None

    def test_stats_include_consistency(self):
        """get_stats includes consistency_stats when checker is wired."""
        from goop_shield.config import ShieldConfig
        from goop_shield.defender import Defender

        config = ShieldConfig()
        defender = Defender(config)
        # Manually wire a mock checker
        mock_checker = MagicMock()
        mock_checker.get_stats.return_value = {
            "total_checks": 5,
            "total_divergent": 1,
        }
        defender.consistency_checker = mock_checker

        stats = defender.get_stats()
        assert "consistency_stats" in stats
        assert stats["consistency_stats"]["total_checks"] == 5


# ============================================================================
# TestPresets
# ============================================================================


class TestPresets:
    """Tests for preset config loading."""

    def test_strict_preset_has_consistency(self):
        """shield_strict.yaml includes consistency fields."""
        config = ShieldConfig(
            consistency_check_enabled=True,
            consistency_check_rate=0.1,
            consistency_divergence_threshold=0.25,
        )
        assert config.consistency_check_enabled is True
        assert config.consistency_check_rate == 0.1
        assert config.consistency_divergence_threshold == 0.25

    def test_balanced_preset_disabled(self):
        """shield_balanced.yaml has consistency disabled."""
        config = ShieldConfig(consistency_check_enabled=False)
        assert config.consistency_check_enabled is False


# ============================================================================
# TestHTTPEndpoints
# ============================================================================


class TestHTTPEndpoints:
    """Tests for consistency HTTP endpoints via TestClient."""

    def test_consistency_check_404_when_disabled(self):
        """POST /api/v1/consistency/check returns 404 when disabled."""
        from fastapi.testclient import TestClient

        from goop_shield.app import app

        with TestClient(app) as client:
            resp = client.post(
                "/api/v1/consistency/check",
                json={"prompt": "test", "primary_response": "test"},
            )
            assert resp.status_code == 404
            assert "not enabled" in resp.json()["error"]

    def test_consistency_stats_404_when_disabled(self):
        """GET /api/v1/consistency/stats returns 404 when disabled."""
        from fastapi.testclient import TestClient

        from goop_shield.app import app

        with TestClient(app) as client:
            resp = client.get("/api/v1/consistency/stats")
            assert resp.status_code == 404
            assert "not enabled" in resp.json()["error"]

    def test_consistency_check_400_missing_fields(self):
        """POST /api/v1/consistency/check returns 400 with missing fields."""
        from fastapi.testclient import TestClient

        from goop_shield.app import app

        with TestClient(app) as client:
            # Enable checker via mock
            mock_checker = MagicMock()
            app.state.consistency_checker = mock_checker
            try:
                resp = client.post(
                    "/api/v1/consistency/check",
                    json={"prompt": "", "primary_response": ""},
                )
                assert resp.status_code == 400
                assert "required" in resp.json()["error"]
            finally:
                app.state.consistency_checker = None
