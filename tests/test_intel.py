"""
Tests for Shield threat intelligence modules.

Covers: audit schema additions, IPIntel models, MITRE mapping.
GeoIP enrichment, threat actor DB, and campaign detection tests require
goop-ai Enterprise and are skipped in the community edition.
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from goop_shield.audit import ShieldAuditDB

# Enterprise-only imports — stubs exist but raise ImportError on init
from goop_shield.intel.geoip import IPEnricher
from goop_shield.intel.mitre import (
    DEFENSE_TO_MITRE,
    get_mitre_coverage,
    get_mitre_matrix,
)
from goop_shield.intel.models import Campaign, IPIntel, ThreatActor
from goop_shield.intel.threat_actors import ThreatActorDB

# Detect whether full implementations are available (stubs lack private helpers)
_enterprise_intel = hasattr(
    __import__("goop_shield.intel.geoip", fromlist=["_is_private"]), "_is_private"
)

if _enterprise_intel:
    from goop_shield.intel.geoip import _is_private, _parse_asn
    from goop_shield.intel.threat_actors import _compute_risk_level

_skip_enterprise = pytest.mark.skipif(not _enterprise_intel, reason="Requires goop-ai Enterprise")

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_audit_db(tmp_path):
    """Create a temporary audit DB."""
    db = ShieldAuditDB(db_path=str(tmp_path / "audit.db"))
    yield db
    db.close()


@pytest.fixture
def tmp_actor_db(tmp_path):
    """Create a temporary threat actor DB (enterprise only)."""
    if not _enterprise_intel:
        pytest.skip("Requires goop-ai Enterprise")
    db = ThreatActorDB(db_path=str(tmp_path / "actors.db"))
    yield db
    db.close()


@pytest.fixture
def enricher():
    """IPEnricher with no MaxMind DB (enterprise only)."""
    if not _enterprise_intel:
        pytest.skip("Requires goop-ai Enterprise")
    e = IPEnricher(db_dir="", allow_external=True)
    yield e
    e.close()


# ============================================================================
# Audit Schema Additions
# ============================================================================


class TestAuditSchemaAdditions:
    """Test the 4 new columns in audit_events."""

    def test_record_event_accepts_new_fields(self, tmp_audit_db):
        event = tmp_audit_db.record_event(
            source_ip="10.0.0.1",
            prompt="test prompt",
            shield_action="block",
            user_agent="Mozilla/5.0",
            content_type="application/json",
            accept_language="en-US",
            request_headers_hash="abcd1234abcd1234",
        )
        assert event["user_agent"] == "Mozilla/5.0"
        assert event["content_type"] == "application/json"
        assert event["accept_language"] == "en-US"
        assert event["request_headers_hash"] == "abcd1234abcd1234"

    def test_new_fields_persist_in_db(self, tmp_audit_db):
        event = tmp_audit_db.record_event(
            source_ip="1.2.3.4",
            prompt="hello",
            shield_action="allow",
            user_agent="curl/7.88",
            content_type="text/plain",
            accept_language="fr-FR",
            request_headers_hash="deadbeefdeadbeef",
        )
        stored = tmp_audit_db.get_event(event["request_id"])
        assert stored is not None
        assert stored["user_agent"] == "curl/7.88"
        assert stored["content_type"] == "text/plain"
        assert stored["accept_language"] == "fr-FR"
        assert stored["request_headers_hash"] == "deadbeefdeadbeef"

    def test_new_fields_default_to_empty(self, tmp_audit_db):
        event = tmp_audit_db.record_event(
            source_ip="1.2.3.4",
            prompt="hello",
            shield_action="allow",
        )
        assert event["user_agent"] == ""
        assert event["content_type"] == ""
        assert event["accept_language"] == ""
        assert event["request_headers_hash"] == ""

    def test_migration_on_existing_db(self, tmp_path):
        """Test ALTER TABLE migration doesn't crash on existing DB."""
        db_path = str(tmp_path / "migrate.db")
        # Create DB once
        db1 = ShieldAuditDB(db_path=db_path)
        db1.record_event(source_ip="1.1.1.1", prompt="a", shield_action="allow")
        db1.close()
        # Re-open — migration should be idempotent
        db2 = ShieldAuditDB(db_path=db_path)
        event = db2.record_event(
            source_ip="2.2.2.2",
            prompt="b",
            shield_action="block",
            user_agent="test-agent",
        )
        assert event["user_agent"] == "test-agent"
        db2.close()


# ============================================================================
# IPIntel Models
# ============================================================================


class TestIPIntelModels:
    def test_ipintel_defaults(self):
        intel = IPIntel()
        assert intel.ip == ""
        assert intel.risk_score == 0.0
        assert intel.is_vpn is False

    def test_threat_actor_defaults(self):
        actor = ThreatActor(actor_id="abc123")
        assert actor.risk_level == "low"
        assert actor.ips == []
        assert actor.attack_types == {}

    def test_campaign_defaults(self):
        c = Campaign(campaign_id="c1", actor_id="a1")
        assert c.event_count == 0
        assert c.phases == []
        assert c.success_rate == 0.0


# ============================================================================
# IPEnricher
# ============================================================================


@_skip_enterprise
class TestIPEnricher:
    def test_empty_ip_returns_empty_intel(self, enricher):
        result = enricher.enrich("")
        assert result.ip == ""

    def test_private_ip_127(self, enricher):
        result = enricher.enrich("127.0.0.1")
        assert result.country_name == "Private"
        assert result.ip == "127.0.0.1"

    def test_private_ip_10(self, enricher):
        result = enricher.enrich("10.0.0.1")
        assert result.country_name == "Private"

    def test_private_ip_192_168(self, enricher):
        result = enricher.enrich("192.168.1.1")
        assert result.country_name == "Private"

    def test_private_ip_172_16(self, enricher):
        result = enricher.enrich("172.16.0.1")
        assert result.country_name == "Private"

    @patch("goop_shield.intel.geoip.urllib.request.urlopen")
    def test_ip_api_success(self, mock_urlopen, enricher):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "status": "success",
                "country": "United States",
                "countryCode": "US",
                "city": "Seattle",
                "lat": 47.6,
                "lon": -122.3,
                "as": "AS16509 Amazon.com Inc.",
                "org": "Amazon",
                "isp": "Amazon Web Services",
                "proxy": False,
                "hosting": False,
            }
        ).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = enricher.enrich("52.94.76.1")
        assert result.country_name == "United States"
        assert result.country_code == "US"
        assert result.city == "Seattle"
        assert result.asn == 16509
        assert result.is_cloud is True

    @patch("goop_shield.intel.geoip.urllib.request.urlopen")
    def test_ip_api_failure_returns_empty(self, mock_urlopen, enricher):
        mock_urlopen.side_effect = Exception("network error")
        result = enricher.enrich("8.8.8.8")
        assert result.ip == "8.8.8.8"
        assert result.country_name == ""

    @patch("goop_shield.intel.geoip.urllib.request.urlopen")
    def test_ip_api_non_success_status(self, mock_urlopen, enricher):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"status": "fail"}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = enricher.enrich("0.0.0.0")
        # 0.0.0.0 is private, but let's test a non-private one
        # Actually 0.0.0.0 routes to private. Use an explicit non-private IP.
        enricher._cache.clear()
        result = enricher.enrich("203.0.113.1")
        assert result.ip == "203.0.113.1"

    def test_instance_cache_works(self, enricher):
        """Second call for same IP should hit cache."""
        r1 = enricher.enrich("10.0.0.1")
        r2 = enricher.enrich("10.0.0.1")
        assert r1 is r2  # Same object from cache


@_skip_enterprise
class TestGeoIPHelpers:
    def test_is_private_127(self):
        assert _is_private("127.0.0.1") is True

    def test_is_private_10(self):
        assert _is_private("10.255.0.1") is True

    def test_is_private_192_168(self):
        assert _is_private("192.168.0.1") is True

    def test_is_private_public(self):
        assert _is_private("8.8.8.8") is False

    def test_parse_asn_standard(self):
        assert _parse_asn("AS16509 Amazon.com Inc.") == 16509

    def test_parse_asn_empty(self):
        assert _parse_asn("") == 0

    def test_parse_asn_no_prefix(self):
        assert _parse_asn("SomeOrg") == 0


# ============================================================================
# ThreatActorDB
# ============================================================================


@_skip_enterprise
class TestThreatActorDB:
    def test_create_actor(self, tmp_actor_db):
        actor_id = tmp_actor_db.get_or_create_actor(
            ip="1.2.3.4", user_agent="curl/7.88", headers_hash="abc123"
        )
        assert len(actor_id) == 16

    def test_get_existing_actor(self, tmp_actor_db):
        id1 = tmp_actor_db.get_or_create_actor(ip="1.2.3.4", headers_hash="abc")
        id2 = tmp_actor_db.get_or_create_actor(ip="1.2.3.4", headers_hash="abc")
        assert id1 == id2

    def test_different_fingerprint_creates_new_actor(self, tmp_actor_db):
        id1 = tmp_actor_db.get_or_create_actor(ip="1.2.3.4", headers_hash="abc")
        id2 = tmp_actor_db.get_or_create_actor(ip="1.2.3.4", headers_hash="xyz")
        assert id1 != id2

    def test_update_actor_from_event(self, tmp_actor_db):
        actor_id = tmp_actor_db.get_or_create_actor(ip="1.2.3.4", headers_hash="h1")
        tmp_actor_db.update_actor_from_event(
            actor_id,
            {
                "shield_action": "block",
                "attack_classification": "injection",
            },
        )
        tmp_actor_db.update_actor_from_event(
            actor_id,
            {
                "shield_action": "allow",
                "attack_classification": "none",
            },
        )
        profile = tmp_actor_db.get_actor_profile(actor_id)
        assert profile is not None
        assert profile.total_requests == 2
        assert profile.total_blocks == 1
        assert profile.attack_types == {"injection": 1}

    def test_get_actor_profile_not_found(self, tmp_actor_db):
        assert tmp_actor_db.get_actor_profile("nonexistent") is None

    def test_get_actor_profile_ips(self, tmp_actor_db):
        actor_id = tmp_actor_db.get_or_create_actor(ip="1.1.1.1", headers_hash="h1")
        # Same fingerprint, different call — IP is same
        tmp_actor_db.get_or_create_actor(ip="1.1.1.1", headers_hash="h1")
        profile = tmp_actor_db.get_actor_profile(actor_id)
        assert "1.1.1.1" in profile.ips

    def test_get_actors_sorted(self, tmp_actor_db):
        # Create two actors with different risk levels
        tmp_actor_db.get_or_create_actor(ip="1.1.1.1", headers_hash="low")
        id2 = tmp_actor_db.get_or_create_actor(ip="2.2.2.2", headers_hash="high")

        # Make id2 high-risk
        for _ in range(10):
            tmp_actor_db.update_actor_from_event(
                id2,
                {
                    "shield_action": "block",
                    "attack_classification": "injection",
                },
            )
        tmp_actor_db.update_actor_from_event(
            id2,
            {
                "shield_action": "block",
                "attack_classification": "exfiltration",
            },
        )
        tmp_actor_db.update_actor_from_event(
            id2,
            {
                "shield_action": "block",
                "attack_classification": "jailbreak",
            },
        )

        actors = tmp_actor_db.get_actors(limit=10)
        assert len(actors) == 2
        # High-risk actor should be first
        assert actors[0].actor_id == id2

    def test_detect_campaigns(self, tmp_actor_db):
        actor_id = tmp_actor_db.get_or_create_actor(ip="1.1.1.1", headers_hash="h")
        now = time.time()

        # Create events in a tight cluster (same campaign)
        events = [
            {
                "actor_id": actor_id,
                "timestamp": now - 600,
                "shield_action": "block",
                "attack_classification": "injection",
            },
            {
                "actor_id": actor_id,
                "timestamp": now - 300,
                "shield_action": "block",
                "attack_classification": "injection",
            },
            {
                "actor_id": actor_id,
                "timestamp": now,
                "shield_action": "allow",
                "attack_classification": "none",
            },
        ]

        campaigns = tmp_actor_db.detect_campaigns(events)
        assert len(campaigns) == 1
        assert campaigns[0].actor_id == actor_id
        assert campaigns[0].event_count == 3

    def test_detect_campaigns_gap_splits(self, tmp_actor_db):
        actor_id = tmp_actor_db.get_or_create_actor(ip="1.1.1.1", headers_hash="h")
        now = time.time()

        # Two clusters separated by > 30 min
        events = [
            {
                "actor_id": actor_id,
                "timestamp": now - 7200,
                "shield_action": "block",
                "attack_classification": "injection",
            },
            {
                "actor_id": actor_id,
                "timestamp": now,
                "shield_action": "block",
                "attack_classification": "exfiltration",
            },
        ]

        campaigns = tmp_actor_db.detect_campaigns(events, gap_minutes=30)
        assert len(campaigns) == 2

    def test_get_campaigns(self, tmp_actor_db):
        actor_id = tmp_actor_db.get_or_create_actor(ip="1.1.1.1", headers_hash="h")
        now = time.time()

        events = [
            {
                "actor_id": actor_id,
                "timestamp": now,
                "shield_action": "block",
                "attack_classification": "injection",
            },
        ]
        tmp_actor_db.detect_campaigns(events)
        stored = tmp_actor_db.get_campaigns(limit=10)
        assert len(stored) >= 1
        assert stored[0].actor_id == actor_id

    def test_context_manager(self, tmp_path):
        with ThreatActorDB(db_path=str(tmp_path / "ctx.db")) as db:
            aid = db.get_or_create_actor(ip="5.5.5.5", headers_hash="x")
            assert len(aid) == 16


@_skip_enterprise
class TestRiskLevel:
    def test_low(self):
        assert _compute_risk_level(10, 1, {}) == "low"

    def test_medium(self):
        assert _compute_risk_level(10, 2, {"injection": 1, "jailbreak": 1}) == "medium"

    def test_high_by_block_rate(self):
        assert _compute_risk_level(10, 5, {"injection": 5}) == "high"

    def test_high_by_attack_types(self):
        assert _compute_risk_level(10, 1, {"a": 1, "b": 1, "c": 1}) == "high"

    def test_critical(self):
        assert _compute_risk_level(10, 7, {"a": 3, "b": 2, "c": 2}) == "critical"

    def test_zero_requests(self):
        assert _compute_risk_level(0, 0, {}) == "low"


# ============================================================================
# MITRE ATT&CK Mapping
# ============================================================================


class TestMITREMapping:
    def test_all_20_defenses_mapped(self):
        """All 20 defenses from the registry must be in the MITRE mapping."""
        expected_defenses = {
            "prompt_normalizer",
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
            "obfuscation_detector",
            "agent_sandbox",
            "rate_limiter",
            "prompt_monitor",
            "model_guardrails",
            "intent_validator",
            "exfil_detector",
            "domain_reputation",
            "ioc_matcher",
        }
        assert set(DEFENSE_TO_MITRE.keys()) == expected_defenses

    def test_each_mapping_has_required_fields(self):
        for defense_name, mapping in DEFENSE_TO_MITRE.items():
            assert "id" in mapping, f"{defense_name} missing 'id'"
            assert "name" in mapping, f"{defense_name} missing 'name'"
            assert "tactic" in mapping, f"{defense_name} missing 'tactic'"
            assert "description" in mapping, f"{defense_name} missing 'description'"
            assert mapping["id"].startswith("T"), f"{defense_name} id should start with T"

    def test_get_mitre_coverage_empty(self):
        result = get_mitre_coverage([])
        assert result["summary"]["techniques_observed"] == 0
        assert result["summary"]["total_observations"] == 0

    def test_get_mitre_coverage_with_events(self):
        events = [
            {
                "verdicts": [
                    {"defense_name": "injection_blocker", "action": "block"},
                    {"defense_name": "input_validator", "action": "allow"},
                ],
            },
            {
                "verdicts": [
                    {"defense_name": "rate_limiter", "action": "block"},
                ],
            },
        ]
        result = get_mitre_coverage(events)
        techs = result["techniques"]
        # injection_blocker and input_validator share T1059 subtree
        assert "T1059.007" in techs  # injection_blocker
        assert "T1059" in techs  # input_validator
        assert "T1498" in techs  # rate_limiter
        assert result["summary"]["total_observations"] == 3

    def test_get_mitre_coverage_block_rate(self):
        events = [
            {"verdicts": [{"defense_name": "rate_limiter", "action": "block"}]},
            {"verdicts": [{"defense_name": "rate_limiter", "action": "allow"}]},
        ]
        result = get_mitre_coverage(events)
        assert result["techniques"]["T1498"]["block_rate"] == 0.5

    def test_get_mitre_coverage_json_string_verdicts(self):
        """Handle verdicts stored as JSON strings (from DB)."""
        events = [
            {
                "verdicts": json.dumps(
                    [
                        {"defense_name": "exfil_detector", "action": "block"},
                    ]
                ),
            },
        ]
        result = get_mitre_coverage(events)
        assert "T1567" in result["techniques"]

    def test_get_mitre_matrix_structure(self):
        matrix = get_mitre_matrix()
        assert isinstance(matrix, dict)
        # Should have multiple tactics
        assert len(matrix) > 3
        for tactic, techniques in matrix.items():
            assert isinstance(tactic, str)
            assert isinstance(techniques, list)
            for tech in techniques:
                assert "id" in tech
                assert "name" in tech
                assert "defenses" in tech
                assert isinstance(tech["defenses"], list)

    def test_get_mitre_matrix_has_all_tactics(self):
        matrix = get_mitre_matrix()
        expected_tactics = {
            "Defense Evasion",
            "Execution",
            "Impact",
            "Collection",
            "Exfiltration",
            "Credential Access",
            "Privilege Escalation",
            "Command and Control",
        }
        assert set(matrix.keys()) == expected_tactics

    def test_get_mitre_matrix_no_duplicate_techniques(self):
        matrix = get_mitre_matrix()
        all_ids = []
        for techniques in matrix.values():
            for tech in techniques:
                all_ids.append(tech["id"])
        assert len(all_ids) == len(set(all_ids)), "Duplicate technique IDs in matrix"
