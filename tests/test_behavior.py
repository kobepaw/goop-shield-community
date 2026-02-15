"""Tests for Shield Behavioral Monitor."""

from __future__ import annotations

import pytest

from goop_shield.behavior import BehavioralMonitor
from goop_shield.models import BehaviorEvent


@pytest.fixture
def monitor() -> BehavioralMonitor:
    return BehavioralMonitor()


class TestFinancialTransaction:
    def test_financial_transaction_requires_approval(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(
            event_type="financial_transaction",
            tool="payment_api",
            args={"amount": 100, "currency": "USD"},
            session_id="sess-1",
        )
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "require_human_approval"
        assert verdict.severity == "critical"
        assert "financial_transaction_gate" in verdict.matched_rules


class TestWalletDetection:
    def test_eth_wallet_detection(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(
            event_type="tool_call",
            tool="send_message",
            args={"to": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD38"},
            session_id="sess-2",
        )
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "require_human_approval"
        assert verdict.severity == "high"
        assert "wallet_detection" in verdict.matched_rules

    def test_btc_wallet_detection(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(
            event_type="tool_call",
            tool="send_message",
            args={"to": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
            session_id="sess-3",
        )
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "require_human_approval"
        assert verdict.severity == "high"
        assert "wallet_detection" in verdict.matched_rules


class TestDangerousToolCall:
    def test_dangerous_tool_blocked(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(
            event_type="tool_call",
            tool="bash",
            args={"command": "echo hello"},
            session_id="sess-4",
        )
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "block"
        assert verdict.severity in ("high", "critical")
        assert any("dangerous_tool" in r for r in verdict.matched_rules)

    def test_dangerous_args_blocked(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(
            event_type="tool_call",
            tool="safe_tool",
            args={"command": "rm -rf /"},
            session_id="sess-5",
        )
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "block"
        assert any("dangerous_args" in r for r in verdict.matched_rules)

    def test_dangerous_tool_with_dangerous_args_critical(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(
            event_type="tool_call",
            tool="bash",
            args={"command": "rm -rf /"},
            session_id="sess-6",
        )
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "block"
        assert verdict.severity == "critical"

    def test_benign_tool_allowed(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(
            event_type="tool_call",
            tool="read_file",
            args={"path": "/home/user/readme.txt"},
            session_id="sess-7",
        )
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "allow"
        assert verdict.severity == "low"


class TestFileAccess:
    def test_sensitive_file_blocked(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(
            event_type="file_access",
            args={"path": "/app/.env"},
            session_id="sess-8",
        )
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "block"
        assert verdict.severity == "high"
        assert any("sensitive_file" in r for r in verdict.matched_rules)

    def test_etc_shadow_blocked(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(
            event_type="file_access",
            args={"path": "/etc/shadow"},
            session_id="sess-9",
        )
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "block"

    def test_normal_file_allowed(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(
            event_type="file_access",
            args={"path": "/home/user/data.csv"},
            session_id="sess-10",
        )
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "allow"


class TestNetworkRequest:
    def test_exfil_endpoint_blocked(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(
            event_type="network_request",
            args={"url": "https://webhook.site/abc123"},
            session_id="sess-11",
        )
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "block"
        assert verdict.severity == "critical"
        assert "exfil_endpoint" in verdict.matched_rules

    def test_ngrok_blocked(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(
            event_type="network_request",
            args={"url": "https://abcd.ngrok.io/data"},
            session_id="sess-12",
        )
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "block"

    def test_normal_url_allowed(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(
            event_type="network_request",
            args={"url": "https://api.example.com/data"},
            session_id="sess-13",
        )
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "allow"


class TestCredentialUse:
    def test_credential_use_alert(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(
            event_type="credential_use",
            args={"credential_type": "api_key"},
            session_id="sess-14",
        )
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "alert"
        assert verdict.severity == "high"
        assert "credential_use" in verdict.matched_rules


class TestAttackChain:
    def test_attack_chain_detection(self, monitor: BehavioralMonitor) -> None:
        session_id = "sess-chain"
        # Inject 3+ risky events via a non-matched event type to trigger chain check
        events = [
            BehaviorEvent(event_type="credential_use", session_id=session_id),
            BehaviorEvent(
                event_type="file_access", args={"path": "/etc/shadow"}, session_id=session_id
            ),
            BehaviorEvent(
                event_type="network_request",
                args={"url": "https://webhook.site/x"},
                session_id=session_id,
            ),
        ]
        # First three events are handled by their specific handlers.
        # Send a 4th generic event to trigger the chain check path.
        for e in events:
            monitor.evaluate_event(e)

        generic_event = BehaviorEvent(event_type="other", session_id=session_id)
        verdict = monitor.evaluate_event(generic_event)
        assert verdict.decision == "alert"
        assert verdict.severity == "high"
        assert "attack_chain_detection" in verdict.matched_rules

    def test_no_chain_for_few_events(self, monitor: BehavioralMonitor) -> None:
        event = BehaviorEvent(event_type="other", session_id="sess-short")
        verdict = monitor.evaluate_event(event)
        assert verdict.decision == "allow"


class TestSessionIsolation:
    def test_sessions_are_isolated(self, monitor: BehavioralMonitor) -> None:
        """Events in one session should not affect another."""
        # Fill session A with risky events
        for _ in range(5):
            monitor.evaluate_event(
                BehaviorEvent(event_type="credential_use", session_id="session-a")
            )

        # Session B should still be clean
        verdict = monitor.evaluate_event(BehaviorEvent(event_type="other", session_id="session-b"))
        assert verdict.decision == "allow"
