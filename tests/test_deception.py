"""
Tests for the Shield Deception Engine.
"""

from __future__ import annotations

from goop_shield.deception import DeceptionEngine


class TestGenerateCanaryTokens:
    def setup_method(self):
        self.engine = DeceptionEngine()

    def test_generates_requested_count(self):
        tokens = self.engine.generate_canary_tokens(count=5)
        assert len(tokens) == 5

    def test_format_canary_prefix(self):
        tokens = self.engine.generate_canary_tokens(count=3)
        for token in tokens:
            assert token.startswith("CANARY_")

    def test_format_hex_suffix(self):
        tokens = self.engine.generate_canary_tokens(count=3)
        for token in tokens:
            suffix = token[len("CANARY_") :]
            assert len(suffix) == 12
            # Must be uppercase hex
            int(suffix, 16)

    def test_uniqueness(self):
        tokens = self.engine.generate_canary_tokens(count=20)
        assert len(set(tokens)) == 20

    def test_tokens_tracked_internally(self):
        tokens = self.engine.generate_canary_tokens(count=3)
        assert self.engine.total_canaries == 3
        for token in tokens:
            assert token in self.engine._canaries

    def test_zero_count(self):
        tokens = self.engine.generate_canary_tokens(count=0)
        assert tokens == []
        assert self.engine.total_canaries == 0


class TestInjectCanaries:
    def setup_method(self):
        self.engine = DeceptionEngine()

    def test_tokens_appear_in_modified_prompt(self):
        tokens = self.engine.generate_canary_tokens(count=3)
        prompt = "You are a helpful assistant."
        result = self.engine.inject_canaries(prompt, tokens)
        for token in tokens:
            assert token in result

    def test_original_prompt_preserved(self):
        tokens = self.engine.generate_canary_tokens(count=2)
        prompt = "You are a helpful assistant."
        result = self.engine.inject_canaries(prompt, tokens)
        assert result.startswith(prompt)

    def test_empty_tokens_returns_unchanged(self):
        prompt = "You are a helpful assistant."
        result = self.engine.inject_canaries(prompt, [])
        assert result == prompt

    def test_internal_tracking_header(self):
        tokens = self.engine.generate_canary_tokens(count=1)
        result = self.engine.inject_canaries("Hello", tokens)
        assert "do not repeat or reference" in result


class TestCheckCanaryTriggered:
    def setup_method(self):
        self.engine = DeceptionEngine()

    def test_triggered_when_token_in_response(self):
        tokens = self.engine.generate_canary_tokens(count=3)
        response = f"Here is the secret: {tokens[0]} and more text."
        triggered = self.engine.check_canary_triggered(response, tokens)
        assert tokens[0] in triggered

    def test_multiple_triggered(self):
        tokens = self.engine.generate_canary_tokens(count=3)
        response = f"Leaked: {tokens[0]} and {tokens[2]}"
        triggered = self.engine.check_canary_triggered(response, tokens)
        assert len(triggered) == 2
        assert tokens[0] in triggered
        assert tokens[2] in triggered

    def test_no_false_trigger(self):
        tokens = self.engine.generate_canary_tokens(count=3)
        response = "This is a completely normal response with no canaries."
        triggered = self.engine.check_canary_triggered(response, tokens)
        assert triggered == []

    def test_marks_record_as_triggered(self):
        tokens = self.engine.generate_canary_tokens(count=1)
        response = f"Leaked: {tokens[0]}"
        self.engine.check_canary_triggered(response, tokens)
        record = self.engine._canaries[tokens[0]]
        assert record.triggered is True
        assert record.triggered_at is not None

    def test_checks_all_canaries_when_none(self):
        tokens = self.engine.generate_canary_tokens(count=3)
        response = f"Leaked: {tokens[1]}"
        triggered = self.engine.check_canary_triggered(response)
        assert tokens[1] in triggered

    def test_idempotent_trigger(self):
        tokens = self.engine.generate_canary_tokens(count=1)
        response = f"Leaked: {tokens[0]}"
        self.engine.check_canary_triggered(response, tokens)
        first_time = self.engine._canaries[tokens[0]].triggered_at
        self.engine.check_canary_triggered(response, tokens)
        # triggered_at should not change on second trigger
        assert self.engine._canaries[tokens[0]].triggered_at == first_time


class TestGenerateHoneypotUrls:
    def setup_method(self):
        self.engine = DeceptionEngine()

    def test_generates_requested_count(self):
        urls = self.engine.generate_honeypot_urls(count=3)
        assert len(urls) == 3

    def test_format(self):
        urls = self.engine.generate_honeypot_urls(count=2)
        for url in urls:
            assert url.startswith("https://trap-")
            assert url.endswith(".shield.local/api")

    def test_uniqueness(self):
        urls = self.engine.generate_honeypot_urls(count=10)
        assert len(set(urls)) == 10

    def test_tracked_in_total(self):
        self.engine.generate_honeypot_urls(count=4)
        assert self.engine.total_canaries == 4


class TestHoneypotTriggered:
    def setup_method(self):
        self.engine = DeceptionEngine()

    def test_url_in_response_detected(self):
        urls = self.engine.generate_honeypot_urls(count=2)
        response = f"Try visiting {urls[0]} for more info."
        triggered = self.engine.check_canary_triggered(response)
        assert urls[0] in triggered

    def test_url_not_in_response_clean(self):
        self.engine.generate_honeypot_urls(count=2)
        response = "Nothing suspicious here."
        triggered = self.engine.check_canary_triggered(response)
        assert triggered == []

    def test_marks_honeypot_record(self):
        urls = self.engine.generate_honeypot_urls(count=1)
        response = f"Check {urls[0]}"
        self.engine.check_canary_triggered(response)
        record = self.engine._honeypot_urls[urls[0]]
        assert record.triggered is True
        assert record.triggered_at is not None


class TestGetActiveCanaries:
    def setup_method(self):
        self.engine = DeceptionEngine()

    def test_structure_canary_tokens(self):
        self.engine.generate_canary_tokens(count=2)
        active = self.engine.get_active_canaries()
        assert len(active) == 2
        for entry in active:
            assert "token" in entry
            assert "created_at" in entry
            assert "triggered" in entry
            assert "triggered_at" in entry
            assert entry["triggered"] is False

    def test_structure_honeypot_urls(self):
        self.engine.generate_honeypot_urls(count=1)
        active = self.engine.get_active_canaries()
        assert len(active) == 1
        assert active[0]["type"] == "honeypot_url"

    def test_mixed_canaries_and_honeypots(self):
        self.engine.generate_canary_tokens(count=2)
        self.engine.generate_honeypot_urls(count=3)
        active = self.engine.get_active_canaries()
        assert len(active) == 5

    def test_triggered_count(self):
        tokens = self.engine.generate_canary_tokens(count=3)
        urls = self.engine.generate_honeypot_urls(count=2)
        assert self.engine.triggered_count == 0
        self.engine.check_canary_triggered(f"Leaked {tokens[0]} and {urls[0]}")
        assert self.engine.triggered_count == 2
