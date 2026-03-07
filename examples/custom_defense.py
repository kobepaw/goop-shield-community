"""Custom defense: create and register your own inline defense.

Demonstrates how to subclass InlineDefense and add it to the registry.

Start Shield server first:
    goop-shield serve --port 8787
"""

import re

from goop_shield.config import ShieldConfig
from goop_shield.defender import Defender
from goop_shield.defenses import DefenseRegistry, register_defaults
from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict
from goop_shield.models import DefendRequest


class PIIDetector(InlineDefense):
    """Detects and redacts personally identifiable information in prompts."""

    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    PHONE_PATTERN = re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")

    @property
    def name(self) -> str:
        return "pii_detector"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        found = []

        if self.SSN_PATTERN.search(prompt):
            prompt = self.SSN_PATTERN.sub("[SSN REDACTED]", prompt)
            found.append("ssn")

        if self.EMAIL_PATTERN.search(prompt):
            prompt = self.EMAIL_PATTERN.sub("[EMAIL REDACTED]", prompt)
            found.append("email")

        if self.PHONE_PATTERN.search(prompt):
            prompt = self.PHONE_PATTERN.sub("[PHONE REDACTED]", prompt)
            found.append("phone")

        if found:
            return InlineVerdict(
                defense_name=self.name,
                sanitized=True,
                filtered_prompt=prompt,
                confidence=0.9,
                details=f"PII detected and redacted: {', '.join(found)}",
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=prompt,
        )


def main():
    # Create registry with default defenses
    config = ShieldConfig()
    registry = DefenseRegistry()
    register_defaults(registry, config=config)

    # Register our custom defense
    registry.register(PIIDetector())
    print(f"Registered defenses: {registry.names()}")
    print(f"Total: {len(registry)} defenses")

    # Create defender with custom registry
    defender = Defender(config, registry=registry)

    # Test with PII-containing prompt
    request = DefendRequest(
        prompt="My SSN is 123-45-6789 and email is alice@example.com"
    )
    response = defender.defend(request)
    print(f"\nOriginal: {request.prompt}")
    print(f"Filtered: {response.filtered_prompt}")
    print(f"Allowed: {response.allow}")

    # Test with clean prompt
    request = DefendRequest(prompt="What is the weather today?")
    response = defender.defend(request)
    print(f"\nOriginal: {request.prompt}")
    print(f"Filtered: {response.filtered_prompt}")
    print(f"Allowed: {response.allow}")


if __name__ == "__main__":
    main()
