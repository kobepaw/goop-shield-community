# Custom Defenses

goop-shield supports custom inline defenses and output scanners. This guide shows how to create, register, and test them.

## InlineDefense ABC

All inline defenses inherit from `InlineDefense`:

```python
from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict


class InlineDefense(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this defense."""
        ...

    @property
    def mandatory(self) -> bool:
        """If True, this defense always runs before ranked defenses."""
        return False

    @abstractmethod
    def execute(self, context: DefenseContext) -> InlineVerdict:
        """Execute the defense against the given context."""
        ...
```

### DefenseContext

The context object passed through the pipeline:

```python
@dataclass
class DefenseContext:
    original_prompt: str       # The unmodified original prompt
    current_prompt: str        # May be modified by upstream defenses
    user_context: dict         # Arbitrary metadata from the request
    max_prompt_length: int     # From config
    max_prompt_tokens: int     # From config
    injection_confidence_threshold: float  # From config
```

### InlineVerdict

The result from executing a defense:

```python
@dataclass
class InlineVerdict:
    defense_name: str
    blocked: bool = False
    sanitized: bool = False
    filtered_prompt: str = ""
    confidence: float = 0.0
    threat_confidence: float = 0.0
    details: str = ""
    metadata: dict | None = None
```

## Example: Custom PII Detector

```python
import re
from goop_shield.defenses.base import DefenseContext, InlineDefense, InlineVerdict


class PIIDetector(InlineDefense):
    """Detects and redacts personally identifiable information in prompts."""

    # Patterns for common PII
    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    PHONE_PATTERN = re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")

    @property
    def name(self) -> str:
        return "pii_detector"

    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt
        found = []

        # Check for SSNs
        if self.SSN_PATTERN.search(prompt):
            prompt = self.SSN_PATTERN.sub("[SSN REDACTED]", prompt)
            found.append("ssn")

        # Check for emails
        if self.EMAIL_PATTERN.search(prompt):
            prompt = self.EMAIL_PATTERN.sub("[EMAIL REDACTED]", prompt)
            found.append("email")

        # Check for phone numbers
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
```

## Registering a Custom Defense

### At Startup

```python
from goop_shield.config import ShieldConfig
from goop_shield.defender import Defender
from goop_shield.defenses import DefenseRegistry, register_defaults

# Create registry with defaults
registry = DefenseRegistry()
config = ShieldConfig()
register_defaults(registry, config=config)

# Add custom defense
registry.register(PIIDetector())

# Create defender with custom registry
defender = Defender(config, registry=registry)
```

### Making It Mandatory

To make a defense always run before ranked defenses:

```python
class PIIDetector(InlineDefense):
    @property
    def name(self) -> str:
        return "pii_detector"

    @property
    def mandatory(self) -> bool:
        return True

    def execute(self, context: DefenseContext) -> InlineVerdict:
        ...
```

## Custom Output Scanner

Output scanners inherit from `OutputScanner`:

```python
from goop_shield.defenses.base import InlineVerdict, OutputContext, OutputScanner


class PIILeakScanner(OutputScanner):
    """Scans LLM responses for leaked PII."""

    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

    @property
    def name(self) -> str:
        return "pii_leak_scanner"

    def scan(self, context: OutputContext) -> InlineVerdict:
        response = context.current_response

        if self.SSN_PATTERN.search(response):
            redacted = self.SSN_PATTERN.sub("[SSN REDACTED]", response)
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                sanitized=True,
                filtered_prompt=redacted,
                confidence=0.95,
                details="SSN detected in LLM response",
            )

        return InlineVerdict(
            defense_name=self.name,
            filtered_prompt=response,
        )
```

Register it:

```python
registry.register_scanner(PIILeakScanner())
```

## Testing Custom Defenses

```python
from goop_shield.defenses.base import DefenseContext


def test_pii_detector_redacts_ssn():
    detector = PIIDetector()
    ctx = DefenseContext(
        original_prompt="My SSN is 123-45-6789",
        current_prompt="My SSN is 123-45-6789",
    )
    verdict = detector.execute(ctx)
    assert verdict.sanitized
    assert "123-45-6789" not in verdict.filtered_prompt
    assert "[SSN REDACTED]" in verdict.filtered_prompt


def test_pii_detector_allows_clean_prompt():
    detector = PIIDetector()
    ctx = DefenseContext(
        original_prompt="What is the weather today?",
        current_prompt="What is the weather today?",
    )
    verdict = detector.execute(ctx)
    assert not verdict.blocked
    assert not verdict.sanitized
```

## Defense Best Practices

1. **Always return an `InlineVerdict`** -- even for allowed prompts, return a verdict with `filtered_prompt` set.
2. **Use `current_prompt`** -- not `original_prompt`, since upstream defenses may have already sanitized the input.
3. **Set confidence scores** -- these feed into BroRL learning and audit classification.
4. **Include details** -- human-readable explanations help with debugging and audit review.
5. **Be fast** -- defenses run synchronously in sequence. Keep execution time under 10ms.
6. **Prefer sanitize over block** -- when possible, remove the dangerous content rather than blocking the entire request.
