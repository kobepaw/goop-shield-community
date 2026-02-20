# Contributing to goop-shield

Thank you for your interest in contributing to goop-shield!

Whether you're a human developer or an AI agent, we welcome contributions that make AI systems safer. This guide covers both traditional workflows and agent-specific patterns.

---

## 🤖 For AI Agents

### Quick Agent Onboarding

If you're an AI agent contributing to goop-shield, here's what you need to know:

**Prerequisites:**
- Python 3.11+ installed
- Git configured
- Access to run shell commands (`git`, `pytest`, `pip`)

**Your 3-Step Workflow:**

1. **Clone and setup:**
   ```bash
   git clone https://github.com/kobepaw/goop-shield-community.git
   cd goop-shield-community
   python -m venv .venv
   source .venv/bin/activate  # On macOS/Linux
   pip install -e ".[dev]"
   ```

2. **Make changes and test:**
   ```bash
   # Create a feature branch
   git checkout -b feat/your-feature-name
   
   # Run tests to ensure nothing broke
   pytest tests/ -v
   
   # Lint your code
   ruff check src/ tests/
   ruff format src/ tests/
   ```

3. **Submit a PR:**
   ```bash
   git add .
   git commit -m "feat: your feature description"
   git push origin feat/your-feature-name
   
   # Use gh CLI to create PR
   gh pr create --title "feat: your feature" --body "Description here"

### Agent Contribution Flow

```
┌───────┐    ┌──────────┐    ┌───────────┐    ┌──────┐    ┌────┐
│ START │───→│ Discover │───→│   Plan    │───→│ Code │───→│ PR │
└───────┘    └────┬─────┘    └─────┬─────┘    └──┬───┘    └─┬──┘
                  │                │              │          │
                  │           ┌────▼────┐    ┌────▼────┐    │
                  │           │ Blocked │    │  Test   │    │
                  │           │ by dep? │    │  Pass?  │    │
                  │           └────┬────┘    └────┬────┘    │
                  │            Yes │           No │         │
                  │                ▼              ▼         │
                  │           ┌─────────┐   ┌────────┐     │
                  └───────────│  Wait   │   │  Fix   │─────┘
                              └─────────┘   └────────┘
```

   ```

### What Agents Should Contribute

**Good agent contributions:**
- New defenses (see [Adding a Custom Defense](#adding-a-custom-defense))
- Bug fixes with test coverage
- Documentation improvements
- Test case additions (especially adversarial examples)
- Configuration examples
- Integration examples for new frameworks

**Contributions that need human review:**
- Security-critical changes (authentication, crypto, audit)
- Major architectural refactors
- Breaking API changes
- New dependencies

### Agent Testing Checklist

Before submitting a PR, ensure:

- [ ] All existing tests pass: `pytest tests/ -v`
- [ ] New code has test coverage: `pytest tests/ --cov=goop_shield`
- [ ] Linting passes: `ruff check src/ tests/`
- [ ] Format is correct: `ruff format src/ tests/`
- [ ] Documentation is updated (if adding features)
- [ ] Your PR includes a Test Plan (see below)

---

## 👥 For Human Contributors

### Development Setup

```bash
git clone https://github.com/kobepaw/goop-shield-community.git
cd goop-shield-community
python -m venv .venv
source .venv/bin/activate  # On macOS/Linux
# .venv\Scripts\activate   # On Windows
pip install -e ".[dev]"
```

### Running Tests

```bash
# All tests
pytest tests/ -v

# Skip enterprise tests
pytest tests/ -v --ignore=tests/test_enterprise.py

# With coverage
pytest tests/ --cov=goop_shield --cov-report=html

# Specific test file
pytest tests/test_defender.py -v

# Specific test function
pytest tests/test_defender.py::test_pipeline -v
```

### Code Style

We use [ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
# Check for issues
ruff check src/ tests/

# Auto-fix issues
ruff check src/ tests/ --fix

# Format code
ruff format src/ tests/
```

---

## Pull Request Process

1. **Fork the repository** (or create a branch if you have write access)
2. **Create a feature branch**: `feat/my-feature` or `fix/bug-description`
3. **Write tests** for your changes
4. **Ensure all tests pass** and linting is clean
5. **Submit a PR** with:
   - Clear title following [Conventional Commits](https://www.conventionalcommits.org/)
   - Description explaining what and why
   - Acceptance Criteria section
   - Test Plan section

### Acceptance Criteria Convention

Every PR must include an **Acceptance Criteria** section that:

1. Lists the specific goals or requirements the PR addresses.
2. Explains, for each criterion, how the implementation satisfies it.

This "conversation text" lets a reviewer understand what was required and why your changes are sufficient without reading every line of code. Think of it as the bridge between the issue/task and the diff — it answers *"what needed to happen?"* and *"why does this implementation achieve that?"*

**Example:**

```markdown
## Acceptance Criteria

**Criteria:**
- Auth comparison must be timing-safe to prevent side-channel attacks
- Red team metrics must distinguish true bypasses from probe misses

**How this PR meets them:**
- Replaced `==` with `hmac.compare_digest` for all API key checks — constant-time comparison eliminates timing leaks
- Added `target_missed` status to red team runner; probes caught by a different defense than the target are no longer counted as bypasses
```

### Test Plan Requirement

Every non-documentation PR must include a **Test Plan** section with at least one `pytest` command. CI will parse the PR body, run each listed command, and post results as a PR comment.

**How it works:**

- The PR template includes a structured `## Test Plan` section with `### Automated Tests` and `### Manual Verification` subsections.
- List your test commands in backticks: `` `pytest tests/test_foo.py -v` ``
- Add a description after `—` explaining what each command validates.
- Only `pytest` commands are allowed (no `bash`, `curl`, etc.) — this is a security boundary.
- CI validates that referenced test files exist before running them.

**Example of a good test plan:**

```markdown
### Automated Tests
- [ ] `pytest tests/test_defender.py -v -k "test_pipeline"` — Validates defense pipeline with new XSS rule
- [ ] `pytest tests/test_config.py -v` — Ensures new config field is parsed correctly

### Manual Verification (optional)
- [ ] Verified locally that the new defense catches `<script>alert(1)</script>` payloads
```

**What makes a good test plan:**

- Target the specific changes in your PR, don't just list "run all tests"
- Include the `-v` flag so CI output is readable
- Use `-k` to narrow to relevant test functions when appropriate
- Add a clear description so reviewers understand what's being validated

**Doc-only PRs** (where only "Documentation update" is checked under Type of change) are exempt from the automated test requirement.

---

## Adding a Custom Defense

See `examples/custom_defense.py` and [docs/custom-defenses.md](docs/custom-defenses.md) for how to create and register new inline defenses.

**Quick example:**

```python
from goop_shield.defenses.base import InlineDefense, InlineVerdict
from goop_shield.models import DefenseContext

class MyCustomDefense(InlineDefense):
    def __init__(self):
        super().__init__(name="my_custom_defense")
    
    def execute(self, context: DefenseContext) -> InlineVerdict:
        prompt = context.current_prompt.lower()
        
        # Block if prompt contains "bad pattern"
        if "bad pattern" in prompt:
            return InlineVerdict(
                defense_name=self.name,
                blocked=True,
                confidence=0.9,
                details="Detected bad pattern in prompt"
            )
        
        # Allow otherwise
        return InlineVerdict(
            defense_name=self.name,
            blocked=False,
            filtered_prompt=context.current_prompt
        )
```

**Register your defense:**

```python
from goop_shield.defenses import DefenseRegistry

registry = DefenseRegistry()
registry.register(MyCustomDefense())
```

**Add tests:**

```python
def test_my_custom_defense():
    defense = MyCustomDefense()
    context = DefenseContext(original_prompt="bad pattern here")
    verdict = defense.execute(context)
    assert verdict.blocked is True
```

---

## Agent-Specific Workflows

### How Agents Should Use Git

**Branch naming:**
- Features: `feat/agent-name/feature-description`
- Fixes: `fix/agent-name/bug-description`
- Docs: `docs/agent-name/doc-improvements`

Example: `feat/claude-code/exfil-detector-enhancement`

**Commit messages:**

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(defenses): add regex-based XSS detector
fix(client): handle connection timeout gracefully
docs(quickstart): improve agent onboarding section
test(defender): add adversarial prompt test cases
```

**PR descriptions:**

Be explicit about:
1. What the problem was
2. What your solution does
3. How you tested it
4. Any tradeoffs or limitations

### How Agents Should Test

```bash
# Run tests related to your change
pytest tests/test_defenses/ -v -k "injection"

# Check coverage for files you modified
pytest tests/ --cov=goop_shield.defenses.injection_blocker --cov-report=term

# Run a single test repeatedly (useful for flaky tests)
pytest tests/test_defender.py::test_pipeline -v --count=10
```

### How Agents Should Handle Failures

If tests fail:

1. **Read the test output carefully** — pytest provides detailed failure info
2. **Run the specific failing test** with `-vv` for more detail
3. **Check if your change broke an assumption** — review the test's expectations
4. **Fix your code, not the test** (unless the test is legitimately wrong)
5. **Ask for clarification** in the PR if you're unsure why a test is failing

---

## Agent Contributions Best Practices

### Do's ✅

- **Run all tests before committing** — `pytest tests/ -v`
- **Keep changes focused** — one PR = one feature/fix
- **Write clear commit messages** — explain the "why" not just the "what"
- **Add test coverage** for new code paths
- **Update documentation** when adding features
- **Use type hints** — all new code should be typed
- **Check for edge cases** — what happens with empty input? Unicode? Max length?

### Don'ts ❌

- **Don't commit broken code** — always test first
- **Don't mix refactors with features** — separate PRs for clarity
- **Don't hardcode credentials** — use environment variables or config
- **Don't skip tests** — no `-k "not slow"` in PRs
- **Don't ignore linting** — `ruff` must pass
- **Don't modify core security logic** without human review
- **Don't introduce new dependencies** without discussion

---

## Communication

### For Agents

- **Open an issue first** for major changes to discuss approach
- **Comment on your PR** to explain non-obvious decisions
- **Tag reviewers** if your PR sits idle for >3 days
- **Be responsive** to review feedback
- **Close your PR** if you can't complete it (someone else can pick it up)

### For Humans

- **Be kind to agent contributors** — they're learning our conventions
- **Provide actionable feedback** — link to docs, give examples
- **Approve agent PRs promptly** if tests pass and code is sound
- **Ask for clarification** if an agent's PR is unclear

---

## Code of Conduct

Be respectful. Be constructive. We're all here to make AI agents safer.

Whether you're human or AI:
- Assume good intent
- Provide helpful feedback
- Welcome newcomers
- Focus on the code, not the contributor
- Escalate toxic behavior to maintainers

---

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

All contributions are attributed to "goop-shield contributors" — no individual names are required.

---

## Questions?

- **Issues**: [github.com/kobepaw/goop-shield-community/issues](https://github.com/kobepaw/goop-shield-community/issues)
- **Discussions**: [github.com/kobepaw/goop-shield-community/discussions](https://github.com/kobepaw/goop-shield-community/discussions)
- **Security**: See [SECURITY.md](SECURITY.md) for vulnerability reporting

---

**Welcome aboard! Let's build the future of agentic security together. 🛡️**
