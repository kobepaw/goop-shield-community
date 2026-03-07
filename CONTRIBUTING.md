# Contributing to goop-shield

Thank you for your interest in contributing to goop-shield!

## Development Setup

```bash
git clone https://github.com/kobepaw/goop-shield-community.git
cd goop-shield-community
python -m venv .venv
source .venv/bin/activate  # On macOS/Linux
# .venv\Scripts\activate   # On Windows
pip install -e ".[dev]"
```

## Running Tests

```bash
# All tests
pytest tests/ -v

# Skip enterprise tests
pytest tests/ -v --ignore=tests/test_enterprise.py

# With coverage
pytest tests/ --cov=goop_shield --cov-report=html
```

## Code Style

We use [ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
ruff check src/ tests/
ruff format src/ tests/
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`feat/my-feature` or `fix/bug-description`)
3. Write tests for your changes
4. Ensure all tests pass and linting is clean
5. Submit a PR with a clear description and a structured **Test Plan**

### Acceptance Criteria Convention

Every PR must include an **Acceptance Criteria** section that:

1. Lists the specific goals or requirements the PR addresses.
2. Explains, for each criterion, how the implementation satisfies it.

This "conversation text" lets a reviewer understand what was required and why
your changes are sufficient without reading every line of code. Think of it as
the bridge between the issue/task and the diff — it answers *"what needed to
happen?"* and *"why does this implementation achieve that?"*

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

Every non-documentation PR must include a **Test Plan** section with at least one
`pytest` command. CI will parse the PR body, run each listed command, and post results
as a PR comment.

**How it works:**

- The PR template includes a structured `## Test Plan` section with
  `### Automated Tests` and `### Manual Verification` subsections.
- List your test commands in backticks: `` `pytest tests/test_foo.py -v` ``
- Add a description after `—` explaining what each command validates.
- Only `pytest` commands are allowed (no `bash`, `curl`, etc.) — this is a
  security boundary.
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

**Doc-only PRs** (where only "Documentation update" is checked under Type of change)
are exempt from the automated test requirement.

## Adding a Custom Defense

See `examples/custom_defense.py` and `docs/custom-defenses.md` for how to create
and register new inline defenses.

## Code of Conduct

Be respectful. Be constructive. We're all here to make AI agents safer.

## License

By contributing, you agree that your contributions will be licensed under the
Apache License 2.0.
