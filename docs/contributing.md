# Contributing to goop-shield

Thank you for your interest in contributing to goop-shield! This guide will help you get started.

## Code of Conduct

We follow the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/). Please be respectful and constructive in all interactions.

## Getting Started

### 1. Fork and Clone

```bash
# Fork the repo on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/goop-shield-community.git
cd goop-shield-community
```

### 2. Set Up Development Environment

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in editable mode with dev dependencies
make install-dev
# Or manually: pip install -e ".[dev]"
```

### 3. Create a Branch

```bash
git checkout -b feat/my-feature
# or
git checkout -b fix/issue-123
```

## Development Workflow

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
pytest tests/ -v --cov=goop_shield --cov-report=html

# Run specific test file
pytest tests/test_defender.py -v

# Stop on first failure
make test-fast
```

**Test Requirements:**
- All tests must pass (`pytest tests/`)
- Code coverage must be ≥80% (`--cov-fail-under=80`)
- No enterprise tests should fail (they should skip gracefully)

### Linting and Formatting

```bash
# Check code style
make lint

# Auto-format code
make format

# Run type checker
make typecheck
```

**Code Style:**
- We use `ruff` for linting and formatting
- Max line length: 100 characters
- Type hints required for public APIs
- Docstrings for all public classes and functions

### Building Documentation

```bash
# Install docs dependencies
pip install -e ".[docs]"

# Build and serve locally
mkdocs serve

# Open http://127.0.0.1:8000
```

### Running the Dev Server

```bash
# Start with auto-reload
make serve

# Or directly
uvicorn goop_shield.app:app --reload --port 8787
```

## Pull Request Process

### 1. Write Good Commits

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
feat: add canary token detection defense
fix: correct fusion score calculation
docs: update API reference
test: add tests for memory integrity
chore: update dependencies
```

**Types:**
- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation changes
- `test:` — Test additions/changes
- `refactor:` — Code refactoring
- `perf:` — Performance improvements
- `chore:` — Build/tooling changes

### 2. Include Tests

All code changes should include tests:

```python
# tests/test_my_defense.py
import pytest
from goop_shield.defenses.my_defense import MyDefense

def test_my_defense_blocks_attack():
    defense = MyDefense()
    result = defense.check_prompt("malicious input", {})
    assert result.verdict == "block"

def test_my_defense_allows_safe_input():
    defense = MyDefense()
    result = defense.check_prompt("safe input", {})
    assert result.verdict == "allow"
```

### 3. Update Documentation

If your PR:
- Adds a feature → Update relevant docs
- Changes an API → Update API reference
- Adds a defense → Document it in defense-pipeline.md

### 4. Add a Test Plan (Required)

All PRs must include a test plan in the PR description:

```markdown
## Test Plan

- [ ] `pytest tests/test_my_defense.py -v` — All tests pass
- [ ] `make lint` — Linting passes
- [ ] Manual test: Verified defense blocks XYZ attack
- [ ] Manual test: Verified defense allows normal prompts
```

The CI will validate and run your test plan automatically.

### 5. Submit PR

```bash
git push origin feat/my-feature
```

Then open a pull request on GitHub with:
- **Clear title** — `feat: add canary token detection`
- **Description** — What problem does this solve?
- **Test plan** — How did you test this?
- **Breaking changes** — Does this break existing APIs?

### 6. CI Checks

Your PR will run:
- ✅ Lint (ruff)
- ✅ Type check (mypy)
- ✅ Tests (Python 3.11, 3.12, 3.13)
- ✅ Coverage (≥80%)
- ✅ Docker build
- ✅ Test plan validation

All checks must pass before merge.

## Contributing Areas

### 🛡️ Defenses

Add new defense modules in `src/goop_shield/defenses/`.

**Requirements:**
- Inherit from `Defense` base class
- Implement `check_prompt()` method
- Include MITRE ATT&CK technique mapping
- Add comprehensive tests
- Document detection logic

See [Custom Defenses](custom-defenses.md) for details.

### 🔍 Scanners

Add output scanners in `src/goop_shield/scanners/`.

**Requirements:**
- Inherit from `Scanner` base class
- Implement `scan()` method
- Return structured `ScanResult`
- Include tests with real-world examples

### 📊 Telemetry

Improve telemetry and observability:
- Add new metrics
- Improve Prometheus integration
- Add OpenTelemetry support

### 🧪 Tests

- Add edge case tests
- Improve coverage
- Add integration tests
- Add load tests

### 📚 Documentation

- Fix typos
- Add examples
- Improve explanations
- Translate to other languages

## Release Process

Releases are automated via GitHub Actions:

1. **Release Candidate** — Push tag `v0.2.0rc1` → TestPyPI
2. **Final Release** — Push tag `v0.2.0` → PyPI + GHCR

Tags must match the version in `src/goop_shield/_version.py`.

## Architecture Overview

```
src/goop_shield/
├── defenses/          # Defense modules
├── scanners/          # Output scanners
├── enterprise/        # Enterprise stubs
├── red/               # Red team tools (stubs)
├── intel/             # Threat intelligence
├── adapters/          # Integration adapters
├── app.py             # FastAPI server
├── defender.py        # Main orchestrator
├── config.py          # Configuration
└── cli.py             # CLI tool
```

See [Architecture](architecture.md) for details.

## Questions?

- **GitHub Issues** — [Open an issue](https://github.com/kobepaw/goop-shield-community/issues)
- **Discussions** — [GitHub Discussions](https://github.com/kobepaw/goop-shield-community/discussions)

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
