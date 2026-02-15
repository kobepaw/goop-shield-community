# goop-shield Makefile
# Usage: make <target>
# Run `make help` to see available targets.

.PHONY: lint format typecheck test test-fast build clean install-dev serve load-test help

lint:  ## Run ruff linter
	ruff check src/ tests/

format:  ## Run ruff formatter
	ruff format src/ tests/

typecheck:  ## Run mypy type checker
	mypy src/

test:  ## Run all tests with verbose output
	pytest tests/ -v

test-fast:  ## Run tests, stop on first failure
	pytest tests/ -x -q

build:  ## Build distribution packages
	python -m build

clean:  ## Remove build artifacts and caches
	rm -rf build/ dist/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .mypy_cache -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete

install-dev:  ## Install in editable mode with dev dependencies
	pip install -e ".[dev]"

serve:  ## Start the Shield dev server with auto-reload
	uvicorn goop_shield.app:app --reload

load-test:  ## Run load tests against a running Shield instance
	locust -f tests/load/locustfile.py --headless -u 50 -r 10 --run-time 60s --host ${HOST:-http://127.0.0.1:8787}

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
