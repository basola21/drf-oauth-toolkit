# Variables
POETRY = poetry

# Install all dependencies and pre-commit hooks
install:
	$(POETRY) install
	$(POETRY) run pre-commit install

# Run all linters using Ruff
lint:
	$(POETRY) run ruff check .

# Format code using Ruff
format:
	$(POETRY) run ruff format .

# Check type hints
mypy:
	$(POETRY) run mypy .

# Run all tests
.PHONY: test

test:
	$(POETRY) run pytest

cov:
	$(POETRY) run pytest --cov=drf_oauth_toolkit

# Run pre-commit on all files
pre-commit:
	$(POETRY) run pre-commit run --all-files

# Clean up temporary files and caches
clean:
	rm -rf .mypy_cache __pycache__ .pytest_cache .tox

# Run all checks (lint, mypy, pre-commit, test)
check: lint mypy pre-commit test

# Update pre-commit hooks
update-hooks:
	$(POETRY) run pre-commit autoupdate
