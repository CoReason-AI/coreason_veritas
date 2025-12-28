# Contributing Guide

Thank you for your interest in contributing to `coreason_veritas`. This project adheres to strict GxP (Good Practice) standards. Please read this guide carefully.

## Environment Setup

We use **Poetry** for dependency management.

1.  **Clone the repo:**
    ```bash
    git clone https://github.com/CoReason-AI/coreason_veritas.git
    cd coreason_veritas
    ```

2.  **Install Dependencies:**
    ```bash
    poetry install
    ```
    This will install the virtual environment and all dev dependencies.

3.  **Activate Shell:**
    ```bash
    poetry shell
    ```

## Development Protocol

### 1. Atomic Units
Break your work down into small, testable units. Do not try to implement massive features in one commit.

### 2. Testing
**100% Code Coverage is Mandatory.**

*   Run tests:
    ```bash
    poetry run pytest
    ```
*   We use `pytest-cov` to enforce coverage. PRs with <100% coverage will fail CI.

### 3. Linting & Formatting
We use **Ruff** and **Mypy**.

*   Format code:
    ```bash
    poetry run ruff format .
    ```
*   Check types:
    ```bash
    poetry run mypy .
    ```
*   Run all pre-commit hooks:
    ```bash
    poetry run pre-commit run --all-files
    ```

### 4. Documentation
If you change the API, you **must** update the documentation.

*   Build docs locally:
    ```bash
    poetry run mkdocs build --strict
    ```
*   Serve docs locally:
    ```bash
    poetry run mkdocs serve
    ```

## Pull Request Process

1.  Create a branch for your feature.
2.  Ensure all tests pass and coverage is 100%.
3.  Ensure pre-commit hooks pass.
4.  Submit PR with a clear description of the changes.
