# Contributing to Intellicrack

Thank you for your interest in contributing to Intellicrack! This document
provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) to ensure a
welcoming environment for all contributors.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:

    ```bash
    git clone https://github.com/ZachFlint/Intellicrack.git
    cd Intellicrack
    ```

3. Add the upstream repository as a remote:

    ```bash
    git remote add upstream https://github.com/ZachFlint/Intellicrack.git
    ```

## Development Setup

### Prerequisites

- **Python 3.13+** (required for full functionality)
- **Git** for version control
- **Windows 11**
- **[Pixi](https://pixi.sh)** for environment management (the project manifest
  lives in `pyproject.toml`)
- **Docker** — the test suites run inside a Docker sandbox
- **[`just`](https://github.com/casey/just)** command runner — all quality-gate,
  build, and test recipes are defined in the `justfile`

### Virtual Environment Setup

1. Create and activate the environment (the manifest already exists in
   `pyproject.toml`, so there is nothing to initialize):

    ```bash
    # Installs all runtime and development dependencies from pyproject.toml
    pixi install
    pixi shell
    ```

2. Install dependencies:

    All runtime and development dependencies are provided by the Pixi
    environment created above, so no separate install step is required. If you
    need a pip-based fallback, install from the root `requirements.txt`:

    ```bash
    pip install -r requirements.txt
    ```

3. Build the Rust hex editor core (`intellicrack-hexcore`):

    ```bash
    just build-hexcore
    ```

4. Install pre-commit hooks:

    ```bash
    pre-commit install
    ```

## Project Structure

```text
intellicrack/
├── src/intellicrack/      # Main package source code
│   ├── assets/           # Bundled icons and static assets
│   ├── bridges/          # Bridge layer for external tools and internal modules
│   ├── core/             # Core orchestration, logging, and shared functionality
│   ├── credentials/      # Credential storage and management
│   ├── providers/        # AI provider connectivity
│   ├── sandbox/          # Sandbox analysis and orchestration
│   ├── ui/               # User interface components
│   ├── main.py           # Application entry point
│   ├── __main__.py       # `python -m intellicrack` entry point
│   └── _metadata.py      # Package metadata
├── src/intellicrack-hexcore/  # Rust hex editor core crate
├── tests/                # Test suite
├── docs/                 # Documentation
├── data/                 # Runtime data (gitignored)
└── .github/              # GitHub workflows and templates
```

## Making Changes

1. Create a new branch for your feature or fix:

    ```bash
    git checkout -b feature/your-feature-name
    ```

2. Make your changes following the coding standards

3. Write or update tests as needed

4. Update documentation if you've changed functionality

5. Commit your changes with clear, descriptive messages:

    ```bash
    git commit -m "Add feature: description of what you added"
    ```

## Coding Standards

### Python Code Style

- Follow PEP 8 style guide
- Format with ruff (`just ruff-fmt`); line length 140
- All code must pass `ruff check`, `basedpyright`, `pydoclint`, and `pydocstyle`
- Every function, method, and variable must have precise type hints and
  annotations
- Write Google-style docstrings for all functions, methods, and classes
- Keep functions focused and under 50 lines when possible

### Import Order

1. Standard library imports
2. Third-party imports
3. Local application imports

Example:

```python
import os
import sys
from typing import Dict, List

import numpy as np
from PyQt6.QtWidgets import QWidget

from intellicrack.core.logging import get_logger
from intellicrack.core.tools import ToolRegistry
```

### Naming Conventions

- Classes: `PascalCase`
- Functions/variables: `snake_case`

- Constants: `UPPER_SNAKE_CASE`
- Private methods/attributes: `_leading_underscore`

## Testing

### Running Tests

Tests run inside a Docker sandbox and are driven through `just` recipes.
Invoking `pytest` directly is not supported.

```bash
# Run the test suite in the Docker sandbox
just test

# Run with coverage
just test-coverage
```

### Writing Tests

- Place tests under `tests/` in the subsystem subdirectory that matches the code
  under test: `bridges/`, `core/`, `providers/`, `sandbox/`, `hexpat/`,
  `integration/`, or `ui/`
- Never place tests at the `tests/` root or beside the source files
- Use descriptive test names that explain what is being tested
- Include both positive and negative test cases
- Every test must be a real, falsifiable quality gate that fails when the
  behavior it asserts is broken — do not assert on mocks or stubs in place of
  the real behavior under test

Example:

```python
from intellicrack.core.logging import get_logger


def test_get_logger_returns_named_logger():
    """Verify get_logger returns a logger bound to the requested name."""
    logger = get_logger("intellicrack.example")
    assert logger is not None
```

## Submitting Changes

1. Push your changes to your fork:

    ```bash
    git push origin feature/your-feature-name
    ```

2. Create a Pull Request on GitHub:
    - Provide a clear title and description
    - Reference any related issues
    - Include screenshots for UI changes
    - Ensure all tests pass
    - Address review feedback promptly

### Pull Request Checklist

- [ ] Code follows the project's style guidelines
- [ ] Self-review of code completed
- [ ] Comments added for complex logic
- [ ] Documentation updated if needed
- [ ] Tests added/updated and passing
- [ ] No new linting warnings
- [ ] Commit messages are clear and descriptive

## Additional Resources

- [Issue Tracker](https://github.com/ZachFlint/Intellicrack/issues)
- [Documentation](docs/) - Local documentation in project repository

## Questions?

Feel free to open an issue for any questions about contributing. We're here to
help!
