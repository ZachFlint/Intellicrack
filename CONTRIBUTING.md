# Contributing to Intellicrack

Thank you for your interest in contributing to Intellicrack. This document
covers how to set up a development environment, the quality gates every
change must pass, and how to get your work reviewed and merged.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Commit Messages](#commit-messages)
- [Submitting Changes](#submitting-changes)
- [Questions](#questions)

## Code of Conduct

Please read and follow the [Code of Conduct](CODE_OF_CONDUCT.md) so the
project stays welcoming to everyone.

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork locally:

    ```bash
    git clone https://github.com/<your-user>/Intellicrack.git
    cd Intellicrack
    ```

3. Add the upstream repository as a remote so you can keep your fork in
   sync:

    ```bash
    git remote add upstream https://github.com/ZachFlint/Intellicrack.git
    ```

## Development Setup

### Prerequisites

Intellicrack is developed on 64-bit Windows. Install these yourself:

- **Git**
- **[Pixi](https://pixi.sh)** - provisions Python 3.13 and every
  development tool from `pyproject.toml`
- **Docker Desktop** - the test suite runs inside a Docker sandbox

Everything else the project uses (`just`, `ruff`, `basedpyright`, the Rust
toolchain, and so on) is provided by the Pixi environment; run those tools
from a `pixi shell` or by prefixing them with `pixi run`.

### Setup

1. Create the environment and enter it:

    ```bash
    pixi install
    pixi shell
    ```

2. Build the native hex editor core (`intellicrack-hexcore`):

    ```bash
    just build-hexcore
    ```

3. Install the pre-commit hooks:

    ```bash
    pre-commit install
    ```

`just install` runs the full bootstrap (environment, native core, and Node
dev tooling) in one step, and `just --list` shows every available recipe.

### Building components

The other native and packaged components have their own recipes:

- `just build-x64dbg-plugin` - the C++ x64dbg bridge plugin
- `just build-hexbench` - the standalone Hexbench GUI
- `just build-intellicrack` - the frozen application (PyInstaller)
- `just build-installer` - the Windows installer (see
  [packaging/README.md](packaging/README.md))

The external analysis tools can be fetched with `just install-ghidra`,
`just install-radare2`, `just install-cutter`, `just install-x64dbg`, and
`just install-qemu`.

## Project Structure

```text
src/
  intellicrack/          Main application package (Python)
    core/                Orchestration, config, sessions, types, logging
    bridges/             Tool integrations and direct binary operations
    providers/           LLM provider implementations
    sandbox/             Windows Sandbox and QEMU backends
    ui/                  PyQt6 interface (chat, tool panels, dialogs)
    credentials/         API keys and OAuth
    assets/              Bundled icons and resources
  intellicrack-hexcore/  Native hex editor core (Rust / PyO3)
  x64dbg-plugin/         x64dbg bridge plugin (C++)
  hexbench/              Standalone hex-core tester (web GUI)
tests/                   Test suite (mirrors the src subsystems)
packaging/               Windows installer (Inno Setup)
scripts/                 Build, install, and tooling scripts
docs/                    Sphinx documentation
justfile                 Build, lint, and test recipes
```

## Making Changes

1. Branch off `main`:

    ```bash
    git checkout -b feat/short-description
    ```

2. Make your changes, following the coding standards below.
3. Add or update tests, and update documentation when behavior changes.
4. Run the quality gates and the test suite locally before pushing.

## Coding Standards

- Target Python 3.13. Format with ruff (`just ruff-fmt`); the line length
  is 140.
- All code must pass `just lint` (ruff), `just basedpyright`,
  `just pydoclint`, and `just pydocstyle` with zero findings.
- Give every function, method, and attribute precise type annotations;
  basedpyright runs in strict mode.
- Write Google-style docstrings for every module, class, and function.
- Do not use suppression comments (no `type: ignore`, no pyright-ignore,
  no blanket `noqa`). Fix the underlying issue instead.
- Keep code Windows-compatible, and follow SOLID, DRY, and KISS.
- Files use CRLF line endings, enforced by `.gitattributes` and
  pre-commit.

`just lint-fix` and `just ruff-fmt` apply safe fixes and formatting;
`just run-all-tools` runs the full linter suite; and the pre-commit hooks
run the core gates on every commit.

### Import order

Group imports as standard library, third-party, then first-party, with a
blank line between groups (ruff's isort enforces this):

```python
import json
from pathlib import Path

from PyQt6.QtWidgets import QWidget

from intellicrack.core.logging import get_logger
from intellicrack.core.tools import ToolRegistry
```

### Naming conventions

- Classes: `PascalCase`
- Functions and variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private members: `_leading_underscore`

## Testing

The tests run inside a Docker sandbox and are driven through `just`
recipes; invoking `pytest` directly is not the supported path.

```bash
# Run the default (unit) suite, followed by the host-native pass
just test

# Run one subsystem, e.g. the bridges
just test module --module bridges

# Measure coverage; run the Rust hex-core tests
just test-coverage
just test-hexcore
```

`just test <TYPE>` selects a suite (`unit`, `integration`, `all`,
`module`, and others listed in the recipe header). `just test-host` runs
only the host-native pass.

When writing tests:

- Place each test under `tests/` in the subsystem directory that matches
  the code: `bridges/`, `core/`, `providers/`, `sandbox/`, `hexpat/`,
  `integration/`, `ui/`, or `packaging/`. Never at the `tests/` root or
  beside the source.
- Use descriptive names and cover both success and failure paths.
- Every test must be a real, falsifiable gate: it must fail when the
  behavior it asserts is broken. Exercise genuine operations against real
  inputs rather than asserting on mocks or stubs.

## Commit Messages

The project uses [Conventional Commits](https://www.conventionalcommits.org).
Write each message as `<type>(<scope>): <summary>`:

```text
feat(bridges): add memory-map enumeration to the Frida bridge
fix(cutter): use ASCII labels for the relative-seek toolbar
test(ghidra): drive the real ProgramTree widget in the L3 gate
```

Common types are `feat`, `fix`, `docs`, `test`, `refactor`, and `chore`.
The changelog is generated from these messages, so keep them accurate.

## Submitting Changes

1. Push your branch to your fork:

    ```bash
    git push origin feat/short-description
    ```

2. Open a Pull Request against `main`. Give it a clear description,
   reference any related issues, and include screenshots for UI changes.

### Pull Request Checklist

- [ ] `just lint`, `just basedpyright`, `just pydoclint`, and
      `just pydocstyle` pass with no findings
- [ ] Tests added or updated, and `just test` passes
- [ ] Type hints and Google-style docstrings are complete
- [ ] Commit messages follow Conventional Commits
- [ ] No suppression comments, placeholders, or stubbed-out behavior

## Questions

Open an issue for anything about contributing, or browse the local
[documentation](docs/). We are happy to help.
