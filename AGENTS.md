# Intellicrack Agent Guidelines

## Core Development Principles

<system-reminder>
[1] ALL code must be production-ready with genuine, effective, & sophisticated functionality. Absolutely NO placeholders, stubs, mocks, hardcoded data/responses, simulated, or simple ineffective implementations.
[2] Code must be error-free and strictly adhere to language-specific coding standards and best practices. ALL new code and edits must be validated with ruff and ALL findings must be corrected.
[3] Real-world binary analysis and software cracking capabilities are ESSENTIAL to Intellicrack's functionality. They must be sophisticated and effective against modern licensing protections.
[4] Follow common development principles (where relevant) including:
 • SOLID(Single Responsibility Principle, Open/Closed Principle, Liskov Substitution Principle, Interface Segregation Principle, and Dependency Inversion Principle)
 • DRY (Don't Repeat Yourself)
 • KISS (Keep It Simple, Stupid)
[5] ALL code requires explicit type hints/annotations that are fully basedpyright compliant. Code must be absolutely and completely type correct with zero basedpyright findings acceptable. NEVER use type suppression comments (type-ignore directives, pyright-ignore directives, or any inline suppression mechanism) under any circumstance - fix the actual type error instead. NEVER edit the [tool.basedpyright] section in pyproject.toml - the basedpyright configuration is locked and immutable. Windows compatibility PRIORITY with proper platform checks. NEVER delete method bindings - create FUNCTIONAL missing functions instead. NO comments/emojis/TODO markers unless requested. MAINTAIN functionality over "cleaner" code.
</system-reminder>

## Build, Lint, and Test Commands

- Use `just` for development workflows:
  - `just test` - Run all unit tests with real data validation
  - `just test-coverage` - Run tests with 95%+ coverage requirement
  - `just lint` - Run Ruff linting for Python
  - `just lint-all` - Lint all languages (Python, JS, Java, Rust, Markdown)
- To run a single test, use pytest directly, e.g.:

    ```bash
    pytest tests/path/to/test_file.py::test_function_name
    ```

## Code Style Guidelines

- No stubs, mocks, or placeholders; all code must be production-ready
- No TODO or explanatory comments unless explicitly requested
- Prioritize Windows 11 compatibility
- Use lazy and conditional imports for heavy modules (e.g., PyTorch, Frida)
- Use `getattr()` and `hasattr()` for safe attribute access
- Use try/except blocks for import errors with graceful fallbacks
- Follow thread-safe import patterns for PyTorch (`safe_torch_import()`)
- Naming conventions: clear, descriptive, consistent with existing codebase

## Development Guidelines

This repository follows strict AI assistant guidelines to ensure high-quality,
production-ready code:

- NO stubs, mocks, or placeholders; all code must be fully functional
- NO TODO or explanatory comments unless explicitly requested
- Prioritize Windows 11 compatibility
- Use lazy and conditional imports for heavy modules (e.g., PyTorch, Frida) to
  avoid circular dependencies
- Use `getattr()` and `hasattr()` for safe attribute access
- Use try/except blocks for import errors with meaningful fallbacks
- Follow thread-safe import patterns for PyTorch (`safe_torch_import()`)
- Naming conventions must be clear, descriptive, and consistent with the
  existing codebase

## Error Handling Patterns

- Use safe attribute access methods (`getattr()`, `hasattr()`)
- Implement try/except blocks for import errors with graceful degradation

## Import Structure Conventions

- Lazy imports for heavy modules to avoid circular dependencies
- Conditional imports with availability flags (e.g., `HAS_TORCH`,
  `FRIDA_MODULES_AVAILABLE`)
- Thread-safe imports for PyTorch modules

## Build, Lint, and Test Commands

- Use `just` for development workflows:
  - `just test` - Run all unit tests with real data validation
  - `just test-coverage` - Run tests with 95%+ coverage requirement
  - `just lint` - Ruff linting for Python
  - `just lint-all` - Lint all languages (Python, JS, Java, Rust, Markdown)
- To run a single test, use pytest directly, e.g.:

    ```bash
    pytest tests/path/to/test_file.py::test_function_name
    ```

## Application Launch

- Primary launch method:

    ```bash
    python -m intellicrack
    ```

- Or import and call main directly:

    ```python
    from intellicrack import main
    main()
    ```

## Environment Setup

- Pixi environment located at `D:\Intellicrack\.pixi\envs\default`
- Activate with `pixi shell` or run commands with `pixi run <command>`
- Configuration via `intellicrack.core.config.Config`
- Dependencies managed via `pyproject.toml` and `pixi.toml`

## Project-Specific Patterns

- Configuration management via `intellicrack.core.config.Config`
- Binary analysis supports PE, ELF, Mach-O formats via `bridges/binary.py`
- License protection detection via `intellicrack.core.license_analyzer`
- AI model integration supports multiple providers (Anthropic, OpenAI, Google, Ollama, OpenRouter, Hugging Face, Grok)

## Security & Ethics Context

- Tool is exclusively for security research on licensing protection mechanisms
- Focus on defensive security analysis by software developers
- Not for malware creation, system exploitation, or unauthorized access

## Documentation Standards

- Architecture docs in `docs/architecture/`
- API docs auto-generated from docstrings via Sphinx
- User guides in `docs/guides/`
- Configuration reference documentation

Maintain these standards strictly to ensure consistency and production readiness
in all agentic coding operations.
