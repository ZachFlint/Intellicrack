This document provides an overview of the Intellicrack project, its setup, and development conventions, generated for use as instructional context for QWEN.

## Project Overview

Intellicrack is a comprehensive binary analysis and security research tool. It features a modern GUI, AI integration, and advanced analysis capabilities. It is a highly sophisticated analysis tool designed to detect licensing protections used in commercial software. Once it detects the correct protections used, Intellicrack will use or create an exploit to bypass the protections. It is essentially a highly sophisticated cracking tool.

### Intellicrack Principles

<system-reminder>
[1] ALL code must be production-ready with genuine, effective, & sophisticated functionality. Absolutely NO placeholders, pseudocode, stubs, mocks, hardcoded data/responses, simulated, or simple ineffective implementations.
[2] Code must be error-free and strictly adhere to language-specific coding standards and best practices. ALL new code and edits must be validated with ruff and ALL findings must be corrected.
[3] Real-world binary analysis and software cracking capabilities are ESSENTIAL to Intellicrack's functionality. They must be sophisticated and effective against modern licensing protections.
[4] Follow common development principles (where relevant) including:
 • SOLID(Single Responsibility Principle, Open/Closed Principle, Liskov Substitution Principle, Interface Segregation Principle, and Dependency Inversion Principle)
 • DRY (Don't Repeat Yourself)
 • KISS (Keep It Simple, Stupid)
[5] ALL code requires explicit type hints/annotations that are fully basedpyright compliant. Code must be absolutely and completely type correct with zero basedpyright findings acceptable. NEVER use type suppression comments (type-ignore directives, pyright-ignore directives, or any inline suppression mechanism) under any circumstance - fix the actual type error instead. NEVER edit the [tool.basedpyright] section in pyproject.toml - the basedpyright configuration is locked and immutable. Windows compatibility PRIORITY with proper platform checks. NEVER delete method bindings - create FUNCTIONAL missing functions instead. NO comments/emojis/TODO markers unless requested. MAINTAIN functionality over "cleaner" code.
</system-reminder>

### Project Structure

```text
intellicrack/
├── src/intellicrack/      # Main package source code
│   ├── core/             # Configuration, orchestration, types, session, logging
│   ├── bridges/          # Tool integrations (Ghidra, x64dbg, Frida, radare2)
│   ├── providers/        # LLM providers (Anthropic, OpenAI, Google, Ollama, etc.)
│   ├── sandbox/          # Windows Sandbox isolation
│   ├── ui/               # PyQt6 graphical interface
│   ├── credentials/      # API key management
│   ├── plugins/          # Plugin infrastructure
│   └── assets/           # Configuration files and resources
├── tests/                # Test suite
├── tools/                # External tool binaries
└── config.toml           # Main configuration
```

### Coding Standards

- All code must be written for complete compatibility with Windows platforms as a priority.

- **Python Code Style:**
  - Follow PEP 8.
  - Use Black for code formatting (line length: 100).
  - Use type hints.
  - Write docstrings for all public functions and classes.
  - Keep functions focused and under 50 lines when possible.
- **Import Order:**
  1. Standard library imports
  2. Third-party imports
  3. Local application imports

### Testing

- **Running Tests:**

    ```bash
    pytest                 # Run all tests
    pytest --cov=intellicrack # Run with coverage
    pytest tests/test_core_components.py # Run specific test file
    pytest -v              # Run with verbose output
    ```

- **Writing Tests:**
  - Place tests in the `tests/` directory, mirroring the source code structure.
  - Use descriptive test names.
  - Include positive and negative test cases.
  - Must test Intellicrack functionality with genuine real tests

### Environment Usage

- **Pixi environment location**: `D:\Intellicrack\.pixi\envs\default`
- **Activation**: `pixi shell` or use `pixi run <command>`

### Submitting Changes

1. Create a new branch for your feature or fix.
2. Make changes, write/update tests, and update documentation.
3. Commit with clear, descriptive messages.
4. Push to your fork.
5. Create a Pull Request on GitHub, ensuring:
   - Clear title and description.
   - Reference related issues.
   - Screenshots for UI changes.
   - All tests pass.
   - Code follows style guidelines.
   - Self-review completed.
   - Comments for complex logic.
   - No new linting warnings.
   - Commit messages are clear and descriptive.
