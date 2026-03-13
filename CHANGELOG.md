# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-24

### Initial Release

- **Core Framework**:
  - AI-powered reverse engineering orchestration platform
  - Multi-format binary support (PE, ELF, Mach-O) via pefile and lief
  - License protection analysis with algorithm detection
  - Session management with SQLite persistence

- **Tool Bridges**:
  - Ghidra integration for static analysis and decompilation
  - x64dbg integration for Windows debugging via named pipe
  - Frida integration for runtime instrumentation and hooking
  - Cutter/Rizin integration for multi-platform binary analysis
  - Direct binary operations via pefile/lief/capstone

- **LLM Providers**:
  - Anthropic Claude (up to 200k context)
  - OpenAI GPT-4/3.5
  - Google Gemini (up to 2M context)
  - Ollama (local and cloud)
  - OpenRouter (200+ models)
  - Hugging Face Inference API
  - xAI Grok

- **User Interface**:
  - PyQt6-based GUI with chat interface
  - Tool output panels with disassembly viewing
  - Provider/model configuration dialogs
  - Embedded tool widgets (x64dbg, Cutter, HxD)
  - Session management for saving/loading analysis
  - Licensing analysis panel

- **Sandbox Support**:
  - Windows Sandbox integration for isolated execution
  - Process/file/registry/network activity monitoring

- **License Analysis**:
  - Algorithm detection (MD5, SHA256, RSA, AES, HWID, time-based)
  - Validation function identification
  - Crypto API usage detection
  - Magic constant extraction
  - Confidence scoring

### Technical Infrastructure

- **Development Environment**:
  - Python 3.13+ support
  - Windows platform priority
  - Pixi package management
  - TOML-based configuration

- **Code Quality**:
  - Full type hints with mypy strict compliance
  - Ruff linting
  - pytest test framework
  - Google-style docstrings
