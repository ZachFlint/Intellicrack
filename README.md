# Intellicrack

An AI-powered reverse engineering orchestration platform that provides a unified interface for controlling multiple reverse engineering tools through natural language interaction.

![Python](https://img.shields.io/badge/python-3.13%2B-blue)
![License](https://img.shields.io/badge/license-GPL%20v3%2B-green)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

## Overview

Intellicrack (v0.1.0a1) is designed for analyzing and defeating software licensing protections. It serves as a unified orchestration layer where an LLM provider acts as central intelligence, coordinating between the user interface, tool bridges, and analysis modules.

### What Intellicrack Does

- **License Protection Analysis**: Detects algorithm types (MD5, SHA256, RSA, AES, HWID, time-based), validation functions, crypto API calls, and magic constants
- **Binary Analysis**: PE/ELF/Mach-O parsing, section enumeration, entropy analysis, import/export extraction, string extraction
- **Dynamic Analysis**: Process attachment, function hooking, memory read/write, breakpoint management, register inspection
- **Script Generation**: AI-generated Frida hooks, Ghidra plugins, radare2 commands, x64dbg scripts
- **Sandbox Execution**: Windows Sandbox integration with process/file/registry/network activity monitoring
- **Binary Patching**: Direct modification with offset/RVA support and patch tracking

## Architecture

### Core Modules

- **Orchestrator** (`core/orchestrator.py`): Manages conversation flow, tool calling with confirmation workflow, and iterative tool execution
- **Session Manager** (`core/session.py`): SQLite-based persistence for conversations, loaded binaries, tool states, and patches
- **License Analyzer** (`core/license_analyzer.py`): Specialized module for detecting protection algorithms, validation functions, and crypto API usage
- **Config** (`core/config.py`): TOML-based configuration management
- **Types** (`core/types.py`): Comprehensive type system with 70+ dataclasses

### Tool Bridges

Unified interfaces for external reverse engineering tools:

- **Ghidra** (`bridges/ghidra.py`): Static analysis and decompilation via ghidra_bridge
- **x64dbg** (`bridges/x64dbg.py`): Windows debugging via named pipe communication with custom plugin
- **Frida** (`bridges/frida_bridge.py`): Runtime instrumentation, function hooking, memory manipulation
- **radare2** (`bridges/radare2.py`): Multi-platform binary analysis via r2pipe
- **Binary** (`bridges/binary.py`): Direct PE/ELF/Mach-O parsing using pefile/lief

### LLM Providers

Multiple provider implementations with unified interface:

- Anthropic Claude (up to 200k context)
- OpenAI GPT-4/3.5
- Google Gemini (up to 2M context)
- Ollama (local + cloud)
- OpenRouter (200+ models)
- Hugging Face
- xAI Grok

### User Interface

PyQt6-based GUI featuring:

- Chat interface for natural language interaction
- Tool output panels with disassembly/decompilation viewing
- Provider/model selection and configuration dialogs
- Embedded tool widgets (x64dbg, Cutter, HxD)
- Session management for saving/loading analysis sessions
- Licensing analysis panel displaying detected protections

## Requirements

- **OS**: Windows
- **Python**: 3.13+
- **RAM**: 8GB minimum (16GB recommended)

### Optional Tools

- Ghidra (static analysis/decompilation)
- x64dbg (Windows debugging)
- radare2 (binary analysis)
- Frida (runtime instrumentation)

## Installation

### Prerequisites

Install Pixi package manager:

```powershell
iwr -useb https://pixi.sh/install.ps1 | iex
```

### Setup

```bash
git clone https://github.com/ZachFlint/Intellicrack.git
cd Intellicrack
pixi install
```

### Activate Environment

```bash
pixi shell
```

## Usage

### GUI Mode

```bash
python -m intellicrack
```

### Python API

```python
from intellicrack import main
main()
```

## Project Structure

```
intellicrack/
├── src/intellicrack/
│   ├── core/           # Configuration, orchestration, types, session, logging
│   ├── bridges/        # Tool integrations (Ghidra, x64dbg, Frida, radare2)
│   ├── providers/      # LLM providers (Anthropic, OpenAI, Google, Ollama, etc.)
│   ├── sandbox/        # Windows Sandbox isolation
│   ├── ui/             # PyQt6 graphical interface
│   ├── credentials/    # API key management
│   ├── plugins/        # Plugin infrastructure
│   └── assets/         # Configuration files and resources
├── tests/              # Test suite
├── tools/              # External tool binaries
└── config.toml         # Main configuration
```

## Configuration

Intellicrack uses TOML-based configuration (`config.toml`) with credential loading from `.env` files. Settings include:

- Provider configurations (API base, timeouts, retries)
- Tool configurations (paths, enable/disable, timeouts)
- Sandbox settings (memory, network, timeout)
- UI preferences (theme, fonts, window state)

## License

GNU General Public License v3.0 - see [LICENSE](LICENSE)

## Disclaimer

Intellicrack is developed for defensive security research to help software developers identify weaknesses in their own licensing protection mechanisms, test robustness of protection implementations, and strengthen defenses by understanding bypass techniques. This tool operates in controlled research environments for authorized security assessment.
