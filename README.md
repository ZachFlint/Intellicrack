# Intellicrack

An AI-powered reverse engineering orchestration platform that provides a
unified interface for controlling multiple reverse engineering tools
through natural language interaction.

![Python](https://img.shields.io/badge/python-3.13%2B-blue)
![License](https://img.shields.io/badge/license-GPL%20v3%2B-green)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

## Overview

Intellicrack (v0.1.0a1) is a unified workspace for reverse engineering and
binary analysis. It serves as an orchestration layer where an LLM provider
acts as central intelligence, coordinating between the user interface, tool
bridges, and analysis modules so that disassemblers, debuggers, runtime
instrumentation, and sandboxes operate against a shared analysis context.
Workflows range from general binary inspection and vulnerability research to
protocol reversing, malware triage, and software protection analysis.

### What Intellicrack Does

- **Static Binary Analysis**: PE/ELF/Mach-O parsing, section enumeration,
  entropy analysis, import/export extraction, string extraction, and
  disassembly/decompilation through integrated tooling
- **Dynamic Analysis**: Process attachment, function hooking, memory
  read/write, breakpoint management, register inspection
- **Algorithm & Protection Detection**: Identifies crypto primitives (MD5,
  SHA256, RSA, AES), HWID/time-based checks, validation routines, crypto API
  calls, and magic constants for use in vulnerability research, malware
  triage, and software protection analysis
- **Script Generation**: AI-generated Frida hooks, Ghidra plugins,
  Cutter/Rizin commands, x64dbg scripts
- **Sandbox Execution**: Windows Sandbox integration with
  process/file/registry/network activity monitoring
- **Binary Patching**: Direct modification with offset/RVA support and patch tracking

## Architecture

### Core Modules

- **Orchestrator** (`core/orchestrator.py`): Manages conversation flow,
  tool calling with confirmation workflow, and iterative tool execution
- **Session Manager** (`core/session.py`): SQLite-based persistence for
  conversations, loaded binaries, tool states, and patches
- **Analysis Aggregator** (`core/analysis_aggregator.py`): Queries connected
  bridges and aggregates their output into a unified `BridgeAnalysisSummary`,
  including detected protection algorithms, validation routines, and crypto
  API usage
- **Config** (`core/config.py`): TOML-based configuration management
- **Types** (`core/types.py`): Comprehensive type system with 50+ dataclasses
  (72 total type definitions including enums and protocols)

### Tool Bridges

Unified interfaces for external reverse engineering tools:

- **Ghidra** (`bridges/ghidra.py`): Static analysis and decompilation via ghidra_bridge
- **x64dbg** (`bridges/x64dbg.py`): Windows debugging via named pipe
  communication with custom plugin
- **Frida** (`bridges/frida_bridge.py`): Runtime instrumentation, function
  hooking, memory manipulation
- **Cutter/Rizin** (`bridges/cutter.py`): Multi-platform binary analysis via
  rzpipe/r2pipe (prefers rzpipe/rizin, falls back to r2pipe/radare2)
- **Binary** (`BinaryOperationsBridge` in `bridges/base.py`): Direct
  PE/ELF/Mach-O parsing via lief, orchestrated through `core/orchestrator.py`

### LLM Providers

Multiple provider implementations with unified interface:

- Anthropic Claude
- OpenAI GPT-4/3.5
- Google Gemini
- Ollama
- OpenRouter
- Hugging Face
- xAI Grok
- Local Transformers (in-process HuggingFace models with Intel XPU/CPU
  acceleration)

### User Interface

PyQt6-based GUI featuring:

- Chat interface for natural language interaction
- Tool output panels with disassembly/decompilation viewing
- Provider/model selection and configuration dialogs
- Embedded tool widgets (x64dbg, Cutter, Ghidra, Frida)
- Built-in native hex editor (HexEditorBridge)
- Session management for saving/loading analysis sessions
- Protection analysis panel displaying detected algorithms, validation
  routines, and crypto usage

## Requirements

- **OS**: Windows
- **Python**: 3.13+
- **RAM**: 8GB minimum (16GB recommended)

### Optional Tools

- Ghidra (static analysis/decompilation)
- x64dbg (Windows debugging)
- Cutter/Rizin (binary analysis)
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

```text
intellicrack/
├── src/intellicrack/
│   ├── core/           # Configuration, orchestration, types, session, logging
│   ├── bridges/        # Tool integrations (Ghidra, x64dbg, Frida, Cutter/Rizin)
│   ├── providers/      # LLM providers (Anthropic, OpenAI, Google, Ollama, etc.)
│   ├── sandbox/        # Windows Sandbox isolation
│   ├── ui/             # PyQt6 graphical interface
│   ├── credentials/    # API key management
│   └── assets/         # Configuration files and resources
├── tests/              # Test suite
├── tools/              # External tool binaries
└── config.toml         # Main configuration
```

## Configuration

Intellicrack uses TOML-based configuration (`config.toml`) with credential
loading from `.env` files. Settings include:

- Provider configurations (API base, timeouts, retries)
- Tool configurations (paths, enable/disable, timeouts)
- Sandbox settings (memory, network, timeout)
- UI preferences (theme, fonts, window state)

## License

GNU General Public License v3.0 - see [LICENSE](LICENSE)

## Disclaimer

Intellicrack is developed for reverse engineering, vulnerability research,
and defensive security work. Typical uses include understanding unknown
binaries, auditing third-party code, researching software protection
mechanisms, and helping developers identify weaknesses in their own
implementations. This tool is intended for controlled research environments
and authorized security assessment.
