# Intellicrack

Intellicrack is a Windows desktop application that unifies binary-analysis
and reverse-engineering tools with AI model providers in a single,
orchestrated workspace.

![Python](https://img.shields.io/badge/python-3.13%2B-blue)
![License](https://img.shields.io/badge/license-GPL%20v3%2B-green)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

## Overview

Intellicrack brings disassemblers, debuggers, decompilers, runtime
instrumentation, sandboxes, and a hex editor together with AI providers,
and coordinates them against a shared analysis context. Instead of juggling
separate windows and copying results between them, you drive everything
from one interface: load a target, run tools, inspect their output, and
hand that context to an AI assistant that can call the same tools on your
behalf.

Work is grouped into sessions that keep your conversation, loaded binaries,
tool state, and patches together, so you can pick a target back up where
you left off.

Intellicrack is in early development (version 0.1.0a1).

## Features

- **AI assistance** from the provider of your choice: Anthropic Claude,
  OpenAI, Google Gemini, xAI Grok, OpenRouter, Ollama, Hugging Face, or a
  local model running in-process. The assistant can drive the analysis
  tools for you, and asks for confirmation before anything changes a
  target.
- **Static analysis**: parse PE, ELF, and Mach-O files; inspect sections,
  imports and exports, strings, and entropy; disassemble; and decompile
  and explore with Ghidra, Cutter, rizin, and radare2.
- **Dynamic analysis**: debug with x64dbg, hook and instrument running
  code with Frida, and inspect and control live Windows processes.
- **Sandboxing**: run a target in an isolated Windows Sandbox or QEMU
  virtual machine and review the file, registry, network, and process
  activity it produced.
- **Hex editor**: a fast built-in editor with binary-structure templates,
  data transforms, hashing, diffing, and patch export.
- **Binary patching**: apply edits by file offset or RVA and keep track of
  them.
- **Script generation**: have the assistant write Frida, Ghidra, x64dbg,
  or Cutter / rizin scripts for the task at hand.
- **YARA scanning**: match rules against files and process memory.

## Requirements

Intellicrack runs on 64-bit Windows 10 or later. The built-in hex editor
requires a CPU that supports the x86-64-v2 level (SSE4.2 and POPCNT).
Everything else Intellicrack needs is included in the installer.

## Installation

Intellicrack ships as a single, offline installer for 64-bit Windows,
`Intellicrack-Setup.exe`. It contains everything needed to run on a clean
machine, including a private Python runtime, a private Java runtime, and
the tools it drives (Ghidra, radare2, rizin / Cutter, x64dbg, NASM, and
QEMU), so there is nothing to install beforehand.

Run `Intellicrack-Setup.exe` and follow the wizard. The bundled tools, the
sandbox guest image, and local model support are optional components you
can include or leave out. Leave a tool out to use your own copy instead,
and point Intellicrack at it later from Tools > Tool Settings. The
installer changes no system-wide settings; your configuration, API keys,
logs, and data are kept under `%LOCALAPPDATA%\Intellicrack` and remain
after an uninstall.

## Usage

Start Intellicrack from the Start Menu or the installed `Intellicrack.exe`.
It requests administrator rights on Windows, which it uses for its
debugging and sandbox features.

On first launch, open Providers to add an API key (or select a local
Ollama or Transformers model), then load a binary and work with it from the
chat panel or the individual tool tabs.

## Configuration

Intellicrack reads its settings from a `config.toml` file (providers, tool
locations and timeouts, sandbox limits, the UI theme, and session and
logging options) and API keys from a `.env` file. Both live under
`%LOCALAPPDATA%\Intellicrack`, and most settings are also editable from the
application's Preferences and settings dialogs.

## Contributing

Development setup, the build and test workflow, coding standards, and the
pull-request process are documented in
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Intellicrack is released under the GNU General Public License v3.0 or
later. See [LICENSE](LICENSE).
