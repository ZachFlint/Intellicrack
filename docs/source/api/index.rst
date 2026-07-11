API Reference
=============

This section contains the complete API reference for Intellicrack.

.. autosummary::
   :toctree: _autosummary
   :template: custom-module-template.rst
   :recursive:

   intellicrack

Module Index
------------

Core Modules
~~~~~~~~~~~~

.. autosummary::
   :toctree: _autosummary
   :recursive:

   intellicrack.core

Bridge Integrations
~~~~~~~~~~~~~~~~~~~

The ``intellicrack.bridges`` module provides external tool integrations:

* **GhidraBridge** - Ghidra headless analysis and decompilation
* **CutterBridge** - Cutter/rizin binary analysis
* **FridaBridge** - Dynamic instrumentation via Frida
* **X64DbgBridge** - x64dbg debugger integration
* **BinaryOperationsBridge** - Generic binary operations (PE/ELF/Mach-O)
* **ProcessBridge** - Windows process manipulation

AI Providers
~~~~~~~~~~~~

The ``intellicrack.providers`` module contains LLM integrations:

* **AnthropicProvider** - Claude API integration
* **OpenAIProvider** - GPT API integration
* **GoogleProvider** - Gemini API integration
* **OllamaProvider** - Local Ollama models
* **OpenRouterProvider** - OpenRouter API aggregator
* **HuggingFaceProvider** - Transformers integration
* **GrokProvider** - xAI Grok integration

Sandbox Environment
~~~~~~~~~~~~~~~~~~~

The ``intellicrack.sandbox`` module provides isolated execution:

* **WindowsSandbox** - Windows Sandbox integration
* **QEMUSandbox** - QEMU VM sandbox for cross-platform analysis
* **SandboxManager** - Unified sandbox management interface
* **SandboxConfig** - Configuration for sandbox instances
* **ExecutionReport** - Analysis execution results

Credentials Management
~~~~~~~~~~~~~~~~~~~~~~

.. autosummary::
   :toctree: _autosummary
   :recursive:

   intellicrack.credentials

User Interface
~~~~~~~~~~~~~~

The ``intellicrack.ui`` module contains PyQt6 GUI components:

* **MainWindow** - Primary application window
* **ChatPanel** - AI chat interface
* **HexEditorWidget** - Binary hex editor
* **GhidraPanel** - Ghidra analysis panel
* **CutterPanel** - Cutter/rizin analysis panel
* **X64DbgPanel** - x64dbg debugger panel
