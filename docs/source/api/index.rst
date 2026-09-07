API Reference
=============

This section contains the complete API reference for Intellicrack. Every
package, module, class, and function below is generated directly from the
source tree, so the reference always reflects the current implementation.

.. autosummary::
   :toctree: _autosummary
   :recursive:

   intellicrack

Subsystem Overview
------------------

The generated tree above documents every module. The summaries below orient
you to the major subsystems before you drill into their pages.

Core Orchestration
~~~~~~~~~~~~~~~~~~~

The ``intellicrack.core`` package holds session management, the tool
orchestrator, process management, configuration, and shared type definitions
that tie the platform together.

Bridge Integrations
~~~~~~~~~~~~~~~~~~~~

The ``intellicrack.bridges`` package provides external tool integrations:

* **GhidraBridge** - Ghidra headless analysis and decompilation
* **CutterBridge** - Cutter/rizin binary analysis
* **FridaBridge** - Dynamic instrumentation via Frida
* **X64DbgBridge** - x64dbg debugger integration
* **HexEditorBridge** - Hex editor / hexcore operations
* **ProcessBridge** - Windows process manipulation

AI Providers
~~~~~~~~~~~~

The ``intellicrack.providers`` package contains LLM integrations:

* **AnthropicProvider** - Claude API integration
* **OpenAIProvider** - GPT API integration
* **GoogleProvider** - Gemini API integration
* **OllamaProvider** - Local Ollama models
* **OpenRouterProvider** - OpenRouter API aggregator
* **HuggingFaceProvider** - HuggingFace Inference integration
* **GrokProvider** - xAI Grok integration

Sandbox Environment
~~~~~~~~~~~~~~~~~~~

The ``intellicrack.sandbox`` package provides isolated execution:

* **WindowsSandbox** - Windows Sandbox integration
* **QEMUSandbox** - QEMU VM sandbox for cross-platform analysis
* **SandboxManager** - Unified sandbox management interface
* **SandboxConfig** - Configuration for sandbox instances
* **ExecutionReport** - Analysis execution results

Credentials Management
~~~~~~~~~~~~~~~~~~~~~~

The ``intellicrack.credentials`` package handles API key storage, environment
loading, and OAuth flows for the connected providers.

User Interface
~~~~~~~~~~~~~~

The ``intellicrack.ui`` package contains PyQt6 GUI components:

* **MainWindow** - Primary application window
* **ChatPanel** - AI chat interface
* **HexEditorWidget** - Binary hex editor
* **GhidraPanel** - Ghidra analysis panel
* **CutterPanel** - Cutter/rizin analysis panel
* **X64DbgPanel** - x64dbg debugger panel
