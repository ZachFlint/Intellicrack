Architecture
============

Intellicrack is built with a modular architecture designed for extensibility
and maintainability.

Overview
--------

.. code-block:: text

   intellicrack/
   ├── bridges/         # External tool integrations (Ghidra, Cutter/rizin, Frida, x64dbg)
   ├── core/            # Core analysis engine
   ├── credentials/     # Credential and OAuth management
   ├── providers/       # AI provider integrations
   ├── sandbox/         # Sandbox environment management
   └── ui/              # PyQt6 GUI components

Core Components
---------------

AI Providers
~~~~~~~~~~~~

The providers module provides integration with multiple AI providers:

* OpenAI (GPT-4, GPT-3.5)
* Anthropic (Claude)
* Google (Gemini)
* Grok (xAI)
* OpenRouter (multi-provider aggregator)
* HuggingFace / transformers (local models)
* Local models (Ollama, GGUF)

Core Analysis
~~~~~~~~~~~~~

The core module handles binary analysis:

* PE/ELF/Mach-O parsing
* Disassembly and decompilation
* Control flow analysis
* Protection detection

UI Layer
~~~~~~~~

The GUI is built with PyQt6:

* Modern dark theme (QDarkStyle)
* Syntax-highlighted code views
* Interactive hex editor
* Analysis result visualization

Bridge Integrations
~~~~~~~~~~~~~~~~~~~

External tool integrations:

* **Ghidra**: Advanced decompilation and static analysis
* **Cutter/rizin**: Binary analysis and disassembly framework
* **Frida**: Dynamic instrumentation
* **x64dbg**: Windows debugger integration
* **Process**: Windows process inspection and manipulation
* **Hex editor**: Binary editing backed by the native hexcore module
* **Sandbox**: Isolated execution environments
