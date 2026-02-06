Architecture
============

Intellicrack is built with a modular architecture designed for extensibility
and maintainability.

Overview
--------

.. code-block:: text

   intellicrack/
   ├── bridges/         # External tool integrations (Ghidra, radare2, Frida)
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

* **Ghidra**: Advanced decompilation
* **radare2**: Binary analysis framework
* **Frida**: Dynamic instrumentation
* **Capstone**: Disassembly engine
