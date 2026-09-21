Intellicrack Documentation
===========================

**Intellicrack** is a unified desktop workspace that orchestrates external
binary-analysis tools (Ghidra, Cutter/rizin, Frida, x64dbg) and AI providers
behind a single PyQt6 GUI. Rather than replacing debuggers, disassemblers, or
model backends, it connects and coordinates them so reverse-engineering and
analysis workflows share context, outputs, and AI assistance in one interface.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   getting_started
   architecture
   api/index
   development

Features
--------

* **AI assistance**: Anthropic, OpenAI, Google, xAI, OpenRouter, Ollama,
  Hugging Face, or a local in-process model, able to drive the analysis tools
* **Static analysis**: parse PE, ELF, and Mach-O; inspect sections, imports and
  exports, strings, and entropy; disassemble and decompile with Ghidra, Cutter,
  rizin, and radare2
* **Dynamic analysis**: debug with x64dbg, instrument with Frida, and inspect
  live Windows processes
* **Sandboxing**: run a target in an isolated Windows Sandbox or QEMU virtual
  machine and review the activity it produced
* **Hex editor**: binary-structure templates, data transforms, hashing,
  diffing, and patch export
* **Binary patching**: apply edits by file offset or RVA and track them
* **Script generation**: Frida, Ghidra, x64dbg, and Cutter / rizin scripts
* **YARA scanning**: match rules against files and process memory
* **GUI**: PyQt6 desktop workspace with session state

Quick Start
-----------

Installation
~~~~~~~~~~~~

.. code-block:: bash

   pixi install
   pixi run dev

Running the GUI
~~~~~~~~~~~~~~~

.. code-block:: bash

   pixi run gui

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
