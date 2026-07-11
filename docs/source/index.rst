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

* **Binary Analysis**: Deep analysis of PE, ELF, and Mach-O executables
* **Protection Detection**: Identify common protection schemes (VMProtect, Themida, etc.)
* **License Analysis**: Analyze licensing validation mechanisms
* **AI-Powered**: Integrated AI assistance for complex analysis tasks
* **GUI Interface**: Modern PyQt6-based graphical interface

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
