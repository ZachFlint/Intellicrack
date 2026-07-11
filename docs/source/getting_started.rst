Getting Started
===============

This guide will help you get started with Intellicrack.

Prerequisites
-------------

* Python 3.13 or later
* Windows 10/11 (primary platform)
* Pixi package manager
* ``just`` command runner (every workflow command is invoked as ``just ...``)
* Docker (``just test`` runs the test suite inside a Docker sandbox container)
* Rust toolchain (for the native ``intellicrack-hexcore`` hex-editor module,
  built via ``just build-hexcore``)

Installation
------------

Clone the repository and install dependencies:

.. code-block:: bash

   git clone https://github.com/zacharyflint/intellicrack.git
   cd intellicrack
   just install

This will:

1. Install Python dependencies via Pixi
2. Build the Rust ``intellicrack-hexcore`` native module
3. Download and install Ghidra
4. Download and install radare2
5. Download and install QEMU
6. Download and install x64dbg (plus the x64dbg bridge plugin)
7. Download and install Cutter

Running Intellicrack
--------------------

Command Line
~~~~~~~~~~~~

.. code-block:: bash

   pixi run dev

GUI Mode
~~~~~~~~

.. code-block:: bash

   pixi run gui

Configuration
-------------

Intellicrack uses environment variables and configuration files for settings.
Copy the example configuration:

.. code-block:: bash

   cp .env.example .env

Edit ``.env`` to configure:

* AI provider settings (OpenAI, Anthropic, etc.)
* Tool paths (Ghidra, radare2)
* Analysis options
