Development Guide
=================

This guide covers development practices for contributing to Intellicrack.

Development Setup
-----------------

1. Clone the repository
2. Install dependencies with ``just install``
3. Activate the environment with ``pixi shell``

Code Style
----------

Intellicrack follows strict code style guidelines:

* **Python**: PEP 8 with Ruff enforcement
* **Type Hints**: Full basedpyright strict compliance
* **Docstrings**: Google-style docstrings

Running Linters
~~~~~~~~~~~~~~~

.. code-block:: bash

   just lint        # Check code style
   just lint-fix    # Auto-fix issues
   just basedpyright    # Type checking
   just ruff        # Ruff linting

Testing
-------

Tests run inside a Docker sandbox container for isolation (``just test``):

.. code-block:: bash

   just test              # Unit tests
   just test all          # Full test suite
   just test-coverage     # With coverage report

Writing Tests
~~~~~~~~~~~~~

* Tests must use REAL data, no mocks
* Place tests in ``tests/`` directory
* Use pytest fixtures for setup

Building Documentation
----------------------

Generate documentation with Sphinx:

.. code-block:: bash

   just docs build   # Build HTML docs
   just docs open    # Open in browser
   just docs apidoc  # Regenerate API docs

Project Structure
-----------------

.. code-block:: text

   Intellicrack/
   ├── src/intellicrack/    # Main package
   ├── tests/               # Test suite
   ├── docs/                # Documentation
   ├── scripts/             # Utility scripts
   ├── tools/               # External tools
   └── reports/             # Lint reports

Contributing
------------

1. Create a feature branch
2. Make changes following code style
3. Run all linters and tests
4. Submit a pull request

Commit messages should follow conventional commits format.
