# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for the bridges/core import cycle.

Guards against re-introducing the circular import between
``intellicrack.bridges.base`` and ``intellicrack.core.tools``. The cycle
only manifests when a bridge submodule is imported as the *first* import
in a fresh interpreter (before ``intellicrack.core`` is loaded), so every
assertion here runs in an isolated subprocess whose single statement is
the import under test. An in-process import cannot reproduce the failure
because the test session's own ``conftest`` has already imported
``intellicrack.core`` and warmed the module cache.

The historical failure was::

    ImportError: cannot import name 'TOOL_CAPABILITY_MAP' from partially
    initialized module 'intellicrack.bridges.base'

raised when ``intellicrack.core.__init__`` eagerly imported
``intellicrack.core.tools`` (which imports back from the still-executing
``intellicrack.bridges.base``) while resolving ``get_logger`` for the
bridge base module.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Final

import pytest

import intellicrack.core as core_pkg


_IMPORT_TIMEOUT_S: Final[float] = 120.0

_BRIDGE_MODULES: Final[tuple[str, ...]] = (
    "base",
    "schemas",
    "cutter",
    "frida_bridge",
    "ghidra",
    "hex_editor",
    "installer",
    "process",
    "sandbox_bridge",
    "x64dbg",
)


def _run_fresh_import(statement: str) -> subprocess.CompletedProcess[str]:
    """Execute a single import statement in an isolated interpreter.

    The child process inherits this interpreter and its environment (so
    the installed ``intellicrack`` distribution resolves), but starts with
    an empty module cache. This reproduces the exact condition under which
    the circular import fired: the given statement is the first thing the
    fresh interpreter imports.

    Args:
        statement: Python source executed via ``python -c`` in the child.

    Returns:
        subprocess.CompletedProcess[str]: The completed child process,
        with captured stdout and stderr as text.
    """
    return subprocess.run(
        [sys.executable, "-c", statement],
        capture_output=True,
        text=True,
        timeout=_IMPORT_TIMEOUT_S,
        check=False,
    )


@pytest.mark.parametrize("module_name", _BRIDGE_MODULES)
def test_bridge_module_imports_as_first_import(module_name: str) -> None:
    """Each bridge submodule must import cleanly as a fresh first import.

    Args:
        module_name: Unqualified bridge submodule name under
            ``intellicrack.bridges``.
    """
    statement = f"import intellicrack.bridges.{module_name}"
    result = _run_fresh_import(statement)

    assert result.returncode == 0, (
        f"`{statement}` failed as a first import in a fresh interpreter "
        f"(exit {result.returncode}). This indicates the bridges/core "
        f"import cycle has regressed.\nstderr:\n{result.stderr}"
    )
    assert "partially initialized module" not in result.stderr
    assert "circular import" not in result.stderr.lower()


def test_tool_capability_map_available_after_first_bridge_import() -> None:
    """The originally-failing symbol resolves after a fresh bridge import.

    Reproduces the precise historical failure: importing a bridge first,
    then reading ``TOOL_CAPABILITY_MAP`` off the partially-loaded
    ``bridges.base``. The subprocess prints the map size and exits 0 only
    when the module finished initializing.
    """
    statement = (
        "import intellicrack.bridges.cutter; "
        "from intellicrack.bridges.base import TOOL_CAPABILITY_MAP; "
        "assert isinstance(TOOL_CAPABILITY_MAP, dict) and TOOL_CAPABILITY_MAP; "
        "print(len(TOOL_CAPABILITY_MAP))"
    )
    result = _run_fresh_import(statement)

    assert result.returncode == 0, (
        f"Reading TOOL_CAPABILITY_MAP after a first-import of a bridge failed (exit {result.returncode}).\nstderr:\n{result.stderr}"
    )
    assert int(result.stdout.strip()) > 0


def test_tool_registry_lazy_reexport_resolves_after_bridge_import() -> None:
    """``core.ToolRegistry`` resolves lazily without eager tools import.

    Confirms the lazy PEP 562 re-export in ``intellicrack.core`` still
    exposes ``ToolRegistry``/``ToolStatus`` when a bridge module is the
    first import, and that the resolved objects are the real classes from
    ``intellicrack.core.tools``.
    """
    statement = (
        "import intellicrack.bridges.process; "
        "from intellicrack.core import ToolRegistry, ToolStatus; "
        "import intellicrack.core.tools as t; "
        "assert ToolRegistry is t.ToolRegistry; "
        "assert ToolStatus is t.ToolStatus; "
        "print(ToolRegistry.__name__, ToolStatus.__name__)"
    )
    result = _run_fresh_import(statement)

    assert result.returncode == 0, (
        "Lazy core re-export of ToolRegistry/ToolStatus failed after a "
        f"first-import of a bridge (exit {result.returncode}).\n"
        f"stderr:\n{result.stderr}"
    )
    assert result.stdout.strip() == "ToolRegistry ToolStatus"


def test_core_getattr_rejects_unknown_attribute() -> None:
    """The package ``__getattr__`` still raises for unknown attributes.

    The lazy hook must not mask genuine ``AttributeError`` for names it
    does not export, otherwise ``from intellicrack.core import <typo>``
    would silently trigger an unrelated import attempt.
    """
    missing_name = "DefinitelyNotARealSymbol"
    with pytest.raises(AttributeError, match=f"no attribute '{missing_name}'"):
        getattr(core_pkg, missing_name)
