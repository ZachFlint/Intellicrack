# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Third-pass tests for the import-time fallbacks of ``intellicrack.bridges.hex_editor``.

The bridge imports seven optional pieces at module load: the native hexcore extension, the HexPat
compiler, the HexPat interpreter package, the disassembler, the YARA scanner, the transform pipeline
and pefile. Each import sits in a handler that must leave the module importable, mark its feature
unavailable and make the dependent public calls report that outcome instead of crashing.

Each test starts a real child interpreter, makes exactly one package unimportable with
``sys.modules[name] = None`` (the import system then raises ``ModuleNotFoundError`` for it), imports
the bridge, and prints one JSON line with the module's availability flags, which sentinels stayed
``None``, and the results of the public calls that depend on the missing package. The expectations
below are written out from the module's documented contract: a missing package gives a false flag,
a ``None`` sentinel and the documented ``RuntimeError`` text, or an empty list where the docstring
promises one.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import TYPE_CHECKING, Any, Final, cast

import pytest


if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.spawns_process

_CHILD_TIMEOUT_S: Final[float] = 150.0
_RESULT_PREFIX: Final[str] = "RESULT "

_FLAG_NAMES: Final[tuple[str, ...]] = (
    "_hexcore_available",
    "_hexpat_available",
    "_hexpat_interpreter_available",
    "_disasm_available",
    "_yara_bridge_available",
    "_pipeline_available",
    "_pefile_available",
)
_OBJECT_NAMES: Final[tuple[str, ...]] = (
    "_hexcore_mod",
    "_HexPatCompiler",
    "_HexPatError",
    "_HexPatInterpreter",
    "_PatternRegistry",
    "_DataReader",
    "_get_disassembler",
    "_YaraScanner",
    "_get_all_transform_nodes",
    "_TransformPipeline",
    "_pefile_mod",
)

_CHILD_CODE: Final[str] = r"""
import asyncio
import json
import sys

blocked = json.loads(sys.argv[1])
scenario = sys.argv[2]
target = sys.argv[3]
for name in blocked:
    sys.modules[name] = None

from intellicrack.bridges import hex_editor as m

flag_names = json.loads(sys.argv[4])
object_names = json.loads(sys.argv[5])
out = {
    "flags": {n: getattr(m, n) for n in flag_names},
    "none": {n: getattr(m, n) is None for n in object_names},
}


async def err(coro):
    try:
        value = await coro
    except Exception as exc:
        return [type(exc).__name__, str(exc)]
    return ["ok", repr(value)[:200]]


async def run():
    bridge = m.HexEditorBridge()
    res = {}
    try:
        if scenario == "hexcore":
            res["is_available"] = await bridge.is_available()
            await bridge.initialize()
            res["connected"] = bridge.state.connected
            res["tool_running"] = bridge.state.tool_running
            res["last_error"] = bridge.state.last_error
            res["open_file"] = await err(bridge.open_file(target))
            res["document_is_none"] = bridge.document is None
        elif scenario == "compiler":
            res["compile_pattern"] = await err(bridge.compile_pattern("struct A { u8 a; };"))
            listed = await bridge.list_hexpat_patterns()
            res["patterns_listed"] = len(listed)
        elif scenario == "hexpat":
            res["compile_pattern"] = await err(bridge.compile_pattern("struct A { u8 a; };"))
            res["list_hexpat_patterns"] = await err(bridge.list_hexpat_patterns())
            res["get_interpreter"] = None
            try:
                bridge._get_interpreter()
            except Exception as exc:
                res["get_interpreter"] = [type(exc).__name__, str(exc)]
            await bridge.open_file(target)
            res["auto_detect_pattern"] = await err(bridge.auto_detect_pattern())
        elif scenario == "disasm":
            await bridge.open_file(target)
            res["disassemble"] = await err(bridge.disassemble(0, 4))
        elif scenario == "yara":
            await bridge.open_file(target)
            res["yara_scan"] = await err(bridge.yara_scan("rule r { condition: true }"))
            res["yara_scan_files"] = await err(bridge.yara_scan_files("missing.yar"))
        elif scenario == "pipeline":
            res["list_transforms_len"] = len(await bridge.list_transforms())
            await bridge.open_file(target)
            res["apply_pipeline"] = await err(bridge.apply_pipeline("[]", 0, 4))
        elif scenario == "pefile":
            await bridge.open_file(target)
            res["imports_len"] = len(await bridge.get_pe_imports())
            res["exports_len"] = len(await bridge.get_pe_exports())
    finally:
        await bridge.close_file()
    return res


out["result"] = asyncio.run(run())
print("RESULT " + json.dumps(out))
"""


def _run_child(blocked: list[str], scenario: str, target: Path) -> dict[str, Any]:
    """Run one scenario in a fresh interpreter with the named modules made unimportable.

    Args:
        blocked: Dotted module names set to ``None`` in the child's ``sys.modules`` before the
            bridge is imported.
        scenario: Scenario selector understood by the child code.
        target: Real PE file the child opens in the bridge when the scenario needs a document.

    Returns:
        dict[str, Any]: The decoded JSON object the child printed on its ``RESULT`` line, with the
            keys ``flags``, ``none`` and ``result``.
    """
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            _CHILD_CODE,
            json.dumps(blocked),
            scenario,
            str(target),
            json.dumps(list(_FLAG_NAMES)),
            json.dumps(list(_OBJECT_NAMES)),
        ],
        capture_output=True,
        text=True,
        timeout=_CHILD_TIMEOUT_S,
        check=False,
    )
    assert proc.returncode == 0, f"child with {blocked} exited {proc.returncode}:\n{proc.stderr}\n{proc.stdout[-2000:]}"
    lines = [line for line in proc.stdout.splitlines() if line.startswith(_RESULT_PREFIX)]
    assert len(lines) == 1, f"expected one RESULT line, got {len(lines)}:\n{proc.stdout[-2000:]}"
    return cast("dict[str, Any]", json.loads(lines[0][len(_RESULT_PREFIX) :]))


def _assert_module_state(out: dict[str, Any], *, unavailable: tuple[str, ...], none_names: tuple[str, ...]) -> None:
    """Assert the availability flags and the ``None`` sentinels the child reported.

    Args:
        out: Decoded child output.
        unavailable: Flag names that must be false; every other flag must be true.
        none_names: Sentinel names that must be ``None``; every other sentinel must be set.
    """
    assert out["flags"] == {name: name not in unavailable for name in _FLAG_NAMES}
    assert out["none"] == {name: name in none_names for name in _OBJECT_NAMES}


def test_missing_hexcore_leaves_module_importable_and_bridge_reports_unavailable(real_pe_dll: Path) -> None:
    """Without ``intellicrack_hexcore`` the bridge imports, is unavailable and refuses to open files.

    Args:
        real_pe_dll: A real PE file used as the path ``open_file`` is asked to open.
    """
    out = _run_child(["intellicrack_hexcore"], "hexcore", real_pe_dll)

    _assert_module_state(out, unavailable=("_hexcore_available",), none_names=("_hexcore_mod",))
    assert out["result"] == {
        "is_available": False,
        "connected": False,
        "tool_running": False,
        "last_error": "intellicrack_hexcore backend unavailable",
        "open_file": ["RuntimeError", "intellicrack_hexcore not installed"],
        "document_is_none": True,
    }


def test_missing_hexpat_compiler_disables_only_compilation(real_pe_dll: Path) -> None:
    """Without ``intellicrack.core.hexpat_compiler`` pattern compilation fails but the interpreter survives.

    Args:
        real_pe_dll: A real PE file passed through to the child (unused by this scenario).
    """
    out = _run_child(["intellicrack.core.hexpat_compiler"], "compiler", real_pe_dll)

    _assert_module_state(out, unavailable=("_hexpat_available",), none_names=("_HexPatCompiler", "_HexPatError"))
    assert out["result"]["compile_pattern"] == ["RuntimeError", "hexpat_compiler not available"]
    assert out["result"]["patterns_listed"] > 0


def test_missing_hexpat_package_disables_compiler_interpreter_and_registry(real_pe_dll: Path) -> None:
    """Without ``intellicrack.core.hexpat`` the compiler, interpreter, registry and data reader are all gone.

    The compiler module itself imports ``intellicrack.core.hexpat.ast_nodes``, so blocking the
    package makes both HexPat handlers fire.

    Args:
        real_pe_dll: A real PE file opened by the child to reach the document-dependent guard.
    """
    out = _run_child(["intellicrack.core.hexpat"], "hexpat", real_pe_dll)

    _assert_module_state(
        out,
        unavailable=("_hexpat_available", "_hexpat_interpreter_available"),
        none_names=("_HexPatCompiler", "_HexPatError", "_HexPatInterpreter", "_PatternRegistry", "_DataReader"),
    )
    assert out["result"] == {
        "compile_pattern": ["RuntimeError", "hexpat_compiler not available"],
        "list_hexpat_patterns": ["RuntimeError", "pattern registry not available"],
        "get_interpreter": ["RuntimeError", "hexpat interpreter not available"],
        "auto_detect_pattern": ["RuntimeError", "hexpat interpreter not available; cannot auto-detect patterns"],
    }


def test_missing_disassembler_makes_disassemble_report_the_module_unavailable(real_pe_dll: Path) -> None:
    """Without ``intellicrack.core.disassembler`` an open document cannot be disassembled.

    Args:
        real_pe_dll: A real PE file opened by the child so the no-document guard passes.
    """
    out = _run_child(["intellicrack.core.disassembler"], "disasm", real_pe_dll)

    _assert_module_state(out, unavailable=("_disasm_available",), none_names=("_get_disassembler",))
    assert out["result"] == {"disassemble": ["RuntimeError", "disassembler module not available"]}


def test_missing_yara_scanner_makes_both_yara_scans_report_the_module_unavailable(real_pe_dll: Path) -> None:
    """Without ``intellicrack.core.yara_scanner`` neither YARA scan entry point can run.

    Args:
        real_pe_dll: A real PE file opened by the child so the no-document guard passes.
    """
    out = _run_child(["intellicrack.core.yara_scanner"], "yara", real_pe_dll)

    _assert_module_state(out, unavailable=("_yara_bridge_available",), none_names=("_YaraScanner",))
    assert out["result"] == {
        "yara_scan": ["RuntimeError", "yara_scanner module not available"],
        "yara_scan_files": ["RuntimeError", "yara_scanner module not available"],
    }


def test_missing_transform_pipeline_lists_no_transforms_and_refuses_pipelines(real_pe_dll: Path) -> None:
    """Without ``intellicrack.core.transform_pipeline`` no transforms are listed and pipelines are refused.

    Args:
        real_pe_dll: A real PE file opened by the child so the no-document guard passes.
    """
    out = _run_child(["intellicrack.core.transform_pipeline"], "pipeline", real_pe_dll)

    _assert_module_state(
        out,
        unavailable=("_pipeline_available",),
        none_names=("_get_all_transform_nodes", "_TransformPipeline"),
    )
    assert out["result"] == {
        "list_transforms_len": 0,
        "apply_pipeline": ["RuntimeError", "transform_pipeline module not available"],
    }


def test_missing_pefile_makes_pe_import_and_export_walks_return_empty_lists(real_pe_dll: Path) -> None:
    """Without ``pefile`` the PE import and export walks return empty lists for a real DLL that has entries.

    The same scenario is run once with nothing blocked, so the empty lists in the blocked run are
    known to come from the missing package and not from the file.

    Args:
        real_pe_dll: ``kernel32.dll``, a real PE that has both an import and an export directory.
    """
    blocked = _run_child(["pefile"], "pefile", real_pe_dll)
    control = _run_child([], "pefile", real_pe_dll)

    _assert_module_state(blocked, unavailable=("_pefile_available",), none_names=("_pefile_mod",))
    assert blocked["result"] == {"imports_len": 0, "exports_len": 0}
    _assert_module_state(control, unavailable=(), none_names=())
    assert control["result"]["imports_len"] > 0
    assert control["result"]["exports_len"] > 0
