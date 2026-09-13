# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates binding the local Frida type stubs and the bridge to the installed Frida.

Frida 17 removed the ``frida.core`` source module (it survives only as a
``sys.modules`` alias) and dropped the ``cancellable=`` keyword that Frida 16
accepted on ``Device.attach``, ``Device.spawn``, ``Session.create_script`` and
``Compiler.build``. Cancellation is now scoped through the ``Cancellable``
context manager. These tests exercise the real installed Frida so a future
upgrade that shifts either contract fails loudly instead of silently breaking
the bridge at runtime.
"""

from __future__ import annotations

import ast
import asyncio
import importlib
import inspect
from pathlib import Path
from typing import TYPE_CHECKING

import frida
import pytest
from frida import _frida

from intellicrack.bridges.frida_bridge import FridaBridge


if TYPE_CHECKING:
    from collections.abc import Coroutine, Iterator

_REPO_ROOT = Path(__file__).resolve().parents[3]
_STUB_DIR = _REPO_ROOT / "typings" / "frida"
_INSTALLED_FRIDA_DIR = Path(inspect.getfile(frida)).resolve().parent


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run a coroutine on a fresh event loop and return its result.

    Args:
        coro: Coroutine produced by one of the bridge's async entrypoints.

    Returns:
        T: Whatever the coroutine resolved to.
    """
    return asyncio.run(coro)


def _stub_module_names() -> list[str]:
    """Collect the module basenames declared by the local Frida stub package.

    Returns:
        list[str]: Stub basenames without the ``.pyi`` suffix, sorted.
    """
    return sorted(path.stem for path in _STUB_DIR.glob("*.pyi"))


def _iter_stub_classes(tree: ast.Module) -> Iterator[ast.ClassDef]:
    """Yield the top-level class definitions of a parsed stub module.

    Args:
        tree: Parsed stub module.

    Yields:
        ast.ClassDef: Each top-level class definition.
    """
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            yield node


def _defined_on_class(cls: type, name: str) -> bool:
    """Report whether ``name`` is defined by ``cls`` itself rather than inherited.

    Args:
        cls: Runtime class to inspect.
        name: Attribute name to look for.

    Returns:
        bool: ``True`` when some class in the MRO below ``object`` defines it.
    """
    return any(name in vars(base) for base in cls.__mro__ if base is not object)


def test_stub_modules_all_have_installed_sources() -> None:
    """Every stub module must shadow a real module file in the installed Frida.

    This is the exact condition basedpyright enforces as
    ``reportMissingModuleSource``; ``frida/core.pyi`` violated it because Frida
    17 keeps ``frida.core`` only as a ``sys.modules`` alias.
    """
    stub_names = _stub_module_names()
    assert "__init__" in stub_names, "stub package must declare frida/__init__.pyi"

    for name in stub_names:
        candidates = [
            path
            for path in _INSTALLED_FRIDA_DIR.iterdir()
            if path.is_file() and path.name.split(".")[0] == name and path.suffix in {".py", ".pyd", ".so"}
        ]
        assert candidates, (
            f"typings/frida/{name}.pyi shadows a module with no source file in "
            f"{_INSTALLED_FRIDA_DIR}; the stub package has drifted from the "
            f"installed frida {frida.__version__}"
        )


def test_frida_core_has_no_module_file() -> None:
    """``frida.core`` resolves at runtime only through an alias, never a file."""
    core = importlib.import_module("frida.core")

    assert core is frida, "frida.core is expected to alias the frida package"
    assert not (_INSTALLED_FRIDA_DIR / "core.py").exists(), "frida ships a real core.py again; the stub package may declare core.pyi"


def test_stub_top_level_names_exist_in_installed_frida() -> None:
    """Every name the stub declares must be present on the installed module."""
    tree = ast.parse((_STUB_DIR / "__init__.pyi").read_text(encoding="utf-8"))
    declared: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
            declared.append(node.name)
        elif isinstance(node, ast.Assign):
            declared.extend(target.id for target in node.targets if isinstance(target, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            declared.append(node.target.id)

    assert declared, "stub parsing produced no names"
    missing = [name for name in declared if not hasattr(frida, name)]
    assert not missing, f"typings/frida/__init__.pyi declares names absent from installed frida {frida.__version__}: {missing}"


def test_stub_class_members_exist_in_installed_frida() -> None:
    """Every method and property a stub class declares must exist at runtime."""
    tree = ast.parse((_STUB_DIR / "__init__.pyi").read_text(encoding="utf-8"))
    missing: list[str] = []
    checked = 0

    for class_node in _iter_stub_classes(tree):
        runtime_cls = getattr(frida, class_node.name, None)
        if not isinstance(runtime_cls, type):
            continue
        for member in class_node.body:
            if not isinstance(member, ast.FunctionDef):
                continue
            checked += 1
            if not _defined_on_class(runtime_cls, member.name):
                missing.append(f"{class_node.name}.{member.name}")

    assert checked > 100, f"stub member scan covered only {checked} members"
    assert not missing, (
        f"typings/frida/__init__.pyi declares members absent from installed frida {frida.__version__}: {sorted(set(missing))}"
    )


def test_script_exports_sync_is_still_assigned_by_frida() -> None:
    """The bridge's RPC path depends on ``Script.exports_sync`` existing."""
    source = inspect.getsource(frida.Script)
    assert "self.exports_sync = " in source, (
        "frida.Script no longer assigns exports_sync; the bridge RPC dispatch and the stub's Script.exports_sync annotation are both stale"
    )


@pytest.mark.parametrize("options_cls", [_frida.SessionOptions, _frida.BuildOptions])
def test_frida_option_objects_reject_a_cancellable_keyword(options_cls: type) -> None:
    """Frida 17 option objects have no ``cancellable`` slot.

    Passing ``cancellable=`` to ``Device.attach`` or ``Compiler.build`` routes
    the value into these option objects, so the Frida 16 idiom now raises.

    Args:
        options_cls: Frida option class backing one of the affected calls.
    """
    options = options_cls()
    with pytest.raises(AttributeError):
        options.cancellable = frida.Cancellable()


def test_create_script_signature_rejects_a_cancellable_keyword() -> None:
    """``Session.create_script`` takes no keyword bucket in Frida 17."""
    parameters = inspect.signature(frida.Session.create_script).parameters
    assert "cancellable" not in parameters
    assert not any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()), (
        "create_script would silently swallow a cancellable= keyword"
    )


def test_cancellable_context_publishes_the_current_token() -> None:
    """Entering a ``Cancellable`` is what scopes cancellation in Frida 17."""
    token = frida.Cancellable()
    assert frida.Cancellable.get_current() is None

    with token:
        assert frida.Cancellable.get_current() is token

    assert frida.Cancellable.get_current() is None


def test_compile_typescript_runs_under_a_registered_cancellable(tmp_path: Path) -> None:
    """The bridge compiles real TypeScript while a cancellation token is scoped.

    Drives ``FridaBridge.compile_typescript`` end to end against a real
    ``frida.Compiler``. Restoring the Frida 16 ``cancellable=`` keyword makes
    this raise ``AttributeError`` out of Frida's option marshalling.

    Args:
        tmp_path: Pytest-provided directory holding the agent entrypoint.
    """
    entrypoint = tmp_path / "agent.ts"
    entrypoint.write_text(
        'const marker: string = "intellicrack-cancellable-gate";\nsend(marker);\n',
        encoding="utf-8",
    )

    async def driver() -> str:
        bridge = FridaBridge()
        cancellable_id = await bridge.create_cancellable()
        return await bridge.compile_typescript(
            str(entrypoint),
            str(tmp_path),
            cancellable_id=cancellable_id,
        )

    built = _run(driver())

    assert "intellicrack-cancellable-gate" in built
    assert frida.Cancellable.get_current() is None


def test_compile_typescript_runs_without_a_cancellable(tmp_path: Path) -> None:
    """The untokened path must produce the same real compiler output.

    Args:
        tmp_path: Pytest-provided directory holding the agent entrypoint.
    """
    entrypoint = tmp_path / "agent.ts"
    entrypoint.write_text(
        'const marker: string = "intellicrack-plain-gate";\nsend(marker);\n',
        encoding="utf-8",
    )

    async def driver() -> str:
        return await FridaBridge().compile_typescript(str(entrypoint), str(tmp_path))

    assert "intellicrack-plain-gate" in _run(driver())
