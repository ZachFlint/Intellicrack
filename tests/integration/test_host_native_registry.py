# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
"""Falsifiable gates for the host-native test registry and selection wiring.

These gates protect the mechanism that routes host-only tests (Intel XPU, local
Ollama, debug symbols, raw disk, loopback, elevation) to the host-native pass:

* every registry entry must resolve to a real, collected test (drift detection);
* the classifier must include registry members and exclude container-safe
  siblings;
* the marker must be registered; and
* in a sandboxed run the collection hook must actually deselect them.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import cast

import pytest

from tests._helpers.host_native import (
    HOST_NATIVE_CLASSES,
    HOST_NATIVE_FUNCTIONS,
    HOST_NATIVE_MARKER,
    HOST_NATIVE_METHODS,
    deselect_host_native,
    is_host_native_nodeid,
    keep_only_host_native,
    mark_host_native_items,
    split_nodeid,
)
from tests._helpers.process_cleanup import is_sandboxed


_REPO_ROOT = Path(__file__).resolve().parents[2]


def _module_symbols(module_path: str) -> tuple[dict[str, set[str]], set[str]]:
    """Parse a test module's source and return its class and function symbols.

    Uses ``ast`` rather than importing the module so the drift gate never loads
    heavy native dependencies (torch, Qt, LIEF), which are unstable to import in
    bulk inside the sandbox.

    Args:
        module_path: Forward-slashed path such as ``tests/providers/test_x.py``.

    Returns:
        tuple[dict[str, set[str]], set[str]]: A mapping of class name to the set
            of methods defined directly in its body, and the set of
            module-level function names.
    """
    source = (_REPO_ROOT / module_path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    classes: dict[str, set[str]] = {}
    functions: set[str] = set()
    func_nodes = (ast.FunctionDef, ast.AsyncFunctionDef)
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            classes[node.name] = {child.name for child in node.body if isinstance(child, func_nodes)}
        elif isinstance(node, func_nodes):
            functions.add(node.name)
    return classes, functions


@pytest.mark.parametrize(("module_path", "class_name"), sorted(HOST_NATIVE_CLASSES))
def test_registry_class_resolves(module_path: str, class_name: str) -> None:
    """Every whole-class registry entry must name a real test class.

    Args:
        module_path: Registry module path.
        class_name: Registry class name.
    """
    classes, _ = _module_symbols(module_path)
    assert class_name in classes, f"{module_path}::{class_name} not defined (registry drift)"
    test_methods = {name for name in classes[class_name] if name.startswith("test_")}
    assert test_methods, f"{module_path}::{class_name} has no test_ methods (registry drift)"


@pytest.mark.parametrize(("module_path", "class_name", "func_name"), sorted(HOST_NATIVE_METHODS))
def test_registry_method_resolves(module_path: str, class_name: str, func_name: str) -> None:
    """Every per-method registry entry must name a real test method.

    Args:
        module_path: Registry module path.
        class_name: Registry class name.
        func_name: Registry method name.
    """
    classes, _ = _module_symbols(module_path)
    assert class_name in classes, f"{module_path}::{class_name} not defined (registry drift)"
    assert func_name in classes[class_name], f"{module_path}::{class_name}::{func_name} not defined (registry drift)"


@pytest.mark.parametrize(("module_path", "func_name"), sorted(HOST_NATIVE_FUNCTIONS))
def test_registry_function_resolves(module_path: str, func_name: str) -> None:
    """Every module-level registry entry must name a real test function.

    Args:
        module_path: Registry module path.
        func_name: Registry function name.
    """
    _, functions = _module_symbols(module_path)
    assert func_name in functions, f"{module_path}::{func_name} not defined (registry drift)"


def test_split_nodeid_classed() -> None:
    """A classed node id splits into (module, class, function)."""
    assert split_nodeid("tests/x/test_y.py::TestC::test_f") == ("tests/x/test_y.py", "TestC", "test_f")


def test_split_nodeid_module_level() -> None:
    """A module-level node id splits with a ``None`` class."""
    assert split_nodeid("tests/x/test_y.py::test_f") == ("tests/x/test_y.py", None, "test_f")


def test_split_nodeid_strips_parametrization() -> None:
    """Parametrized ids collapse to the base function name."""
    assert split_nodeid("tests/x/test_y.py::TestC::test_f[case-1]") == ("tests/x/test_y.py", "TestC", "test_f")


def test_split_nodeid_normalizes_backslashes() -> None:
    """Windows-style separators are normalised to forward slashes."""
    assert split_nodeid(r"tests\x\test_y.py::test_f") == ("tests/x/test_y.py", None, "test_f")


def test_classifier_includes_whole_class_member() -> None:
    """A method of a whole-class registry entry is host-native."""
    assert is_host_native_nodeid(
        "tests/providers/test_local_xpu_e2e.py::TestRealInference::test_simple_chat_returns_response",
    )


def test_classifier_includes_registered_method() -> None:
    """A per-method registry entry is host-native."""
    assert is_host_native_nodeid(
        "tests/bridges/test_process_bridge.py::TestF0024SymbolInfoSizeOfStruct::test_resolve_symbol_returns_nonempty_name",
    )


def test_classifier_includes_module_function() -> None:
    """A module-level registry entry is host-native."""
    assert is_host_native_nodeid(
        "tests/sandbox/monitors/test_service_monitor.py::test_script_records_lifecycle_transitions",
    )


def test_classifier_includes_parametrized_member() -> None:
    """Parametrization does not defeat classification."""
    assert is_host_native_nodeid(
        "tests/providers/test_local_xpu_e2e.py::TestMaxTokensControl::test_max_tokens_1_minimal_output[x]",
    )


@pytest.mark.parametrize(
    "nodeid",
    [
        "tests/providers/test_local_xpu_e2e.py::TestCPUFallbackInference::test_cpu_provider_device_is_cpu",
        "tests/providers/test_ollama_provider.py::TestOllamaConnection::test_connection_with_invalid_url_raises_error",
        "tests/core/test_config.py::TestConfig::test_load",
        "tests/bridges/test_process_bridge.py::TestF0001Nonexistent::test_bar",
    ],
)
def test_classifier_excludes_container_safe(nodeid: str) -> None:
    """Container-safe siblings and unrelated tests are not host-native.

    Args:
        nodeid: A node id that must classify as not host-native.
    """
    assert not is_host_native_nodeid(nodeid)


def test_marker_is_registered(pytestconfig: pytest.Config) -> None:
    """The ``host_native`` marker is registered for ``--strict-markers``.

    Args:
        pytestconfig: The active pytest configuration.
    """
    markers = cast("list[str]", pytestconfig.getini("markers"))
    assert any(entry.startswith(f"{HOST_NATIVE_MARKER}:") for entry in markers)


class _FakeItem:
    """Test double carrying a node id and applied markers like a pytest Item."""

    def __init__(self, nodeid: str) -> None:
        """Initialise with a node id and no markers.

        Args:
            nodeid: The item's node id.
        """
        self.nodeid = nodeid
        self._markers: list[object] = []

    def add_marker(self, marker: object) -> None:
        """Record an applied marker.

        Args:
            marker: The marker object being applied.
        """
        self._markers.append(marker)

    def get_closest_marker(self, name: str) -> object | None:
        """Return the most recently applied marker with ``name``.

        Args:
            name: Marker name to look up.

        Returns:
            object | None: The matching marker, or ``None``.
        """
        for marker in reversed(self._markers):
            if getattr(marker, "name", None) == name:
                return marker
        return None


class _FakeHook:
    """Records items passed to ``pytest_deselected``."""

    def __init__(self) -> None:
        """Initialise an empty deselected record."""
        self.deselected: list[object] = []

    def pytest_deselected(self, items: list[object]) -> None:
        """Record deselected items.

        Args:
            items: Items being deselected.
        """
        self.deselected.extend(items)


class _FakeConfig:
    """Test double exposing the ``.hook`` surface the helpers use."""

    def __init__(self) -> None:
        """Initialise with a fresh fake hook."""
        self.hook = _FakeHook()


def _make_items() -> list[pytest.Item]:
    """Build a mixed list of host-native and container-safe fake items.

    Returns:
        list[pytest.Item]: One host-native item followed by one container-safe
            item, typed as pytest items for the helpers under test.
    """
    host = _FakeItem("tests/providers/test_local_xpu_e2e.py::TestRealInference::test_simple_chat_returns_response")
    safe = _FakeItem("tests/core/test_config.py::TestConfig::test_load")
    return cast("list[pytest.Item]", [host, safe])


def test_mark_host_native_items_marks_only_registry_members() -> None:
    """Marking tags exactly the host-native item, not its container-safe peer."""
    items = _make_items()
    marked = mark_host_native_items(items)
    assert marked == 1
    assert items[0].get_closest_marker(HOST_NATIVE_MARKER) is not None
    assert items[1].get_closest_marker(HOST_NATIVE_MARKER) is None


def test_deselect_host_native_removes_marked_item() -> None:
    """In a sandboxed run the marked item is removed and reported deselected."""
    items = _make_items()
    _ = mark_host_native_items(items)
    config = cast("pytest.Config", _FakeConfig())
    dropped = deselect_host_native(config, items)
    assert dropped == 1
    assert len(items) == 1
    assert items[0].nodeid.endswith("test_load")
    hook = cast("_FakeConfig", config).hook
    assert len(hook.deselected) == 1


def test_keep_only_host_native_keeps_marked_item() -> None:
    """The host-native pass keeps only the marked item and drops the rest."""
    items = _make_items()
    _ = mark_host_native_items(items)
    config = cast("pytest.Config", _FakeConfig())
    kept = keep_only_host_native(config, items)
    assert kept == 1
    assert len(items) == 1
    assert "TestRealInference" in items[0].nodeid


def test_sandboxed_session_collected_no_host_native(request: pytest.FixtureRequest) -> None:
    """End-to-end: a sandboxed run must not collect any host-native test.

    This asserts against the *real* collection of the current session. Inside
    the container the conftest hook deselects host-native tests, so none may
    remain in ``session.items``; if deselection regresses, they reappear here
    and this gate fails.

    Args:
        request: The active fixture request, used to reach the session items.
    """
    if not is_sandboxed():
        pytest.skip("deselection guarantee only applies inside the Docker sandbox")
    assert HOST_NATIVE_CLASSES, "registry unexpectedly empty; the gate would be vacuous"
    leaked = [item.nodeid for item in request.session.items if item.get_closest_marker(HOST_NATIVE_MARKER) is not None]
    assert not leaked, f"host_native tests leaked into the sandbox run: {leaked[:5]}"
