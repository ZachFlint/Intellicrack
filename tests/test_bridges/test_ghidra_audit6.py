# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit-6 GHIDRA-A and GHIDRA-B regression tests.

GHIDRA-A foundation findings:

Covers F-0001 (``remote_exec`` discards trailing expression results),
F-0002 (call-site indentation reaches the remote interpreter as
``IndentationError``), F-0005/F-0028 (read methods relayed empty data
from a swallowed-exception return), F-0006/F-0025 (read methods caught
every exception and returned empty containers despite advertising
``Raises: ToolError``), and F-0011 (``get_call_graph`` and
``get_call_tree`` issued per-byte ``getReferencesFrom`` lookups instead
of using ``Function.getCalledFunctions``).

Tests substitute a deterministic in-process double for the
``ghidra_bridge`` client. The double mirrors the upstream
``BridgeClient.remote_exec`` / ``remote_eval`` semantics at the smallest
viable boundary: ``remote_exec`` runs the script via :func:`exec`,
``remote_eval`` evaluates a single expression by wrapping it in a
return statement and executing it in the shared globals namespace. This
is the same boundary the real bridge crosses, so the tests exercise
the corrected ``_execute_remote`` dispatch path end-to-end.

GHIDRA-B headless launcher and lifecycle findings:

* F-0003 - Bridge script must call ``GhidraBridgeServer.run_server`` (the real
  upstream API) instead of the non-existent constructor and ``start()``.
* F-0004 - The deployed script must run ``run_server`` with
  ``background=False`` so the JVM stays alive after the post-script returns.
* F-0009 - The bridge script writer must use explicit ``utf-8`` encoding and
  convert ``OSError`` into ``ToolError``.
* F-0012 - ``shutdown`` must close the ``ghidra_bridge`` RPC client socket so
  the connection does not leak.
* F-0013 - Concurrent ``start_headless`` invocations must not race over a
  single shared script directory; cleanup must serialise via a global lock.
* F-0014 - The bridge port wait loop must not deadlock when Ghidra writes more
  stderr than the OS pipe buffer holds; stderr drain threads must run
  continuously throughout the wait loop.
* F-0015 - ``Popen`` must be invoked with ``cwd``, scrubbed environment, and
  ``creationflags=CREATE_NO_WINDOW`` on Windows.
* F-0016 - ``analyzeHeadless`` resolution must respect the current platform
  (``.bat`` on Windows, the POSIX shell variant otherwise).
* F-0019 - The ``file_written`` log line must only run after the on-disk
  contents have been verified against the rendered script content.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import sys
import threading
import time
import types
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast
from unittest.mock import patch

import pytest

import intellicrack.bridges.ghidra as ghidra_mod
from intellicrack.bridges.ghidra import GhidraBridge, prepare_remote_script
from intellicrack.core._subprocess import CREATE_NO_WINDOW, PIPE, Popen
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Coroutine


_TEST_ADDRESS: Final[int] = 0x401000


class _FakeBridgeClient:
    """In-process double for the upstream ``ghidra_bridge`` client.

    The double mirrors the public ``remote_exec`` / ``remote_eval``
    contract that ``intellicrack.bridges.ghidra._execute_remote``
    depends on. Both methods share a single globals dictionary so
    variables assigned inside ``remote_exec`` are visible to a follow-up
    ``remote_eval`` - matching the real bridge, which uses
    ``__main__.__dict__`` as the shared global namespace for both calls.
    """

    def __init__(self) -> None:
        """Initialise the shared global namespace."""
        self.globals: dict[str, Any] = {}
        self.exec_payloads: list[str] = []
        self.eval_payloads: list[str] = []

    def remote_exec(self, code: str) -> None:
        """Execute ``code`` against the shared globals via :func:`exec`.

        Args:
            code: Python source to execute.
        """
        self.exec_payloads.append(code)
        compiled = compile(code, "<remote_exec>", "exec")
        exec(compiled, self.globals)

    def remote_eval(self, expr: str) -> object:
        """Evaluate ``expr`` against the shared globals.

        Mirrors ``BridgeClient.remote_eval`` semantics. The expression
        is compiled with mode ``"eval"`` so non-expression input is
        rejected the same way the upstream client rejects it, then
        executed via a return-statement wrapper so the value flows back
        without invoking :func:`eval` directly. Variables previously
        assigned by :meth:`remote_exec` are visible through the shared
        globals dictionary.

        Args:
            expr: Python expression to evaluate.

        Returns:
            object: Deserialized expression value.
        """
        self.eval_payloads.append(expr)
        compile(expr, "<remote_eval>", "eval")
        wrapper_source = f"def __intellicrack_test_eval():\n    return ({expr})\n"
        wrapper_code = compile(wrapper_source, "<remote_eval-wrapper>", "exec")
        local_namespace: dict[str, Any] = {}
        exec(wrapper_code, self.globals, local_namespace)
        wrapper_fn: Any = local_namespace["__intellicrack_test_eval"]
        return wrapper_fn()


@pytest.fixture
def bridge_with_fake() -> tuple[GhidraBridge, _FakeBridgeClient]:
    """Wire a ``GhidraBridge`` to a deterministic fake RPC client.

    Returns:
        tuple[GhidraBridge, _FakeBridgeClient]: A live bridge instance
        whose backing client is the fake, plus the fake itself for
        direct introspection.
    """
    bridge = GhidraBridge()
    fake = _FakeBridgeClient()
    bridge.attach_remote_bridge(fake)
    return bridge, fake


def _run(coro: Coroutine[Any, Any, object]) -> object:
    """Run an async coroutine to completion in a fresh event loop.

    Args:
        coro: Coroutine to run.

    Returns:
        object: Return value of the coroutine.
    """
    return asyncio.run(coro)


def test_f0001_trailing_expression_round_trips_via_execute_script(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """F-0001: trailing expression statements must round-trip end-to-end.

    The pre-fix bridge dispatched every script through ``remote_exec``,
    whose underlying :func:`exec` discards expression-statement values
    and forced public methods like ``execute_script`` to return an
    empty string. The fix rewrites the trailing expression into an
    assignment to a sentinel and reads the sentinel back via
    ``remote_eval``. We drive the public ``execute_script`` entry point
    with a multi-statement script that produces a string value and
    confirm the value reaches the caller.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a
            deterministic fake RPC client.
    """
    bridge, fake = bridge_with_fake
    payload = """
        a = 7
        b = 35
        'audit6:' + str(a + b)
    """
    result = _run(bridge.execute_script(payload))
    assert result == "audit6:42"
    assert len(fake.exec_payloads) == 1
    assert len(fake.eval_payloads) == 1


def test_f0001_pure_statement_script_returns_empty_string(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """Pure-statement scripts must dispatch via remote_exec only.

    Side-effect scripts (e.g. ``analyzeAll(currentProgram)``) have no
    trailing expression and must therefore avoid the second
    ``remote_eval`` roundtrip while still completing the side effect.
    ``execute_script`` returns the empty string in that case.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a
            deterministic fake RPC client.
    """
    bridge, fake = bridge_with_fake
    fake.globals["touched"] = False
    payload = """
        touched = True
    """
    result = _run(bridge.execute_script(payload))
    assert not result
    assert fake.globals["touched"] is True
    assert len(fake.exec_payloads) == 1
    assert len(fake.eval_payloads) == 0


def test_f0002_indented_call_site_does_not_leak_indentation(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """F-0002: call-site indentation must be stripped before dispatch.

    Inline scripts in the bridge are written inside method bodies, so
    every line carries the surrounding indentation. The pre-fix path
    forwarded that indentation directly to ``exec`` on the remote side,
    which raises ``IndentationError`` on the first statement. The fix
    runs every script through :func:`textwrap.dedent` before dispatch.
    This test simulates the real call-site shape (16 leading spaces per
    line) by passing a script through the public ``execute_script``
    entry point and asserts the script reaches ``remote_exec`` dedented
    and parseable.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a
            deterministic fake RPC client.
    """
    bridge, fake = bridge_with_fake
    indented_payload = """
                values = []
                for i in range(3):
                    values.append(i * i)
                str(values)
    """
    result = _run(bridge.execute_script(indented_payload))
    assert result == "[0, 1, 4]"
    transmitted = fake.exec_payloads[0]
    assert transmitted.splitlines()[0].startswith("values"), f"remote_exec received indented script: {transmitted!r}"


def test_f0002_indented_script_would_have_failed_without_dedent() -> None:
    """The raw indented script must indeed be unparseable.

    Confirms that the indentation pattern produced by inline call sites
    is genuinely invalid Python at module scope. Without dedent, the
    pre-fix path passes this string straight to ``exec``, which rejects
    it. Establishing this baseline makes it explicit that the dedent
    in ``_execute_remote`` is load-bearing rather than cosmetic.
    """
    indented = """
                values = []
                for i in range(3):
                    values.append(i * i)
                values
    """
    with pytest.raises(IndentationError):
        compile(indented, "<test>", "exec")


def test_prepare_remote_script_rewrites_trailing_expression() -> None:
    """The AST rewrite must promote a trailing expression to an assignment."""
    rewritten, sentinel = prepare_remote_script(
        """
            x = 1
            x + 2
        """,
    )
    assert sentinel is not None
    assert sentinel.startswith("_intellicrack_ghidra_result_")
    assert f"{sentinel} = x + 2" in rewritten


def test_prepare_remote_script_no_trailing_expression() -> None:
    """Scripts with no trailing expression must skip the sentinel rewrite."""
    rewritten, sentinel = prepare_remote_script(
        """
            x = 1
            y = 2
        """,
    )
    assert sentinel is None
    assert "_intellicrack_ghidra_result_" not in rewritten
    assert "x = 1" in rewritten
    assert "y = 2" in rewritten


def test_prepare_remote_script_invalid_syntax_raises_tool_error() -> None:
    """Malformed Jython source must surface as ``ToolError`` immediately."""
    with pytest.raises(ToolError):
        prepare_remote_script("def broken(:\n    pass\n")


def test_unique_sentinels_across_calls(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """Each call must allocate a fresh sentinel name to avoid stale reads.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a
            deterministic fake RPC client.
    """
    bridge, fake = bridge_with_fake
    first = _run(bridge.execute_script("'first:' + str(1 + 1)"))
    second = _run(bridge.execute_script("'second:' + str(2 + 2)"))
    assert first == "first:2"
    assert second == "second:4"
    assert fake.eval_payloads[0] != fake.eval_payloads[1]


def test_disconnected_bridge_raises_tool_error() -> None:
    """A disconnected bridge must raise ``ToolError`` from public reads."""
    bridge = GhidraBridge()
    with pytest.raises(ToolError):
        _run(bridge.read_bytes(_TEST_ADDRESS, 4))


def test_remote_exec_failure_propagates(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """Real failures from the remote side must propagate as ``ToolError``.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a
            deterministic fake RPC client.
    """
    bridge, _fake = bridge_with_fake
    with pytest.raises(ToolError):
        _run(bridge.execute_script("raise RuntimeError('remote boom')"))


def test_f0005_f0028_read_bytes_returns_real_payload(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """F-0005/F-0028: ``read_bytes`` must surface the actual byte payload.

    Pre-fix: ``_execute_remote`` returned ``None``, the
    ``isinstance(result, dict)`` guard fell through, and the method
    returned an empty list of bytes for every successful read. Now we
    drive the call through a fake remote that returns the expected
    Ghidra-shaped dict and confirm the bridge surfaces the bytes.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a
            deterministic fake RPC client.
    """
    bridge, fake = bridge_with_fake

    class _FakeAddr:
        """Minimal stand-in for :class:`ghidra.program.model.address.Address`."""

        def __init__(self, off: int) -> None:
            """Store the address offset.

            Args:
                off: Numeric address offset.
            """
            self._off = off

        def getOffset(self) -> int:  # noqa: N802
            """Return the address offset.

            Returns:
                int: Offset value the address was constructed with.
            """
            return self._off

    class _FakeMemory:
        """Stand-in for :class:`ghidra.program.model.mem.Memory`."""

        def getBytes(self, _addr: object, buf: list[int]) -> None:  # noqa: N802
            """Fill ``buf`` with deterministic bytes mimicking memory content.

            Args:
                _addr: Address to read from (ignored by the test double).
                buf: Buffer the caller allocated; populated in place.
            """
            for index in range(len(buf)):
                buf[index] = (0x90 + index) % 256

    class _FakeProgram:
        """Stand-in for :class:`ghidra.program.model.listing.Program`."""

        def __init__(self) -> None:
            """Initialise with a single fake memory subsystem."""
            self._memory = _FakeMemory()

        def getMemory(self) -> _FakeMemory:  # noqa: N802
            """Return the fake memory subsystem.

            Returns:
                _FakeMemory: Memory double exposed by this program.
            """
            return self._memory

    fake.globals["currentProgram"] = _FakeProgram()
    fake.globals["toAddr"] = _FakeAddr

    def _zeros(length: int, _typecode: str) -> list[int]:
        """Allocate a zero-filled list of the requested length.

        Args:
            length: Number of elements to allocate.
            _typecode: Jython typecode (ignored by the test double).

        Returns:
            list[int]: Zero-filled list with ``length`` elements.
        """
        return [0] * length

    jarray_module = types.ModuleType("jarray")
    setattr(jarray_module, "zeros", _zeros)
    sys.modules["jarray"] = jarray_module

    try:
        result = _run(bridge.read_bytes(_TEST_ADDRESS, 4))
    finally:
        sys.modules.pop("jarray", None)

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    assert payload["address"] == hex(_TEST_ADDRESS)
    assert payload["length"] == 4
    assert payload["bytes"] == [0x90, 0x91, 0x92, 0x93]
    assert payload["hex"] == "90 91 92 93"


def test_f0006_f0025_get_functions_raises_on_remote_failure(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """F-0006/F-0025: ``get_functions`` must raise instead of returning [].

    Pre-fix: every exception was caught and the method returned an
    empty list, so callers could not distinguish "no functions" from
    "RPC failed". The fix raises ``ToolError`` for every non-success
    path. We trigger a real failure on the remote side and confirm the
    contract.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a
            deterministic fake RPC client.
    """
    bridge, fake = bridge_with_fake

    class _BoomFunctionManager:
        """Function manager double whose ``getFunctions`` always raises."""

        def getFunctions(self, _forward: bool) -> list[object]:  # noqa: N802, FBT001
            """Mirror Ghidra's ``FunctionManager.getFunctions`` and always raise.

            Args:
                _forward: Forward-iteration flag from the Ghidra API.

            Returns:
                list[object]: Never returns; the body always raises.

            Raises:
                RuntimeError: Always raised to drive the failure path.
            """
            error_message = "function manager unavailable"
            raise RuntimeError(error_message)

    class _BoomProgram:
        """Program double whose function manager always raises."""

        def getFunctionManager(self) -> _BoomFunctionManager:  # noqa: N802
            """Return the failure-injecting function manager.

            Returns:
                _BoomFunctionManager: Manager double that raises on access.
            """
            return _BoomFunctionManager()

    fake.globals["currentProgram"] = _BoomProgram()

    with pytest.raises(ToolError):
        _run(bridge.get_functions())


def test_f0011_call_graph_uses_get_called_functions(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """F-0011: ``get_call_graph`` must use ``Function.getCalledFunctions``.

    Pre-fix: the bridge iterated every byte of the function body and
    issued a per-byte ``getReferencesFrom`` lookup, producing O(N*M)
    RPC calls. The fix delegates to
    ``Function.getCalledFunctions(monitor)`` which Ghidra implements as
    a single call-target query. This test builds a tiny call graph
    using the Ghidra-shaped API surface, confirms the result, and
    asserts the per-byte API is never invoked.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a
            deterministic fake RPC client.
    """
    bridge, fake = bridge_with_fake

    class _FakeAddr:
        """Stand-in for :class:`ghidra.program.model.address.Address`."""

        def __init__(self, off: int) -> None:
            """Store the address offset.

            Args:
                off: Numeric address offset.
            """
            self._off = off

        def getOffset(self) -> int:  # noqa: N802
            """Return the address offset.

            Returns:
                int: Offset value the address was constructed with.
            """
            return self._off

    class _FakeFunction:
        """Stand-in for :class:`ghidra.program.model.listing.Function`."""

        def __init__(self, name: str, off: int) -> None:
            """Construct a fake function with empty call relationships.

            Args:
                name: Function display name.
                off: Entry-point address offset.
            """
            self._name = name
            self._addr = _FakeAddr(off)
            self.called: list[_FakeFunction] = []
            self.callers: list[_FakeFunction] = []

        def getName(self) -> str:  # noqa: N802
            """Return the function name.

            Returns:
                str: Display name supplied at construction.
            """
            return self._name

        def getEntryPoint(self) -> _FakeAddr:  # noqa: N802
            """Return the function entry point address.

            Returns:
                _FakeAddr: Address double for the entry point.
            """
            return self._addr

        def getCalledFunctions(self, _monitor: object) -> list[_FakeFunction]:  # noqa: N802
            """Return the configured callee list.

            Args:
                _monitor: Ghidra task monitor (ignored in the test double).

            Returns:
                list[_FakeFunction]: Callees configured on this function.
            """
            return list(self.called)

        def getCallingFunctions(self, _monitor: object) -> list[_FakeFunction]:  # noqa: N802
            """Return the configured caller list.

            Args:
                _monitor: Ghidra task monitor (ignored in the test double).

            Returns:
                list[_FakeFunction]: Callers configured on this function.
            """
            return list(self.callers)

    root = _FakeFunction("root", _TEST_ADDRESS)
    leaf_a = _FakeFunction("leaf_a", _TEST_ADDRESS + 0x10)
    leaf_b = _FakeFunction("leaf_b", _TEST_ADDRESS + 0x20)
    caller = _FakeFunction("caller", _TEST_ADDRESS + 0x30)
    root.called = [leaf_a, leaf_b]
    root.callers = [caller]

    perbyte_calls = 0

    def _references_from(_addr: object) -> list[object]:
        """Track per-byte reference-from lookups so the test can assert none occur.

        Args:
            _addr: Address being queried (ignored).

        Returns:
            list[object]: Always empty; presence of any call is itself the failure.
        """
        nonlocal perbyte_calls
        perbyte_calls += 1
        return []

    def _references_to(_addr: object) -> list[object]:
        """Return an empty reference-to list for any address.

        Args:
            _addr: Address being queried (ignored).

        Returns:
            list[object]: Always empty.
        """
        return []

    def _to_addr(off: object) -> _FakeAddr:
        """Construct a fake address for the supplied offset.

        Args:
            off: Numeric or numeric-coercible offset.

        Returns:
            _FakeAddr: Address double for ``off``.
        """
        return _FakeAddr(int(cast("int", off)))

    def _function_containing(_addr: object) -> _FakeFunction:
        """Return the root fake function for any address query.

        Args:
            _addr: Address being queried (ignored).

        Returns:
            _FakeFunction: The single fake root function.
        """
        return root

    def _function_at(_addr: object) -> _FakeFunction | None:
        """Return ``None`` so the bridge falls through to ``getFunctionContaining``.

        Args:
            _addr: Address being queried (ignored).

        Returns:
            _FakeFunction | None: Always ``None`` in this test setup.
        """
        return None

    fake.globals["toAddr"] = _to_addr
    fake.globals["getFunctionContaining"] = _function_containing
    fake.globals["monitor"] = object()
    fake.globals["getReferencesFrom"] = _references_from
    fake.globals["getReferencesTo"] = _references_to
    fake.globals["getFunctionAt"] = _function_at

    result = _run(bridge.get_call_graph(_TEST_ADDRESS, depth=1))

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    assert payload["name"] == "root"
    assert payload["address"] == _TEST_ADDRESS
    callee_names = sorted(cast("str", child["name"]) for child in cast("list[dict[str, Any]]", payload["callees"]))
    assert callee_names == ["leaf_a", "leaf_b"]
    caller_names = [cast("str", child["name"]) for child in cast("list[dict[str, Any]]", payload["callers"])]
    assert caller_names == ["caller"]
    assert perbyte_calls == 0, f"get_call_graph still issuing per-byte getReferencesFrom calls: {perbyte_calls}"


def test_f0011_call_tree_uses_get_called_functions(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """F-0011: ``get_call_tree`` must also use ``Function.getCalledFunctions``.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a
            deterministic fake RPC client.
    """
    bridge, fake = bridge_with_fake

    class _FakeAddr:
        """Stand-in for :class:`ghidra.program.model.address.Address`."""

        def __init__(self, off: int) -> None:
            """Store the address offset.

            Args:
                off: Numeric address offset.
            """
            self._off = off

        def getOffset(self) -> int:  # noqa: N802
            """Return the address offset.

            Returns:
                int: Offset value the address was constructed with.
            """
            return self._off

    class _FakeFunction:
        """Stand-in for :class:`ghidra.program.model.listing.Function`."""

        def __init__(self, name: str, off: int) -> None:
            """Construct a fake function with empty call relationships.

            Args:
                name: Function display name.
                off: Entry-point address offset.
            """
            self._name = name
            self._addr = _FakeAddr(off)
            self.called: list[_FakeFunction] = []
            self.callers: list[_FakeFunction] = []

        def getName(self) -> str:  # noqa: N802
            """Return the function name.

            Returns:
                str: Display name supplied at construction.
            """
            return self._name

        def getEntryPoint(self) -> _FakeAddr:  # noqa: N802
            """Return the function entry point address.

            Returns:
                _FakeAddr: Address double for the entry point.
            """
            return self._addr

        def getCalledFunctions(self, _monitor: object) -> list[_FakeFunction]:  # noqa: N802
            """Return the configured callee list.

            Args:
                _monitor: Ghidra task monitor (ignored in the test double).

            Returns:
                list[_FakeFunction]: Callees configured on this function.
            """
            return list(self.called)

        def getCallingFunctions(self, _monitor: object) -> list[_FakeFunction]:  # noqa: N802
            """Return the configured caller list.

            Args:
                _monitor: Ghidra task monitor (ignored in the test double).

            Returns:
                list[_FakeFunction]: Callers configured on this function.
            """
            return list(self.callers)

    root = _FakeFunction("root", _TEST_ADDRESS)
    child = _FakeFunction("child", _TEST_ADDRESS + 0x10)
    root.called = [child]

    perbyte_calls = 0

    def _references_from(_addr: object) -> list[object]:
        """Track per-byte reference-from lookups so the test can assert none occur.

        Args:
            _addr: Address being queried (ignored).

        Returns:
            list[object]: Always empty; presence of any call is itself the failure.
        """
        nonlocal perbyte_calls
        perbyte_calls += 1
        return []

    def _to_addr(off: object) -> _FakeAddr:
        """Construct a fake address for the supplied offset.

        Args:
            off: Numeric or numeric-coercible offset.

        Returns:
            _FakeAddr: Address double for ``off``.
        """
        return _FakeAddr(int(cast("int", off)))

    def _function_containing(_addr: object) -> _FakeFunction:
        """Return the root fake function for any address query.

        Args:
            _addr: Address being queried (ignored).

        Returns:
            _FakeFunction: The single fake root function.
        """
        return root

    def _function_at(_addr: object) -> _FakeFunction | None:
        """Return ``None`` so the bridge falls through to ``getFunctionContaining``.

        Args:
            _addr: Address being queried (ignored).

        Returns:
            _FakeFunction | None: Always ``None`` in this test setup.
        """
        return None

    def _references_to(_addr: object) -> list[object]:
        """Return an empty reference-to list for any address.

        Args:
            _addr: Address being queried (ignored).

        Returns:
            list[object]: Always empty.
        """
        return []

    fake.globals["toAddr"] = _to_addr
    fake.globals["getFunctionContaining"] = _function_containing
    fake.globals["monitor"] = object()
    fake.globals["getReferencesFrom"] = _references_from
    fake.globals["getReferencesTo"] = _references_to
    fake.globals["getFunctionAt"] = _function_at

    result = _run(bridge.get_call_tree(_TEST_ADDRESS, direction="callees", depth=1))

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    assert payload["function"] == "root"
    assert payload["address"] == _TEST_ADDRESS
    children = [cast("str", c["function"]) for c in cast("list[dict[str, Any]]", payload["children"])]
    assert children == ["child"]
    assert perbyte_calls == 0, f"get_call_tree still issuing per-byte getReferencesFrom calls: {perbyte_calls}"


def test_f0028_decompile_raises_on_function_not_found(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """F-0028: ``decompile`` must raise instead of returning a sentinel string.

    Pre-fix: the method silently returned the literal string
    ``"Decompilation failed"`` when the function did not exist or the
    decompiler did not complete, conflating success and failure. The
    fix raises ``ToolError`` with a structured message.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a
            deterministic fake RPC client.
    """
    bridge, fake = bridge_with_fake

    class _FakeAddr:
        """Stand-in for :class:`ghidra.program.model.address.Address`."""

        def __init__(self, off: int) -> None:
            """Store the address offset.

            Args:
                off: Numeric address offset.
            """
            self._off = off

        def getOffset(self) -> int:  # noqa: N802
            """Return the address offset.

            Returns:
                int: Offset value the address was constructed with.
            """
            return self._off

    class _FakeOptions:
        """Decompiler-options double that accepts every setter call."""

        def setSimplificationStyle(self, _value: str) -> None:  # noqa: N802
            """Accept and ignore the simplification style.

            Args:
                _value: Simplification style name.
            """
            return

        def setMaxInstructions(self, _value: int) -> None:  # noqa: N802
            """Accept and ignore the maximum-instructions setting.

            Args:
                _value: Numeric instruction cap.
            """
            return

        def setOption(self, _key: str, _value: str) -> None:  # noqa: N802
            """Accept and ignore an arbitrary option key/value pair.

            Args:
                _key: Option name.
                _value: Option value.
            """
            return

    class _FakeDecompInterface:
        """Decompiler-interface double that opens but never decompiles."""

        def openProgram(self, _prog: object) -> None:  # noqa: N802
            """Accept and ignore the program-open call.

            Args:
                _prog: Program to attach (ignored by the test double).
            """
            return

        def getOptions(self) -> _FakeOptions:  # noqa: N802
            """Return a fresh options double.

            Returns:
                _FakeOptions: Options double for the decompiler.
            """
            return _FakeOptions()

        def setOptions(self, _opts: _FakeOptions) -> None:  # noqa: N802
            """Accept and ignore the options override.

            Args:
                _opts: Options bundle (ignored by the test double).
            """
            return

    decompiler_module = types.ModuleType("ghidra.app.decompiler")
    setattr(decompiler_module, "DecompInterface", _FakeDecompInterface)
    sys.modules["ghidra"] = types.ModuleType("ghidra")
    sys.modules["ghidra.app"] = types.ModuleType("ghidra.app")
    sys.modules["ghidra.app.decompiler"] = decompiler_module

    def _to_addr(off: object) -> _FakeAddr:
        """Construct a fake address for the supplied offset.

        Args:
            off: Numeric or numeric-coercible offset.

        Returns:
            _FakeAddr: Address double for ``off``.
        """
        return _FakeAddr(int(cast("int", off)))

    fake.globals["currentProgram"] = object()
    fake.globals["toAddr"] = _to_addr

    def _function_containing(_addr: object) -> object:
        """Return ``None`` so the bridge surfaces the not-found ``ToolError``.

        Args:
            _addr: Address being queried (ignored).

        Returns:
            object: Always ``None`` for this test setup.
        """
        return None

    fake.globals["getFunctionContaining"] = _function_containing
    fake.globals["monitor"] = object()

    try:
        with pytest.raises(ToolError):
            _run(bridge.decompile(_TEST_ADDRESS))
    finally:
        sys.modules.pop("ghidra.app.decompiler", None)
        sys.modules.pop("ghidra.app", None)
        sys.modules.pop("ghidra", None)


def _alloc_port() -> int:
    """Return an unused TCP port for tests that need a fresh listener.

    Returns:
        int: An OS-assigned ephemeral port number.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    finally:
        sock.close()
    return port


def _make_stub_headless(path: Path) -> Path:
    """Create a tiny platform-appropriate ``analyzeHeadless`` stub.

    The stub stays alive for several seconds, prints diagnostic messages on
    both stdout and stderr, then exits. Tests can spawn it via the real
    ``subprocess.Popen`` to exercise the launcher, env scrubbing, drain
    threads, and shutdown without requiring a full Ghidra install.

    Args:
        path: Directory in which to create the ``support`` tree.

    Returns:
        Path: Full path to the stub launcher (``.bat`` on Windows).
    """
    support = path / "support"
    support.mkdir(parents=True, exist_ok=True)

    if os.name == "nt":
        stub = support / "analyzeHeadless.bat"
        stub.write_text(
            "@echo off\r\necho headless-stdout-line\r\necho headless-stderr-line 1>&2\r\nping -n 5 127.0.0.1 >nul\r\nexit /b 0\r\n",
            encoding="utf-8",
        )
    else:
        stub = support / "analyzeHeadless"
        stub.write_text(
            "#!/usr/bin/env bash\necho headless-stdout-line\necho headless-stderr-line 1>&2\nsleep 4\nexit 0\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)

    return stub


def _bridge_script_lock() -> threading.Lock:
    """Return the module-level bridge-script lock used by GhidraBridge.

    Returns:
        threading.Lock: The lock instance from ``intellicrack.bridges.ghidra``.
    """
    return cast("threading.Lock", getattr(ghidra_mod, "_BRIDGE_SCRIPT_LOCK"))


def _env_blocklist() -> tuple[str, ...]:
    """Return the headless env blocklist tuple.

    Returns:
        tuple[str, ...]: Variables stripped from ``Popen``'s ``env``.
    """
    return cast("tuple[str, ...]", getattr(ghidra_mod, "_HEADLESS_ENV_BLOCKLIST"))


@pytest.fixture
def fresh_bridge() -> GhidraBridge:
    """Return a freshly constructed ``GhidraBridge``.

    Returns:
        GhidraBridge: A new bridge instance with no active connection.
    """
    bridge = GhidraBridge()
    bridge.set_port(_alloc_port())
    return bridge


def test_create_bridge_script_uses_run_server(fresh_bridge: GhidraBridge, tmp_path: Path) -> None:
    """F-0003: Deployed script must call ``GhidraBridgeServer.run_server``.

    Args:
        fresh_bridge: Bridge fixture.
        tmp_path: Pytest-provided per-test temp directory.
    """
    with patch("tempfile.gettempdir", return_value=str(tmp_path)):
        script_path = fresh_bridge.create_bridge_script()

    text = script_path.read_text(encoding="utf-8")
    assert "GhidraBridgeServer.run_server" in text, text
    assert "GhidraBridgeServer(" not in text, "must not invoke non-existent constructor"
    assert ").start()" not in text, "must not call non-existent start() instance method"


def test_create_bridge_script_background_false(fresh_bridge: GhidraBridge, tmp_path: Path) -> None:
    """F-0004: ``run_server`` must be invoked with ``background=False``.

    Args:
        fresh_bridge: Bridge fixture.
        tmp_path: Pytest temp dir.
    """
    with patch("tempfile.gettempdir", return_value=str(tmp_path)):
        script_path = fresh_bridge.create_bridge_script()

    text = script_path.read_text(encoding="utf-8")
    assert "background=False" in text, text


def test_create_bridge_script_utf8_encoding(fresh_bridge: GhidraBridge, tmp_path: Path) -> None:
    """F-0009: Script must be written with explicit utf-8 encoding.

    Args:
        fresh_bridge: Bridge fixture.
        tmp_path: Pytest temp dir.
    """
    with patch("tempfile.gettempdir", return_value=str(tmp_path)):
        script_path = fresh_bridge.create_bridge_script()

    raw = script_path.read_bytes()
    decoded = raw.decode("utf-8")
    assert "ghidra_bridge_server" in decoded
    assert raw == decoded.encode("utf-8"), "round-trip via utf-8 must produce byte-identical content"


def test_create_bridge_script_oserror_raises_toolerror(
    fresh_bridge: GhidraBridge,
    tmp_path: Path,
) -> None:
    """F-0009: ``OSError`` during write must surface as ``ToolError``.

    Args:
        fresh_bridge: Bridge fixture.
        tmp_path: Pytest temp dir.
    """
    real_write_text = Path.write_text
    failure_msg = "simulated disk full"

    def _failing_write_text(self: Path, data: str, *, encoding: str | None = None, errors: str | None = None) -> int:
        if self.name == "start_bridge.py":
            raise OSError(failure_msg)
        return real_write_text(self, data, encoding=encoding, errors=errors)

    with (
        patch("tempfile.gettempdir", return_value=str(tmp_path)),
        patch.object(Path, "write_text", _failing_write_text),
        pytest.raises(ToolError, match="Failed to write ghidra bridge script"),
    ):
        fresh_bridge.create_bridge_script()


def test_create_bridge_script_unique_tempdirs(fresh_bridge: GhidraBridge) -> None:
    """F-0013 / F-0021: Each invocation must get its own tempdir under the lock.

    Args:
        fresh_bridge: Bridge fixture.
    """
    first = fresh_bridge.create_bridge_script()
    second = fresh_bridge.create_bridge_script()

    try:
        assert first != second
        assert first.parent != second.parent
        assert first.parent.name.startswith("intellicrack_ghidra_")
        assert second.parent.name.startswith("intellicrack_ghidra_")
    finally:
        for p in (first, second):
            if p.exists():
                p.unlink()
            if p.parent.exists():
                with contextlib.suppress(OSError):
                    p.parent.rmdir()


def test_create_bridge_script_concurrent_no_collisions() -> None:
    """F-0013: Parallel ``create_bridge_script`` calls must not collide."""
    bridges = [GhidraBridge() for _ in range(8)]
    for b in bridges:
        b.set_port(_alloc_port())

    results: list[Path] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def _runner(b: GhidraBridge) -> None:
        try:
            p = b.create_bridge_script()
        except (ToolError, OSError) as exc:
            with lock:
                errors.append(exc)
        else:
            with lock:
                results.append(p)

    threads = [threading.Thread(target=_runner, args=(b,)) for b in bridges]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    try:
        assert not errors, f"unexpected errors: {errors}"
        unique_parents = len({p.parent for p in results})
        assert unique_parents == len(results), "every concurrent invocation must get a unique parent dir"
    finally:
        for p in results:
            if p.exists():
                p.unlink()
            with contextlib.suppress(OSError):
                p.parent.rmdir()


def test_create_bridge_script_logs_after_verification(
    fresh_bridge: GhidraBridge,
    tmp_path: Path,
) -> None:
    """F-0019: ``file_written`` must follow successful readback.

    Args:
        fresh_bridge: Bridge fixture.
        tmp_path: Pytest temp dir.
    """
    real_write_text = Path.write_text

    def _truncating_write_text(self: Path, data: str, *, encoding: str | None = None, errors: str | None = None) -> int:
        if self.name == "start_bridge.py":
            return real_write_text(self, "WRONG", encoding=encoding or "utf-8", errors=errors)
        return real_write_text(self, data, encoding=encoding, errors=errors)

    with (
        patch("tempfile.gettempdir", return_value=str(tmp_path)),
        patch.object(Path, "write_text", _truncating_write_text),
        pytest.raises(ToolError, match="bridge script verification failed"),
    ):
        fresh_bridge.create_bridge_script()


def test_close_bridge_client_closes_socket() -> None:
    """F-0012: ``GhidraBridge`` shutdown closure helper must close the RPC socket."""

    class _DummySock:
        """Minimal socket stand-in tracking ``close`` calls."""

        def __init__(self) -> None:
            """Initialize the dummy socket flag tracker."""
            self.closed: bool = False

        def close(self) -> None:
            """Mark the dummy socket as closed."""
            self.closed = True

    class _DummyClient:
        """Minimal BridgeConn stand-in carrying the socket and comms thread."""

        def __init__(self) -> None:
            """Initialize sock and a sentinel comms thread reference."""
            self.sock: _DummySock = _DummySock()
            self.comms_thread: threading.Thread | None = None

    class _DummyBridge:
        """Minimal ghidra_bridge.GhidraBridge stand-in exposing ``client``."""

        def __init__(self) -> None:
            """Initialize the dummy bridge with an attached dummy client."""
            self.client: _DummyClient = _DummyClient()

    closer = cast("Callable[[object], None]", getattr(GhidraBridge, "_close_bridge_client"))
    bridge_obj = _DummyBridge()
    closer(bridge_obj)
    assert bridge_obj.client.sock.closed is True


def test_close_bridge_client_no_client_attr_safe() -> None:
    """F-0012: Missing ``client`` attribute must not raise."""

    class _Empty:
        """Bridge stand-in without a ``client`` attribute."""

    closer = cast("Callable[[object], None]", getattr(GhidraBridge, "_close_bridge_client"))
    closer(_Empty())


def test_resolve_headless_executable_platform_specific(tmp_path: Path) -> None:
    """F-0016: ``analyzeHeadless`` resolution must be platform-aware.

    Args:
        tmp_path: Pytest temp dir.
    """
    resolver = cast("Callable[[Path], Path]", getattr(GhidraBridge, "_resolve_headless_executable"))
    support = tmp_path / "support"
    support.mkdir()

    if os.name == "nt":
        (support / "analyzeHeadless.bat").write_text("@echo off", encoding="utf-8")
        resolved = resolver(tmp_path)
        assert resolved.name == "analyzeHeadless.bat"

        wrong = tmp_path.parent / f"wrong_root_{os.getpid()}"
        (wrong / "support").mkdir(parents=True, exist_ok=True)
        (wrong / "support" / "analyzeHeadless").write_text(
            "#!/usr/bin/env bash\n",
            encoding="utf-8",
        )
        try:
            with pytest.raises(ToolError, match="Ghidra headless script not found"):
                resolver(wrong)
        finally:
            for p in (wrong / "support" / "analyzeHeadless", wrong / "support", wrong):
                if p.exists():
                    if p.is_file():
                        p.unlink()
                    else:
                        with contextlib.suppress(OSError):
                            p.rmdir()
    else:
        (support / "analyzeHeadless").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
        resolved = resolver(tmp_path)
        assert resolved.name == "analyzeHeadless"


def test_scrubbed_environment_strips_blocklist() -> None:
    """F-0015: Env scrub must strip every variable in the blocklist."""
    scrubber = cast("Callable[[], dict[str, str]]", getattr(GhidraBridge, "_scrubbed_environment"))
    blocklist = _env_blocklist()
    inserted: list[str] = []
    for key in blocklist:
        if key not in os.environ:
            os.environ[key] = "intellicrack-test-value"
            inserted.append(key)
    try:
        env = scrubber()
        for key in blocklist:
            assert key not in env, f"{key} must be stripped"
        assert "PATH" in env, "PATH must survive scrubbing"
    finally:
        for key in inserted:
            os.environ.pop(key, None)


def test_cleanup_bridge_script_removes_files(tmp_path: Path) -> None:
    """F-0013: cleanup must serialize via lock and remove files.

    Args:
        tmp_path: Pytest temp dir.
    """
    cleanup = cast("Callable[[Path], None]", getattr(GhidraBridge, "_cleanup_bridge_script"))
    script_dir = tmp_path / "intellicrack_ghidra_unit"
    script_dir.mkdir()
    script = script_dir / "start_bridge.py"
    script.write_text("# stub", encoding="utf-8")

    cleanup(script)

    assert not script.exists()
    assert not script_dir.exists()


def test_cleanup_bridge_script_uses_global_lock(tmp_path: Path) -> None:
    """F-0013: ``_cleanup_bridge_script`` must hold the bridge-script lock.

    Args:
        tmp_path: Pytest temp dir.
    """
    cleanup = cast("Callable[[Path], None]", getattr(GhidraBridge, "_cleanup_bridge_script"))
    bridge_lock = _bridge_script_lock()
    observed: list[bool] = []
    real_unlink = Path.unlink

    def _spy_unlink(self: Path, *, missing_ok: bool = False) -> None:
        observed.append(bridge_lock.locked())
        real_unlink(self, missing_ok=missing_ok)

    with patch.object(Path, "unlink", _spy_unlink):
        d = tmp_path / f"intellicrack_lock_test_{os.getpid()}"
        d.mkdir(exist_ok=True)
        f = d / "start_bridge.py"
        f.write_text("x", encoding="utf-8")
        try:
            cleanup(f)
        finally:
            if f.exists():
                f.unlink()
            if d.exists():
                d.rmdir()

    assert observed, "expected at least one unlink call"
    assert all(observed), "global lock must be held during unlink"


_LogLineGetter = Callable[[], list[str]]


def _wait_for_log_lines(buf_getter: _LogLineGetter, count: int, timeout: float = 6.0) -> list[str]:
    """Poll until the bridge stderr buffer has at least ``count`` lines.

    Args:
        buf_getter: Callable returning the current snapshot of stderr lines.
        count: Minimum number of lines to wait for.
        timeout: Maximum seconds to wait.

    Returns:
        list[str]: The collected stderr lines.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = buf_getter()
        if len(lines) >= count:
            return lines
        time.sleep(0.1)
    return buf_getter()


def test_drain_threads_consume_stderr_in_real_subprocess(
    fresh_bridge: GhidraBridge,
    tmp_path: Path,
) -> None:
    """F-0014: drain threads must consume stderr from a real subprocess.

    Args:
        fresh_bridge: Bridge fixture.
        tmp_path: Pytest temp dir.
    """
    stub = _make_stub_headless(tmp_path)

    if os.name == "nt":
        cmd = ["cmd.exe", "/c", str(stub)]
        creation_flags = CREATE_NO_WINDOW
    else:
        cmd = [str(stub)]
        creation_flags = 0

    process = Popen(
        cmd,
        stdout=PIPE,
        stderr=PIPE,
        cwd=str(stub.parent),
        creationflags=creation_flags,
    )

    start_drain = cast(
        "Callable[[Popen[bytes]], None]",
        getattr(fresh_bridge, "_start_drain_threads"),
    )

    try:
        start_drain(process)
        process.wait(timeout=15)

        buffer_lock = cast("threading.Lock", getattr(fresh_bridge, "_stderr_buffer_lock"))

        def _snapshot() -> list[str]:
            with buffer_lock:
                return list(cast("list[str]", getattr(fresh_bridge, "_stderr_buffer")))

        lines = _wait_for_log_lines(_snapshot, 1)
        assert any("headless-stderr-line" in line for line in lines), lines
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        for thread_attr in ("_stderr_drain_thread", "_stdout_drain_thread"):
            thread = cast("threading.Thread | None", getattr(fresh_bridge, thread_attr))
            if thread is not None:
                thread.join(timeout=2)


def test_start_headless_uses_correct_popen_kwargs(
    fresh_bridge: GhidraBridge,
    tmp_path: Path,
) -> None:
    """F-0015 + F-0016: real Popen invocation must include cwd, env, and creationflags.

    Args:
        fresh_bridge: Bridge fixture.
        tmp_path: Pytest temp dir.
    """
    _ = _make_stub_headless(tmp_path)
    fresh_bridge.ghidra_path = tmp_path

    captured: dict[str, Any] = {}
    real_popen = Popen

    def _spy_popen(
        cmd: list[str],
        *,
        stdout: int | None = None,
        stderr: int | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        creationflags: int = 0,
    ) -> Popen[bytes]:
        captured["cmd"] = cmd
        captured["kwargs"] = {
            "stdout": stdout,
            "stderr": stderr,
            "cwd": cwd,
            "env": env,
            "creationflags": creationflags,
        }
        return real_popen(
            cmd,
            stdout=stdout,
            stderr=stderr,
            cwd=cwd,
            env=env,
            creationflags=creationflags,
        )

    project_dir = tmp_path / "proj"

    async def _run() -> None:
        try:
            with patch("intellicrack.bridges.ghidra.Popen", _spy_popen):
                await asyncio.wait_for(
                    fresh_bridge.start_headless(project_dir, "intellicrack_test"),
                    timeout=8,
                )
        except (ToolError, TimeoutError):
            pass
        finally:
            running = cast("Popen[bytes] | None", getattr(fresh_bridge, "_process"))
            if running is not None and running.poll() is None:
                running.kill()
                running.wait()
            await fresh_bridge.shutdown()

    asyncio.run(_run())

    assert "kwargs" in captured, "Popen was not invoked"
    kwargs = cast("dict[str, Any]", captured["kwargs"])
    assert kwargs.get("cwd") is not None, "cwd must be set"
    assert kwargs.get("env") is not None, "env must be passed"

    if os.name == "nt":
        assert kwargs.get("creationflags") == CREATE_NO_WINDOW, kwargs.get("creationflags")
    else:
        assert kwargs.get("creationflags") in {0, None}, kwargs.get("creationflags")

    env = cast("dict[str, str]", kwargs["env"])
    for key in _env_blocklist():
        assert key not in env, f"{key} must be scrubbed in Popen env"

    cmd = cast("list[str]", captured["cmd"])
    if os.name == "nt":
        assert cmd[0].endswith("analyzeHeadless.bat"), cmd[0]
    else:
        assert cmd[0].endswith("analyzeHeadless"), cmd[0]


def test_shutdown_closes_bridge_client_socket() -> None:
    """F-0012: shutdown must close ``self._bridge.client.sock``."""

    class _DummySock:
        """Socket stand-in for shutdown closure assertion."""

        def __init__(self) -> None:
            """Initialize closed flag."""
            self.closed: bool = False

        def close(self) -> None:
            """Mark socket as closed."""
            self.closed = True

    class _DummyClient:
        """BridgeConn stand-in with sock + thread sentinel."""

        def __init__(self) -> None:
            """Initialize sock and a sentinel thread reference."""
            self.sock: _DummySock = _DummySock()
            self.comms_thread: threading.Thread | None = None

    class _DummyBridge:
        """Bridge stand-in carrying the dummy client."""

        def __init__(self) -> None:
            """Initialize a dummy bridge with attached dummy client."""
            self.client: _DummyClient = _DummyClient()

    bridge = GhidraBridge()
    dummy = _DummyBridge()
    bridge_attr = "_bridge"
    setattr(bridge, bridge_attr, dummy)

    asyncio.run(bridge.shutdown())

    assert dummy.client.sock.closed is True
    assert getattr(bridge, bridge_attr) is None
