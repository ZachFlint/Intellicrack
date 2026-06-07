# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit-6 GHIDRA-A, GHIDRA-B, GHIDRA-C, and GHIDRA-D regression tests.

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

GHIDRA-C write-method and analyze findings:

* F-0007 - ``decompile`` raises ``ToolError`` on every real failure mode
  (function not found, decompiler did not complete) instead of
  returning the literal sentinel string ``"Decompilation failed"``.
* F-0008 - ``analyze`` blocks on
  ``AutoAnalysisManager.waitForAnalysis`` instead of returning the
  moment ``analyzeAll`` is dispatched.
* F-0010 - ``search_bytes`` raises ``ToolError`` on malformed hex
  tokens and on empty hex input rather than silently returning ``[]``.
* F-0020 - ``set_label`` / ``add_comment`` / ``rename_function`` /
  ``create_bookmark`` / ``add_reference`` / ``create_equate`` /
  ``set_program_metadata`` verify the remote-side outcome via
  ``remote_eval`` readback before returning ``success: True``.
* F-0024 - ``set_color`` raises ``ToolError`` in headless mode instead
  of returning fake-success via the ``IntPropertyMap`` fallback.
* F-0027 - ``analyze`` emits structured logs that distinguish the
  ``analyzeAll`` start phase from the
  ``waitForAnalysis``-returned phase.

GHIDRA-D parsing/xrefs/security/capability findings:

* F-0017 - MD5 must not be exposed in :class:`BinaryInfo`.
* F-0018 - ``import_debug_info`` must canonicalise + existence-check the path.
* F-0022 - ``get_xrefs_to`` / ``get_xrefs_from`` must preserve the full
  Ghidra reference-type taxonomy (call/jump/read/write/data) instead of
  flattening to ``call``/``data``.
* F-0023 - ``BridgeCapabilities.supports_patching`` must be ``False`` because
  ``GhidraBridge`` exposes no ``apply_patch`` implementation.
* F-0026 - xref results must populate ``from_function`` / ``to_function``
  enrichment fields when Ghidra resolves a containing function.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import socket
import sys
import threading
import time
import types
from collections.abc import Callable
from dataclasses import fields
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal, cast
from unittest.mock import patch

import pytest

import intellicrack.bridges.ghidra as ghidra_mod
from intellicrack.bridges.ghidra import GhidraBridge, prepare_remote_script
from intellicrack.core.subprocess_compat import CREATE_NO_WINDOW, PIPE, Popen
from intellicrack.core.types import BinaryInfo, CrossReference, ToolError


if TYPE_CHECKING:
    from collections.abc import Coroutine


_TEST_ADDRESS: Final[int] = 0x401000
_TEST_TO_ADDRESS: Final[int] = 0x402000
_TEST_COLOR_RED: Final[int] = 0xFF0000

_EvalResponder = Callable[[str], object]


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

    The patch intercepts only ``write_text`` calls on the bridge script
    file (``start_bridge.py``) by checking ``self.name`` before raising,
    so every other ``write_text`` call (e.g. for tmp dir creation) still
    uses the real implementation. The error message in the raised
    ``ToolError`` must contain both the fixed prefix and the original
    ``OSError`` text so callers can diagnose the cause.

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
        pytest.raises(ToolError) as exc_info,
    ):
        fresh_bridge.create_bridge_script()

    raised_msg = str(exc_info.value)
    assert "Failed to write ghidra bridge script" in raised_msg, (
        f"Expected 'Failed to write ghidra bridge script' in error, got: {raised_msg!r}"
    )
    assert failure_msg in raised_msg, f"Expected original OSError text {failure_msg!r} in ToolError, got: {raised_msg!r}"
    assert "start_bridge.py" in raised_msg, f"Expected script path 'start_bridge.py' in error message, got: {raised_msg!r}"


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
        _drive_drain_threads_and_assert(fresh_bridge, process, start_drain)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        for thread_attr in ("_stderr_drain_thread", "_stdout_drain_thread"):
            thread = cast("threading.Thread | None", getattr(fresh_bridge, thread_attr))
            if thread is not None:
                thread.join(timeout=2)


def _drive_drain_threads_and_assert(
    fresh_bridge: GhidraBridge,
    process: Popen[bytes],
    start_drain: Callable[[Popen[bytes]], None],
) -> None:
    """Start drain threads, wait, and assert headless stderr was captured.

    Args:
        fresh_bridge: GhidraBridge under test.
        process: Subprocess running the headless stub.
        start_drain: Bound ``_start_drain_threads`` from ``fresh_bridge``.
    """
    start_drain(process)
    process.wait(timeout=15)

    buffer_lock = cast("threading.Lock", getattr(fresh_bridge, "_stderr_buffer_lock"))

    def _snapshot() -> list[str]:
        """Return a thread-safe snapshot of the bridge's stderr buffer.

        Returns:
            list[str]: Captured stderr lines collected by the drain thread.
        """
        with buffer_lock:
            return list(cast("list[str]", getattr(fresh_bridge, "_stderr_buffer")))

    lines = _wait_for_log_lines(_snapshot, 1)
    assert any("headless-stderr-line" in line for line in lines), lines


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


class FakeGhidraBridge:
    """Test double exposing the subset of ``ghidra_bridge`` GHIDRA-C uses.

    ``GhidraBridge`` accesses two callables on the underlying RPC
    client: :py:meth:`remote_exec` for statement scripts and
    :py:meth:`remote_eval` for value-returning expressions. The fake
    records every script and expression so tests can assert on the
    exact code sent across the bridge, and lets each test programme a
    deterministic value to return from ``remote_eval`` (the readback
    primitive the new readback-verification logic relies on).
    """

    def __init__(self) -> None:
        """Initialise empty exec/eval traces and default eval responder."""
        self.exec_calls: list[str] = []
        self.eval_calls: list[str] = []
        self.eval_response: object = None
        self.exec_response: object = None
        self._eval_responder: _EvalResponder | None = None
        self.exec_raises: BaseException | None = None
        self.eval_raises: BaseException | None = None

    def set_eval_responder(self, responder: _EvalResponder) -> None:
        """Install a callable computing the eval response from the expression.

        Args:
            responder: Callable that receives the eval expression string
                and returns the desired value. Overrides ``eval_response``
                while installed.
        """
        self._eval_responder = responder

    def remote_exec(self, code: str) -> object:
        """Record the script and optionally raise.

        ``ghidra_bridge.remote_exec`` returns ``None`` because the real
        runtime swallows trailing-expression results, but tests for
        scripts that capture their outcome in a trailing dict literal
        can override this by setting ``exec_response`` on the fake.

        Args:
            code: The Jython source the bridge would execute remotely.

        Returns:
            object: ``exec_response`` if set, otherwise ``None``.

        Raises:
            exc: Re-raised when the caller has set ``exec_raises`` on
                the fake. ``exc`` is bound to whatever exception
                instance the caller installed.
        """
        self.exec_calls.append(code)
        exc = self.exec_raises
        if exc is not None:
            raise exc
        return self.exec_response

    def remote_eval(self, expression: str, **_kwargs: object) -> object:
        """Record the expression and return the programmed value.

        Args:
            expression: The Jython expression to evaluate.
            **_kwargs: Ignored eval kwargs accepted to match the real
                ``jfx_bridge`` signature.

        Returns:
            object: Either the responder's return value (if a responder
            was installed) or the static ``eval_response``.

        Raises:
            exc: Re-raised when the caller has set ``eval_raises`` on
                the fake. ``exc`` is bound to whatever exception
                instance the caller installed.
        """
        self.eval_calls.append(expression)
        exc = self.eval_raises
        if exc is not None:
            raise exc
        if self._eval_responder is not None:
            responder = self._eval_responder
            return responder(expression)
        return self.eval_response


@pytest.fixture
def fake_bridge() -> FakeGhidraBridge:
    """Provide a fresh ``FakeGhidraBridge``.

    Returns:
        FakeGhidraBridge: A test double with empty traces.
    """
    return FakeGhidraBridge()


@pytest.fixture
def bridge(fake_bridge: FakeGhidraBridge) -> GhidraBridge:
    """Provide a ``GhidraBridge`` whose underlying client is the fake.

    Args:
        fake_bridge: The fake bridge fixture.

    Returns:
        GhidraBridge: Connected bridge wired to ``fake_bridge``.
    """
    real_bridge = GhidraBridge()
    setattr(real_bridge, "_bridge", fake_bridge)
    real_bridge.state.connected = True
    return real_bridge


# ---------------------------------------------------------------------------
# F-0008 + F-0027: analyze must block on waitForAnalysis and emit phased logs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyze_blocks_on_wait_for_analysis(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0008: analyze must dispatch waitForAnalysis on every successful run.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Recording fake.
    """
    await bridge.analyze()
    assert len(fake_bridge.exec_calls) == 1
    script = fake_bridge.exec_calls[0]
    assert "analyzeAll(currentProgram)" in script
    assert "AutoAnalysisManager" in script
    assert "waitForAnalysis" in script


@pytest.mark.asyncio
async def test_analyze_logs_distinguish_phases(
    bridge: GhidraBridge,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """F-0027: analyze emits ``started`` and ``complete`` log records.

    Args:
        bridge: Connected bridge fixture.
        capsys: pytest stdout/stderr capture fixture.
    """
    await bridge.analyze()
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "ghidra_analysis_started" in output
    assert "ghidra_analysis_complete" in output
    assert "wait_for_analysis_returned" in output


@pytest.mark.asyncio
async def test_analyze_propagates_remote_failure(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0008: analyze surfaces a ``ToolError`` when wait phase raises.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose ``remote_exec`` raises.
    """
    fake_bridge.exec_raises = RuntimeError("monitor cancelled")
    with pytest.raises(ToolError, match="monitor cancelled"):
        await bridge.analyze()


# ---------------------------------------------------------------------------
# F-0007: decompile must raise ToolError on every real failure mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_decompile_raises_when_function_not_found(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0007: missing function at address must raise instead of returning a string.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake programmed to report ``function_not_found``.
    """
    fake_bridge.eval_response = {
        "status": "function_not_found",
        "text": "",
        "error": "",
    }
    with pytest.raises(ToolError, match="Function not found"):
        await bridge.decompile(_TEST_ADDRESS)


@pytest.mark.asyncio
async def test_decompile_raises_when_decompiler_fails(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0007: decompiler-completed=False must raise rather than return sentinel.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake programmed to report ``failed`` status.
    """
    fake_bridge.eval_response = {
        "status": "failed",
        "text": "",
        "error": "Out of memory in decompiler",
    }
    with pytest.raises(ToolError, match="Out of memory in decompiler"):
        await bridge.decompile(_TEST_ADDRESS)


@pytest.mark.asyncio
async def test_decompile_returns_pseudocode_on_success(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0007: a successful decompile returns the recovered C source.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake programmed to report ``ok`` status.
    """
    fake_bridge.eval_response = {
        "status": "ok",
        "code": "void main(void) { return; }",
        "error": None,
    }
    text = await bridge.decompile(_TEST_ADDRESS)
    assert text == "void main(void) { return; }"


# ---------------------------------------------------------------------------
# F-0010: search_bytes hex validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_bytes_rejects_malformed_hex_token(
    bridge: GhidraBridge,
) -> None:
    """F-0010: a non-hex token must raise instead of being silently ignored.

    Args:
        bridge: Connected bridge fixture.
    """
    with pytest.raises(ToolError, match=re.escape("Malformed hex token")):
        await bridge.search_bytes("ZZ 90 90")


@pytest.mark.asyncio
async def test_search_bytes_rejects_empty_hex_pattern(
    bridge: GhidraBridge,
) -> None:
    """F-0010: empty hex input must raise instead of returning ``[]``.

    Args:
        bridge: Connected bridge fixture.
    """
    with pytest.raises(ToolError, match="empty"):
        await bridge.search_bytes(hex_pattern="   ")


@pytest.mark.asyncio
async def test_search_bytes_rejects_short_hex_token(
    bridge: GhidraBridge,
) -> None:
    """F-0010: a single-nibble token must raise instead of being parsed.

    Args:
        bridge: Connected bridge fixture.
    """
    with pytest.raises(ToolError, match="Malformed hex token"):
        await bridge.search_bytes(hex_pattern="48 8")


@pytest.mark.asyncio
async def test_search_bytes_accepts_wildcards_with_valid_bytes(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0010: valid hex with ``??`` wildcards must reach the bridge unchanged.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake recording the dispatched script.
    """
    fake_bridge.eval_response = None  # exec only, no eval used
    addrs = await bridge.search_bytes(hex_pattern="48 8B ?? ??")
    assert addrs == []
    assert len(fake_bridge.exec_calls) == 1
    script = fake_bridge.exec_calls[0]
    assert "findBytes" in script


# ---------------------------------------------------------------------------
# F-0020: write methods must verify remote outcome via remote_eval readback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_label_verifies_via_readback(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: a successful set_label round-trips the name through readback.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback contains the requested label.
    """
    fake_bridge.eval_response = ["my_label", "DEFAULT_LAB_00401000"]
    info = await bridge.set_label(_TEST_ADDRESS, "my_label")
    assert info["success"] is True
    assert any("getSymbols" in expr for expr in fake_bridge.eval_calls)


@pytest.mark.asyncio
async def test_set_label_raises_when_readback_missing_name(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: missing label in readback must raise instead of fake-success.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback omits the requested label.
    """
    fake_bridge.eval_response = ["DEFAULT_LAB_00401000"]
    with pytest.raises(ToolError, match="Label verification failed"):
        await bridge.set_label(_TEST_ADDRESS, "my_label")


@pytest.mark.asyncio
async def test_add_comment_verifies_via_readback(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: a successful add_comment round-trips through readback.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback returns the requested comment.
    """
    fake_bridge.eval_response = "investigated by analyst"
    ok = await bridge.add_comment(_TEST_ADDRESS, "investigated by analyst")
    assert ok is True
    assert any("getComment" in expr for expr in fake_bridge.eval_calls)


@pytest.mark.asyncio
async def test_add_comment_raises_when_readback_mismatches(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: comment mismatch on readback must raise rather than fake-success.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback differs from the requested comment.
    """
    fake_bridge.eval_response = "stale prior comment"
    with pytest.raises(ToolError, match="Comment verification failed"):
        await bridge.add_comment(_TEST_ADDRESS, "investigated by analyst")


@pytest.mark.asyncio
async def test_rename_function_verifies_via_readback(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: rename_function returns only when readback confirms the name.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback returns the new function name.
    """
    fake_bridge.eval_response = "decryptor"
    ok = await bridge.rename_function(_TEST_ADDRESS, "decryptor")
    assert ok is True


@pytest.mark.asyncio
async def test_rename_function_raises_when_readback_diverges(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: rename_function readback divergence must raise.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback returns the original name.
    """
    fake_bridge.eval_response = "FUN_00401000"
    with pytest.raises(ToolError, match="Rename verification failed"):
        await bridge.rename_function(_TEST_ADDRESS, "decryptor")


@pytest.mark.asyncio
async def test_create_bookmark_verifies_via_readback(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: create_bookmark requires the readback to contain the new entry.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback contains the requested pair.
    """
    fake_bridge.eval_response = [("analysis", "needs review")]
    info = await bridge.create_bookmark(
        _TEST_ADDRESS,
        category="analysis",
        comment="needs review",
        bookmark_type="Note",
    )
    assert info["success"] is True


@pytest.mark.asyncio
async def test_create_bookmark_raises_when_readback_missing_pair(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: create_bookmark fails closed when readback lacks the entry.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback misses the requested bookmark.
    """
    fake_bridge.eval_response = [("misc", "unrelated")]
    with pytest.raises(ToolError, match="Bookmark verification failed"):
        await bridge.create_bookmark(
            _TEST_ADDRESS,
            category="analysis",
            comment="needs review",
            bookmark_type="Note",
        )


@pytest.mark.asyncio
async def test_add_reference_verifies_via_readback(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: add_reference confirms via getReferencesFrom readback.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback contains the new target offset.
    """
    fake_bridge.eval_response = [_TEST_TO_ADDRESS]
    info = await bridge.add_reference(_TEST_ADDRESS, _TEST_TO_ADDRESS, ref_type="DATA")
    assert info["success"] is True


@pytest.mark.asyncio
async def test_add_reference_raises_when_readback_missing_target(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: add_reference raises when readback does not include the target.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback contains an unrelated target only.
    """
    fake_bridge.eval_response = [0xDEADBEEF]
    with pytest.raises(ToolError, match="Reference verification failed"):
        await bridge.add_reference(_TEST_ADDRESS, _TEST_TO_ADDRESS, ref_type="DATA")


@pytest.mark.asyncio
async def test_create_equate_verifies_via_readback(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: create_equate confirms via equate-table readback.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback shows the new equate.
    """
    fake_bridge.eval_response = {
        "value": 42,
        "addresses": [_TEST_ADDRESS],
    }
    info = await bridge.create_equate(_TEST_ADDRESS, 42, "ANSWER")
    assert info["success"] is True


@pytest.mark.asyncio
async def test_create_equate_raises_when_readback_missing(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: create_equate raises when no equate of that name is present.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback returns ``None``.
    """
    fake_bridge.eval_response = None
    with pytest.raises(ToolError, match="Equate verification failed"):
        await bridge.create_equate(_TEST_ADDRESS, 42, "ANSWER")


@pytest.mark.asyncio
async def test_create_equate_raises_when_value_diverges(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: create_equate raises when the readback value differs.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback shows a different stored value.
    """
    fake_bridge.eval_response = {
        "value": 41,
        "addresses": [_TEST_ADDRESS],
    }
    with pytest.raises(ToolError, match="Equate verification failed"):
        await bridge.create_equate(_TEST_ADDRESS, 42, "ANSWER")


@pytest.mark.asyncio
async def test_set_program_metadata_verifies_via_readback(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: set_program_metadata confirms via program-name/imagebase readback.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback returns the requested name and base.
    """
    fake_bridge.eval_response = {"name": "patched.exe", "image_base": 0x140000000}
    info = await bridge.set_program_metadata(name="patched.exe", image_base=0x140000000)
    assert info["success"] is True


@pytest.mark.asyncio
async def test_set_program_metadata_raises_when_name_diverges(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0020: program-metadata raises when readback name differs.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose readback returns a divergent program name.
    """
    fake_bridge.eval_response = {"name": "stale.exe", "image_base": 0x140000000}
    with pytest.raises(ToolError, match="Program name verification failed"):
        await bridge.set_program_metadata(name="patched.exe", image_base=0x140000000)


# ---------------------------------------------------------------------------
# F-0024: set_color must raise in headless mode when ColorizingService is absent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_color_raises_in_headless_without_service(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0024: headless mode without ColorizingService must raise ``ToolError``.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose script result reports headless and unapplied.
    """
    fake_bridge.eval_response = {
        "applied": False,
        "backend": "none",
        "error": (
            "set_color requires an interactive Ghidra ColorizingService; IntPropertyMap fallback has no visual effect in headless mode"
        ),
        "headless": True,
    }
    with pytest.raises(ToolError, match="set_color requires an interactive Ghidra"):
        await bridge.set_color(_TEST_ADDRESS, _TEST_COLOR_RED)


@pytest.mark.asyncio
async def test_set_color_succeeds_when_service_applies(
    bridge: GhidraBridge,
    fake_bridge: FakeGhidraBridge,
) -> None:
    """F-0024: set_color returns success when ColorizingService applied the color.

    Args:
        bridge: Connected bridge fixture.
        fake_bridge: Fake whose script result reports the service backend.
    """
    fake_bridge.eval_response = {
        "applied": True,
        "backend": "colorizing_service",
        "error": None,
        "headless": False,
    }
    info = await bridge.set_color(_TEST_ADDRESS, _TEST_COLOR_RED)
    assert info["success"] is True
    assert info["backend"] == "colorizing_service"


# ---------------------------------------------------------------------------
# Disconnected guards (sanity)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disconnected_decompile_raises() -> None:
    """A disconnected bridge surfaces ``ToolError`` from ``decompile``."""
    b = GhidraBridge()
    with pytest.raises(ToolError, match="not connected"):
        await b.decompile(_TEST_ADDRESS)


@pytest.mark.asyncio
async def test_disconnected_search_bytes_raises() -> None:
    """A disconnected bridge surfaces ``ToolError`` from ``search_bytes``."""
    b = GhidraBridge()
    with pytest.raises(ToolError, match="not connected"):
        await b.search_bytes(hex_pattern="48 8B")


# ---------------------------------------------------------------------------
# GHIDRA-D parsing/xrefs/security/capability tests
# ---------------------------------------------------------------------------


_XRefRefType = Literal["call", "jump", "data", "read", "write"]
_map_ghidra_ref_type: Callable[[str], _XRefRefType] = cast(
    "Callable[[str], _XRefRefType]",
    getattr(ghidra_mod, "_map_ghidra_ref_type"),
)
_resolve_debug_info_path: Callable[[str], Path] = cast(
    "Callable[[str], Path]",
    getattr(ghidra_mod, "_resolve_debug_info_path"),
)


_BRIDGE_ATTR: Final[str] = "_bridge"
_TARGET_ADDR: Final[int] = 0x401000
_FROM_ADDR_CALL: Final[int] = 0x401100
_FROM_ADDR_JUMP: Final[int] = 0x401200
_FROM_ADDR_READ: Final[int] = 0x401300
_FROM_ADDR_WRITE: Final[int] = 0x401400
_FROM_ADDR_DATA: Final[int] = 0x401500


class _StubGhidraRemote:
    """Stub for ``ghidra_bridge`` exposing ``remote_exec`` + ``remote_eval``.

    Stores a callable that replaces the live Jython evaluator. Tests
    inject canned xref payloads through this hook so the production
    parsing/mapping code is exercised end-to-end without needing a live
    Ghidra installation. The stub mirrors the sentinel-readback contract
    that ``GhidraBridge._execute_remote`` depends on: the evaluator's
    return value is stashed under the sentinel name produced by
    ``prepare_remote_script`` so the follow-up ``remote_eval`` returns
    the same canned payload the test wired in.
    """

    def __init__(self, evaluator: Callable[[str], object]) -> None:
        """Wire the supplied evaluator as the stub's remote backend.

        Args:
            evaluator: Callable invoked with the Jython source string
                forwarded by :meth:`GhidraBridge._execute_remote`. Its
                return value is what the bridge will see when it reads
                the sentinel back via ``remote_eval``.
        """
        self._evaluator = evaluator
        self._sentinel_value: object = None

    def remote_exec(self, code: str) -> None:
        """Capture the canned result for the upcoming ``remote_eval``.

        Args:
            code: Jython source string emitted by the bridge after
                ``prepare_remote_script`` has rewritten any trailing
                expression as a sentinel assignment.
        """
        self._sentinel_value = self._evaluator(code)

    def remote_eval(self, _expr: str) -> object:
        """Return the canned sentinel value stashed during ``remote_exec``.

        Args:
            _expr: Sentinel variable name produced by
                ``prepare_remote_script``. Ignored because the stub
                stores exactly one canned value at a time.

        Returns:
            object: The canned value supplied by the evaluator on the
            preceding ``remote_exec``.
        """
        return self._sentinel_value


def _attach_stub_bridge(
    target_bridge: GhidraBridge,
    evaluator: Callable[[str], object],
) -> None:
    """Replace the bridge's live Ghidra connection with a deterministic stub.

    Args:
        target_bridge: GhidraBridge instance to mutate.
        evaluator: Callable that returns canned values for any Jython source
            forwarded by the bridge.
    """
    setattr(target_bridge, _BRIDGE_ATTR, _StubGhidraRemote(evaluator))


@pytest.fixture
def disconnected_bridge() -> GhidraBridge:
    """Return a freshly-constructed disconnected ``GhidraBridge``.

    Returns:
        GhidraBridge: Disconnected bridge instance.
    """
    return GhidraBridge()


# F-0017 - MD5 must not be exposed in BinaryInfo.


def test_binary_info_dataclass_has_no_md5_field() -> None:
    """Verify ``BinaryInfo`` no longer carries an ``md5`` field (F-0017)."""
    field_names = {f.name for f in fields(BinaryInfo)}
    assert "md5" not in field_names, (
        "BinaryInfo must not expose MD5; the algorithm is cryptographically "
        "broken and an integrity hash that says 'md5' implies a guarantee "
        "Intellicrack cannot uphold."
    )
    assert "sha256" in field_names, "SHA-256 must remain the integrity hash."


def test_binary_info_construction_rejects_md5_keyword() -> None:
    """Verify constructing :class:`BinaryInfo` with ``md5=`` raises (F-0017)."""
    binary_info_constructor = cast("Callable[..., BinaryInfo]", BinaryInfo)
    with pytest.raises(TypeError):
        binary_info_constructor(
            path=Path.cwd(),
            name="x",
            size=0,
            md5="d41d8cd98f00b204e9800998ecf8427e",  # pragma: allowlist secret
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # pragma: allowlist secret
            file_type="raw",
            architecture="x86_64",
            is_64bit=True,
            entry_point=0,
            sections=[],
            imports=[],
            exports=[],
        )


# F-0023 - Capability flag accuracy.


def test_capability_supports_patching_is_false(disconnected_bridge: GhidraBridge) -> None:
    """Verify ``supports_patching`` is False because no ``apply_patch`` exists.

    Args:
        disconnected_bridge: Disconnected GhidraBridge fixture.
    """
    assert disconnected_bridge.capabilities.supports_patching is False


def test_capability_no_apply_patch_method(disconnected_bridge: GhidraBridge) -> None:
    """Verify the bridge does not advertise an ``apply_patch`` method (F-0023).

    Args:
        disconnected_bridge: Disconnected GhidraBridge fixture.
    """
    assert not hasattr(disconnected_bridge, "apply_patch")


# F-0018 - import_debug_info path canonicalisation + existence check.


@pytest.mark.asyncio
async def test_import_debug_info_rejects_empty_path(disconnected_bridge: GhidraBridge) -> None:
    """Verify empty path is rejected before reaching Ghidra.

    Args:
        disconnected_bridge: Disconnected GhidraBridge fixture.
    """

    def _evaluator(_code: str) -> object:
        msg = "remote should not be invoked for empty path"
        raise AssertionError(msg)

    _attach_stub_bridge(disconnected_bridge, _evaluator)
    with pytest.raises(ToolError, match="invalid"):
        await disconnected_bridge.import_debug_info("")


@pytest.mark.asyncio
async def test_import_debug_info_rejects_whitespace_path(disconnected_bridge: GhidraBridge) -> None:
    """Verify whitespace-only path is rejected.

    Args:
        disconnected_bridge: Disconnected GhidraBridge fixture.
    """

    def _evaluator(_code: str) -> object:
        msg = "remote should not be invoked for whitespace path"
        raise AssertionError(msg)

    _attach_stub_bridge(disconnected_bridge, _evaluator)
    with pytest.raises(ToolError, match="invalid"):
        await disconnected_bridge.import_debug_info("   \t  ")


@pytest.mark.asyncio
async def test_import_debug_info_rejects_nonexistent_path(
    disconnected_bridge: GhidraBridge,
    tmp_path: Path,
) -> None:
    """Verify non-existent path raises before any remote dispatch.

    Args:
        disconnected_bridge: Disconnected GhidraBridge fixture.
        tmp_path: pytest temp path.
    """
    missing = tmp_path / "does_not_exist.pdb"

    def _evaluator(_code: str) -> object:
        msg = "remote should not be invoked for missing path"
        raise AssertionError(msg)

    _attach_stub_bridge(disconnected_bridge, _evaluator)
    with pytest.raises(ToolError, match="not found"):
        await disconnected_bridge.import_debug_info(str(missing))


@pytest.mark.asyncio
async def test_import_debug_info_rejects_path_traversal_to_missing_target(
    disconnected_bridge: GhidraBridge,
    tmp_path: Path,
) -> None:
    r"""Verify a traversal path that resolves to a missing target is rejected.

    The canonicaliser collapses ``..`` segments via ``Path.resolve(strict=True)``
    so a craft path like ``<tmp>\..\<tmp>\nope.pdb`` either resolves to a
    non-existent file (rejected by ``not found``) or to a path outside the
    intended root.

    Args:
        disconnected_bridge: Disconnected GhidraBridge fixture.
        tmp_path: pytest temp path.
    """
    traversal = tmp_path / ".." / tmp_path.name / "nope.pdb"

    def _evaluator(_code: str) -> object:
        msg = "remote should not be invoked for traversal path"
        raise AssertionError(msg)

    _attach_stub_bridge(disconnected_bridge, _evaluator)
    with pytest.raises(ToolError):
        await disconnected_bridge.import_debug_info(str(traversal))


@pytest.mark.asyncio
async def test_import_debug_info_rejects_directory_path(
    disconnected_bridge: GhidraBridge,
    tmp_path: Path,
) -> None:
    """Verify directory paths are rejected (only regular files are allowed).

    Args:
        disconnected_bridge: Disconnected GhidraBridge fixture.
        tmp_path: pytest temp path.
    """

    def _evaluator(_code: str) -> object:
        msg = "remote should not be invoked for directory path"
        raise AssertionError(msg)

    _attach_stub_bridge(disconnected_bridge, _evaluator)
    with pytest.raises(ToolError, match="not a regular file"):
        await disconnected_bridge.import_debug_info(str(tmp_path))


@pytest.mark.asyncio
async def test_import_debug_info_rejects_unsupported_extension_after_resolve(
    disconnected_bridge: GhidraBridge,
    tmp_path: Path,
) -> None:
    """Verify unsupported extensions are rejected after canonicalisation.

    Args:
        disconnected_bridge: Disconnected GhidraBridge fixture.
        tmp_path: pytest temp path.
    """
    bogus = tmp_path / "real_file.txt"
    bogus.write_bytes(b"")

    def _evaluator(_code: str) -> object:
        msg = "remote should not be invoked for unsupported extension"
        raise AssertionError(msg)

    _attach_stub_bridge(disconnected_bridge, _evaluator)
    with pytest.raises(ToolError, match="Unsupported"):
        await disconnected_bridge.import_debug_info(str(bogus))


def test_resolve_debug_info_path_returns_absolute(tmp_path: Path) -> None:
    """Verify the resolver returns an absolute, canonical path.

    Args:
        tmp_path: pytest temp path.
    """
    real = tmp_path / "x.pdb"
    real.write_bytes(b"")
    relative_via_traversal = tmp_path / ".." / tmp_path.name / "x.pdb"

    resolved = _resolve_debug_info_path(str(relative_via_traversal))

    assert resolved.is_absolute()
    assert resolved == real.resolve()


# F-0022 / F-0026 - xref taxonomy + function enrichment.


def test_map_ghidra_ref_type_call() -> None:
    """Verify CALL variants map to ``call``."""
    assert _map_ghidra_ref_type("UNCONDITIONAL_CALL") == "call"
    assert _map_ghidra_ref_type("COMPUTED_CALL") == "call"
    assert _map_ghidra_ref_type("CONDITIONAL_CALL") == "call"


def test_map_ghidra_ref_type_jump() -> None:
    """Verify JUMP variants map to ``jump``."""
    assert _map_ghidra_ref_type("CONDITIONAL_JUMP") == "jump"
    assert _map_ghidra_ref_type("UNCONDITIONAL_JUMP") == "jump"
    assert _map_ghidra_ref_type("COMPUTED_JUMP") == "jump"


def test_map_ghidra_ref_type_read() -> None:
    """Verify READ maps to ``read``."""
    assert _map_ghidra_ref_type("READ") == "read"
    assert _map_ghidra_ref_type("READ_IND") == "read"


def test_map_ghidra_ref_type_write() -> None:
    """Verify WRITE variants map to ``write``."""
    assert _map_ghidra_ref_type("WRITE") == "write"
    assert _map_ghidra_ref_type("WRITE_IND") == "write"
    assert _map_ghidra_ref_type("READ_WRITE") == "write"


def test_map_ghidra_ref_type_data_default() -> None:
    """Verify unknown / DATA types map to ``data``."""
    assert _map_ghidra_ref_type("DATA") == "data"
    assert _map_ghidra_ref_type("PARAM") == "data"
    assert _map_ghidra_ref_type("EXTERNAL_REF") == "data"
    assert _map_ghidra_ref_type("") == "data"


def _xref_payload_full_taxonomy() -> list[dict[str, Any]]:
    """Build a fixture xref payload covering every taxonomy bucket.

    Returns:
        list[dict[str, Any]]: Five xref dicts simulating the dictionary
        structure produced by the bridge's remote Jython script.
    """
    return [
        {
            "from": _FROM_ADDR_CALL,
            "to": _TARGET_ADDR,
            "type": "UNCONDITIONAL_CALL",
            "from_function": "caller_call",
            "to_function": "target_fn",
        },
        {
            "from": _FROM_ADDR_JUMP,
            "to": _TARGET_ADDR,
            "type": "CONDITIONAL_JUMP",
            "from_function": "caller_jump",
            "to_function": "target_fn",
        },
        {
            "from": _FROM_ADDR_READ,
            "to": _TARGET_ADDR,
            "type": "READ",
            "from_function": "caller_read",
            "to_function": None,
        },
        {
            "from": _FROM_ADDR_WRITE,
            "to": _TARGET_ADDR,
            "type": "WRITE",
            "from_function": "caller_write",
            "to_function": None,
        },
        {
            "from": _FROM_ADDR_DATA,
            "to": _TARGET_ADDR,
            "type": "DATA",
            "from_function": None,
            "to_function": "target_fn",
        },
    ]


@pytest.mark.asyncio
async def test_get_xrefs_to_preserves_full_taxonomy(disconnected_bridge: GhidraBridge) -> None:
    """Verify ``get_xrefs_to`` returns call/jump/read/write/data distinctly.

    Args:
        disconnected_bridge: Disconnected GhidraBridge fixture mutated to use a stub
            remote that returns a deterministic xref payload.
    """
    payload = _xref_payload_full_taxonomy()

    def _evaluator(_code: str) -> object:
        return payload

    _attach_stub_bridge(disconnected_bridge, _evaluator)

    refs = await disconnected_bridge.get_xrefs_to(_TARGET_ADDR)

    assert len(refs) == len(payload)
    types = [r.ref_type for r in refs]
    assert types == ["call", "jump", "read", "write", "data"]


@pytest.mark.asyncio
async def test_get_xrefs_to_populates_function_enrichment(disconnected_bridge: GhidraBridge) -> None:
    """Verify ``get_xrefs_to`` surfaces ``from_function`` / ``to_function``.

    Args:
        disconnected_bridge: Disconnected GhidraBridge fixture mutated to use a stub
            remote that returns a deterministic xref payload.
    """
    payload = _xref_payload_full_taxonomy()

    def _evaluator(_code: str) -> object:
        return payload

    _attach_stub_bridge(disconnected_bridge, _evaluator)

    refs = await disconnected_bridge.get_xrefs_to(_TARGET_ADDR)

    by_type: dict[str, CrossReference] = {r.ref_type: r for r in refs}
    assert by_type["call"].from_function == "caller_call"
    assert by_type["call"].to_function == "target_fn"
    assert by_type["jump"].from_function == "caller_jump"
    assert by_type["read"].from_function == "caller_read"
    assert by_type["read"].to_function is None
    assert by_type["data"].from_function is None
    assert by_type["data"].to_function == "target_fn"


@pytest.mark.asyncio
async def test_get_xrefs_from_preserves_full_taxonomy(disconnected_bridge: GhidraBridge) -> None:
    """Verify ``get_xrefs_from`` returns call/jump/read/write/data distinctly.

    Args:
        disconnected_bridge: Disconnected GhidraBridge fixture mutated to use a stub
            remote that returns a deterministic xref payload.
    """
    payload = _xref_payload_full_taxonomy()

    def _evaluator(_code: str) -> object:
        return payload

    _attach_stub_bridge(disconnected_bridge, _evaluator)

    refs = await disconnected_bridge.get_xrefs_from(_TARGET_ADDR)

    types = [r.ref_type for r in refs]
    assert types == ["call", "jump", "read", "write", "data"]


@pytest.mark.asyncio
async def test_get_xrefs_from_populates_function_enrichment(disconnected_bridge: GhidraBridge) -> None:
    """Verify ``get_xrefs_from`` surfaces ``from_function`` / ``to_function``.

    Args:
        disconnected_bridge: Disconnected GhidraBridge fixture mutated to use a stub
            remote that returns a deterministic xref payload.
    """
    payload = _xref_payload_full_taxonomy()

    def _evaluator(_code: str) -> object:
        return payload

    _attach_stub_bridge(disconnected_bridge, _evaluator)

    refs = await disconnected_bridge.get_xrefs_from(_TARGET_ADDR)

    by_type: dict[str, CrossReference] = {r.ref_type: r for r in refs}
    assert by_type["call"].from_function == "caller_call"
    assert by_type["call"].to_function == "target_fn"
    assert by_type["write"].from_function == "caller_write"
    assert by_type["write"].to_function is None
    assert by_type["data"].from_function is None
    assert by_type["data"].to_function == "target_fn"
