# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit-6 GHIDRA-A regression tests.

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
"""

from __future__ import annotations

import asyncio
import sys
import types
from typing import TYPE_CHECKING, Any, Final, cast

import pytest

from intellicrack.bridges.ghidra import GhidraBridge, prepare_remote_script
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
