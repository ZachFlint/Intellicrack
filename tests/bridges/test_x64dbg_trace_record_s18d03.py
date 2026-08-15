# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gates for S18-D03: trace-record hit counts need the page armed first.

``get_trace_record`` could not return a non-zero ``hitCount`` for any address
under any circumstances. x64dbg allocates a page's per-byte execution counters
only once a trace record type has been set for that page, and nothing in the
bridge or the plugin ever called ``SetTraceRecordType`` - so the
``GetTraceRecordHitCount`` the plugin read had no buffer behind it and answered
zero forever. The step half of the same audit item worked; only the hit-count
accounting was inert.

Driven live against a real x64dbg and a real ``notepad.exe`` before these gates
were written. The probe read the entry point at ``0x7FFFEEB21194`` four times:

===========================  ==========  ==========
stage                        page type   hit count
===========================  ==========  ==========
before arming                ``none``    0
after ``set_trace_record``   ``word``    0
after 12 single-steps        ``word``    1
after releasing the page     ``none``    0
===========================  ==========  ==========

and the eleven stepped addresses that landed on a *second* page
(``0x7FFFEE9CA000``, never armed) stayed at zero throughout even though the
debuggee had just executed every one of them.

:class:`_X64DbgTraceRecordEngine` below is derived from those observations -
per-page arming, counters that exist only for armed pages, a release that
discards them - rather than from the bridge's own logic, so each gate fails
when its half of the fix is reverted.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.bridges.x64dbg import (
    TRACE_RECORD_PAGE_SIZE,
    TRACE_RECORD_TYPE_UNKNOWN,
    X64DbgBridge,
)
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Callable


# The live probe's entry point, and an address the probe showed on a different
# page: 0x7FFFEEB21194 vs 0x7FFFEE9CA399 differ well beyond one page.
_ENTRY_ADDR: Final[int] = 0x7FFFEEB21194
_OTHER_PAGE_ADDR: Final[int] = 0x7FFFEE9CA399
_ENTRY_PAGE: Final[int] = 0x7FFFEEB21000
_UNARMED: Final[str] = "none"
_ARMED: Final[str] = "word"
_EXECUTIONS: Final[int] = 3
_READ_SPAN: Final[int] = 4


class _X64DbgTraceRecordEngine:
    """x64dbg's trace-record behaviour as the live probe observed it.

    Four properties, each read off the probe rather than off the bridge:

    * every page starts at record type ``none``;
    * setting a type stores it for the 4 KiB page an address falls in, and
      reading the type back returns it - the probe's replies named the
      queried address' page, masked to 4 KiB;
    * a page at ``none`` has no counters, so every address on it reads
      back as zero no matter how often the debuggee executed it - which is
      what the eleven addresses on the never-armed second page did;
    * executing an address on an armed page increments that address'
      counter, which is how the entry point reached 1 after stepping.
    """

    def __init__(self) -> None:
        """Start with every page unarmed, as a fresh debuggee does."""
        self._types: dict[int, str] = {}
        self._counts: dict[int, int] = {}

    @staticmethod
    def page_of(address: int) -> int:
        """Return the page an address belongs to.

        Args:
            address: The address to locate.

        Returns:
            int: The address masked down to its 4 KiB page.
        """
        return address & ~(TRACE_RECORD_PAGE_SIZE - 1)

    def set_type(self, address: int, record_type: str) -> bool:
        """Arm or release the page holding ``address``.

        Args:
            address: Any address inside the page.
            record_type: The record type to store, or ``none`` to release
                the page and discard the counters it held.

        Returns:
            bool: True, matching the ``applied: true`` the live probe saw
            for both the ``word`` arming and the ``none`` release.
        """
        page = self.page_of(address)
        if record_type == _UNARMED:
            _ = self._types.pop(page, None)
            self._counts = {addr: hits for addr, hits in self._counts.items() if self.page_of(addr) != page}
        else:
            self._types[page] = record_type
        return True

    def type_of(self, address: int) -> str:
        """Return the record type held for an address' page.

        Args:
            address: Any address inside the page.

        Returns:
            str: The stored type, or ``none`` for a page never armed.
        """
        return self._types.get(self.page_of(address), _UNARMED)

    def execute(self, address: int) -> None:
        """Run one instruction at ``address``, as x64dbg's step engine does.

        Args:
            address: The address the debuggee executed.
        """
        if self.page_of(address) in self._types:
            self._counts[address] = self._counts.get(address, 0) + 1

    def hit_count(self, address: int) -> int:
        """Return the recorded execution count for an address.

        Args:
            address: The address to query.

        Returns:
            int: The counter's value, or 0 when the page holds no counters.
        """
        if self.page_of(address) not in self._types:
            return 0
        return self._counts.get(address, 0)


class _FakePipeClient:
    """In-process substitute for ``NamedPipeClient`` backed by the engine."""

    def __init__(
        self,
        responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
    ) -> None:
        """Initialise the fake pipe client.

        Args:
            responder: Callable mapping ``(command, params)`` to the
                response dict the pipe layer would have returned.
        """
        self._responder = responder
        self.sent: list[tuple[str, dict[str, Any] | None]] = []

    @property
    def is_connected(self) -> bool:
        """Report the fake as permanently connected.

        Returns:
            bool: Always ``True``.
        """
        return True

    async def send_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record the request and return the scripted response.

        Args:
            command: RPC command name.
            params: Optional parameters dict.

        Returns:
            dict[str, Any]: Response produced by the responder.
        """
        self.sent.append((command, params))
        return self._responder(command, params)


class _PlaceholderProcess:
    """Sentinel satisfying the bridge's ``self._process is not None`` guards."""


def _install_fake_pipe(
    bridge: X64DbgBridge,
    responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
) -> _FakePipeClient:
    """Attach a fake pipe client to ``bridge`` and mark the plugin deployed.

    Args:
        bridge: Bridge instance under test.
        responder: Per-command response generator.

    Returns:
        _FakePipeClient: The installed fake, useful for asserting on ``sent``.
    """
    fake = _FakePipeClient(responder)
    setattr(bridge, "_pipe_client", fake)
    setattr(bridge, "_plugin_deployed", True)
    setattr(bridge, "_process", _PlaceholderProcess())
    return fake


def _plugin_responder(
    engine: _X64DbgTraceRecordEngine,
) -> Callable[[str, dict[str, Any] | None], dict[str, Any]]:
    """Answer the two trace-record RPCs the way the real plugin does.

    Args:
        engine: The trace-record engine the replies are read out of.

    Returns:
        Callable[[str, dict[str, Any] | None], dict[str, Any]]: A responder
        producing the exact payload shape the live probe received.
    """

    def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
        assert params is not None, f"{command} was sent with no parameters"
        address = int(str(params["address"]), 16)
        page = engine.page_of(address)
        if command == "trace_record_set":
            requested = str(params["type"])
            applied = engine.set_type(address, requested)
            return {
                "success": applied,
                "result": {
                    "address": hex(address),
                    "page": hex(page),
                    "requested": requested,
                    "type": engine.type_of(address),
                    "applied": applied,
                },
            }
        if command == "trace_record":
            size = int(params.get("size", 1))
            return {
                "success": True,
                "result": {
                    "address": hex(address),
                    "page": hex(page),
                    "type": engine.type_of(address),
                    "size": size,
                    "hitCount": engine.hit_count(address),
                    "hits": [engine.hit_count(address + offset) for offset in range(size)],
                },
            }
        msg = f"unexpected command: {command!r}"
        raise AssertionError(msg)

    return responder


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Construct a fresh, unattached bridge instance.

    Returns:
        X64DbgBridge: A bridge with no attached PID.
    """
    return X64DbgBridge()


@pytest.fixture
def engine() -> _X64DbgTraceRecordEngine:
    """Construct a trace-record engine with every page unarmed.

    Returns:
        _X64DbgTraceRecordEngine: The engine backing the fake plugin.
    """
    return _X64DbgTraceRecordEngine()


@pytest.mark.asyncio
class TestHitCountsRequireAnArmedPage:
    """The defect and its fix, against the observed x64dbg engine."""

    async def test_execution_alone_records_nothing_and_says_so(
        self,
        bridge: X64DbgBridge,
        engine: _X64DbgTraceRecordEngine,
    ) -> None:
        """An unarmed page counts nothing however often the debuggee runs it.

        This is S18-D03 itself: without ``set_trace_record`` there is no
        counter to read, which is why the pre-fix bridge could only ever
        report zero. The reply must now also carry the page's ``type``, so
        that zero is diagnosable rather than indistinguishable from an
        address that genuinely never ran.

        Args:
            bridge: Fixture bridge instance.
            engine: The trace-record engine backing the fake plugin.
        """
        _install_fake_pipe(bridge, _plugin_responder(engine))
        for _ in range(_EXECUTIONS):
            engine.execute(_ENTRY_ADDR)

        record = await bridge.get_trace_record(_ENTRY_ADDR)

        assert record["hitCount"] == 0, f"an unarmed page reported executions it cannot have counted: {record!r}"
        assert record["type"] == _UNARMED, (
            f"a zero hit count came back with no way to tell an unarmed page from an unexecuted address: {record!r}"
        )

    async def test_arming_the_page_makes_the_same_execution_countable(
        self,
        bridge: X64DbgBridge,
        engine: _X64DbgTraceRecordEngine,
    ) -> None:
        """Arming the page turns the identical execution into a real count.

        The only difference from the gate above is the ``set_trace_record``
        call, so a fix that stops arming the page - or arms it with the
        wrong type - drops this straight back to zero.

        Args:
            bridge: Fixture bridge instance.
            engine: The trace-record engine backing the fake plugin.
        """
        _install_fake_pipe(bridge, _plugin_responder(engine))
        armed = await bridge.set_trace_record(_ENTRY_ADDR, _ARMED)
        for _ in range(_EXECUTIONS):
            engine.execute(_ENTRY_ADDR)

        record = await bridge.get_trace_record(_ENTRY_ADDR)

        assert armed["type"] == _ARMED, f"the page did not come back armed: {armed!r}"
        assert armed["page"] == hex(_ENTRY_PAGE), f"a page other than the address' own was armed: {armed!r}"
        assert record["hitCount"] == _EXECUTIONS, f"an armed page did not count the {_EXECUTIONS} executions it saw: {record!r}"
        assert record["type"] == _ARMED, f"the armed page did not report its record type: {record!r}"

    async def test_arming_reaches_only_the_page_it_was_asked_for(
        self,
        bridge: X64DbgBridge,
        engine: _X64DbgTraceRecordEngine,
    ) -> None:
        """A second page keeps counting nothing until it is armed in turn.

        The live probe saw exactly this: eleven stepped addresses on a page
        the probe never armed stayed at zero while the armed entry point
        reached one.

        Args:
            bridge: Fixture bridge instance.
            engine: The trace-record engine backing the fake plugin.
        """
        _install_fake_pipe(bridge, _plugin_responder(engine))
        _ = await bridge.set_trace_record(_ENTRY_ADDR, _ARMED)
        engine.execute(_ENTRY_ADDR)
        engine.execute(_OTHER_PAGE_ADDR)

        armed_page = await bridge.get_trace_record(_ENTRY_ADDR)
        other_page = await bridge.get_trace_record(_OTHER_PAGE_ADDR)

        assert armed_page["hitCount"] == 1, f"the armed page lost the execution it saw: {armed_page!r}"
        assert other_page["hitCount"] == 0, f"arming one page silently armed another, which x64dbg does not do: {other_page!r}"
        assert other_page["type"] == _UNARMED, f"an unarmed page claimed a record type: {other_page!r}"

    async def test_releasing_a_page_stops_it_counting_again(
        self,
        bridge: X64DbgBridge,
        engine: _X64DbgTraceRecordEngine,
    ) -> None:
        """``none`` releases the page's counters, as the probe's teardown did.

        Args:
            bridge: Fixture bridge instance.
            engine: The trace-record engine backing the fake plugin.
        """
        _install_fake_pipe(bridge, _plugin_responder(engine))
        _ = await bridge.set_trace_record(_ENTRY_ADDR, _ARMED)
        engine.execute(_ENTRY_ADDR)
        released = await bridge.set_trace_record(_ENTRY_ADDR, _UNARMED)
        engine.execute(_ENTRY_ADDR)

        record = await bridge.get_trace_record(_ENTRY_ADDR)

        assert released["type"] == _UNARMED, f"the page was not released: {released!r}"
        assert record["hitCount"] == 0, f"a released page kept counting: {record!r}"

    async def test_a_span_reports_one_count_per_byte(
        self,
        bridge: X64DbgBridge,
        engine: _X64DbgTraceRecordEngine,
    ) -> None:
        """``size`` selects how many bytes' counters come back, not just one.

        x64dbg keeps a counter per byte, so a caller asking about a span of
        an instruction's bytes gets the whole span. The pre-fix reply
        ignored ``size`` entirely.

        Args:
            bridge: Fixture bridge instance.
            engine: The trace-record engine backing the fake plugin.
        """
        _install_fake_pipe(bridge, _plugin_responder(engine))
        _ = await bridge.set_trace_record(_ENTRY_ADDR, _ARMED)
        engine.execute(_ENTRY_ADDR)
        engine.execute(_ENTRY_ADDR + 2)
        engine.execute(_ENTRY_ADDR + 2)

        record = await bridge.get_trace_record(_ENTRY_ADDR, _READ_SPAN)

        assert record["hits"] == [1, 0, 2, 0], f"the per-byte counts across the span were wrong: {record!r}"


@pytest.mark.asyncio
class TestArmingIsVerifiedBeforeItIsBelieved:
    """A page that did not take the requested type must not read as armed."""

    async def test_the_request_carries_the_normalised_type_and_address(
        self,
        bridge: X64DbgBridge,
        engine: _X64DbgTraceRecordEngine,
    ) -> None:
        """The RPC is ``trace_record_set`` with a hex address and lowercase type.

        Args:
            bridge: Fixture bridge instance.
            engine: The trace-record engine backing the fake plugin.
        """
        fake = _install_fake_pipe(bridge, _plugin_responder(engine))

        _ = await bridge.set_trace_record(_ENTRY_ADDR, "  WORD  ")

        assert fake.sent == [("trace_record_set", {"address": hex(_ENTRY_ADDR), "type": _ARMED})], (
            f"the arming request was framed wrongly: {fake.sent!r}"
        )

    async def test_an_unknown_record_type_never_reaches_the_debugger(
        self,
        bridge: X64DbgBridge,
        engine: _X64DbgTraceRecordEngine,
    ) -> None:
        """A type x64dbg has no enumerator for is refused, not forwarded.

        Args:
            bridge: Fixture bridge instance.
            engine: The trace-record engine backing the fake plugin.
        """
        fake = _install_fake_pipe(bridge, _plugin_responder(engine))

        with pytest.raises(ToolError, match="invalid trace record type"):
            _ = await bridge.set_trace_record(_ENTRY_ADDR, "dword")

        assert fake.sent == [], f"an unusable record type was sent to the debugger anyway: {fake.sent!r}"

    async def test_a_page_that_reports_another_type_is_a_failure(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Arming that x64dbg accepted but did not apply must raise.

        x64dbg allocates the page's counter buffer inside
        ``SetTraceRecordType``; when that allocation fails the page keeps
        its old type while the call still returns. Trusting the call alone
        would leave the caller reading zeros forever and believing the page
        armed - the exact shape of the original defect.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            assert params is not None, "the arming request carried no parameters"
            return {
                "success": True,
                "result": {
                    "address": str(params["address"]),
                    "page": hex(_ENTRY_PAGE),
                    "requested": str(params["type"]),
                    "type": _UNARMED,
                    "applied": True,
                },
            }

        _install_fake_pipe(bridge, responder)

        with pytest.raises(ToolError, match="did not take on the page"):
            _ = await bridge.set_trace_record(_ENTRY_ADDR, _ARMED)

    async def test_an_unreachable_plugin_is_not_reported_as_an_unarmed_page(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A plugin without the RPC reports ``unknown``, never ``none``.

        Both read back a zero hit count, but only one of them means "arm
        this page and try again". Collapsing them would send a caller
        chasing an arming call that could never have worked.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": False, "error": "Unknown command 'trace_record'"}

        _install_fake_pipe(bridge, responder)

        record = await bridge.get_trace_record(_ENTRY_ADDR)

        assert record["hitCount"] == 0, f"an unreachable plugin invented a hit count: {record!r}"
        assert record["type"] == TRACE_RECORD_TYPE_UNKNOWN, (
            f"an unreachable plugin was reported as a page x64dbg holds no record for: {record!r}"
        )
