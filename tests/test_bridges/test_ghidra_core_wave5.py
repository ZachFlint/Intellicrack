# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Wave-5 real-gate suite — GhidraBridge core operations.

Scope:

  ``analyze``         — asserts the Jython script emitted to Ghidra contains
                        the required AutoAnalysisManager API calls.

  ``get_xrefs_from``  — asserts (a) the Jython script contains the correct
                        ``getReferencesFrom`` / ``toAddr`` API calls and (b)
                        the parsed result exposes correct ``from_address`` and
                        ``to_address`` fields (gaps left by the existing
                        audit6 tests).

The seam: ``_FakeGhidraRemote`` captures every payload the bridge sends via
``remote_exec`` in ``exec_calls`` and every sentinel expression via
``remote_eval`` in ``eval_calls``, and returns a pre-configured
``eval_response`` on the next ``remote_eval`` call.  This exercises
``prepare_remote_script`` rewriting and ``_execute_remote`` dispatch without
a live Ghidra installation.

Oracle notes:
  - ``analyze`` script oracle: the ghidra.app.plugin.core.analysis API
    documented in the Ghidra javadocs; ``analyzeAll`` + ``waitForAnalysis``
    are the two mandatory calls to schedule and block on full analysis.
  - ``get_xrefs_from`` script oracle: Ghidra FlatProgramAPI
    ``getReferencesFrom(addr)`` + ``toAddr(offset)``.
  - Parsed-result oracle: independently-known dicts injected as the fake
    ``eval_response``; field extraction is verified by asserting exact
    int values for ``from_address`` / ``to_address``.
"""

from __future__ import annotations

from typing import Any, Final

import pytest

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import CrossReference, ToolError


_FROM_ADDR: Final[int] = 0x401000
_TO_ADDR: Final[int] = 0x402FE0


class _FakeGhidraRemote:
    """In-process double for the ``ghidra_bridge`` RPC client.

    Records every exec/eval payload the bridge sends; returns
    ``eval_response`` from every ``remote_eval`` call.  Inspect
    ``exec_calls`` after calling a bridge method to assert what Jython
    was emitted; set ``eval_response`` before calling to inject the
    canned remote result.
    """

    def __init__(self, response: object = None) -> None:
        """Initialise with an optional pre-configured eval response.

        Args:
            response: Value returned by the next ``remote_eval`` call.
                Defaults to ``None``.
        """
        self.exec_calls: list[str] = []
        self.eval_calls: list[str] = []
        self.eval_response: object = response

    def remote_exec(self, code: str) -> None:
        """Record the rewritten Jython source.

        Args:
            code: Jython source emitted by the bridge after
                ``prepare_remote_script`` has rewritten any trailing
                expression as a sentinel assignment.
        """
        self.exec_calls.append(code)

    def remote_eval(self, expr: str) -> object:
        """Record the sentinel name and return the pre-configured response.

        Args:
            expr: Sentinel variable name produced by
                ``prepare_remote_script``.

        Returns:
            object: The ``eval_response`` configured at construction or
            via direct attribute assignment.
        """
        self.eval_calls.append(expr)
        return self.eval_response


def _make_bridge(response: object = None) -> tuple[GhidraBridge, _FakeGhidraRemote]:
    """Return a connected GhidraBridge backed by a deterministic fake.

    Args:
        response: Value the fake's ``remote_eval`` returns.

    Returns:
        tuple[GhidraBridge, _FakeGhidraRemote]: Connected bridge and the
        fake for direct introspection.
    """
    bridge = GhidraBridge()
    fake = _FakeGhidraRemote(response)
    bridge.attach_remote_bridge(fake)
    return bridge, fake


class TestAnalyzeScriptFraming:
    """Real-gate suite for ``GhidraBridge.analyze`` script framing.

    The ``analyze`` method must emit a Jython script that:

    1. Imports ``AutoAnalysisManager`` from the Ghidra analysis plugin
       package so ``getAnalysisManager`` is callable.
    2. Invokes ``analyzeAll(currentProgram)`` to schedule every pending
       analysis pass.
    3. Invokes ``mgr.waitForAnalysis(...)`` to block until analysis
       finishes so callers that immediately query symbols/functions see a
       fully analysed program.

    Mutation caught: removing any of the three API tokens from the script
    causes the matching assertion to fail.
    """

    @pytest.mark.asyncio
    async def test_analyze_script_imports_auto_analysis_manager(self) -> None:
        """``analyze`` script must import ``AutoAnalysisManager``.

        The import is the prerequisite for calling
        ``AutoAnalysisManager.getAnalysisManager``; omitting it produces
        a ``NameError`` on the remote Jython interpreter.

        Mutation caught: deleting the import line from the script →
        assertion fails.
        """
        bridge, fake = _make_bridge()

        await bridge.analyze()

        assert len(fake.exec_calls) >= 1
        script: str = fake.exec_calls[0]
        assert "AutoAnalysisManager" in script

    @pytest.mark.asyncio
    async def test_analyze_script_calls_analyze_all(self) -> None:
        """``analyze`` script must invoke ``analyzeAll``.

        ``analyzeAll(currentProgram)`` schedules every registered analysis
        pass.  Without it no analysis runs.

        Mutation caught: replacing ``analyzeAll`` with a no-op →
        assertion fails.
        """
        bridge, fake = _make_bridge()

        await bridge.analyze()

        assert len(fake.exec_calls) >= 1
        script: str = fake.exec_calls[0]
        assert "analyzeAll" in script

    @pytest.mark.asyncio
    async def test_analyze_script_calls_wait_for_analysis(self) -> None:
        """``analyze`` script must invoke ``waitForAnalysis``.

        ``waitForAnalysis`` blocks until every scheduled pass completes.
        Without it callers may observe a partially-analysed program.

        Mutation caught: removing the ``waitForAnalysis`` call →
        assertion fails.
        """
        bridge, fake = _make_bridge()

        await bridge.analyze()

        assert len(fake.exec_calls) >= 1
        script: str = fake.exec_calls[0]
        assert "waitForAnalysis" in script

    @pytest.mark.asyncio
    async def test_analyze_raises_when_not_connected(self) -> None:
        """``analyze`` raises ``ToolError`` when the bridge is not connected.

        Mutation caught: removing the connection guard →
        ``remote_exec``/``remote_eval`` are called on ``None`` and raise
        ``AttributeError``, not ``ToolError``.
        """
        bridge = GhidraBridge()

        with pytest.raises(ToolError, match="not connected"):
            await bridge.analyze()

    @pytest.mark.asyncio
    async def test_analyze_propagates_remote_exec_failure_as_tool_error(self) -> None:
        """``analyze`` wraps a remote exec failure in a ``ToolError``.

        When the remote Jython execution raises (e.g. the Ghidra server
        dropped the connection), the bridge must surface that as a
        ``ToolError``, not leak an untyped exception.

        Mutation caught: removing the except/raise block → caller sees
        ``RuntimeError`` instead of ``ToolError``.
        """

        class _FailingRemote:
            def remote_exec(self, _code: str) -> None:
                msg = "simulated remote failure"
                raise RuntimeError(msg)

            def remote_eval(self, _expr: str) -> object:
                return None

        bridge = GhidraBridge()
        bridge.attach_remote_bridge(_FailingRemote())

        with pytest.raises(ToolError):
            await bridge.analyze()


class TestGetXrefsFromScriptAndParsing:
    """Real-gate suite for ``GhidraBridge.get_xrefs_from`` script framing and parsing.

    Existing tests in ``test_ghidra_audit6.py`` (F-0022/F-0026) already
    assert ``ref_type`` taxonomy and ``from_function``/``to_function``
    enrichment.  This class closes the remaining gaps:

    1. Script framing — ``getReferencesFrom`` and ``toAddr(address)``
       must appear in the Jython payload.
    2. Address parsing — ``result[0].from_address`` and
       ``result[0].to_address`` must equal the integer values from the
       injected payload.

    Oracle: the canned payload injected as ``eval_response`` is an
    independently-known list with deterministic ``from``/``to`` int values;
    the assertions compare the bridge-parsed ``CrossReference`` fields
    against those constants.
    """

    def _make_xref_payload(self) -> list[dict[str, Any]]:
        """Build a one-item reference payload with known from/to addresses.

        Returns:
            list[dict[str, Any]]: Single xref dict matching the structure
            produced by the remote Jython script.
        """
        return [
            {
                "from": _FROM_ADDR,
                "to": _TO_ADDR,
                "type": "UNCONDITIONAL_CALL",
                "from_function": "caller_fn",
                "to_function": "target_fn",
            },
        ]

    @pytest.mark.asyncio
    async def test_get_xrefs_from_script_contains_get_references_from(self) -> None:
        """``get_xrefs_from`` script must call ``getReferencesFrom``.

        ``getReferencesFrom(addr)`` is the Ghidra Flat API that enumerates
        all references originating from a given address.  Without it the
        method returns an empty list regardless of real references.

        Mutation caught: replacing ``getReferencesFrom`` with
        ``getReferencesTo`` → the command assertion fails and the
        method silently queries the wrong direction.
        """
        bridge, fake = _make_bridge(self._make_xref_payload())

        await bridge.get_xrefs_from(_FROM_ADDR)

        assert len(fake.exec_calls) >= 1
        script: str = fake.exec_calls[0]
        assert "getReferencesFrom" in script

    @pytest.mark.asyncio
    async def test_get_xrefs_from_script_encodes_address(self) -> None:
        """``get_xrefs_from`` script must embed the address via ``toAddr``.

        The script passes ``toAddr({address})`` to convert the Python
        integer offset to a Ghidra ``Address`` object.  If the address is
        omitted or hard-coded, the method silently queries the wrong
        location.

        Mutation caught: removing ``toAddr`` from the f-string →
        assertion fails.
        """
        bridge, fake = _make_bridge(self._make_xref_payload())

        await bridge.get_xrefs_from(_FROM_ADDR)

        assert len(fake.exec_calls) >= 1
        script: str = fake.exec_calls[0]
        assert "toAddr" in script
        assert str(_FROM_ADDR) in script

    @pytest.mark.asyncio
    async def test_get_xrefs_from_parses_from_address_exactly(self) -> None:
        """``get_xrefs_from`` must map the ``from`` field to ``from_address``.

        The bridge reads ``payload["from"]`` and stores it as
        ``CrossReference.from_address``.  Swapping the key name
        (e.g. to ``"source"``) silently zeroes every from_address field.

        Mutation caught: changing ``payload.get("from", 0)`` to
        ``payload.get("source", 0)`` → assertion on ``from_address``
        fails.
        """
        bridge, _fake = _make_bridge(self._make_xref_payload())

        refs: list[CrossReference] = await bridge.get_xrefs_from(_FROM_ADDR)

        assert len(refs) == 1
        assert refs[0].from_address == _FROM_ADDR

    @pytest.mark.asyncio
    async def test_get_xrefs_from_parses_to_address_exactly(self) -> None:
        """``get_xrefs_from`` must map the ``to`` field to ``to_address``.

        The bridge reads ``payload["to"]`` and stores it as
        ``CrossReference.to_address``.  Swapping the key name silently
        zeroes every to_address field.

        Mutation caught: changing ``payload.get("to", 0)`` to
        ``payload.get("dest", 0)`` → assertion on ``to_address`` fails.
        """
        bridge, _fake = _make_bridge(self._make_xref_payload())

        refs: list[CrossReference] = await bridge.get_xrefs_from(_FROM_ADDR)

        assert len(refs) == 1
        assert refs[0].to_address == _TO_ADDR

    @pytest.mark.asyncio
    async def test_get_xrefs_from_returns_empty_list_when_no_refs(self) -> None:
        """``get_xrefs_from`` returns ``[]`` when the remote returns an empty list.

        Mutation caught: returning ``None`` instead of ``[]`` on an
        empty payload → caller sees ``None`` instead of an empty list,
        breaking ``len(result) == 0`` invariants.
        """
        bridge, _ = _make_bridge([])

        refs: list[CrossReference] = await bridge.get_xrefs_from(_FROM_ADDR)

        assert not refs

    @pytest.mark.asyncio
    async def test_get_xrefs_from_raises_when_not_connected(self) -> None:
        """``get_xrefs_from`` raises ``ToolError`` when bridge not connected.

        Mutation caught: removing the connection guard → ``AttributeError``
        is raised instead of ``ToolError``.
        """
        bridge = GhidraBridge()

        with pytest.raises(ToolError, match="not connected"):
            await bridge.get_xrefs_from(_FROM_ADDR)

    @pytest.mark.asyncio
    async def test_get_xrefs_from_call_type_maps_to_call_string(self) -> None:
        """``get_xrefs_from`` maps ``UNCONDITIONAL_CALL`` to ``ref_type == "call"``.

        This closes the loop with the address assertions: the same item
        whose from/to addresses are verified also has the correct
        ``ref_type`` so neither field can be accidentally wrong.

        Mutation caught: returning ``"jump"`` for any CALL-containing
        raw type → assertion fails.
        """
        bridge, _ = _make_bridge(self._make_xref_payload())

        refs: list[CrossReference] = await bridge.get_xrefs_from(_FROM_ADDR)

        assert len(refs) == 1
        assert refs[0].ref_type == "call"
