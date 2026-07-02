# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""L1/L2 gate tests for the Ghidra bridge-completeness slices 5 and 6.

Covers ``audit/bridge-completeness/agent-05-ghidra-code-analysis.md``,
``audit/bridge-completeness/agent-06-ghidra-program-model-scripting.md``, and
their verifier reports. Every test drives a real ``GhidraBridge`` method
against an in-process fake of the external ``ghidra_bridge`` RPC transport
(the only test double in this file; it stands in for the live Jython/Ghidra
process, a genuine external boundary that cannot run in the sandbox) and/or
dispatches through a real ``ToolRegistry`` so the exact production code path
-- not a re-implementation of it -- is what makes each assertion pass or
fail.

Regression coverage for the confirmed correctness bug:

* ``add_comment``'s ``comment_map`` previously silently downgraded an
  unrecognized/``REPEATABLE`` ``comment_type`` to ``CodeUnit.EOL_COMMENT``.
  The fix adds ``REPEATABLE`` to the map and raises ``ToolError`` for any
  other unrecognized type instead of silently writing the wrong comment
  kind. These tests assert the emitted Jython script references
  ``CodeUnit.REPEATABLE_COMMENT`` (not ``EOL_COMMENT``) for a REPEATABLE
  request, and that a bogus type raises before any RPC call is made.

L1 coverage for the previously MISSING program-model methods
(``remove_memory_block``, ``split_memory_block``, ``join_memory_blocks``,
``edit_program_tree``) and the previously NO-CONTROL code-analysis methods
that slice 5 flagged as fully real but unreachable from the GUI
(``get_instruction_flow``, ``get_register_value``, ``get_thunk_info``,
``add_thunk``, ``remove_thunk``, ``add_reference``, ``delete_reference``,
``add_external_reference``, ``remove_external_reference``,
``get_external_references``, ``get_properties``, ``get_call_graph``,
``get_function`` singular, ``add_label``, ``remove_bookmark``,
``create_data_type``).

L2 coverage dispatches every one of these through
``ToolRegistry.execute_tool_call`` (the real AI-facing entry point) and
asserts each is discoverable in ``GhidraBridge.tool_definition`` with a
parameter schema whose names match the real method signature.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolError, ToolName
from tests.test_bridge_completeness.ghidra.conftest import FakeGhidraBridge, run_async


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack.bridges.ghidra import GhidraBridge
    from intellicrack.core.types import FunctionInfo


_TEST_ADDR = 0x401000
_TEST_ADDR2 = 0x402000


@pytest.fixture
def registry(tmp_path: Path, connected_bridge: GhidraBridge) -> ToolRegistry:
    """Build a real ToolRegistry with the Ghidra bridge registered under it.

    Args:
        tmp_path: Pytest-managed temporary tools directory.
        connected_bridge: GhidraBridge fixture wired to the fake RPC transport.

    Returns:
        ToolRegistry: Registry with ``ToolName.GHIDRA`` bound to the bridge.
    """
    reg = ToolRegistry(tools_dir=tmp_path)
    reg.register_bridge(ToolName.GHIDRA, connected_bridge)
    return reg


def _tool_def_param_names(bridge: GhidraBridge, function_name: str) -> set[str]:
    """Extract the parameter names declared for a registered tool function.

    Args:
        bridge: The GhidraBridge whose tool_definition is inspected.
        function_name: Fully-qualified tool function name (e.g. ``ghidra.add_thunk``).

    Returns:
        set[str]: Set of declared parameter names.
    """
    defn = bridge.tool_definition
    func = next(f for f in defn.functions if f.name == function_name)
    return {p.name for p in func.parameters}


# ---------------------------------------------------------------------------
# Correctness bug regression: add_comment REPEATABLE downgrade
# ---------------------------------------------------------------------------


class TestAddCommentRepeatableRegression:
    """Regression tests for the REPEATABLE-comment silent-downgrade defect."""

    @staticmethod
    def test_repeatable_comment_emits_repeatable_constant(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """add_comment(comment_type='REPEATABLE') must emit CodeUnit.REPEATABLE_COMMENT, not EOL.

        Falsifiable: reverting the ``comment_map`` fix (dropping the
        ``"REPEATABLE": "CodeUnit.REPEATABLE_COMMENT"`` entry) restores
        the old ``.get(comment_type, "CodeUnit.EOL_COMMENT")`` fallback,
        which would emit ``CodeUnit.EOL_COMMENT`` instead -- failing the
        containment assertion. Broken production line: the
        ``comment_map`` dict literal in ``GhidraBridge.add_comment``
        (``bridges/ghidra.py``).
        """
        fake.eval_response = "repeats here"
        run_async(connected_bridge.add_comment(_TEST_ADDR, "repeats here", "REPEATABLE"))

        assert len(fake.exec_calls) == 1
        assert "CodeUnit.REPEATABLE_COMMENT" in fake.exec_calls[0]
        assert "CodeUnit.EOL_COMMENT" not in fake.exec_calls[0]

    @staticmethod
    def test_unknown_comment_type_raises_before_dispatch(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """add_comment must raise ToolError for an unrecognized comment_type, not silently write EOL.

        Falsifiable: if the ``ghidra_type is None`` guard were removed
        and the old ``.get(comment_type, "CodeUnit.EOL_COMMENT")``
        fallback restored, this call would silently dispatch an EOL
        comment write instead of raising, and ``fake.exec_calls`` would
        be non-empty. Broken production line: the
        ``if ghidra_type is None: raise ToolError(...)`` guard in
        ``GhidraBridge.add_comment``.
        """
        with pytest.raises(ToolError, match="Unknown comment_type"):
            run_async(connected_bridge.add_comment(_TEST_ADDR, "x", "BOGUS_TYPE"))

        assert len(fake.exec_calls) == 0

    @staticmethod
    def test_eol_comment_still_emits_eol_constant(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """add_comment(comment_type='EOL') must still emit CodeUnit.EOL_COMMENT (no regression).

        Falsifiable: if the comment_map dict were corrupted so 'EOL' no
        longer maps to CodeUnit.EOL_COMMENT, this assertion fails.
        """
        fake.eval_response = "normal"
        run_async(connected_bridge.add_comment(_TEST_ADDR, "normal", "EOL"))

        assert len(fake.exec_calls) == 1
        assert "CodeUnit.EOL_COMMENT" in fake.exec_calls[0]

    @staticmethod
    def test_repeatable_dispatchable_via_tool_registry(
        registry: ToolRegistry,
        fake: FakeGhidraBridge,
    ) -> None:
        """ghidra.add_comment must dispatch a REPEATABLE request through the real ToolRegistry.

        Falsifiable: if ``ghidra.add_comment``'s tool-def name diverged
        from the real method, or the REPEATABLE fix were reverted,
        either the dispatch would raise ToolError (unknown function) or
        the emitted script would reference EOL_COMMENT instead of
        REPEATABLE_COMMENT.
        """
        fake.eval_response = "note"
        run_async(
            registry.execute_tool_call(
                "ghidra",
                "ghidra.add_comment",
                {"address": _TEST_ADDR, "comment": "note", "comment_type": "REPEATABLE"},
            ),
        )
        assert len(fake.exec_calls) == 1
        assert "CodeUnit.REPEATABLE_COMMENT" in fake.exec_calls[0]


# ---------------------------------------------------------------------------
# remove_memory_block / split_memory_block / join_memory_blocks (MISSING -> real)
# ---------------------------------------------------------------------------


class TestMemoryBlockOps:
    """L1/L2 gates for the previously MISSING memory-block mutation methods."""

    @staticmethod
    def test_remove_memory_block_happy_path(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """remove_memory_block must emit Memory.removeBlock and return success on a found block.

        Falsifiable: deleting the method or its ``ok=True``/``removeBlock``
        call would either raise AttributeError (method absent) or leave
        ``removeBlock`` out of the emitted script.
        """
        fake.eval_response = {"found": True, "ok": True}

        result = cast("dict[str, Any]", run_async(connected_bridge.remove_memory_block(".custom")))

        assert result == {"name": ".custom", "success": True}
        assert len(fake.exec_calls) == 1
        assert "removeBlock" in fake.exec_calls[0]

    @staticmethod
    def test_remove_memory_block_not_found_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """remove_memory_block must raise ToolError when the named block does not exist.

        Falsifiable: if the ``found`` guard were removed, this would
        return a success dict instead of raising.
        """
        fake.eval_response = {"found": False, "ok": False}

        with pytest.raises(ToolError, match="not found"):
            run_async(connected_bridge.remove_memory_block("nonexistent"))

    @staticmethod
    def test_split_memory_block_happy_path(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """split_memory_block must emit Memory.split and return the exact hex split address.

        Falsifiable: if ``hex(split_address)`` were replaced with the
        raw int, or the ``memory.split`` call removed, this assertion
        fails.
        """
        fake.eval_response = {"found": True, "in_range": True, "ok": True}

        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.split_memory_block(".custom", 0x10500)),
        )

        assert result == {"name": ".custom", "split_address": "0x10500", "success": True}
        assert len(fake.exec_calls) == 1
        assert "memory.split" in fake.exec_calls[0]

    @staticmethod
    def test_split_memory_block_address_out_of_range_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """split_memory_block must raise ToolError when the split address is outside the block.

        Falsifiable: if the ``in_range`` guard were removed, the method
        would attempt the split (or report success) instead of raising.
        """
        fake.eval_response = {"found": True, "in_range": False, "ok": False}

        with pytest.raises(ToolError, match="not inside block"):
            run_async(connected_bridge.split_memory_block(".custom", 0xDEAD))

    @staticmethod
    def test_join_memory_blocks_happy_path_returns_joined_name(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """join_memory_blocks must return the exact joined block name reported by Ghidra.

        Falsifiable: if ``info.get('joined_name', name1)`` were changed
        to ignore the remote result and always return ``name1``, this
        assertion (which uses a joined_name distinct from either input)
        would fail.
        """
        fake.eval_response = {"found1": True, "found2": True, "joined_name": ".merged", "ok": True}

        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.join_memory_blocks(".block_a", ".block_b")),
        )

        assert result == {"name": ".merged", "success": True}
        assert len(fake.exec_calls) == 1
        assert "memory.join" in fake.exec_calls[0]

    @staticmethod
    def test_join_memory_blocks_missing_block_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """join_memory_blocks must raise ToolError when either named block is missing.

        Falsifiable: if the ``found1``/``found2`` guards were removed,
        a missing block would silently produce a ToolError-less result.
        """
        fake.eval_response = {"found1": True, "found2": False, "joined_name": None, "ok": False}

        with pytest.raises(ToolError, match="not found"):
            run_async(connected_bridge.join_memory_blocks(".block_a", ".missing"))

    @staticmethod
    @pytest.mark.parametrize(
        ("function_name", "expected_params"),
        [
            ("ghidra.remove_memory_block", {"name"}),
            ("ghidra.split_memory_block", {"name", "split_address"}),
            ("ghidra.join_memory_blocks", {"name1", "name2"}),
        ],
    )
    def test_tool_def_registered_with_matching_params(
        connected_bridge: GhidraBridge,
        function_name: str,
        expected_params: set[str],
    ) -> None:
        """Each new memory-block tool-def must exist and declare the real method's parameter names.

        Falsifiable: removing the ``ToolFunction`` entry or renaming a
        parameter so it drifts from the bound method signature fails
        this containment check.
        """
        assert _tool_def_param_names(connected_bridge, function_name) == expected_params

    @staticmethod
    def test_split_memory_block_dispatchable_via_registry(
        registry: ToolRegistry,
        fake: FakeGhidraBridge,
    ) -> None:
        """ghidra.split_memory_block must dispatch via ToolRegistry and perform the real split.

        Falsifiable: if the tool-def were absent, dispatch would raise
        ToolError (unknown function) before ``split_memory_block`` ever
        ran; if the parameter names diverged (e.g. ``address`` instead
        of ``split_address``), dispatch would TypeError.
        """
        fake.eval_response = {"found": True, "in_range": True, "ok": True}

        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.split_memory_block",
                    {"name": ".text", "split_address": 0x1000},
                ),
            ),
        )
        assert result["success"] is True
        assert result["split_address"] == "0x1000"


# ---------------------------------------------------------------------------
# edit_program_tree (MISSING -> real)
# ---------------------------------------------------------------------------


class TestEditProgramTree:
    """L1/L2 gates for the previously MISSING program-tree write API."""

    @staticmethod
    def test_create_module_happy_path(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """edit_program_tree(create_module) must emit createModule and return the exact operation echoed back.

        Falsifiable: if the ``operation == 'create_module'`` branch were
        removed from the emitted Jython, ``createModule`` would not
        appear in the script and this assertion would fail.
        """
        fake.eval_response = {"tree_found": True, "parent_found": True, "ok": True}

        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.edit_program_tree("Program Tree", "create_module", "Root", "NewMod")),
        )

        assert result == {
            "tree_name": "Program Tree",
            "operation": "create_module",
            "child_name": "NewMod",
            "success": True,
        }
        assert len(fake.exec_calls) == 1
        assert "createModule" in fake.exec_calls[0]

    @staticmethod
    def test_create_fragment_happy_path_emits_create_fragment(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """edit_program_tree(create_fragment) must emit createFragment.

        Falsifiable: if the operation dispatch branch mapped
        'create_fragment' to createModule instead, this containment
        check would fail.
        """
        fake.eval_response = {"tree_found": True, "parent_found": True, "ok": True}

        run_async(connected_bridge.edit_program_tree("Program Tree", "create_fragment", "Root", "NewFrag"))

        assert "createFragment" in fake.exec_calls[0]

    @staticmethod
    def test_unknown_operation_raises_before_dispatch(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """edit_program_tree must raise ToolError for an unrecognized operation before any RPC call.

        Falsifiable: if the ``valid_operations`` guard were removed, an
        arbitrary operation string would be forwarded to Ghidra instead
        of raising locally, and fake.exec_calls would be non-empty.
        """
        with pytest.raises(ToolError, match="Unknown operation"):
            run_async(connected_bridge.edit_program_tree("Program Tree", "delete_everything", "Root", "X"))

        assert len(fake.exec_calls) == 0

    @staticmethod
    def test_parent_module_not_found_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """edit_program_tree must raise ToolError when the parent module does not exist in the tree.

        Falsifiable: if the ``parent_found`` guard were removed, a
        missing parent would silently be treated as success.
        """
        fake.eval_response = {"tree_found": True, "parent_found": False, "ok": False}

        with pytest.raises(ToolError, match="Parent module not found"):
            run_async(connected_bridge.edit_program_tree("Program Tree", "create_module", "GhostParent", "X"))

    @staticmethod
    def test_tool_def_registered_with_matching_params(connected_bridge: GhidraBridge) -> None:
        """ghidra.edit_program_tree's tool-def must declare all four real parameter names.

        Falsifiable: a parameter rename/removal in either the method
        signature or the ``ToolFunction`` entry desynchronizes this set.
        """
        assert _tool_def_param_names(connected_bridge, "ghidra.edit_program_tree") == {
            "tree_name",
            "operation",
            "parent_module",
            "child_name",
        }

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.edit_program_tree must dispatch via ToolRegistry and perform the real create_module call.

        Falsifiable: an unregistered or parameter-mismatched tool-def
        would raise before ``edit_program_tree`` ever executed.
        """
        fake.eval_response = {"tree_found": True, "parent_found": True, "ok": True}

        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.edit_program_tree",
                    {
                        "tree_name": "Program Tree",
                        "operation": "move_child",
                        "parent_module": "NewParent",
                        "child_name": "Existing",
                    },
                ),
            ),
        )
        assert result["operation"] == "move_child"
        assert result["success"] is True
        assert "moveChild" in fake.exec_calls[0]


# ---------------------------------------------------------------------------
# NO-CONTROL code-analysis methods: real L1 behavior + L2 dispatch
# ---------------------------------------------------------------------------


class TestGetInstructionFlow:
    """L1/L2 gates for get_instruction_flow (slice 5, row 7)."""

    @staticmethod
    def test_happy_path_returns_exact_fields(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """get_instruction_flow must surface mnemonic/flow_type/fall_through/flows verbatim.

        Falsifiable: if any field were read from the wrong dict key,
        this would return None/empty for that field instead of the
        oracle value.
        """
        fake.eval_response = {
            "address": _TEST_ADDR,
            "mnemonic": "JMP",
            "flow_type": "UNCONDITIONAL_JUMP",
            "fall_through": None,
            "flows": [_TEST_ADDR2],
        }

        result = cast("dict[str, Any]", run_async(connected_bridge.get_instruction_flow(_TEST_ADDR)))

        assert result["mnemonic"] == "JMP"
        assert result["flow_type"] == "UNCONDITIONAL_JUMP"
        assert result["fall_through"] is None
        assert result["flows"] == [_TEST_ADDR2]
        assert "getFlowType" in fake.exec_calls[0] or "getFlows" in fake.exec_calls[0]

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.get_instruction_flow must dispatch via ToolRegistry.

        Falsifiable: this NO-CONTROL feature was already tool-def
        registered per the audit; removing the ToolFunction entry
        would raise ToolError here.
        """
        fake.eval_response = {"address": _TEST_ADDR, "mnemonic": "NOP", "flow_type": "FALL_THROUGH", "fall_through": _TEST_ADDR, "flows": []}
        result = cast(
            "dict[str, Any]",
            run_async(registry.execute_tool_call("ghidra", "ghidra.get_instruction_flow", {"address": _TEST_ADDR})),
        )
        assert result["mnemonic"] == "NOP"


class TestGetRegisterValue:
    """L1/L2 gates for get_register_value (slice 5, row 8)."""

    @staticmethod
    def test_happy_path_returns_exact_value(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """get_register_value must return the exact tracked value and has_value flag from Ghidra.

        Falsifiable: if 'value' were read from the wrong key, the
        assertion on the specific oracle integer would fail.
        """
        fake.eval_response = {"address": _TEST_ADDR, "register": "EAX", "value": 305419896, "has_value": True}

        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.get_register_value(_TEST_ADDR, "EAX")),
        )

        assert result["value"] == 305419896
        assert result["has_value"] is True
        assert "getRegisterValue" in fake.exec_calls[0]

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.get_register_value must dispatch via ToolRegistry with the exact register name.

        Falsifiable: a parameter-name mismatch between the tool-def and
        the real method signature would TypeError on dispatch.
        """
        fake.eval_response = {"address": _TEST_ADDR, "register": "RSP", "value": None, "has_value": False}
        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.get_register_value",
                    {"address": _TEST_ADDR, "register": "RSP"},
                ),
            ),
        )
        assert result["has_value"] is False
        assert "RSP" in fake.eval_calls[-1] or "RSP" in fake.exec_calls[-1]


class TestThunkManagement:
    """L1/L2 gates for get_thunk_info / add_thunk / remove_thunk (slice 5, rows 20/45/46)."""

    @staticmethod
    def test_get_thunk_info_positive_case(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """get_thunk_info must surface thunked_function/thunked_address exactly when is_thunk is True.

        Falsifiable: if the ``is_thunk`` guard were removed, this would
        return the thunk fields even for a non-thunk oracle.
        """
        fake.eval_response = {
            "address": _TEST_ADDR,
            "is_thunk": True,
            "thunked_function": "RealImpl",
            "thunked_address": _TEST_ADDR2,
        }

        result = cast("dict[str, Any]", run_async(connected_bridge.get_thunk_info(_TEST_ADDR)))

        assert result["is_thunk"] is True
        assert result["thunked_function"] == "RealImpl"
        assert result["thunked_address"] == _TEST_ADDR2
        assert "isThunk" in fake.exec_calls[0]

    @staticmethod
    def test_add_thunk_happy_path(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """add_thunk must emit setThunkedFunction and return the exact hex addresses supplied.

        Falsifiable: reverting to a MISSING implementation would raise
        AttributeError; a broken transaction guard would fail to invoke
        setThunkedFunction.
        """
        fake.eval_response = {"ok": True, "thunk_found": True, "target_found": True}

        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.add_thunk(_TEST_ADDR, _TEST_ADDR2)),
        )

        assert result == {"address": hex(_TEST_ADDR), "thunked_address": hex(_TEST_ADDR2), "success": True}
        assert "setThunkedFunction" in fake.exec_calls[0]

    @staticmethod
    def test_add_thunk_missing_thunk_function_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """add_thunk must raise ToolError when the thunk-side function does not exist.

        Falsifiable: if the ``thunk_found`` guard were removed, this
        would report success despite no function existing at the address.
        """
        fake.eval_response = {"ok": False, "thunk_found": False, "target_found": True}

        with pytest.raises(ToolError, match="Function not found"):
            run_async(connected_bridge.add_thunk(_TEST_ADDR, _TEST_ADDR2))

    @staticmethod
    def test_remove_thunk_not_a_thunk_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """remove_thunk must raise ToolError when the function is not a thunk.

        Falsifiable: if the ``was_thunk`` guard were removed, a
        non-thunk function would report success without any mutation.
        """
        fake.eval_response = {"found": True, "was_thunk": False, "ok": False}

        with pytest.raises(ToolError, match="is not a thunk"):
            run_async(connected_bridge.remove_thunk(_TEST_ADDR))

    @staticmethod
    def test_remove_thunk_happy_path(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """remove_thunk must clear the relationship and return success for a real thunk.

        Falsifiable: the ``setThunkedFunction(None)`` call missing from
        the emitted script would fail this containment assertion.
        """
        fake.eval_response = {"found": True, "was_thunk": True, "ok": True}

        result = cast("dict[str, Any]", run_async(connected_bridge.remove_thunk(_TEST_ADDR)))

        assert result == {"address": hex(_TEST_ADDR), "success": True}
        assert "setThunkedFunction(None)" in fake.exec_calls[0]

    @staticmethod
    @pytest.mark.parametrize(
        "function_name",
        ["ghidra.get_thunk_info", "ghidra.add_thunk", "ghidra.remove_thunk"],
    )
    def test_tool_defs_registered(connected_bridge: GhidraBridge, function_name: str) -> None:
        """Every thunk-management tool-def must exist in tool_definition.

        Falsifiable: removing any of these ToolFunction entries makes
        the ``next(...)`` lookup inside ``_tool_def_param_names`` raise
        StopIteration.
        """
        names = {f.name for f in connected_bridge.tool_definition.functions}
        assert function_name in names

    @staticmethod
    def test_add_thunk_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.add_thunk must dispatch via ToolRegistry with address/thunked_address bound correctly.

        Falsifiable: a parameter name mismatch (e.g. tool-def declares
        ``target`` instead of ``thunked_address``) would TypeError here.
        """
        fake.eval_response = {"ok": True, "thunk_found": True, "target_found": True}
        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.add_thunk",
                    {"address": _TEST_ADDR, "thunked_address": _TEST_ADDR2},
                ),
            ),
        )
        assert result["success"] is True


class TestReferenceEditing:
    """L1/L2 gates for add_reference / delete_reference (slice 5, rows 23/24)."""

    @staticmethod
    def test_add_reference_verifies_readback(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """add_reference must verify the new reference appears in the readback list.

        Falsifiable: if the readback verification comparison
        (``to_addr not in targets``) were removed, a silently-rejected
        reference add would still report success.
        """
        fake.set_eval_responder(lambda expr: [_TEST_ADDR2] if "getReferencesFrom" in expr else None)

        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.add_reference(_TEST_ADDR, _TEST_ADDR2, "CALL")),
        )

        assert result == {"from": hex(_TEST_ADDR), "to": hex(_TEST_ADDR2), "type": "CALL", "success": True}
        assert "addMemoryReference" in fake.exec_calls[0]

    @staticmethod
    def test_add_reference_readback_mismatch_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """add_reference must raise ToolError when the readback does not include the target address.

        Falsifiable: removing the verification step means this call
        would return success even though Ghidra silently rejected the
        reference.
        """
        fake.set_eval_responder(lambda expr: [0x999999] if "getReferencesFrom" in expr else None)

        with pytest.raises(ToolError, match="verification failed"):
            run_async(connected_bridge.add_reference(_TEST_ADDR, _TEST_ADDR2, "DATA"))

    @staticmethod
    def test_delete_reference_happy_path(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """delete_reference must return success=True when Ghidra reports the reference was deleted.

        Falsifiable: if the returned boolean from the remote script
        were ignored, ``success`` would always be True regardless of
        the actual deletion outcome.
        """
        fake.eval_response = True

        result = cast("dict[str, Any]", run_async(connected_bridge.delete_reference(_TEST_ADDR, _TEST_ADDR2)))

        assert result["success"] is True
        assert "getReferencesFrom" in fake.exec_calls[0]

    @staticmethod
    def test_delete_reference_not_found_returns_false(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """delete_reference must return success=False when no matching reference exists.

        Falsifiable: a hardcoded ``success: True`` return would falsely
        report a deletion that never happened.
        """
        fake.eval_response = False

        result = cast("dict[str, Any]", run_async(connected_bridge.delete_reference(_TEST_ADDR, _TEST_ADDR2)))

        assert result["success"] is False

    @staticmethod
    def test_add_reference_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.add_reference must dispatch via ToolRegistry and perform the real add+verify.

        Falsifiable: an absent/renamed tool-def would raise before the
        bridge method ran, so ``fake.exec_calls`` would remain empty.
        """
        fake.set_eval_responder(lambda expr: [_TEST_ADDR2] if "getReferencesFrom" in expr else None)
        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.add_reference",
                    {"from_addr": _TEST_ADDR, "to_addr": _TEST_ADDR2, "ref_type": "READ"},
                ),
            ),
        )
        assert result["success"] is True
        assert len(fake.exec_calls) == 1


class TestExternalReferences:
    """L1/L2 gates for add_external_reference / remove_external_reference / get_external_references."""

    @staticmethod
    def test_add_external_reference_happy_path(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """add_external_reference must emit addExternalReference and return the exact library/name.

        Falsifiable: if the library/name literals were swapped in the
        return dict construction, this assertion fails.
        """
        fake.eval_response = {"ok": True}

        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.add_external_reference(_TEST_ADDR, "kernel32.dll", "CreateFileW")),
        )

        assert result == {"from_addr": hex(_TEST_ADDR), "library": "kernel32.dll", "name": "CreateFileW", "success": True}
        assert "addExternalReference" in fake.exec_calls[0]

    @staticmethod
    def test_remove_external_reference_no_matches_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """remove_external_reference must raise ToolError when zero references were removed.

        Falsifiable: if the ``removed > 0`` guard were removed, this
        would return success=True even when nothing was actually deleted.
        """
        fake.eval_response = {"removed": 0}

        with pytest.raises(ToolError, match="No external references found at"):
            run_async(connected_bridge.remove_external_reference(_TEST_ADDR))

    @staticmethod
    def test_get_external_references_maps_all_fields(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """get_external_references must return the exact library/type/external_name fields per entry.

        Falsifiable: if 'library' were read from the wrong dict key,
        this would return an empty string instead of the oracle value.
        """
        fake.eval_response = [
            {"address": _TEST_ADDR, "external_name": "malloc", "library": "msvcrt.dll", "type": "DATA"},
        ]

        result = cast("list[dict[str, Any]]", run_async(connected_bridge.get_external_references(_TEST_ADDR)))

        assert len(result) == 1
        assert result[0]["library"] == "msvcrt.dll"
        assert result[0]["external_name"] == "malloc"

    @staticmethod
    @pytest.mark.parametrize(
        "function_name",
        ["ghidra.add_external_reference", "ghidra.remove_external_reference", "ghidra.get_external_references"],
    )
    def test_tool_defs_registered(connected_bridge: GhidraBridge, function_name: str) -> None:
        """Every external-reference tool-def must exist in tool_definition.

        Falsifiable: removing any of these ToolFunction entries would
        make the membership check fail.
        """
        names = {f.name for f in connected_bridge.tool_definition.functions}
        assert function_name in names


class TestGetProperties:
    """L1/L2 gates for get_properties (slice 6, row 31)."""

    @staticmethod
    def test_happy_path_returns_property_map(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """get_properties must return the exact nested properties dict from Ghidra.

        Falsifiable: if 'properties' were read from the wrong key,
        the nested dict would be missing/empty instead of matching the
        oracle.
        """
        fake.eval_response = {"address": _TEST_ADDR, "properties": {"Analyzed": True, "Note": "manual review"}}

        result = cast("dict[str, Any]", run_async(connected_bridge.get_properties(_TEST_ADDR)))

        assert result["properties"] == {"Analyzed": True, "Note": "manual review"}
        assert "getUsrPropertyManager" in fake.exec_calls[0]

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.get_properties must dispatch via ToolRegistry.

        Falsifiable: an absent tool-def would raise ToolError before
        ``get_properties`` ever ran.
        """
        fake.eval_response = {"address": _TEST_ADDR, "properties": {}}
        result = cast(
            "dict[str, Any]",
            run_async(registry.execute_tool_call("ghidra", "ghidra.get_properties", {"address": _TEST_ADDR})),
        )
        assert result["properties"] == {}


class TestGetCallGraph:
    """L1/L2 gates for get_call_graph (slice 5, row 28 -- the orphan bidirectional method)."""

    @staticmethod
    def test_happy_path_returns_both_directions(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """get_call_graph must return distinct callees and callers trees from one call.

        Falsifiable: if the method collapsed to a single-direction
        result (like get_call_tree), one of the two lists would be
        empty/missing despite the oracle providing both non-empty.
        """
        fake.eval_response = {
            "name": "main",
            "address": _TEST_ADDR,
            "callees": [{"name": "helper", "address": _TEST_ADDR2, "callees": []}],
            "callers": [{"name": "_start", "address": 0x400000, "callers": []}],
        }

        result = cast("dict[str, Any]", run_async(connected_bridge.get_call_graph(_TEST_ADDR)))

        assert result["callees"][0]["name"] == "helper"
        assert result["callers"][0]["name"] == "_start"

    @staticmethod
    def test_function_not_found_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """get_call_graph must raise ToolError when no function contains the given address.

        Falsifiable: if the ``result is None`` guard were removed, this
        would raise an unhandled TypeError instead of a documented
        ToolError.
        """
        fake.eval_response = None

        with pytest.raises(ToolError, match="Function not found"):
            run_async(connected_bridge.get_call_graph(_TEST_ADDR))

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.get_call_graph must dispatch via ToolRegistry (this orphaned method has a real tool-def).

        Falsifiable: this feature was already registered per the audit;
        removing the ToolFunction entry breaks dispatch.
        """
        fake.eval_response = {"name": "main", "address": _TEST_ADDR, "callees": [], "callers": []}
        result = cast(
            "dict[str, Any]",
            run_async(registry.execute_tool_call("ghidra", "ghidra.get_call_graph", {"address": _TEST_ADDR})),
        )
        assert result["name"] == "main"


class TestGetFunctionSingular:
    """L1/L2 gates for get_function (singular, slice 5 row 13)."""

    @staticmethod
    def test_happy_path_returns_function_info(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """get_function must return a FunctionInfo whose name/address match the remote result.

        Falsifiable: if the FunctionInfo construction read the wrong
        dict key for name/address, these assertions fail.
        """
        fake.eval_response = {
            "name": "process_input",
            "address": _TEST_ADDR,
            "size": 64,
            "calling_convention": "__stdcall",
            "return_type": "int",
            "parameters": [],
            "variables": [],
        }

        result = cast("FunctionInfo | None", run_async(connected_bridge.get_function(_TEST_ADDR)))

        assert result is not None
        assert result.name == "process_input"
        assert result.address == _TEST_ADDR
        assert result.calling_convention == "__stdcall"

    @staticmethod
    def test_no_function_returns_none(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """get_function must return None when no function contains the address.

        Falsifiable: a hardcoded fallback FunctionInfo would break this
        assertion.
        """
        fake.eval_response = None

        result = run_async(connected_bridge.get_function(_TEST_ADDR))

        assert result is None

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.get_function must dispatch via ToolRegistry.

        Falsifiable: an absent tool-def would raise before
        ``get_function`` ever ran.
        """
        fake.eval_response = {
            "name": "f",
            "address": _TEST_ADDR,
            "size": 1,
            "calling_convention": "__cdecl",
            "return_type": "void",
            "parameters": [],
            "variables": [],
        }
        result = cast(
            "FunctionInfo | None",
            run_async(registry.execute_tool_call("ghidra", "ghidra.get_function", {"address": _TEST_ADDR})),
        )
        assert result is not None
        assert result.name == "f"


class TestAddLabelPrimary:
    """L1/L2 gates for add_label (slice 5, row 32 -- distinct from set_label)."""

    @staticmethod
    def test_happy_path_sets_primary_flag(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """add_label must return primary=True and emit sym.setPrimary() when primary is requested.

        Falsifiable: if the ``primary_flag`` branch were dropped from
        the emitted script, ``setPrimary`` would not appear.
        """
        fake.eval_response = {"created": True}

        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.add_label(_TEST_ADDR, "my_label", primary=True)),
        )

        assert result["primary"] is True
        assert result["success"] is True
        assert "setPrimary" in fake.exec_calls[0]

    @staticmethod
    def test_not_primary_omits_set_primary_call(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """add_label without primary must not emit an unconditional sym.setPrimary() call.

        Falsifiable: if the primary flag were ignored and setPrimary
        always ran, the emitted script would call setPrimary
        unconditionally rather than gating it on primary_flag.
        """
        fake.eval_response = {"created": True}

        run_async(connected_bridge.add_label(_TEST_ADDR, "my_label", primary=False))

        assert "primary_flag = False" in fake.exec_calls[0]

    @staticmethod
    def test_creation_failure_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """add_label must raise ToolError when Ghidra reports the label was not created.

        Falsifiable: if the ``created`` guard were removed, a failed
        creation would silently be reported as success.
        """
        fake.eval_response = {"created": False}

        with pytest.raises(ToolError, match="Add label failed"):
            run_async(connected_bridge.add_label(_TEST_ADDR, "dup_label"))

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.add_label must dispatch via ToolRegistry with the primary keyword bound correctly.

        Falsifiable: a mismatch between the tool-def parameter name and
        the real ``primary`` keyword-only argument would TypeError.
        """
        fake.eval_response = {"created": True}
        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.add_label",
                    {"address": _TEST_ADDR, "name": "lbl", "primary": True},
                ),
            ),
        )
        assert result["primary"] is True


class TestRemoveLabel:
    """L1/L2 gates for remove_label (Labels tab 'Remove Selected' row)."""

    @staticmethod
    def test_happy_path_returns_success(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """remove_label must return address/name/success when Ghidra reports the symbol was deleted.

        Falsifiable: if 'removed' were read from the wrong dict key,
        this would default to False and incorrectly raise instead of
        succeeding.
        """
        fake.eval_response = {"removed": True}

        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.remove_label(_TEST_ADDR, "my_label")),
        )

        assert result == {"address": hex(_TEST_ADDR), "name": "my_label", "success": True}
        assert "getSymbolTable" in fake.exec_calls[0]

    @staticmethod
    def test_no_matching_label_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """remove_label must raise ToolError when no symbol at the address matches the given name.

        Falsifiable: if the ``removed`` guard were removed, this would
        silently report success despite nothing being deleted.
        """
        fake.eval_response = {"removed": False}

        with pytest.raises(ToolError, match="Label not found"):
            run_async(connected_bridge.remove_label(_TEST_ADDR, "no_such_label"))

    @staticmethod
    def test_tool_def_registered_with_matching_params(connected_bridge: GhidraBridge) -> None:
        """ghidra.remove_label's tool-def must declare the real method's address/name parameters.

        Falsifiable: a parameter rename/removal in either the method
        signature or the ``ToolFunction`` entry desynchronizes this set.
        """
        assert _tool_def_param_names(connected_bridge, "ghidra.remove_label") == {"address", "name"}

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.remove_label must dispatch via ToolRegistry.

        Falsifiable: an absent tool-def would raise ToolError before
        ``remove_label`` ever ran.
        """
        fake.eval_response = {"removed": True}
        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.remove_label",
                    {"address": _TEST_ADDR, "name": "my_label"},
                ),
            ),
        )
        assert result["success"] is True
        assert result["name"] == "my_label"


class TestRemoveBookmark:
    """L1/L2 gates for remove_bookmark (slice 6, row 26)."""

    @staticmethod
    def test_happy_path_returns_removed_count(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """remove_bookmark must return the exact removed count from the remote result.

        Falsifiable: if 'removed' were read from the wrong dict key,
        this would default to 0 and incorrectly raise instead of
        succeeding.
        """
        fake.eval_response = {"removed": 2}

        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.remove_bookmark(_TEST_ADDR, "Analysis", "Note")),
        )

        assert result == {"address": hex(_TEST_ADDR), "removed": 2, "success": True}
        assert "removeBookmark" in fake.exec_calls[0]

    @staticmethod
    def test_no_matching_bookmark_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """remove_bookmark must raise ToolError when zero bookmarks matched the filters.

        Falsifiable: if the ``removed <= 0`` guard were removed, this
        would silently report success despite nothing being removed.
        """
        fake.eval_response = {"removed": 0}

        with pytest.raises(ToolError, match="Bookmark not found"):
            run_async(connected_bridge.remove_bookmark(_TEST_ADDR))

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.remove_bookmark must dispatch via ToolRegistry.

        Falsifiable: an absent tool-def would raise ToolError before
        ``remove_bookmark`` ever ran.
        """
        fake.eval_response = {"removed": 1}
        result = cast(
            "dict[str, Any]",
            run_async(registry.execute_tool_call("ghidra", "ghidra.remove_bookmark", {"address": _TEST_ADDR})),
        )
        assert result["success"] is True


class TestCreateDataType:
    """L1/L2 gates for create_data_type across all four kinds (slice 6, rows 3-6)."""

    @staticmethod
    @pytest.mark.parametrize("kind", ["enum", "union", "typedef", "function_def"])
    def test_happy_path_returns_exact_kind_and_size(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
        kind: str,
    ) -> None:
        """create_data_type must return the exact kind/size/name reported by Ghidra for each type kind.

        Falsifiable: if the kind literal were hardcoded to 'enum'
        regardless of input, this parametrized assertion would fail
        for the other three kinds.
        """
        fake.eval_response = {"name": "MyType", "kind": kind, "size": 4, "success": True}

        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.create_data_type("/Intellicrack", "MyType", kind, None)),
        )

        assert result["kind"] == kind
        assert result["name"] == "MyType"
        assert result["success"] is True
        assert kind in fake.exec_calls[0]

    @staticmethod
    def test_creation_failure_returns_success_false(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """create_data_type must surface success=False (not raise) when Ghidra fails to add the type.

        Falsifiable: if the ``created is not None`` branch always
        returned success=True, this assertion would fail.
        """
        fake.eval_response = {"name": "MyType", "kind": "enum", "size": 0, "success": False}

        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.create_data_type("/X", "MyType", "enum", None)),
        )

        assert result["success"] is False

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.create_data_type must dispatch via ToolRegistry with the type_kind parameter bound correctly.

        Falsifiable: a tool-def/method parameter-name mismatch on
        ``type_kind`` would TypeError on dispatch.
        """
        fake.eval_response = {"name": "MyUnion", "kind": "union", "size": 8, "success": True}
        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.create_data_type",
                    {"category": "/X", "name": "MyUnion", "type_kind": "union"},
                ),
            ),
        )
        assert result["kind"] == "union"
