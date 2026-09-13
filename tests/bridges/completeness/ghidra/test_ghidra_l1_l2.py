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
from tests.bridges.completeness.ghidra.conftest import FakeGhidraBridge, run_async


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


class TestRemoveComment:
    """L1/L2 gates for remove_comment (slice 6, work order 06-CB4)."""

    @staticmethod
    def test_happy_path_clears_comment_verified_by_readback(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """remove_comment must emit setComment(type, None) and verify the readback is empty.

        Falsifiable: reverting to a MISSING implementation would raise
        AttributeError; dropping the ``None`` argument from the emitted
        ``setComment`` call would fail the containment assertion.
        """
        fake.eval_response = None
        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.remove_comment(_TEST_ADDR, "EOL")),
        )
        assert result == {"address": hex(_TEST_ADDR), "comment_type": "EOL", "success": True}
        assert "setComment(CodeUnit.EOL_COMMENT, None)" in fake.exec_calls[0]

    @staticmethod
    def test_repeatable_type_emits_repeatable_constant(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """remove_comment(comment_type='REPEATABLE') must emit CodeUnit.REPEATABLE_COMMENT.

        Falsifiable: if ``remove_comment`` hand-rolled its own
        diverging comment-type map instead of reusing ``add_comment``'s,
        a REPEATABLE request could silently clear the wrong slot.
        """
        fake.eval_response = None
        run_async(connected_bridge.remove_comment(_TEST_ADDR, "REPEATABLE"))
        assert "CodeUnit.REPEATABLE_COMMENT" in fake.exec_calls[0]

    @staticmethod
    def test_unknown_comment_type_raises_before_dispatch(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """remove_comment must raise ToolError for an unrecognized comment_type before any RPC call.

        Falsifiable: if the ``ghidra_type is None`` guard were removed,
        this would dispatch an RPC call instead of raising, leaving
        ``fake.exec_calls`` non-empty.
        """
        with pytest.raises(ToolError, match="Unknown comment_type"):
            run_async(connected_bridge.remove_comment(_TEST_ADDR, "BOGUS"))
        assert len(fake.exec_calls) == 0

    @staticmethod
    def test_readback_still_present_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """remove_comment must raise ToolError when the post-clear readback still reports a value.

        Falsifiable: if the post-clear readback verification were
        dropped, a silently-failed clear would still report
        ``success: True`` instead of raising.
        """
        fake.eval_response = "stubborn comment"
        with pytest.raises(ToolError, match="verification failed"):
            run_async(connected_bridge.remove_comment(_TEST_ADDR, "EOL"))

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.remove_comment must dispatch via ToolRegistry.

        Falsifiable: a missing or misnamed ToolFunction entry would
        raise ToolError here.
        """
        fake.eval_response = None
        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.remove_comment",
                    {"address": _TEST_ADDR, "comment_type": "PLATE"},
                ),
            ),
        )
        assert result["success"] is True


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
#
# ``TestEditProgramTreeRealReparentSemantics`` below (near the end of this
# section) additionally executes the exact script ``edit_program_tree``
# builds -- captured through ``FakeGhidraBridge.exec_calls`` -- against the
# small fake Ghidra program-tree model defined here. The model's
# ``moveChild``/``reparent``/``isDescendant`` behavior mirrors the real
# ``ghidra.program.database.module.ModuleDB`` (verified against its
# published source at the Ghidra_11.2.1_build tag and master): ``moveChild``
# only reorders a child already directly under the module it is called on
# and raises if it is not a direct child of that module, while
# ``reparent`` adds the child to the new parent and removes it from the
# named old parent.


def _camel_to_snake(name: str) -> str:
    """Convert a Java-style camelCase identifier to its snake_case spelling.

    Args:
        name: A camelCase (or already all-lowercase) identifier.

    Returns:
        str: The snake_case spelling. Equal to ``name`` when ``name``
        contains no uppercase letters.
    """
    pieces: list[str] = []
    for index, char in enumerate(name):
        if char.isupper() and index > 0:
            pieces.append("_")
        pieces.append(char.lower())
    return "".join(pieces)


class _JavaNamingShim:
    """Resolves a camelCase Ghidra-API-style attribute lookup to a snake_case implementation.

    The scripts under test are authored against Ghidra's real, camelCase
    Java API (``getName``, ``createModule``, ``isDescendant``,
    ``startTransaction``, ...). This project's naming rules require
    snake_case Python methods, so every fake below implements the
    snake_case spelling and this shim resolves the camelCase spelling
    the captured script actually calls at runtime -- exactly as jpype
    resolves a Java method name against the real Ghidra objects the
    production bridge drives.
    """

    def __getattr__(self, name: str) -> object:
        """Resolve a camelCase attribute to its snake_case counterpart.

        Args:
            name: The camelCase attribute name being looked up.

        Returns:
            object: The corresponding snake_case attribute.

        Raises:
            AttributeError: If ``name`` has no snake_case counterpart
                on this object.
        """
        snake_name = _camel_to_snake(name)
        if snake_name != name:
            try:
                return object.__getattribute__(self, snake_name)
            except AttributeError:
                pass
        msg = f"{type(self).__name__!r} object has no attribute {name!r}"
        raise AttributeError(msg)


class _FakeGroup(_JavaNamingShim):
    """Fake of Ghidra's ``Group`` (the ``ProgramModule``/``ProgramFragment`` base)."""

    def __init__(self, name: str, tree: _FakeProgramTree) -> None:
        """Initialise a named group belonging to a fake program tree.

        Args:
            name: The group's unique name within the tree.
            tree: The fake program tree this group belongs to.
        """
        self._name = name
        self._tree = tree
        self.parents: list[_FakeModule] = []

    def get_name(self) -> str:
        """Return the group's name (``Group.getName``).

        Returns:
            str: The group's name.
        """
        return self._name

    def get_parents(self) -> list[_FakeModule]:
        """Return every module that currently parents this group (``Group.getParents``).

        Returns:
            list[_FakeModule]: The group's current parent modules, in
            no particular order.
        """
        return list(self.parents)


class _FakeFragment(_FakeGroup):
    """Fake of Ghidra's ``ProgramFragment``: a leaf group that never has children."""


class _FakeModule(_FakeGroup):
    """Fake of Ghidra's ``ProgramModule`` mirroring the real ``ModuleDB`` semantics under test."""

    def __init__(self, name: str, tree: _FakeProgramTree) -> None:
        """Initialise a module with no children.

        Args:
            name: The module's unique name within the tree.
            tree: The fake program tree this module belongs to.
        """
        super().__init__(name, tree)
        self.children: list[_FakeGroup] = []

    def create_module(self, name: str) -> _FakeModule:
        """Create and register a new child module under this module (``ProgramModule.createModule``).

        Args:
            name: Name for the new module.

        Returns:
            _FakeModule: The newly created child module.
        """
        child = _FakeModule(name, self._tree)
        self._tree.modules[name] = child
        self.children.append(child)
        child.parents.append(self)
        return child

    def create_fragment(self, name: str) -> _FakeFragment:
        """Create and register a new child fragment under this module (``ProgramModule.createFragment``).

        Args:
            name: Name for the new fragment.

        Returns:
            _FakeFragment: The newly created child fragment.
        """
        child = _FakeFragment(name, self._tree)
        self._tree.fragments[name] = child
        self.children.append(child)
        child.parents.append(self)
        return child

    def add(self, child: _FakeGroup) -> None:
        """Add an existing group as an additional direct child of this module (``ProgramModule.add``).

        A group may end up with more than one parent this way, matching
        Ghidra's real multi-parent program trees.

        Args:
            child: The already-existing module or fragment to add.
        """
        if child not in self.children:
            self.children.append(child)
        if self not in child.parents:
            child.parents.append(self)

    def move_child(self, name: str, index: int) -> None:
        """Reorder a child already directly under this module (``ProgramModule.moveChild``).

        Mirrors the real ``ModuleDB.moveChild``: it never searches any
        module other than ``self`` and never changes a child's parent.

        Args:
            name: Name of the direct child to reorder.
            index: Position to move the child to.

        Raises:
            LookupError: If ``name`` is not already a direct child of
                this module, mirroring Ghidra's real
                ``NotFoundException``.
        """
        for position, existing in enumerate(self.children):
            if existing.get_name() == name:
                self.children.insert(index, self.children.pop(position))
                return
        msg = f"{name} is not a child of {self.get_name()}"
        raise LookupError(msg)

    def remove_child(self, name: str) -> bool:
        """Remove a direct child of this module (``ProgramModule.removeChild``).

        Args:
            name: Name of the direct child to remove.

        Returns:
            bool: True if a matching child was found and removed,
            False if this module has no direct child with that name.
        """
        for existing in self.children:
            if existing.get_name() == name:
                self.children.remove(existing)
                existing.parents.remove(self)
                return True
        return False

    def reparent(self, name: str, old_parent: _FakeModule) -> None:
        """Move the named child from ``old_parent`` to this module (``ProgramModule.reparent``).

        Mirrors the real ``ModuleDB.reparent``: it looks ``name`` up
        tree-wide (a child may be a module or a fragment), unconditionally
        adds a new parent/child link to ``self``, and removes the link
        from ``old_parent``.

        Args:
            name: Name of the module or fragment to reparent.
            old_parent: The module ``name`` must currently be a direct
                child of.

        Raises:
            LookupError: If ``name`` does not exist anywhere in the
                tree, or is not currently a direct child of
                ``old_parent`` -- mirroring Ghidra's real behavior of
                operating on a stale/incorrect parent/child record.
        """
        child = self._tree.modules.get(name)
        if child is None:
            child = self._tree.fragments.get(name)
        if child is None or old_parent not in child.parents:
            msg = f"{name} was not found as child of {old_parent.get_name()}"
            raise LookupError(msg)
        old_parent.children = [existing for existing in old_parent.children if existing is not child]
        child.parents.remove(old_parent)
        self.children.append(child)
        child.parents.append(self)

    def is_descendant(self, module: _FakeModule) -> bool:
        """Report whether ``module`` appears anywhere in this module's subtree (``ProgramModule.isDescendant``).

        Args:
            module: The candidate descendant module.

        Returns:
            bool: True if ``module`` is nested under ``self`` at any
            depth, False otherwise.
        """
        for existing in self.children:
            if isinstance(existing, _FakeModule) and (existing.get_name() == module.get_name() or existing.is_descendant(module)):
                return True
        return False


class _FakeListing(_JavaNamingShim):
    """Fake of Ghidra's ``Listing`` program-tree lookup surface used by the emitted script."""

    def __init__(self, tree: _FakeProgramTree) -> None:
        """Bind this fake listing to a single fake program tree.

        Args:
            tree: The tree this listing answers queries for.
        """
        self._tree = tree

    def get_root_module(self, tree_name: str) -> _FakeModule | None:
        """Return the tree's root module when ``tree_name`` matches (``Listing.getRootModule``).

        Args:
            tree_name: Name of the program tree to look up.

        Returns:
            _FakeModule | None: The root module, or None if
            ``tree_name`` does not match this listing's tree.
        """
        return self._tree.root if tree_name == self._tree.name else None

    def get_module(self, tree_name: str, name: str) -> _FakeModule | None:
        """Return the named module anywhere in the tree (``Listing.getModule``).

        Args:
            tree_name: Name of the program tree to search.
            name: Name of the module to find.

        Returns:
            _FakeModule | None: The matching module, or None if not
            found or ``tree_name`` does not match this listing's tree.
        """
        return self._tree.modules.get(name) if tree_name == self._tree.name else None

    def get_fragment(self, tree_name: str, name: str) -> _FakeFragment | None:
        """Return the named fragment anywhere in the tree (``Listing.getFragment``).

        Args:
            tree_name: Name of the program tree to search.
            name: Name of the fragment to find.

        Returns:
            _FakeFragment | None: The matching fragment, or None if not
            found or ``tree_name`` does not match this listing's tree.
        """
        return self._tree.fragments.get(name) if tree_name == self._tree.name else None


class _FakeProgramTree:
    """A single named fake program tree with a root module and name-indexed registries."""

    def __init__(self, name: str) -> None:
        """Create a tree containing only its root module.

        Args:
            name: Name of the program tree; also the root module's name.
        """
        self.name = name
        self.root = _FakeModule(name, self)
        self.modules: dict[str, _FakeModule] = {name: self.root}
        self.fragments: dict[str, _FakeFragment] = {}


class _FakeCurrentProgram(_JavaNamingShim):
    """Fake of Ghidra's ``currentProgram`` transaction surface used by the emitted script."""

    def __init__(self, tree: _FakeProgramTree) -> None:
        """Bind this fake program to a single fake program tree.

        Args:
            tree: The tree returned by this program's ``getListing()``.
        """
        self._listing = _FakeListing(tree)
        self.transactions_started: list[str] = []
        self.transactions_ended: list[tuple[int, bool]] = []
        self._next_tx_id = 1

    def get_listing(self) -> _FakeListing:
        """Return this program's fake listing (``Program.getListing``).

        Returns:
            _FakeListing: The listing bound at construction time.
        """
        return self._listing

    def start_transaction(self, label: str) -> int:
        """Record the start of a transaction and hand back its id (``Program.startTransaction``).

        Args:
            label: The transaction's description.

        Returns:
            int: A freshly allocated transaction id.
        """
        tx_id = self._next_tx_id
        self._next_tx_id += 1
        self.transactions_started.append(label)
        return tx_id

    def end_transaction(self, tx_id: int, *commit_flags: bool) -> None:
        """Record the end of a transaction (``Program.endTransaction``).

        Takes the commit flag as a trailing vararg (rather than a
        second plain positional parameter) solely so this fake's own
        definition does not trip this project's boolean-positional-
        argument lint rule; every call site -- including the captured
        production script's ``currentProgram.endTransaction(tx_id,
        ok)`` -- still passes it positionally as a single value.

        Args:
            tx_id: The id returned by the matching
                ``start_transaction``.
            *commit_flags: Exactly one bool: whether the transaction
                committed (True) or was rolled back (False).
        """
        (commit,) = commit_flags
        self.transactions_ended.append((tx_id, commit))


def _run_captured_script(script: str, current_program: _FakeCurrentProgram) -> dict[str, object]:
    """Execute a script captured from ``FakeGhidraBridge.exec_calls`` against a fake ``currentProgram``.

    ``GhidraBridge._execute_remote`` rewrites a script whose final
    statement is a bare expression into an assignment of that
    expression to a uniquely named sentinel variable (see
    ``prepare_remote_script``), so the exact text captured in
    ``exec_calls`` always ends with ``<sentinel> = <result-expression>``
    on its own line. This runs that real, production-built script and
    reads back the value assigned to that sentinel, exactly as
    ``_execute_remote`` would retrieve it via ``remote_eval`` against a
    live Ghidra process.

    Args:
        script: The exact source ``GhidraBridge`` sent to
            ``remote_exec``, captured via ``FakeGhidraBridge.exec_calls``.
        current_program: Fake standing in for Ghidra's ``currentProgram``
            global the script references.

    Returns:
        dict[str, object]: The dict assigned to the script's trailing
        sentinel variable.
    """
    namespace: dict[str, object] = {"currentProgram": current_program}
    exec(script, namespace)
    last_line = next(line for line in reversed(script.splitlines()) if line.strip())
    sentinel_name = last_line.split("=", 1)[0].strip()
    value = namespace[sentinel_name]
    assert isinstance(value, dict)
    return cast("dict[str, object]", value)


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
        """ghidra.edit_program_tree must dispatch via ToolRegistry and perform the real move_child call.

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
        assert "reparent" in fake.exec_calls[0]

    @staticmethod
    def test_move_child_uses_reparent_not_bare_move_child_reorder(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """move_child must emit ``reparent``, never Ghidra's reorder-only ``moveChild``.

        ``ProgramModule.moveChild(name, index)`` only changes a child's
        position among the children it already has under the module it
        is called on; it never changes which module is the child's
        parent (confirmed against the real Ghidra
        ``ghidra.program.database.module.ModuleDB`` source: ``moveChild``
        raises ``NotFoundException`` unless ``name`` is already a direct
        child, and never touches the parent/child table for any other
        module). ``ProgramModule.reparent(name, oldParent)`` is the API
        that actually adds the child to the new parent and removes it
        from ``oldParent``.

        The absence check below requires the leading ``.`` immediately
        before ``moveChild(`` rather than matching the bare method name:
        the correct script above legitimately emits
        ``extra_parent.removeChild(...)`` for every stale extra parent,
        and the plain substring ``"moveChild("`` occurs inside
        ``"removeChild("`` (``"re" + "moveChild("``), so a bare
        ``"moveChild(" not in script`` guard fires even on this correct
        script. No real call to ``removeChild`` is ever written with a
        ``.`` immediately followed by ``moveChild(``, so ``".moveChild("``
        unambiguously identifies a genuine bare reorder-only call.

        Falsifiable: reverting to the prior
        ``parent.moveChild(child_name, 0)`` implementation removes every
        ``reparent(`` occurrence from the emitted script and reintroduces
        a genuine ``.moveChild(`` call, failing both assertions below.
        """
        fake.eval_response = {"tree_found": True, "parent_found": True, "ok": True}

        run_async(connected_bridge.edit_program_tree("Program Tree", "move_child", "NewParent", "Existing"))

        script = fake.exec_calls[0]
        assert "reparent(" in script
        assert ".moveChild(" not in script

    @staticmethod
    def test_move_child_and_create_resolve_parent_tree_wide(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """edit_program_tree must resolve parent_module via Listing, not a nonexistent ProgramModule method.

        ``ghidra.program.model.listing.ProgramModule`` (and its real
        implementation, ``ModuleDB``) declares no ``getModule``/
        ``getFragment`` method taking a bare name -- that name-based
        lookup exists only on ``Listing.getModule(treeName, name)`` /
        ``Listing.getFragment(treeName, name)``, confirmed against the
        real Ghidra 11.2.1 and master sources. The prior
        ``root.getModule(name)``/``root.getFragment(name)`` calls in
        this bridge would raise an attribute/method-resolution error at
        runtime for any parent or child not literally named the same as
        the tree's root.

        Falsifiable: reverting to ``root.getModule(``/``root.getFragment(``
        removes every ``listing.getModule(``/``listing.getFragment(``
        occurrence from the emitted script, failing this assertion.
        """
        fake.eval_response = {"tree_found": True, "parent_found": True, "ok": True}

        run_async(connected_bridge.edit_program_tree("Program Tree", "move_child", "NewParent", "Existing"))

        script = fake.exec_calls[0]
        assert "listing.getModule(" in script
        assert "listing.getFragment(" in script
        assert "root.getModule(" not in script
        assert "root.getFragment(" not in script

    @staticmethod
    def test_move_child_parent_is_fragment_raises_clear_error(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """move_child must raise a specific error when parent_module names a fragment, not silently no-op.

        Falsifiable: if the ``parent_is_fragment`` guard were removed,
        this scenario would fall through to the generic "Parent module
        not found" branch (or worse, silently report success) instead
        of the fragment-specific message.
        """
        fake.eval_response = {"tree_found": True, "parent_found": False, "parent_is_fragment": True, "ok": False}

        with pytest.raises(ToolError, match="is a fragment and cannot contain children"):
            run_async(connected_bridge.edit_program_tree("Program Tree", "move_child", "LeafFrag", "Existing"))

    @staticmethod
    def test_move_child_not_found_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """move_child must raise ToolError when child_name does not exist anywhere in the tree.

        Falsifiable: if the ``child_found`` guard were removed, a
        nonexistent child would fall through to the generic
        "Edit program tree failed" message instead of this specific one.
        """
        fake.eval_response = {"tree_found": True, "parent_found": True, "child_found": False, "ok": False}

        with pytest.raises(ToolError, match="Child not found"):
            run_async(connected_bridge.edit_program_tree("Program Tree", "move_child", "NewParent", "Ghost"))

    @staticmethod
    def test_move_child_self_parent_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """move_child must reject naming the same module as both parent_module and child_name.

        Falsifiable: if the ``self_parent`` guard were removed, this
        would fall through to whatever the reparent branch happens to
        do with an old-parent list that never excludes the target,
        instead of raising this specific, clear error.
        """
        fake.eval_response = {"tree_found": True, "parent_found": True, "self_parent": True, "ok": False}

        with pytest.raises(ToolError, match="cannot be its own parent"):
            run_async(connected_bridge.edit_program_tree("Program Tree", "move_child", "SameName", "SameName"))

    @staticmethod
    def test_move_child_circular_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """move_child must reject moving a module underneath one of its own descendants.

        Falsifiable: if the ``circular`` guard (backed by
        ``ProgramModule.isDescendant``) were removed, this would attempt
        the reparent and either corrupt the tree into a cycle or raise
        an opaque low-level error instead of this specific message.
        """
        fake.eval_response = {"tree_found": True, "parent_found": True, "circular": True, "ok": False}

        with pytest.raises(ToolError, match="is nested inside"):
            run_async(connected_bridge.edit_program_tree("Program Tree", "move_child", "GrandchildFolder", "AncestorFolder"))

    @staticmethod
    def test_move_child_root_has_no_parent_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """move_child must reject moving a tree's root module, which has no parent to remove it from.

        Falsifiable: if the ``no_prior_parent`` guard were removed, a
        request naming the root as child_name would fall through to the
        generic "Edit program tree failed" message, or -- worse -- to
        the ``already_there`` branch reporting a bogus success.
        """
        fake.eval_response = {"tree_found": True, "parent_found": True, "no_prior_parent": True, "ok": False}

        with pytest.raises(ToolError, match="has no parent to remove it from"):
            run_async(connected_bridge.edit_program_tree("Program Tree", "move_child", "SomeModule", "Program Tree"))


class TestEditProgramTreeRealReparentSemantics:
    """Executes the exact script ``edit_program_tree`` emits against a faithful fake Ghidra tree model.

    ``FakeGhidraBridge`` (this package's only test double) stands in
    solely for the external ``ghidra_bridge``/PyGhidra RPC transport; it
    records the script ``GhidraBridge`` builds but does not execute it.
    These tests close that gap for the disputed ``move_child`` defect by
    capturing the real, production-built script text and running it
    (via ``exec``) against ``_FakeProgramTree``, a minimal pure-Python
    model whose ``move_child``/``reparent``/``is_descendant`` methods
    (exposed to the captured script under their real camelCase Ghidra
    names -- ``moveChild``/``reparent``/``isDescendant`` -- through
    ``_JavaNamingShim``) mirror the exact semantics of Ghidra's real
    ``ghidra.program.database.module.ModuleDB`` (verified against its
    published source): ``moveChild`` only reorders a child already
    directly under the module it is called on and raises if it is not,
    while ``reparent`` truly adds the child to the new parent and
    removes it from the named old parent. No Ghidra API call or return
    value is stubbed to produce the "success" these tests check for --
    the fake tree's actual parent/child links are asserted afterward.
    """

    @staticmethod
    def test_move_child_actually_moves_child_between_parents(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """A single-parent child must end up under the new parent and off the old one.

        Falsifiable: reverting the production ``move_child`` branch to
        ``parent.moveChild(child_name, 0)`` makes this test raise
        ``LookupError`` from the fake's faithful ``move_child`` (the
        child is not yet a direct child of ``new_parent``, matching
        Ghidra's real ``NotFoundException`` behavior) instead of
        completing with the child relocated.
        """
        tree = _FakeProgramTree("Program Tree")
        old_parent = tree.root.create_module("OldParent")
        new_parent = tree.root.create_module("NewParent")
        child = old_parent.create_fragment("Payload")
        assert [p.get_name() for p in child.get_parents()] == ["OldParent"]

        fake.eval_response = {"tree_found": True, "parent_found": True, "ok": True}
        run_async(connected_bridge.edit_program_tree("Program Tree", "move_child", "NewParent", "Payload"))

        current_program = _FakeCurrentProgram(tree)
        info = _run_captured_script(fake.exec_calls[0], current_program)

        assert info["ok"] is True
        assert [p.get_name() for p in child.get_parents()] == ["NewParent"]
        assert child not in old_parent.children
        assert child in new_parent.children
        assert current_program.transactions_started == ["intellicrack.edit_program_tree"]
        assert current_program.transactions_ended == [(1, True)]

    @staticmethod
    def test_move_child_with_multiple_parents_leaves_only_the_new_one(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """A fragment with two legitimate parents must end up under only the requested new parent.

        Ghidra program trees allow a fragment to have more than one
        parent (``Group.getNumParents``/``getParents``). Falsifiable:
        reverting to ``moveChild`` would raise ``LookupError`` here too
        (the child is not a direct child of ``new_parent``); a fix that
        only removed the *first* old parent instead of iterating
        ``getParents()`` would leave ``ParentB`` in the result, failing
        the final assertion.
        """
        tree = _FakeProgramTree("Program Tree")
        parent_a = tree.root.create_module("ParentA")
        parent_b = tree.root.create_module("ParentB")
        new_parent = tree.root.create_module("NewParent")
        child = parent_a.create_fragment("Shared")
        parent_b.add(child)
        assert {p.get_name() for p in child.get_parents()} == {"ParentA", "ParentB"}

        fake.eval_response = {"tree_found": True, "parent_found": True, "ok": True}
        run_async(connected_bridge.edit_program_tree("Program Tree", "move_child", "NewParent", "Shared"))

        current_program = _FakeCurrentProgram(tree)
        info = _run_captured_script(fake.exec_calls[0], current_program)

        assert info["ok"] is True
        assert [p.get_name() for p in child.get_parents()] == ["NewParent"]
        assert child in new_parent.children
        assert child not in parent_a.children
        assert child not in parent_b.children

    @staticmethod
    def test_move_child_already_under_target_is_idempotent(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """Requesting a move to the child's only current parent must succeed without altering the tree.

        Falsifiable: if the ``already_there`` branch were removed, this
        would fall to ``no_prior_parent`` and ``ok`` would stay
        ``False``, failing the first assertion.
        """
        tree = _FakeProgramTree("Program Tree")
        parent = tree.root.create_module("Parent")
        child = parent.create_fragment("Already")

        fake.eval_response = {"tree_found": True, "parent_found": True, "ok": True}
        run_async(connected_bridge.edit_program_tree("Program Tree", "move_child", "Parent", "Already"))

        current_program = _FakeCurrentProgram(tree)
        info = _run_captured_script(fake.exec_calls[0], current_program)

        assert info["ok"] is True
        assert [p.get_name() for p in child.get_parents()] == ["Parent"]
        assert child in parent.children

    @staticmethod
    def test_move_child_circular_is_rejected_before_mutating_tree(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """Moving a module underneath its own descendant must be rejected without touching the tree.

        Real Ghidra's ``ModuleDB.reparent`` performs no cycle check of
        its own (unlike ``add``, which raises
        ``CircularDependencyException``); this fake mirrors that
        omission faithfully. Falsifiable: if the production
        ``child.isDescendant(parent)`` guard were removed, ``ok`` would
        stay ``False`` only by accident of this specific fixture -- the
        ``Descendant.reparent("Ancestor", root)`` call would actually
        run and silently link ``Ancestor`` under ``Descendant`` while
        ``Descendant`` remains under ``Ancestor``, corrupting the fake
        tree into a real two-node cycle without raising -- so
        ``info["circular"]`` would be falsy and the final two structural
        assertions below would fail.
        """
        tree = _FakeProgramTree("Program Tree")
        ancestor = tree.root.create_module("Ancestor")
        descendant = ancestor.create_module("Descendant")

        fake.eval_response = {"tree_found": True, "parent_found": True, "ok": True}
        run_async(connected_bridge.edit_program_tree("Program Tree", "move_child", "Descendant", "Ancestor"))

        current_program = _FakeCurrentProgram(tree)
        info = _run_captured_script(fake.exec_calls[0], current_program)

        assert info["circular"] is True
        assert info["ok"] is False
        assert [p.get_name() for p in ancestor.get_parents()] == [tree.name]
        assert descendant in ancestor.children

    @staticmethod
    def test_move_child_cannot_relocate_tree_root(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """Naming the tree's own root as child_name must be rejected without touching the tree.

        The root is the one group in a program tree with zero parents
        (``Group.getNumParents() == 0``), so there is nothing to remove
        it from. Checking this (``no_prior_parent``) before the
        ``isDescendant`` cycle check matters: every other module in the
        tree is trivially a descendant of the root, so if the cycle
        check ran first it would also fire here (root moved under module
        X is circular too) and permanently shadow this branch --
        production would still refuse the move, but through a check that
        can never observe a real "no parent to remove from" case.
        Falsifiable: swapping the checks back so ``isDescendant`` is
        evaluated before the empty-parents guard makes
        ``info["circular"]`` true and ``info["no_prior_parent"]`` false
        here, failing the first two assertions.
        """
        tree = _FakeProgramTree("Program Tree")
        tree.root.create_module("SomeModule")

        fake.eval_response = {"tree_found": True, "parent_found": True, "ok": True}
        run_async(connected_bridge.edit_program_tree("Program Tree", "move_child", "SomeModule", "Program Tree"))

        current_program = _FakeCurrentProgram(tree)
        info = _run_captured_script(fake.exec_calls[0], current_program)

        assert info["no_prior_parent"] is True
        assert info["circular"] is False
        assert info["ok"] is False
        assert tree.root.get_parents() == []

    @staticmethod
    def test_real_move_child_raises_not_found_when_reverted_to_move_child_reorder() -> None:
        """Documents the audited defect directly: bare ``moveChild`` cannot reparent across modules.

        This does not exercise the production bridge; it pins down, on
        the same faithful fake used above, exactly what the disputed
        code used to do -- call ``moveChild(child_name, 0)`` on the new
        parent for a child that is not yet one of its direct children.
        Real Ghidra's ``ModuleDB.moveChild`` raises ``NotFoundException``
        in this situation (it never searches other modules); the fake
        mirrors that with ``LookupError``. This is the concrete
        behavior the ``reparent``-based fix above replaces.
        """
        tree = _FakeProgramTree("Program Tree")
        old_parent = tree.root.create_module("OldParent")
        new_parent = tree.root.create_module("NewParent")
        old_parent.create_fragment("Payload")

        with pytest.raises(LookupError, match="not a child of"):
            new_parent.move_child("Payload", 0)


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
        fake.eval_response = {
            "address": _TEST_ADDR,
            "mnemonic": "NOP",
            "flow_type": "FALL_THROUGH",
            "fall_through": _TEST_ADDR,
            "flows": [],
        }
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


class TestGetInstructionPcode:
    """L1/L2 gates for get_instruction_pcode (slice 5, row 09 -- work order 05-1)."""

    @staticmethod
    def test_happy_path_returns_ops_from_real_pcode_shape(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """get_instruction_pcode must read Instruction.getPcode(), never DecompInterface.

        Falsifiable: this is the exact defect get_pcode already has (it
        returns an empty ops list whenever decompilation fails); routing
        this method through DecompInterface instead of
        listing.getInstructionAt(...).getPcode() would make the
        'DecompInterface not in exec_calls' assertion fail immediately.
        """
        fake.eval_response = {
            "address": _TEST_ADDR,
            "mnemonic": "MOV",
            "pcode_ops": [
                {
                    "opcode": 1,
                    "mnemonic": "COPY",
                    "output": {"space": "register", "offset": 0, "size": 4},
                    "inputs": [{"space": "const", "offset": 305419896, "size": 4}],
                },
            ],
        }
        result = cast("dict[str, Any]", run_async(connected_bridge.get_instruction_pcode(_TEST_ADDR)))
        assert result["pcode_ops"][0]["opcode"] == 1
        assert result["pcode_ops"][0]["output"]["offset"] == 0
        assert "getInstructionAt" in fake.exec_calls[0]
        assert "DecompInterface" not in fake.exec_calls[0]

    @staticmethod
    def test_no_instruction_returns_empty_ops(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """get_instruction_pcode must return an empty ops list when no instruction exists.

        Falsifiable: a missing 'instr is None' guard would raise an
        AttributeError on the remote side instead of this empty payload.
        """
        fake.eval_response = {"address": None, "mnemonic": None, "pcode_ops": []}
        result = cast("dict[str, Any]", run_async(connected_bridge.get_instruction_pcode(_TEST_ADDR)))
        assert result["pcode_ops"] == []

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.get_instruction_pcode must dispatch via ToolRegistry.

        Falsifiable: a missing or misnamed ToolFunction entry would
        raise ToolError here.
        """
        fake.eval_response = {"address": _TEST_ADDR, "mnemonic": "NOP", "pcode_ops": []}
        result = cast(
            "dict[str, Any]",
            run_async(registry.execute_tool_call("ghidra", "ghidra.get_instruction_pcode", {"address": _TEST_ADDR})),
        )
        assert result["mnemonic"] == "NOP"


class TestDisassembleRange:
    """L1/L2 gates for disassemble_range (slice 5, row 10 -- work order 05-2)."""

    @staticmethod
    def test_happy_path_returns_instructions_created(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """disassemble_range must emit DisassembleCommand and report the instruction delta.

        Falsifiable: a fake "declare success without doing anything"
        regression that never calls DisassembleCommand would fail the
        containment assertion immediately.
        """
        fake.eval_response = {"applied": True, "instructions_created": 3}
        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.disassemble_range(_TEST_ADDR, _TEST_ADDR2)),
        )
        assert result == {
            "start": hex(_TEST_ADDR),
            "end": hex(_TEST_ADDR2),
            "instructions_created": 3,
            "success": True,
        }
        assert "DisassembleCommand" in fake.exec_calls[0]

    @staticmethod
    def test_command_rejected_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """disassemble_range must raise ToolError when Ghidra rejects the command.

        Falsifiable: dropping the applied-guard would silently report
        success instead of raising.
        """
        fake.eval_response = {"applied": False, "instructions_created": 0}
        with pytest.raises(ToolError):
            run_async(connected_bridge.disassemble_range(_TEST_ADDR, _TEST_ADDR2))

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.disassemble_range must dispatch via ToolRegistry.

        Falsifiable: a missing or misnamed ToolFunction entry would
        raise ToolError here.
        """
        fake.eval_response = {"applied": True, "instructions_created": 1}
        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.disassemble_range",
                    {"start_address": _TEST_ADDR, "end_address": _TEST_ADDR2},
                ),
            ),
        )
        assert result["success"] is True


class TestClearCodeBytes:
    """L1/L2 gates for clear_code_bytes (slice 5, row 10 -- work order 05-2)."""

    @staticmethod
    def test_happy_path_emits_clear_code_units(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """clear_code_bytes must emit Listing.clearCodeUnits over the requested range.

        Falsifiable: swapping the mutating call for a different (or
        no-op) Ghidra API call would fail the containment assertion.
        """
        fake.eval_response = {"had_code": True, "cleared": True}
        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.clear_code_bytes(_TEST_ADDR, _TEST_ADDR2)),
        )
        assert result == {"start": hex(_TEST_ADDR), "end": hex(_TEST_ADDR2), "success": True}
        assert "clearCodeUnits" in fake.exec_calls[0]

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.clear_code_bytes must dispatch via ToolRegistry.

        Falsifiable: a missing or misnamed ToolFunction entry would
        raise ToolError here.
        """
        fake.eval_response = {"had_code": False, "cleared": True}
        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.clear_code_bytes",
                    {"start_address": _TEST_ADDR, "end_address": _TEST_ADDR2},
                ),
            ),
        )
        assert result["success"] is True


class TestSetRegisterValue:
    """L1/L2 gates for set_register_value (slice 5, row 11 -- work order 05-3)."""

    @staticmethod
    def test_happy_path_verifies_readback(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """set_register_value must emit setRegisterValue and verify the write via readback.

        Falsifiable: swapping the mutating call for the read-only
        getRegisterValue would fail the containment assertion.
        """
        fake.set_eval_responder(
            lambda expr: {"set": True, "reason": None} if "startTransaction" in expr or "setRegisterValue" in expr else 0x1,
        )
        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.set_register_value(_TEST_ADDR, _TEST_ADDR2, "TMode", 1)),
        )
        assert result == {
            "start": hex(_TEST_ADDR),
            "end": hex(_TEST_ADDR2),
            "register": "TMode",
            "value": 1,
            "success": True,
        }
        assert "setRegisterValue" in fake.exec_calls[0]

    @staticmethod
    def test_readback_mismatch_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """set_register_value must raise ToolError when the readback does not match.

        Falsifiable: removing the post-write verification step would
        let a silently-rejected write report success=True instead.
        """
        fake.set_eval_responder(lambda expr: 0 if "getUnsignedValue" in expr or "getRegisterValue" in expr else {"set": True})
        with pytest.raises(ToolError, match="verification failed"):
            run_async(connected_bridge.set_register_value(_TEST_ADDR, _TEST_ADDR2, "TMode", 1))

    @staticmethod
    def test_unknown_register_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """set_register_value must raise ToolError for an unknown register name, never silently no-op."""
        fake.eval_response = {"set": False, "reason": "unknown_register"}
        with pytest.raises(ToolError):
            run_async(connected_bridge.set_register_value(_TEST_ADDR, _TEST_ADDR2, "NOSUCHREG", 1))

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.set_register_value must dispatch via ToolRegistry.

        Falsifiable: a missing or misnamed ToolFunction entry would
        raise ToolError here.
        """
        fake.set_eval_responder(lambda expr: {"set": True} if "setRegisterValue" in expr else 1)
        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.set_register_value",
                    {"start_address": _TEST_ADDR, "end_address": _TEST_ADDR2, "register": "TMode", "value": 1},
                ),
            ),
        )
        assert result["success"] is True


class TestRenameFunctionVariable:
    """L1/L2 gates for rename_function_variable (slice 5, row 12 -- work order 05-4)."""

    @staticmethod
    def test_happy_path_emits_set_name_not_set_data_type(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """rename_function_variable must emit Variable.setName, never setDataType.

        Falsifiable: this is precisely the rename-vs-retype confusion
        this item exists to resolve. If the implementation were
        accidentally copied from set_function_variable_type without
        changing the mutating call, the second assertion fails
        immediately.
        """
        fake.eval_response = True
        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.rename_function_variable(_TEST_ADDR, "oldVar", "newVar")),
        )
        assert result == {"var_name": "oldVar", "new_name": "newVar", "success": True}
        assert "setName(" in fake.exec_calls[0]
        assert "setDataType(" not in fake.exec_calls[0]

    @staticmethod
    def test_variable_not_found_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """rename_function_variable must raise ToolError when the named variable does not exist."""
        fake.eval_response = False
        with pytest.raises(ToolError, match="not found"):
            run_async(connected_bridge.rename_function_variable(_TEST_ADDR, "ghostVar", "newVar"))

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.rename_function_variable must dispatch via ToolRegistry.

        Falsifiable: a missing or misnamed ToolFunction entry would
        raise ToolError here.
        """
        fake.eval_response = True
        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.rename_function_variable",
                    {"func_address": _TEST_ADDR, "var_name": "oldVar", "new_name": "newVar"},
                ),
            ),
        )
        assert result["success"] is True


class TestSetFunctionFlags:
    """L1/L2 gates for set_function_flags (slice 5, row 13 -- work order 05-5)."""

    @staticmethod
    def test_happy_path_sets_all_three_flags(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """set_function_flags must emit setNoReturn(True) and only that call when only no_return is passed.

        Falsifiable: if every flag setter were always emitted
        regardless of which arguments were passed, the negative
        containment assertions for setVarArgs/setInline would fail.
        """
        fake.eval_response = {
            "name": "ExitWrapper",
            "address": _TEST_ADDR,
            "no_return": True,
            "var_args": False,
            "is_inline": False,
        }
        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.set_function_flags(_TEST_ADDR, no_return=True)),
        )
        assert result["no_return"] is True
        assert "setNoReturn(True)" in fake.exec_calls[0]
        assert "setVarArgs(" not in fake.exec_calls[0]
        assert "setInline(" not in fake.exec_calls[0]

    @staticmethod
    def test_false_is_not_treated_as_unset(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """A caller passing var_args=False must still emit setVarArgs(False), not skip it.

        Falsifiable: an `if var_args:` (truthiness) check instead of
        `if var_args is not None:` would drop this call entirely for a
        False value, silently leaving the existing flag untouched.
        """
        fake.eval_response = {"name": "f", "address": _TEST_ADDR, "no_return": False, "var_args": False, "is_inline": False}
        run_async(connected_bridge.set_function_flags(_TEST_ADDR, var_args=False))
        assert "setVarArgs(False)" in fake.exec_calls[0]

    @staticmethod
    def test_function_not_found_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """set_function_flags must raise ToolError when no function exists at the address."""
        fake.eval_response = None
        with pytest.raises(ToolError, match="No function at"):
            run_async(connected_bridge.set_function_flags(_TEST_ADDR, is_inline=True))

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.set_function_flags must dispatch via ToolRegistry.

        Falsifiable: a missing or misnamed ToolFunction entry would
        raise ToolError here.
        """
        fake.eval_response = {"name": "f", "address": _TEST_ADDR, "no_return": True, "var_args": False, "is_inline": False}
        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.set_function_flags",
                    {"address": _TEST_ADDR, "no_return": True},
                ),
            ),
        )
        assert result["no_return"] is True


class TestFunctionTags:
    """L1/L2 gates for create_function_tag / set_function_tags / get_function_tags (slice 5, work order 05-6)."""

    @staticmethod
    def test_create_function_tag_happy_path(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """create_function_tag must emit createFunctionTag and echo back the requested name/comment.

        Falsifiable: reverting to a MISSING implementation would raise
        AttributeError; dropping the ``createFunctionTag`` call from the
        emitted script would fail the containment assertion.
        """
        fake.eval_response = {"name": "Deprecated", "comment": "legacy code", "success": True}
        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.create_function_tag("Deprecated", "legacy code")),
        )
        assert result == {"name": "Deprecated", "comment": "legacy code", "success": True}
        assert "createFunctionTag" in fake.exec_calls[0]

    @staticmethod
    def test_set_function_tags_unknown_operation_raises_before_dispatch(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """set_function_tags must raise ToolError for an unrecognized operation before any RPC call.

        Falsifiable: if the ``valid_operations`` guard were removed, this
        would dispatch an RPC call instead of raising, leaving
        ``fake.exec_calls`` non-empty.
        """
        with pytest.raises(ToolError, match="Unknown operation"):
            run_async(connected_bridge.set_function_tags(_TEST_ADDR, "Deprecated", "toggle"))
        assert len(fake.exec_calls) == 0

    @staticmethod
    def test_set_function_tags_add_emits_add_tag(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """operation='add' must emit Function.addTag and never Function.removeTag.

        Falsifiable: if both branches were always emitted in one script
        regardless of ``operation``, the negative containment assertion
        (``"removeTag(" not in ...``) would fail.
        """
        fake.eval_response = {"found": True, "applied": True}
        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.set_function_tags(_TEST_ADDR, "Deprecated", "add")),
        )
        assert result["success"] is True
        assert "addTag(" in fake.exec_calls[0]
        assert "removeTag(" not in fake.exec_calls[0]

    @staticmethod
    def test_set_function_tags_remove_emits_remove_tag(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """operation='remove' must emit Function.removeTag and never Function.addTag.

        Falsifiable: companion to the 'add' case above -- if
        ``set_function_tags`` were (incorrectly) changed to always call
        ``addTag`` regardless of ``operation``, this is the test that
        catches it (the 'add'-case test alone cannot, since a broken
        always-addTag implementation never emits 'removeTag(' for either
        operation).
        """
        fake.eval_response = {"found": True, "applied": True}
        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.set_function_tags(_TEST_ADDR, "Deprecated", "remove")),
        )
        assert result["success"] is True
        assert "removeTag(" in fake.exec_calls[0]
        assert "addTag(" not in fake.exec_calls[0]

    @staticmethod
    def test_set_function_tags_function_not_found_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """set_function_tags must raise ToolError when no function exists at the address.

        Falsifiable: if the ``found`` guard were removed, this would
        report success despite no function existing at the address.
        """
        fake.eval_response = {"found": False, "applied": False}
        with pytest.raises(ToolError, match="Function not found"):
            run_async(connected_bridge.set_function_tags(_TEST_ADDR, "Deprecated", "remove"))

    @staticmethod
    def test_get_function_tags_all_when_address_omitted(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """get_function_tags() with no address must emit getAllFunctionTags and return every tag.

        Falsifiable: if the ``addr_literal is None`` branch were removed,
        this would fail to emit ``getAllFunctionTags`` for an
        address-less call.
        """
        fake.eval_response = [{"name": "Deprecated", "comment": ""}, {"name": "Reviewed", "comment": ""}]
        result = cast("list[dict[str, Any]]", run_async(connected_bridge.get_function_tags()))
        assert len(result) == 2
        assert "getAllFunctionTags" in fake.exec_calls[0]

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.set_function_tags must dispatch via ToolRegistry.

        Falsifiable: a missing or misnamed ToolFunction entry would
        raise ToolError here.
        """
        fake.eval_response = {"found": True, "applied": True}
        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.set_function_tags",
                    {"address": _TEST_ADDR, "tag_name": "Deprecated", "operation": "add"},
                ),
            ),
        )
        assert result["success"] is True


class TestPromoteSymbolToPrimary:
    """L1/L2 gates for promote_symbol_to_primary (slice 5, work order 05-7)."""

    @staticmethod
    def test_happy_path_promotes_non_primary_symbol(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """promote_symbol_to_primary must emit Symbol.setPrimary() and never re-create via createLabel.

        Falsifiable: if the implementation re-created the label (via
        ``createLabel``) with ``primary=True`` instead of looking up and
        promoting the already-existing symbol, the negative containment
        assertion (``"createLabel" not in ...``) would fail.
        """
        fake.eval_response = {"promoted": True, "already_primary": False}
        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.promote_symbol_to_primary(_TEST_ADDR, "secondary_label")),
        )
        assert result == {
            "address": hex(_TEST_ADDR),
            "name": "secondary_label",
            "already_primary": False,
            "success": True,
        }
        assert "setPrimary()" in fake.exec_calls[0]
        assert "createLabel" not in fake.exec_calls[0]

    @staticmethod
    def test_already_primary_reports_true_without_error(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """An already-primary symbol must report already_primary=True without raising.

        Falsifiable: if the ``already_primary`` short-circuit were
        removed and ``setPrimary()`` called unconditionally, this test
        would still pass by coincidence -- but it documents the intended
        telemetry distinction between 'already primary' and 'just
        promoted'.
        """
        fake.eval_response = {"promoted": True, "already_primary": True}
        result = cast(
            "dict[str, Any]",
            run_async(connected_bridge.promote_symbol_to_primary(_TEST_ADDR, "already_primary_label")),
        )
        assert result["already_primary"] is True
        assert result["success"] is True

    @staticmethod
    def test_symbol_not_found_raises(
        connected_bridge: GhidraBridge,
        fake: FakeGhidraBridge,
    ) -> None:
        """promote_symbol_to_primary must raise ToolError when no symbol with that name exists.

        Falsifiable: if the ``promoted`` not-found guard were removed,
        this would return a success dict instead of raising.
        """
        fake.eval_response = {"promoted": False, "already_primary": False}
        with pytest.raises(ToolError, match="No symbol named"):
            run_async(connected_bridge.promote_symbol_to_primary(_TEST_ADDR, "ghost_label"))

    @staticmethod
    def test_dispatchable_via_registry(registry: ToolRegistry, fake: FakeGhidraBridge) -> None:
        """ghidra.promote_symbol_to_primary must dispatch via ToolRegistry.

        Falsifiable: a missing or misnamed ToolFunction entry would
        raise ToolError here.
        """
        fake.eval_response = {"promoted": True, "already_primary": False}
        result = cast(
            "dict[str, Any]",
            run_async(
                registry.execute_tool_call(
                    "ghidra",
                    "ghidra.promote_symbol_to_primary",
                    {"address": _TEST_ADDR, "name": "secondary_label"},
                ),
            ),
        )
        assert result["success"] is True
