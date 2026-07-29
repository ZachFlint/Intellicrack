# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the S15 Ghidra panel mutator missing-transaction defects.

Five user-facing ``GhidraBridge`` mutators built their remote Jython script
without wrapping the actual program write in ``currentProgram.startTransaction``
/``endTransaction``, so each raised ``NoTransactionException('Transaction has
not been started')`` the instant a real (non-headless-analysis-only) Ghidra
program object enforced its transaction invariant:

* S15-D09 -- :meth:`GhidraBridge.add_comment`
* S15-D10 -- :meth:`GhidraBridge.set_label`
* S15-D11 -- :meth:`GhidraBridge.create_bookmark`
* S15-D14 -- :meth:`GhidraBridge.define_structure`
* S15-D15 -- :meth:`GhidraBridge.apply_structure_at`

Their siblings elsewhere in the bridge (``remove_label``, ``add_thunk``,
``add_bookmark``, ...) already wrap their mutating call in
``tx_id = currentProgram.startTransaction(...)`` / ``finally:
currentProgram.endTransaction(tx_id, ...)`` and work correctly; the fix mirrors
that exact pattern for the five methods above.

These gates drive a real headless Ghidra 12.x instance through PyGhidra
against a real PE (the running interpreter's own ``python.exe``/``pythonw.exe``)
-- no ``ghidra_bridge`` RPC client is mocked and no Ghidra API call is
stubbed. Each test performs the mutation through the public bridge method and
then independently reads the result back through the corresponding public
``get_*`` accessor, so the gate is falsifiable purely by reverting the
transaction wrapper in ``src/intellicrack/bridges/ghidra.py``: without it the
mutating call raises ``ToolError`` (wrapping ``NoTransactionException``)
before any readback happens.

Host-native only: the Docker sandbox has no JVM/Ghidra install, so this
module skips itself (via ``pytestmark``) unless ``ghidra_bridge``, ``jpype``
and ``pyghidra`` are importable *and* a real Ghidra installation is named by
``GHIDRA_INSTALL_DIR`` or ``GHIDRA_HOME``. Run explicitly on a host with
Ghidra installed via::

    pixi run pytest tests/bridges/test_ghidra_s15_tx_mutators_real.py -m host_native -v

or as part of the orchestrated host-native pass via
``python scripts/host_native_tests.py``.
"""

from __future__ import annotations

import importlib.util
import os
import socket
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
import pytest_asyncio

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import DataTypeInfo


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


def _resolve_ghidra_install() -> Path | None:
    """Resolve a real Ghidra installation directory from the environment.

    Checks ``GHIDRA_INSTALL_DIR`` then ``GHIDRA_HOME`` (the same variables
    :data:`intellicrack.bridges.ghidra._HEADLESS_ENV_BLOCKLIST` scrubs from
    the spawned headless process, since the launcher receives the install
    path explicitly rather than via environment) for a directory that
    actually contains the platform's ``support/analyzeHeadless`` launcher.

    Returns:
        Path | None: The Ghidra install root when a real installation is
        found, otherwise ``None``.
    """
    for var in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        raw = os.environ.get(var, "").strip()
        if not raw:
            continue
        root = Path(raw)
        launcher_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        launcher = root / "support" / launcher_name
        if launcher.is_file():
            return root
    return None


_GHIDRA_INSTALL: Final[Path | None] = _resolve_ghidra_install()
_PACKAGES_AVAILABLE: Final[bool] = (
    importlib.util.find_spec("ghidra_bridge") is not None
    and importlib.util.find_spec("jpype") is not None
    and importlib.util.find_spec("pyghidra") is not None
)
_SKIP_REASON: Final[str] = (
    ""
    if _PACKAGES_AVAILABLE and _GHIDRA_INSTALL is not None
    else (
        "Requires the ghidra_bridge/jpype/pyghidra packages and a real Ghidra "
        "install named by GHIDRA_INSTALL_DIR or GHIDRA_HOME (host-native only)"
    )
)

pytestmark = [
    pytest.mark.host_native,
    pytest.mark.skipif(bool(_SKIP_REASON), reason=_SKIP_REASON),
    pytest.mark.asyncio,
]

# The running interpreter's own executable is a real, always-present PE
# usable as an analysis target without shipping a binary fixture, matching
# the pattern used for the real x64dbg lifecycle gates.
_TARGET_BINARY: Final[Path] = Path(sys.executable)

_LABEL_ADDR_OFFSET: Final[int] = 0x10
_BOOKMARK_ADDR_OFFSET: Final[int] = 0x20
_APPLY_STRUCT_ADDR_OFFSET: Final[int] = 0x40

_COMMENT_TEXT: Final[str] = "INTELLICRACK_S15_D09_TX_AUDIT"
_LABEL_NAME: Final[str] = "INTELLICRACK_S15_D10_TX_AUDIT"
_BOOKMARK_CATEGORY: Final[str] = "IntellicrackS15D11"
_BOOKMARK_COMMENT: Final[str] = "INTELLICRACK_S15_D11_TX_AUDIT"
_STRUCT_NAME: Final[str] = "IntellicrackS15D14AuditStruct"
_APPLY_STRUCT_NAME: Final[str] = "IntellicrackS15D15AuditStruct"
_STRUCT_FIELDS: Final[list[dict[str, object]]] = [{"name": "audit_field", "type": "dword", "size": 4}]


def _reserve_free_port() -> int:
    """Reserve an ephemeral loopback TCP port and release it immediately.

    Returns:
        int: A port number free at the moment of the call, for the headless
        bridge server to bind.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


@pytest_asyncio.fixture(scope="module")
async def real_bridge(tmp_path_factory: pytest.TempPathFactory) -> AsyncGenerator[GhidraBridge]:
    """Boot a real headless Ghidra bridge and load a real PE for the module.

    Launches ``analyzeHeadless`` through PyGhidra against the genuine Ghidra
    installation resolved by :func:`_resolve_ghidra_install`, waits for the
    bridge RPC server to come up, and imports the current interpreter's own
    executable as the target program. Shared across every test in this
    module so the (slow, cold-JVM) boot happens once; each test mutates a
    distinct address or data type name so the tests do not interfere with
    each other. Shuts the headless process down once the module is done.

    Args:
        tmp_path_factory: Pytest factory for a module-scoped temp directory.

    Yields:
        GhidraBridge: A connected bridge with a real program loaded.
    """
    assert _GHIDRA_INSTALL is not None
    bridge = GhidraBridge()
    bridge.set_port(_reserve_free_port())
    bridge.ghidra_path = _GHIDRA_INSTALL
    project_dir = tmp_path_factory.mktemp("ghidra_s15_project")
    await bridge.start_headless(project_dir, "intellicrack_s15_tx")
    _ = await bridge.load_binary(_TARGET_BINARY)
    yield bridge
    await bridge.shutdown()


@pytest_asyncio.fixture(scope="module")
async def entry_point(real_bridge: GhidraBridge) -> int:
    """Resolve the loaded program's entry point address.

    Reads the entry point of the program already imported by
    :func:`real_bridge` through the public ``execute_script`` accessor
    instead of calling :meth:`GhidraBridge.load_binary` again -- a second
    import against the same project would create (or address) a distinct
    program object and is not what the mutator gates below want to probe.

    Args:
        real_bridge: Module-scoped bridge fixture with a real program loaded.

    Returns:
        int: The entry point address of the currently loaded program,
        guaranteed to sit inside a real, mapped memory block.
    """
    raw = await real_bridge.execute_script(
        "entry_points = currentProgram.getSymbolTable().getExternalEntryPointIterator()\n"
        "entry_points.next().getOffset() if entry_points.hasNext() else 0",
    )
    resolved = int(raw)
    assert resolved != 0
    return resolved


async def test_add_comment_persists_under_transaction(
    real_bridge: GhidraBridge,
    entry_point: int,
) -> None:
    """S15-D09: add_comment must commit its ``setComment`` under a transaction.

    Before the fix, ``cu.setComment(...)`` ran with no active transaction and
    Ghidra raised ``NoTransactionException``, which ``add_comment`` wraps as a
    ``ToolError`` -- so this call itself already falsifies a reverted fix.
    The follow-up readback re-fetches the code unit at ``entry_point``
    through a fresh ``execute_script`` call (a channel independent of
    ``add_comment``'s own internal verification) and confirms the comment is
    genuinely durable in the program.

    Note: the readback deliberately does not use the public
    ``get_comments`` accessor. That method builds its remote script around
    ``Listing.getCodeUnits(Address, Address, boolean)``, an overload that
    does not exist on the real Ghidra ``ListingDB`` (confirmed against this
    host's Ghidra install; only the ``(Address, boolean)``,
    ``(AddressSetView, boolean)`` and ``(boolean)`` overloads exist) and so
    always raises a ``ToolError`` wrapping a Java ``TypeError`` -- a
    separate, pre-existing defect outside this fix's scope.

    Args:
        real_bridge: Module-scoped bridge fixture with a real program loaded.
        entry_point: The loaded program's entry point address.
    """
    ok = await real_bridge.add_comment(entry_point, _COMMENT_TEXT, "EOL")
    assert ok is True

    readback = await real_bridge.execute_script(
        "from ghidra.program.model.listing import CodeUnit\n"
        f"currentProgram.getListing().getCodeUnitAt(toAddr({entry_point})).getComment(CodeUnit.EOL_COMMENT)",
    )
    assert readback == _COMMENT_TEXT


async def test_set_label_persists_under_transaction(
    real_bridge: GhidraBridge,
    entry_point: int,
) -> None:
    """S15-D10: set_label must commit its ``createLabel`` under a transaction.

    Before the fix, ``st.createLabel(...)`` ran with no active transaction
    and raised ``NoTransactionException``, surfaced as ``ToolError``.

    Args:
        real_bridge: Module-scoped bridge fixture with a real program loaded.
        entry_point: The loaded program's entry point address.
    """
    label_addr = entry_point + _LABEL_ADDR_OFFSET

    result = await real_bridge.set_label(label_addr, _LABEL_NAME)
    assert result["success"] is True

    labels = await real_bridge.get_labels(label_addr, radius=1)
    assert any(label.get("name") == _LABEL_NAME and label.get("address") == label_addr for label in labels)


async def test_create_bookmark_persists_under_transaction(
    real_bridge: GhidraBridge,
    entry_point: int,
) -> None:
    """S15-D11: create_bookmark must commit its ``setBookmark`` under a transaction.

    Before the fix, ``bm.setBookmark(...)`` ran with no active transaction
    and raised ``NoTransactionException``, surfaced as ``ToolError``.

    Args:
        real_bridge: Module-scoped bridge fixture with a real program loaded.
        entry_point: The loaded program's entry point address.
    """
    bookmark_addr = entry_point + _BOOKMARK_ADDR_OFFSET

    result = await real_bridge.create_bookmark(bookmark_addr, _BOOKMARK_CATEGORY, _BOOKMARK_COMMENT)
    assert result["success"] is True

    bookmarks = await real_bridge.get_bookmarks(category=_BOOKMARK_CATEGORY)
    assert any(b.get("address") == bookmark_addr and b.get("comment") == _BOOKMARK_COMMENT for b in bookmarks)


async def test_define_structure_persists_under_transaction(real_bridge: GhidraBridge) -> None:
    """S15-D14: define_structure must commit its ``addDataType`` under a transaction.

    Before the fix, ``dtm.addDataType(struct, None)`` ran with no active
    transaction and raised ``NoTransactionException``, surfaced as
    ``ToolError``.

    Args:
        real_bridge: Module-scoped bridge fixture with a real program loaded.
    """
    result = await real_bridge.define_structure(_STRUCT_NAME, _STRUCT_FIELDS)
    assert result.get("name") == _STRUCT_NAME
    assert result.get("field_count") == len(_STRUCT_FIELDS)

    structures = await real_bridge.get_structures(_STRUCT_NAME)
    assert any(s.get("name") == _STRUCT_NAME for s in structures)


async def test_apply_structure_at_persists_under_transaction(
    real_bridge: GhidraBridge,
    entry_point: int,
) -> None:
    """S15-D15: apply_structure_at must commit its clear+createData under a transaction.

    Before the fix, ``listing.clearCodeUnits(...)``/``listing.createData(...)``
    ran with no active transaction and raised ``NoTransactionException``,
    surfaced as ``ToolError``. Defines its own structure (independent of the
    D14 gate) and applies it at an address distinct from every other test in
    this module.

    Args:
        real_bridge: Module-scoped bridge fixture with a real program loaded.
        entry_point: The loaded program's entry point address.
    """
    _ = await real_bridge.define_structure(_APPLY_STRUCT_NAME, _STRUCT_FIELDS)
    apply_addr = entry_point + _APPLY_STRUCT_ADDR_OFFSET

    result = await real_bridge.apply_structure_at(apply_addr, _APPLY_STRUCT_NAME)
    assert result["success"] is True

    data_type = await real_bridge.get_data_type(apply_addr)
    assert isinstance(data_type, DataTypeInfo)
    assert data_type.name == _APPLY_STRUCT_NAME
