# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for finishing the Ghidra bridge PyGhidra/CPython migration.

Ghidra 11.3+/12.x removed the bundled Jython interpreter, so the bridge
drives ``analyzeHeadless`` through PyGhidra and every remote-exec payload
runs under real CPython/jpype rather than Jython. Several remote payloads
still used Jython-only idioms or were missing a Ghidra transaction, so they
either ``ImportError``/``NameError`` immediately under CPython or raised
``NoTransactionException`` the instant a mutating call actually ran against a
real program:

* D13 -- :meth:`GhidraBridge.read_bytes`, :meth:`GhidraBridge.write_bytes`,
  and the masked (hex/wildcard) path of :meth:`GhidraBridge.search_bytes`
  built their Java ``byte[]`` buffers with ``from jarray import array,
  zeros`` -- a Jython-only module that does not exist under CPython. Fixed by
  allocating with ``jpype.JArray(jpype.JByte)``.
* D14 -- Six mutators (:meth:`GhidraBridge.set_data_type`,
  :meth:`GhidraBridge.edit_function_signature`,
  :meth:`GhidraBridge.set_function_variable_type`,
  :meth:`GhidraBridge.define_structure`, :meth:`GhidraBridge.create_data_type`,
  :meth:`GhidraBridge.create_data`) imported
  ``ghidra.app.util.parser.DataTypeParser``, a Swing-backed class that cannot
  load in a headless CPython process. Fixed by resolving type names against
  the program's ``DataTypeManager``/``BuiltInDataTypeManager`` first, then
  falling back to ``ghidra.app.util.cparser.C.CParser`` for compound C
  declarations.
* D15 -- :meth:`GhidraBridge.create_data_type` called
  ``DataTypeManager.addDataType`` (every one of its four ``type_kind``
  branches) with no surrounding Ghidra transaction. Fixed by wrapping the
  whole branch dispatch in a single ``startTransaction``/``endTransaction``
  pair, mirroring the idiom already used by ``set_data_type``.
* D18 -- :meth:`GhidraBridge.get_imports` called
  ``sym.getParentSymbol().getName()`` unconditionally; an external symbol
  with no parent symbol raised an ``AttributeError``
  (``'NoneType' object has no attribute 'getName'``) that aborted the whole
  call. Fixed by binding ``parent = sym.getParentSymbol()`` once and guarding
  both the parent and the symbol name against ``None``.

Every gate below drives a real, bundled headless Ghidra 12.x instance through
PyGhidra against a real target executable -- no ``ghidra_bridge`` RPC client
is mocked and no Ghidra API call is stubbed. Reverting any one of the fixes
above reproduces the exact failure mode the corresponding assertion checks
for, so each assertion is falsifiable purely by reverting
``src/intellicrack/bridges/ghidra.py``.

Host-native only: the Docker sandbox has no JVM/Ghidra install, so this
module skips itself (via ``pytestmark``) unless ``ghidra_bridge``, ``jpype``,
and ``pyghidra`` are importable, a real Ghidra installation is named by
``GHIDRA_INSTALL_DIR``/``GHIDRA_HOME``, and the committed S19 live-audit
target ``ida_lc.exe`` is present under the system temp directory. Run
explicitly on a host with Ghidra installed via::

    pixi run pytest tests/bridges/test_ghidra_cpython_migration.py -m host_native -v

or as part of the orchestrated host-native pass via
``python scripts/host_native_tests.py``.
"""

from __future__ import annotations

import importlib.util
import os
import socket
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pefile
import pytest
import pytest_asyncio

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


def _resolve_ghidra_install() -> Path | None:
    """Resolve a real Ghidra installation directory from the environment.

    Checks ``GHIDRA_INSTALL_DIR`` then ``GHIDRA_HOME`` for a directory that
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
# Committed S19 live-audit target: a real, licensed IDA component executable
# with a genuine import table and a sizeable .text section, staged under the
# system temp directory (never inside the repo -- see audit/S19_LIVE_AUDIT_FINDINGS.md).
_TARGET_BINARY: Final[Path] = Path(tempfile.gettempdir()) / "ic_audit_targets" / "ida_lc.exe"

_SKIP_REASON: Final[str] = (
    ""
    if _PACKAGES_AVAILABLE and _GHIDRA_INSTALL is not None and _TARGET_BINARY.is_file()
    else (
        "Requires the ghidra_bridge/jpype/pyghidra packages, a real Ghidra install named by "
        "GHIDRA_INSTALL_DIR or GHIDRA_HOME, and the S19 live-audit target "
        f"{_TARGET_BINARY} (host-native only)"
    )
)

pytestmark = [
    pytest.mark.host_native,
    pytest.mark.skipif(bool(_SKIP_REASON), reason=_SKIP_REASON),
    pytest.mark.asyncio,
]

_ENUM_CATEGORY: Final[str] = "/Intellicrack"
_ENUM_NAME: Final[str] = "AUDIT_ENUM01"
_ENUM_FIELDS: Final[list[dict[str, object]]] = [{"name": "AUDIT_MEMBER", "value": 1}]
_ENUM_SIZE_BYTES: Final[int] = 4

_EXPECTED_DEFAULT_PORT: Final[int] = 4768

_READ_PROBE_RVA: Final[int] = 0x1000
_READ_PROBE_LENGTH: Final[int] = 16
_SEARCH_PROBE_LENGTH: Final[int] = 6
_WRITE_PROBE_RVA: Final[int] = 0x2000
_WRITE_PROBE_LENGTH: Final[int] = 4
_WRITE_PROBE_MARKER: Final[str] = "DEADBEEF"
_DATA_TYPE_PROBE_RVA: Final[int] = 0x3000
_DWORD_SIZE_BYTES: Final[int] = 4


def _file_bytes_at_rva(target: Path, rva: int, length: int) -> bytes:
    """Read ``length`` bytes directly from ``target`` at the file offset mapped to ``rva``.

    Uses ``pefile`` as an independent oracle for the RVA-to-file-offset
    mapping (consulting the real PE section table) rather than assuming any
    fixed relationship between virtual and file offsets, so the comparison
    against Ghidra's own ``read_bytes`` is a genuine cross-check.

    Args:
        target: Real, on-disk PE file to read from.
        rva: Relative virtual address (offset from the image base) to map.
        length: Number of bytes to read at the mapped file offset.

    Returns:
        bytes: The raw bytes read from disk at the mapped file offset.
    """
    pe = pefile.PE(str(target), fast_load=True)
    try:
        file_offset = pe.get_offset_from_rva(rva)
    finally:
        pe.close()
    with target.open("rb") as handle:
        handle.seek(file_offset)
        return handle.read(length)


@pytest_asyncio.fixture(scope="module")
async def real_bridge(tmp_path_factory: pytest.TempPathFactory) -> AsyncGenerator[GhidraBridge]:
    """Boot a real headless Ghidra bridge, load, and fully analyze a real PE.

    Launches ``analyzeHeadless`` through PyGhidra against the genuine Ghidra
    installation resolved by :func:`_resolve_ghidra_install`, waits for the
    bridge RPC server to come up on the bridge's default port, imports the
    committed S19 live-audit target, and runs full auto-analysis so the
    function list and data-type/import surfaces this module exercises are
    genuinely populated (not just the raw import-time stubs).

    Deliberately does *not* override the RPC port: the bridge's default of
    ``GhidraBridge.DEFAULT_PORT`` (4768) is asserted directly by
    ``test_start_headless_binds_default_port_and_finds_functions`` below.

    Args:
        tmp_path_factory: Pytest factory for a module-scoped temp directory.

    Yields:
        GhidraBridge: A connected bridge with a real, fully analyzed program
        loaded.
    """
    assert _GHIDRA_INSTALL is not None
    bridge = GhidraBridge()
    bridge.ghidra_path = _GHIDRA_INSTALL
    project_dir = tmp_path_factory.mktemp("ghidra_cpython_migration_project")
    await bridge.start_headless(project_dir, "intellicrack_cpython_migration")
    _ = await bridge.load_binary(_TARGET_BINARY)
    await bridge.analyze()
    yield bridge
    await bridge.shutdown()


@pytest_asyncio.fixture(scope="module")
async def image_base(real_bridge: GhidraBridge) -> int:
    """Resolve the loaded program's image base address.

    Args:
        real_bridge: Module-scoped bridge fixture with a real program loaded.

    Returns:
        int: The program's image base, read through the public
        ``get_program_info`` accessor.
    """
    info = await real_bridge.get_program_info()
    base = int(info["image_base"])
    assert base != 0
    return base


async def test_start_headless_binds_default_port_and_finds_functions(
    real_bridge: GhidraBridge,
) -> None:
    """The headless bridge must bind 127.0.0.1:4768 and discover real functions.

    Pins the bridge's default RPC port (the port the "Start Headless" GUI
    control and every other caller assume without configuring one): the
    ``real_bridge`` fixture never calls ``set_port``, so a listener actually
    reachable at ``GhidraBridge.DEFAULT_PORT`` is independent evidence
    (a fresh loopback TCP connect, touching no bridge internals) that
    ``start_headless`` bound the default port rather than something else.
    This also guards against a silent hang: if the CPython postScript ever
    failed to start the bridge server (for example because a live Jython
    extension shadowed the CPython launch -- the D11 code guard's failure
    mode), the fixture's ``start_headless``/``load_binary``/``analyze`` calls
    would already have raised before this test ever ran. Reaching the final
    assertion also proves auto-analysis genuinely ran against a real
    program, since ``get_functions`` returning an empty list would mean
    analysis silently produced nothing.

    Args:
        real_bridge: Module-scoped bridge fixture with a real, analyzed
            program loaded.
    """
    assert GhidraBridge.DEFAULT_PORT == _EXPECTED_DEFAULT_PORT

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.settimeout(3.0)
        connect_result = probe.connect_ex(("127.0.0.1", GhidraBridge.DEFAULT_PORT))
    finally:
        probe.close()
    assert connect_result == 0, f"nothing reachable on 127.0.0.1:{GhidraBridge.DEFAULT_PORT} after start_headless"

    functions = await real_bridge.get_functions()
    assert len(functions) > 0, "get_functions() returned no functions after a full analyze() pass"


async def test_read_bytes_matches_file_on_disk(
    real_bridge: GhidraBridge,
    image_base: int,
) -> None:
    """D13: read_bytes must return the same bytes independently read from disk.

    Before the fix, ``read_bytes`` built its Ghidra ``byte[]`` buffer via
    ``from jarray import zeros``, which raises ``ImportError`` under CPython
    (``No module named 'jarray'``) before a single byte is ever read -- so
    this call itself already falsifies a reverted fix. The 16 bytes read
    through the bridge are cross-checked against the same file offset read
    independently from the executable on disk via :func:`_file_bytes_at_rva`
    (an oracle that never touches the bridge).

    Args:
        real_bridge: Module-scoped bridge fixture with a real program loaded.
        image_base: The loaded program's image base address.
    """
    addr = image_base + _READ_PROBE_RVA

    result = await real_bridge.read_bytes(addr, _READ_PROBE_LENGTH)
    read_via_bridge = bytes(result["bytes"])

    expected = _file_bytes_at_rva(_TARGET_BINARY, _READ_PROBE_RVA, _READ_PROBE_LENGTH)

    assert read_via_bridge == expected


async def test_write_bytes_round_trips_at_scratch_address(
    real_bridge: GhidraBridge,
    image_base: int,
) -> None:
    """D13: write_bytes must round-trip a patch and be restorable.

    Before the fix, ``write_bytes`` built its payload/readback buffers via
    ``from jarray import array, zeros``, which raises ``ImportError`` under
    CPython before the transaction is even opened -- so this call itself
    already falsifies a reverted fix. Captures the original bytes first (an
    independent ``read_bytes`` call), writes a distinctive marker, verifies
    the readback the bridge itself reports, re-reads independently, then
    restores the original bytes and confirms the restoration is durable.

    Args:
        real_bridge: Module-scoped bridge fixture with a real program loaded.
        image_base: The loaded program's image base address.
    """
    addr = image_base + _WRITE_PROBE_RVA

    original = await real_bridge.read_bytes(addr, _WRITE_PROBE_LENGTH)
    original_hex = original["hex"].replace(" ", "")

    write_result = await real_bridge.write_bytes(addr, _WRITE_PROBE_MARKER)
    assert write_result["verified"] is True
    assert write_result["success"] is True

    written_back = await real_bridge.read_bytes(addr, _WRITE_PROBE_LENGTH)
    assert written_back["hex"].replace(" ", "") == _WRITE_PROBE_MARKER

    restore_result = await real_bridge.write_bytes(addr, original_hex)
    assert restore_result["verified"] is True

    restored = await real_bridge.read_bytes(addr, _WRITE_PROBE_LENGTH)
    assert restored["hex"].replace(" ", "") == original_hex


async def test_search_bytes_masked_path_finds_known_pattern(
    real_bridge: GhidraBridge,
    image_base: int,
) -> None:
    """D13: the masked search_bytes path must locate a known byte pattern.

    Before the fix, the hex/wildcard branch of ``search_bytes`` built its
    Java byte/mask arrays via ``from jarray import array``, which raises
    ``ImportError`` under CPython before ``memory.findBytes`` is ever
    called -- so this call itself already falsifies a reverted fix. The
    pattern is derived from the real bytes already confirmed present at
    ``image_base + _READ_PROBE_RVA`` (via the independent disk read in
    :func:`_file_bytes_at_rva`), with one byte wildcarded, so the found
    address is verified against ground truth rather than an assumption.

    Args:
        real_bridge: Module-scoped bridge fixture with a real program loaded.
        image_base: The loaded program's image base address.
    """
    probe_addr = image_base + _READ_PROBE_RVA
    known_bytes = _file_bytes_at_rva(_TARGET_BINARY, _READ_PROBE_RVA, _SEARCH_PROBE_LENGTH)

    tokens = [f"{b:02X}" for b in known_bytes]
    tokens[2] = "??"
    hex_pattern = " ".join(tokens)

    addresses = await real_bridge.search_bytes(hex_pattern=hex_pattern)

    assert probe_addr in addresses


async def test_set_data_type_dword_round_trips(
    real_bridge: GhidraBridge,
    image_base: int,
) -> None:
    """D14: set_data_type must resolve "dword" headless and get_data_type must report it back.

    Before the fix, ``set_data_type`` imported
    ``ghidra.app.util.parser.DataTypeParser``, which raises ``ImportError``
    under headless CPython (it pulls in Swing) -- so this call itself
    already falsifies a reverted fix. Confirms the resolved type name
    contains "dword" and reports a 4-byte length, both read back through the
    independent ``get_data_type`` accessor.

    Args:
        real_bridge: Module-scoped bridge fixture with a real program loaded.
        image_base: The loaded program's image base address.
    """
    addr = image_base + _DATA_TYPE_PROBE_RVA

    applied = await real_bridge.set_data_type(addr, "dword")
    assert applied is True

    data_type = await real_bridge.get_data_type(addr)
    assert data_type is not None
    assert "dword" in data_type.name.lower()
    assert data_type.size == _DWORD_SIZE_BYTES


async def test_create_data_type_enum_is_retrievable_via_data_type_manager(
    real_bridge: GhidraBridge,
) -> None:
    """D14/D15: create_data_type(enum) must resolve headless and commit under a transaction.

    Before the D15 fix, every ``type_kind`` branch of ``create_data_type``
    (including "enum", which never even touches ``DataTypeParser``) called
    ``DataTypeManager.addDataType`` with no surrounding
    ``startTransaction``/``endTransaction`` pair, so Ghidra raised
    ``NoTransactionException`` the instant a real program enforced its
    transaction invariant -- so this call itself already falsifies a
    reverted D15 fix. The readback is independent of
    ``create_data_type``'s own success flag: it re-queries the program's
    ``DataTypeManager`` directly by category path through
    ``execute_script``, proving the enum genuinely persisted rather than
    trusting the mutator's own report.

    Args:
        real_bridge: Module-scoped bridge fixture with a real program loaded.
    """
    result = await real_bridge.create_data_type(_ENUM_CATEGORY, _ENUM_NAME, "enum", _ENUM_FIELDS)
    assert result["success"] is True
    assert result["name"] == _ENUM_NAME

    full_path = f"{_ENUM_CATEGORY}/{_ENUM_NAME}"
    name_readback = await real_bridge.execute_script(
        f"dt = currentProgram.getDataTypeManager().getDataType({full_path!r})\ndt.getName() if dt is not None else None",
    )
    assert name_readback == _ENUM_NAME

    length_readback = await real_bridge.execute_script(
        f"dt = currentProgram.getDataTypeManager().getDataType({full_path!r})\ndt.getLength() if dt is not None else -1",
    )
    assert length_readback == str(_ENUM_SIZE_BYTES)


async def test_get_imports_returns_nonempty_without_none_type_error(
    real_bridge: GhidraBridge,
) -> None:
    """D18: get_imports must return real imports without raising on a parentless symbol.

    Before the fix, ``get_imports`` called ``sym.getParentSymbol().getName()``
    unconditionally; a real PE's external symbol table routinely contains at
    least one symbol with no parent library symbol, which raised
    ``'NoneType' object has no attribute 'getName'`` and aborted the entire
    call -- so this call itself already falsifies a reverted fix. On a real,
    fully analyzed PE the import table always includes genuine
    KERNEL32/api-ms-* style imports, so a non-empty result also confirms
    real import data was returned, not a masked empty fallback.

    Args:
        real_bridge: Module-scoped bridge fixture with a real, analyzed
            program loaded.
    """
    try:
        imports = await real_bridge.get_imports()
    except ToolError as exc:
        pytest.fail(f"get_imports() raised instead of returning import data: {exc}")

    assert len(imports) > 0, "get_imports() returned no imports for a real, analyzed PE"
    assert all(isinstance(entry.dll, str) for entry in imports)
    assert all(isinstance(entry.function, str) and entry.function for entry in imports)
