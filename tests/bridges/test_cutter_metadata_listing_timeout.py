# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gate for the Cutter heavy-listing command-timeout fix.

The whole-binary listing scans exposed by the bridge -- ROP gadget search
(``/Rj``), vtable recovery (``avj``), syscall resolution (``asj``), and the
type/struct enumerations (``tj``/``tsj``) -- used to run through ``_cmd_json``
with no ``command_timeout``, so they inherited the bare 5 s
:data:`intellicrack.bridges.cutter.R2_COMMAND_TIMEOUT`. On any real-world
binary these scans routinely need longer than 5 s, so the panel's best-effort
tab auto-refresh made them time out. Worse, a timed-out ``_r2_cmd`` abandons
its ``asyncio.to_thread`` worker without being able to stop the underlying OS
thread, which keeps reading/writing the single analysis pipe and corrupts the
commands that follow (the cascade of ``r2_command_timeout`` warnings and
``rizin_json_unrecoverable`` parse failures observed in the field). The fix
gives these heavy listings a dedicated :data:`_METADATA_LISTING_TIMEOUT`,
mirroring the existing ``pdg`` (``_PDG_DECOMPILE_TIMEOUT``) precedent, so they
complete instead of spuriously timing out.

These gates drive the real bridge methods and the real ``_r2_cmd`` /
``_cmd_json`` timeout machinery against a genuine slow-I/O pipe double (a real
object whose blocking ``cmd`` sleeps like a heavy rizin scan). The module
default is monkeypatched down to a tiny value; a fixed bridge lets the heavy
listing outlive that tiny default because it passes the larger dedicated
timeout, while an ordinary command still dies against the default. Reverting
the ``command_timeout=_METADATA_LISTING_TIMEOUT`` plumbing makes every heavy
listing inherit the tiny default and time out, turning these gates RED.
"""

from __future__ import annotations

import time
from typing import Any, Final, cast

import pytest

from intellicrack.bridges import cutter as cutter_mod
from intellicrack.bridges.cutter import CutterBridge
from intellicrack.core.types import ToolError


pytestmark = pytest.mark.asyncio

_TINY_DEFAULT: Final[float] = 0.05
_PIPE_DELAY: Final[float] = 0.4

_HEAVY_CASES: Final[list[tuple[str, str]]] = [
    ("search_rop_gadgets", '[{"opcodes":[{"offset":4096,"opcode":"ret"}],"size":1,"retaddr":4096}]'),
    ("get_vtables", '[{"offset":8192,"methods":[],"classname":"Cls"}]'),
    ("get_syscalls", '[{"name":"read","swi":0}]'),
    ("get_structs", '[{"type":"struct","name":"S"}]'),
    ("get_types", '[{"type":"int","name":"T"}]'),
]


class _SlowJSONPipe:
    """Slow-I/O double for a rizin/r2 analysis pipe.

    Emulates a heavy whole-binary scan: the blocking :meth:`cmd` sleeps for a
    fixed delay before returning a fixed JSON payload, exactly the way a real
    ``rzpipe``/``r2pipe`` ``cmd`` call blocks the worker thread while rizin
    scans. The bridge's timeout logic runs for real against it.
    """

    def __init__(self, payload: str, delay: float) -> None:
        """Store the JSON payload and the per-command blocking delay.

        Args:
            payload: JSON text returned by every :meth:`cmd` invocation.
            delay: Seconds :meth:`cmd` blocks before returning, simulating a
                heavy scan.
        """
        self._payload = payload
        self._delay = delay
        self.commands: list[str] = []

    def cmd(self, command: str) -> str:
        """Record the command, block for the configured delay, return payload.

        Args:
            command: The rizin/r2 command issued by the bridge.

        Returns:
            str: The fixed JSON payload configured for this pipe.
        """
        self.commands.append(command)
        time.sleep(self._delay)
        return self._payload

    def quit(self) -> None:
        """Satisfy the pipe teardown contract (no-op for the double)."""


@pytest.mark.parametrize(("method_name", "payload"), _HEAVY_CASES)
async def test_heavy_listing_command_survives_slow_pipe(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    payload: str,
) -> None:
    """Each heavy listing method must outlive the bare command default.

    With the module default squeezed to :data:`_TINY_DEFAULT` and the pipe
    blocking for :data:`_PIPE_DELAY` (an order of magnitude longer), the call
    can only complete if the bridge hands ``_cmd_json`` the dedicated
    :data:`_METADATA_LISTING_TIMEOUT`. Reverting that plumbing makes the call
    inherit the tiny default and raise ``ToolError`` before the pipe returns.

    Args:
        monkeypatch: Fixture used to shrink the module command default.
        method_name: Name of the heavy listing bridge method under test.
        payload: Valid JSON payload the slow pipe returns for the command.
    """
    monkeypatch.setattr(cutter_mod, "R2_COMMAND_TIMEOUT", _TINY_DEFAULT)

    bridge = CutterBridge()
    pipe = _SlowJSONPipe(payload, _PIPE_DELAY)
    bridge.r2 = cast("Any", pipe)

    method = getattr(bridge, method_name)
    result = await method()

    assert result, f"{method_name} returned an empty result for a valid non-empty payload"
    assert pipe.commands, f"{method_name} never issued a command to the pipe"


async def test_ordinary_command_still_honors_default_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The extended timeout must stay scoped to the heavy listings.

    An ordinary command that does not opt into the dedicated timeout
    (``get_callgraph`` -> ``agcj``) must still time out against the squeezed
    default when the pipe blocks past it. This fails if the ``_cmd_json``
    change ever defaulted its ``command_timeout`` to the large listing value
    instead of ``None``, i.e. if the extended ceiling leaked into every
    command.

    Args:
        monkeypatch: Fixture used to shrink the module command default.
    """
    monkeypatch.setattr(cutter_mod, "R2_COMMAND_TIMEOUT", _TINY_DEFAULT)

    bridge = CutterBridge()
    bridge.r2 = cast("Any", _SlowJSONPipe("[]", _PIPE_DELAY))

    with pytest.raises(ToolError):
        await bridge.get_callgraph()


def test_metadata_listing_timeout_exceeds_command_default() -> None:
    """The dedicated listing timeout must be comfortably above the default.

    A fast, backend-free companion (mirroring
    ``test_analysis_timeout_scheme_exceeds_default_command_timeout``): reads
    the real module constants via ``getattr`` and fails immediately if the
    listing timeout is ever reverted to a value at or near the bare command
    default it exists to escape.
    """
    listing_timeout: float = getattr(cutter_mod, "_METADATA_LISTING_TIMEOUT")
    default_command_timeout: float = getattr(cutter_mod, "_R2_COMMAND_TIMEOUT")

    assert listing_timeout > default_command_timeout * 5, (
        f"metadata-listing timeout ({listing_timeout}s) is not comfortably above the {default_command_timeout}s command default"
    )
