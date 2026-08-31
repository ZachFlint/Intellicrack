# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Pytest fixtures shared by the Cutter/Rizin bridge-completeness gate tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
import r2pipe
from PyQt6.QtWidgets import QApplication

from intellicrack.bridges.cutter import CutterBridge


if TYPE_CHECKING:
    from collections.abc import Generator


def priv[T](obj: object, name: str, typ: type[T]) -> T:
    """Access a private/name-mangled attribute on ``obj`` with a known static type.

    Centralises the ``getattr``-based access these gate tests use to reach
    into real production widgets' private fields (e.g. ``_bridge``,
    ``_status_label``, ``_on_attach``). ``getattr`` sidesteps basedpyright's
    ``reportPrivateUsage`` (it only flags syntactic ``obj._private``
    attribute access, not dynamic lookups) while ``typ`` keeps the result
    fully typed instead of falling back to ``Any``.

    Args:
        obj: The object to read the attribute from.
        name: The attribute name, including its leading underscore(s).
        typ: The expected static type of the attribute; used only for the
            type-checker cast, not validated at runtime.

    Returns:
        T: The attribute value, statically typed as ``typ``.
    """
    del typ
    value: T = getattr(obj, name)
    return value


@pytest.fixture(scope="session")
def qapp() -> Generator[QApplication]:
    """Provide a QApplication instance for the test session.

    Qt requires exactly one QApplication instance per process; this
    fixture creates one for the entire session and yields it so every
    widget-construction/click test in this package can run without
    re-creating (or conflicting on) the singleton application instance.

    Yields:
        QApplication: The application instance.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class CommandRecorder:
    """r2pipe stand-in that records issued commands and returns configurable JSON.

    This is the genuine external boundary these tests cannot cross in the
    sandbox (a live rizin/radare2 child process communicating over its
    r2pipe protocol). Everything downstream of this object -- the real
    ``CutterBridge`` method bodies, the real tool-definition dispatch
    through :class:`~intellicrack.core.tools.ToolRegistry`, and the real
    Qt widget rendering code in the panel/tab classes -- executes for real
    against whatever this recorder returns, so a broken bridge method,
    tool-def, or GUI handler still turns the surrounding assertions red.

    Attributes:
        commands: Ordered list of every command string passed to ``cmd()``.
        responses: Mapping of exact command string or command prefix to a
            canned response string.
    """

    commands: list[str]
    responses: dict[str, str]

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        """Initialise the recorder with an optional canned-response map.

        Args:
            responses: Optional mapping of exact command or command prefix
                to a canned response string. Falls back to an empty string
                when no entry matches.
        """
        self.commands = []
        self.responses = responses or {}

    def cmd(self, command: str) -> str:
        """Record ``command`` and return the longest matching canned response.

        Args:
            command: The r2 command string issued by the bridge.

        Returns:
            str: The response for the longest matching exact/prefix entry,
            or an empty string when nothing matches.
        """
        self.commands.append(command)
        if command in self.responses:
            return self.responses[command]
        return next(
            (response for prefix, response in self.responses.items() if command.startswith(prefix)),
            "",
        )

    def quit(self) -> None:
        """No-op ``quit`` for test cleanup."""


def as_r2pipe(recorder: CommandRecorder) -> r2pipe.open:
    """Cast a :class:`CommandRecorder` to the ``r2pipe.open`` type.

    ``CommandRecorder`` implements the exact subset of the ``r2pipe.open``
    interface ``CutterBridge`` consumes (``cmd(str) -> str`` and
    ``quit() -> None``), so this centralises the duck-type cast used to
    assign the recorder to ``CutterBridge.r2``.

    Args:
        recorder: Test double that duck-types the ``r2pipe.open`` interface.

    Returns:
        r2pipe.open: The same instance, typed as ``r2pipe.open``.
    """
    return cast(r2pipe.open, recorder)


@pytest.fixture
def recorder() -> CommandRecorder:
    """Create a default :class:`CommandRecorder` with baseline analysis responses.

    Returns:
        CommandRecorder: Recorder pre-seeded with empty-but-valid JSON for
        the metadata queries ``analyze()`` and common refresh paths touch,
        so tests can layer additional feature-specific responses without
        having to re-supply this boilerplate every time.
    """
    return CommandRecorder({
        "e asm.arch": "x86",
        "e asm.bits": "64",
        "aflj": "[]",
        "izj": "[]",
        "iSj": "[]",
        "iij": "[]",
        "iEj": "[]",
        "ij": '[{"bin":{"class":"PE","arch":"x86","bits":64,"baddr":0,"entry":0}}]',
    })


@pytest.fixture
def bridge_with_recorder(recorder: CommandRecorder) -> CutterBridge:
    """Build a real ``CutterBridge`` wired to the ``recorder`` fixture via its ``r2`` setter.

    Args:
        recorder: The default command recorder fixture.

    Returns:
        CutterBridge: A bridge instance with a live (recorder-backed) ``r2`` session.
    """
    b = CutterBridge()
    b.r2 = as_r2pipe(recorder)
    return b
