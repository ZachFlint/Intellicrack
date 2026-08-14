# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for the Scripts panel and the orchestrator sharing one manager.

``MainWindow._configure_orchestrator`` builds a ``ScriptManager`` rooted at
``<project>/.intellicrack/scripts`` and hands it to the orchestrator, which
uses it to record the outcome of every successful tool call. Startup then
wires a *different* ``ScriptManager`` -- the one built in ``main.py`` over
``config.data_directory / "scripts"`` -- into the Scripts panel, and that call
never reached the orchestrator. Two managers, two directories, two script
registries.

The consequence is not cosmetic. ``ScriptManager.record_execution`` looks the
script up in its own in-memory registry and returns ``False`` when it is
absent, so every execution of a script the user authored in the Scripts panel
was silently discarded by the orchestrator: the panel's script simply did not
exist as far as the recording half was concerned.

The gate drives the real wiring entry point on a real ``MainWindow`` with a
real ``Orchestrator`` and a real ``ScriptManager``, then asserts on behaviour
rather than identity -- a script added through the wired manager must be
recordable through whichever manager the orchestrator ends up holding, and the
record must land on the panel's own script object.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.script_gen import Script, ScriptLanguage, ScriptManager
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.app import MainWindow


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    from PyQt6.QtCore import QCoreApplication

_SCRIPT_NAME = "panel-authored-hook"
_TOOL_NAME = "frida"
_RESULT = "hook installed at 0x140001000"
_SCRIPT_SOURCE = "Interceptor.attach(ptr('0x140001000'), {});\n"


def _panel_script() -> Script:
    """Build the kind of script a user authors in the Scripts panel.

    Returns:
        Script: A real, syntactically valid Frida script.
    """
    return Script(
        name=_SCRIPT_NAME,
        script_type=_TOOL_NAME,
        language=ScriptLanguage.JAVASCRIPT,
        content=_SCRIPT_SOURCE,
        description="attaches to the licence check",
    )


@pytest.fixture
def window_and_orchestrator(
    qapp: QCoreApplication,
    tmp_path: Path,
) -> Generator[tuple[MainWindow, Orchestrator]]:
    """Build a real window over a real orchestrator.

    Args:
        qapp: Qt application fixture.
        tmp_path: Pytest temporary directory fixture.

    Yields:
        tuple[MainWindow, Orchestrator]: The window and its orchestrator.
    """
    del qapp
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    config = Config(
        tools_directory=tools_dir,
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )
    orchestrator = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db")),
    )
    window = MainWindow(config, orchestrator)
    try:
        yield window, orchestrator
    finally:
        window.close()


def _orchestrator_script_manager(orchestrator: Orchestrator) -> ScriptManager | None:
    """Read the manager the orchestrator will actually record executions into.

    Args:
        orchestrator: The live orchestrator under test.

    Returns:
        ScriptManager | None: The manager currently attached to it.
    """
    return cast("ScriptManager | None", getattr(orchestrator, "_script_manager"))


def test_wiring_a_script_manager_repoints_the_orchestrator(
    window_and_orchestrator: tuple[MainWindow, Orchestrator],
    tmp_path: Path,
) -> None:
    """The orchestrator must record into the directory the panel reads from.

    Args:
        window_and_orchestrator: The real window/orchestrator pair.
        tmp_path: Pytest temporary directory fixture.
    """
    window, orchestrator = window_and_orchestrator
    scripts_dir = tmp_path / "data" / "scripts"
    manager = ScriptManager(scripts_dir)

    window.wire_script_manager(manager)

    attached = _orchestrator_script_manager(orchestrator)
    assert attached is not None, "the orchestrator ended up with no script manager at all"
    assert attached.scripts_dir == scripts_dir, (
        f"the orchestrator still records into {attached.scripts_dir}, while the Scripts panel reads and writes {scripts_dir}"
    )


def test_a_panel_authored_script_can_be_recorded_against(
    window_and_orchestrator: tuple[MainWindow, Orchestrator],
    tmp_path: Path,
) -> None:
    """An execution of a panel-authored script must reach that script.

    ``record_execution`` returns ``False`` for a name its own registry does not
    hold, which is exactly what happened to every user script while the two
    halves owned separate managers.

    Args:
        window_and_orchestrator: The real window/orchestrator pair.
        tmp_path: Pytest temporary directory fixture.
    """
    window, orchestrator = window_and_orchestrator
    manager = ScriptManager(tmp_path / "data" / "scripts")
    window.wire_script_manager(manager)
    assert manager.add_script(_panel_script()), "the fixture script failed validation before the test began"

    attached = _orchestrator_script_manager(orchestrator)
    assert attached is not None, "the orchestrator ended up with no script manager at all"
    recorded = attached.record_execution(script_name=_SCRIPT_NAME, tool_name=_TOOL_NAME, result=_RESULT)

    assert recorded, "the orchestrator could not find the panel's script, so the execution was dropped"
    panel_script = manager.scripts[_SCRIPT_NAME]
    assert panel_script.execution_results.get(_TOOL_NAME) == _RESULT, "the execution was recorded somewhere the Scripts panel cannot see"
