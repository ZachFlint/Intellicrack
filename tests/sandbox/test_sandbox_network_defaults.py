# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the Docker network the sandbox attaches by default.

The harness used to hardcode ``bridge`` for the integration and e2e run modes.
``bridge`` is the Linux engine's built-in connected network; the Windows
container engine this project runs on names it ``nat`` instead, so every e2e
run died with ``network bridge not found`` at ``docker run`` time, before a
single test was collected.

These tests drive the real selection code with the network name sets the two
engines actually report, so a return to any hardcoded name fails here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

from scripts.sandbox import docker_sandbox
from scripts.sandbox.docker_sandbox import SandboxError, select_connected_network
from scripts.sandbox.test_types import TestType


if TYPE_CHECKING:
    from collections.abc import Callable

_MODULE_MEMBERS = vars(docker_sandbox)
_default_network = cast(
    "Callable[[TestType | None], str]",
    _MODULE_MEMBERS["_default_network"],
)

_WINDOWS_ENGINE_NETWORKS = frozenset({"Default Switch", "nat", "none"})

_LINUX_ENGINE_NETWORKS = frozenset({"bridge", "host", "none"})


def test_windows_engine_selects_nat() -> None:
    """A Windows container engine, which has no ``bridge``, must select ``nat``."""
    assert "bridge" not in _WINDOWS_ENGINE_NETWORKS
    assert select_connected_network(_WINDOWS_ENGINE_NETWORKS, "e2e") == "nat"


def test_linux_engine_selects_bridge() -> None:
    """A Linux engine, which has no ``nat``, must select ``bridge``."""
    assert "nat" not in _LINUX_ENGINE_NETWORKS
    assert select_connected_network(_LINUX_ENGINE_NETWORKS, "e2e") == "bridge"


def test_selection_never_returns_a_network_the_engine_lacks() -> None:
    """The chosen network must always be one the engine actually defines."""
    for available in (_WINDOWS_ENGINE_NETWORKS, _LINUX_ENGINE_NETWORKS):
        chosen = select_connected_network(available, "integration")
        assert chosen in available, f"selected {chosen!r}, absent from {sorted(available)}"


def test_no_connected_network_fails_loudly() -> None:
    """An engine with only isolated networks must raise, not silently pick one."""
    with pytest.raises(SandboxError, match="needs a connected network"):
        select_connected_network(frozenset({"none"}), "e2e")


def test_failure_message_names_the_mode_and_what_was_found() -> None:
    """The failure must be actionable: which mode failed and what the engine has."""
    with pytest.raises(SandboxError) as excinfo:
        select_connected_network(frozenset({"none", "somethingelse"}), "integration")

    message = str(excinfo.value)
    assert "integration" in message
    assert "somethingelse" in message
    assert "--network" in message


@pytest.mark.parametrize(
    "test_type",
    [TestType.UNIT, TestType.ALL, TestType.CUSTOM, TestType.COVERAGE],
    ids=lambda t: str(t.value),
)
def test_isolated_modes_stay_offline(test_type: TestType) -> None:
    """Modes that do not need connectivity must keep running with no network.

    Args:
        test_type: The isolated run mode under test.
    """
    assert _default_network(test_type) == "none"


def test_shell_invocation_stays_offline() -> None:
    """A shell invocation, which carries no test type, must also stay offline."""
    assert _default_network(None) == "none"
