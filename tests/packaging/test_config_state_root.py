# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for the per-user writable state relocation.

The installed application is spawned as ``pythonw -m intellicrack`` (not frozen),
so ``get_project_root()`` resolves to the read-only, world-readable install
directory under ``Program Files``. Writing credentials (``.env``), config, logs,
and data there is both a disclosure risk and destroyed by the uninstaller's
directory sweep. The launcher therefore exports ``INTELLICRACK_STATE_DIR`` (a
per-user directory under ``%LOCALAPPDATA%``), and the config resolvers honour it.

These gates pin that contract:

* ``get_state_root()`` returns ``INTELLICRACK_STATE_DIR`` when set to a trusted
  per-user location and falls back to ``get_project_root()`` (the unchanged dev
  checkout) when it is not set.
* ``get_config_dir()`` and ``get_env_file()`` -- the credential/config paths --
  are resolved under the state root, not the install root.
* The ``Config`` ``logs_directory``/``data_directory`` defaults and the
  ``[general]`` parser follow the state root, while ``tools_directory`` stays
  pinned to the (read-only, bundled) project root.

They also pin the security validation: because ``.env`` credentials, provider
config, and logs are resolved under the state root, a poisoned
``INTELLICRACK_STATE_DIR`` (a UNC network share, a directory-traversal escape, or
any path outside the current user's own profile) must be rejected in favour of
the safe default (the ``Intellicrack`` directory under ``%LOCALAPPDATA%``) --
never honoured -- so credentials cannot be redirected for exfiltration and config
cannot be poisoned.

Reverting any resolver back to ``get_project_root()`` puts credentials under
Program Files again, and dropping the validation lets an attacker path through;
either turns the corresponding gate red.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.core import config as config_module
from intellicrack.core.config import (
    Config,
    get_config_dir,
    get_env_file,
    get_project_root,
    get_state_root,
)


if TYPE_CHECKING:
    from pathlib import Path


_STATE_ENV: str = "INTELLICRACK_STATE_DIR"
_LOCALAPPDATA_ENV: str = "LOCALAPPDATA"
_APPDATA_ENV: str = "APPDATA"
_USERPROFILE_ENV: str = "USERPROFILE"
_STATE_DIR_NAME: str = "Intellicrack"


@pytest.fixture
def local_app_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Anchor ``%LOCALAPPDATA%`` at a real per-user directory for the test.

    The installed launcher always places the state directory beneath
    ``%LOCALAPPDATA%``, so honouring a supplied ``INTELLICRACK_STATE_DIR`` now
    requires that anchor to be present and to contain the supplied path. Tests
    that want their state directory trusted set it under this anchor. The broader
    ``%APPDATA%``/``%USERPROFILE%`` anchors are cleared so containment is decided
    solely by the directory this fixture returns.

    Args:
        tmp_path: Pytest temporary directory root.
        monkeypatch: Pytest patching fixture.

    Returns:
        Path: The resolved directory now exported as ``%LOCALAPPDATA%``.
    """
    anchor = (tmp_path / "LocalAppData").resolve()
    anchor.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv(_LOCALAPPDATA_ENV, str(anchor))
    monkeypatch.delenv(_APPDATA_ENV, raising=False)
    monkeypatch.delenv(_USERPROFILE_ENV, raising=False)
    return anchor


def test_state_root_honours_the_env_var(local_app_data: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``get_state_root`` returns the installed per-user state directory when set.

    Args:
        local_app_data: Fixture-provided ``%LOCALAPPDATA%`` anchor directory.
        monkeypatch: Pytest patching fixture.
    """
    state = local_app_data / _STATE_DIR_NAME
    monkeypatch.setenv(_STATE_ENV, str(state))
    assert get_state_root() == state


def test_state_root_falls_back_to_project_root_in_dev(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the env var the dev checkout layout (project root) is unchanged.

    Args:
        monkeypatch: Pytest patching fixture.
    """
    monkeypatch.delenv(_STATE_ENV, raising=False)
    assert get_state_root() == get_project_root()


def test_state_root_and_project_root_diverge_when_installed(local_app_data: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When installed, writable state must not resolve under the install root.

    This is the security invariant: the state root points at the per-user
    directory while the project (install) root stays where the bundled read-only
    assets live -- the two must not coincide.

    Args:
        local_app_data: Fixture-provided ``%LOCALAPPDATA%`` anchor directory.
        monkeypatch: Pytest patching fixture.
    """
    state = local_app_data / "state"
    monkeypatch.setenv(_STATE_ENV, str(state))
    assert get_state_root() == state
    assert get_state_root() != get_project_root()


def test_credentials_and_config_resolve_under_state_root(local_app_data: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The ``.env`` credential file and config dir live under the state root.

    Args:
        local_app_data: Fixture-provided ``%LOCALAPPDATA%`` anchor directory.
        monkeypatch: Pytest patching fixture.
    """
    state = local_app_data / "state"
    monkeypatch.setenv(_STATE_ENV, str(state))

    assert get_env_file() == state / ".env"
    assert get_config_dir() == state / ".intellicrack"
    project_root = get_project_root()
    assert get_env_file().parent != project_root, "the .env credential file must never resolve under the install root"


def test_config_defaults_put_logs_and_data_under_state_root(local_app_data: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A default ``Config`` writes logs and data under the state root, tools under project root.

    Args:
        local_app_data: Fixture-provided ``%LOCALAPPDATA%`` anchor directory.
        monkeypatch: Pytest patching fixture.
    """
    state = local_app_data / "state"
    monkeypatch.setenv(_STATE_ENV, str(state))

    config = Config()
    assert config.logs_directory == state / "logs"
    assert config.data_directory == state / "data"
    assert config.tools_directory == get_project_root() / "tools", (
        "tools_directory must stay pinned to the bundled read-only project root, not the writable state root"
    )


def test_general_parser_routes_writable_dirs_to_state_root(local_app_data: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The ``[general]`` parser defaults logs/data to the state root, tools to project root.

    The parser is exercised with an empty ``general`` section so every value comes
    from its default, which is where the relocation lives.

    Args:
        local_app_data: Fixture-provided ``%LOCALAPPDATA%`` anchor directory.
        monkeypatch: Pytest patching fixture.
    """
    state = local_app_data / "state"
    monkeypatch.setenv(_STATE_ENV, str(state))

    config = Config.from_dict({})
    assert config.logs_directory == state / "logs"
    assert config.data_directory == state / "data"
    assert config.tools_directory == get_project_root() / "tools"


def test_state_root_reads_environment_live(local_app_data: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``get_state_root`` reflects the current environment, not an import-time snapshot.

    The launcher sets the variable in the child's environment block, so the
    resolver must read ``os.environ`` at call time. Changing the variable between
    calls must change the result.

    Args:
        local_app_data: Fixture-provided ``%LOCALAPPDATA%`` anchor directory.
        monkeypatch: Pytest patching fixture.
    """
    first = local_app_data / "first"
    second = local_app_data / "second"

    monkeypatch.setenv(_STATE_ENV, str(first))
    assert get_state_root() == first

    monkeypatch.setenv(_STATE_ENV, str(second))
    assert get_state_root() == second

    assert config_module.os.environ.get(_STATE_ENV) == str(second)


def test_state_root_rejects_path_outside_user_profile(local_app_data: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A state dir outside the user profile is rejected for the safe default.

    A path that resolves outside every per-user anchor -- the shape of a poisoned
    variable aimed at a world-writable or attacker-controlled directory -- must
    never be honoured; ``get_state_root`` returns the safe per-user default
    instead so credentials/config are not redirected out of the user profile.

    Args:
        local_app_data: Fixture-provided ``%LOCALAPPDATA%`` anchor directory.
        tmp_path: Pytest temporary directory; ``outside`` is a sibling of the anchor.
        monkeypatch: Pytest patching fixture.
    """
    outside = (tmp_path / "attacker_drop").resolve()
    monkeypatch.setenv(_STATE_ENV, str(outside))

    result = get_state_root()

    assert result == local_app_data / _STATE_DIR_NAME
    assert result != outside
    assert get_env_file().parent == local_app_data / _STATE_DIR_NAME


def test_state_root_rejects_directory_traversal_escape(local_app_data: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``..`` traversal that climbs out of the anchor is collapsed and rejected.

    The candidate textually begins under ``%LOCALAPPDATA%`` but ``..`` segments
    escape it, so a naive prefix check would be fooled. Resolution collapses the
    traversal before the containment check, and the escape is rejected.

    Args:
        local_app_data: Fixture-provided ``%LOCALAPPDATA%`` anchor directory.
        tmp_path: Pytest temporary directory; the escape target is its sibling.
        monkeypatch: Pytest patching fixture.
    """
    escape_target = (tmp_path / "escaped").resolve()
    traversal = local_app_data / _STATE_DIR_NAME / ".." / ".." / escape_target.name
    monkeypatch.setenv(_STATE_ENV, str(traversal))

    result = get_state_root()

    assert result == local_app_data / _STATE_DIR_NAME
    assert result != escape_target


def test_state_root_rejects_unc_network_share(local_app_data: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A UNC network-share target is rejected for the local safe default.

    Redirecting the ``.env`` credential file onto a network share is the
    exfiltration path the validation exists to close. A UNC path is not contained
    by any local per-user anchor, so it is rejected.

    Args:
        local_app_data: Fixture-provided ``%LOCALAPPDATA%`` anchor directory.
        monkeypatch: Pytest patching fixture.
    """
    unc = r"\\attacker-host\exfil\Intellicrack"
    monkeypatch.setenv(_STATE_ENV, unc)

    result = get_state_root()

    assert result == local_app_data / _STATE_DIR_NAME
    assert str(result) != unc


def test_state_root_rejects_when_no_user_anchor_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no per-user anchor to validate against, a supplied path is not trusted.

    When none of ``%LOCALAPPDATA%``/``%APPDATA%``/``%USERPROFILE%`` are set there
    is nothing to prove containment against, so an arbitrary supplied path is
    rejected and the resolver falls back to the project root (there is no
    ``%LOCALAPPDATA%`` to build the per-user default from).

    Args:
        tmp_path: Pytest temporary directory standing in for the supplied path.
        monkeypatch: Pytest patching fixture.
    """
    for var in (_LOCALAPPDATA_ENV, _APPDATA_ENV, _USERPROFILE_ENV):
        monkeypatch.delenv(var, raising=False)
    supplied = (tmp_path / "supplied").resolve()
    monkeypatch.setenv(_STATE_ENV, str(supplied))

    result = get_state_root()

    assert result == get_project_root()
    assert result != supplied


def test_state_root_trusts_path_under_userprofile_anchor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A path under ``%USERPROFILE%`` (not only ``%LOCALAPPDATA%``) is honoured.

    The launcher uses ``%LOCALAPPDATA%``, but the broader user-profile anchor is
    also a trusted containment root, so a state dir beneath ``%USERPROFILE%`` is
    accepted unchanged.

    Args:
        tmp_path: Pytest temporary directory; the profile anchor and state dir live under it.
        monkeypatch: Pytest patching fixture.
    """
    profile = (tmp_path / "UserProfile").resolve()
    profile.mkdir(parents=True, exist_ok=True)
    monkeypatch.delenv(_LOCALAPPDATA_ENV, raising=False)
    monkeypatch.delenv(_APPDATA_ENV, raising=False)
    monkeypatch.setenv(_USERPROFILE_ENV, str(profile))
    state = profile / "AppData" / "Local" / _STATE_DIR_NAME
    monkeypatch.setenv(_STATE_ENV, str(state))

    assert get_state_root() == state
