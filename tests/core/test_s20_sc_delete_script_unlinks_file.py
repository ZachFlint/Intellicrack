# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for ScriptManager.delete_script durably removing backing files.

Covers a deleted script must not leave an orphaned, still-loadable
file on disk, and a delete that cannot unlink its backing file (for example a
read-only file on Windows) must not silently drop the in-memory entry.
"""

from __future__ import annotations

import stat
import sys
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.script_gen import Script, ScriptLanguage, ScriptManager


if TYPE_CHECKING:
    from pathlib import Path


def test_delete_script_unlinks_backing_file_and_blocks_reload(tmp_path: Path) -> None:
    """Deleting a saved script must remove its file, not just the dict entry.

    Saves a script (writing
    ``scripts_dir/<name>.r2``), delete it, and confirm the file that
    ``Test-Path``/``load_script`` would find is actually gone. ``delete_script``
    must remove the persisted file, not only the in-memory dict entry.
    """
    manager = ScriptManager(scripts_dir=tmp_path)
    script = Script(
        name="s20_audit_script",
        script_type="cutter",
        language=ScriptLanguage.R2_COMMANDS,
        content="aaa\naf\n",
        description="S20-D05 repro script",
    )
    assert manager.add_script(script, validate=False) is True

    saved_path = manager.save_script(script.name)
    assert saved_path is not None
    assert saved_path.exists()
    assert saved_path == tmp_path / "s20_audit_script.r2"

    result = manager.delete_script(script.name)

    assert result is True
    assert script.name not in manager.scripts
    assert not saved_path.exists()
    assert manager.load_script(saved_path) is None


def test_delete_script_missing_name_returns_false_without_touching_disk(tmp_path: Path) -> None:
    """Deleting an unknown script name is a no-op that reports failure."""
    manager = ScriptManager(scripts_dir=tmp_path)

    assert manager.delete_script("does_not_exist") is False


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows refuses to delete a read-only file; POSIX unlinks it, so no unlink failure occurs",
)
def test_delete_script_retains_entry_when_backing_file_cannot_be_unlinked(tmp_path: Path) -> None:
    """A real unlink failure must surface, not be swallowed with the entry dropped.

    Marks the saved file read-only, which on Windows makes ``DeleteFile``
    fail with access-denied regardless of the calling process's own
    ownership of the file - a genuine Windows delete failure mode, not a
    mock. The failure must be reported via the return value, and the in-memory
    entry must be retained so the user can retry (for example after clearing the
    read-only attribute), rather than leaving the list entry gone while the file
    whose deletion failed still exists.
    """
    manager = ScriptManager(scripts_dir=tmp_path)
    script = Script(
        name="s20_locked_script",
        script_type="cutter",
        language=ScriptLanguage.R2_COMMANDS,
        content="aaa\n",
        description="S20-D05 undeletable-file repro",
    )
    assert manager.add_script(script, validate=False) is True
    saved_path = manager.save_script(script.name)
    assert saved_path is not None
    assert saved_path.exists()

    saved_path.chmod(stat.S_IREAD)
    try:
        result = manager.delete_script(script.name)

        assert result is False
        assert saved_path.exists()
        assert script.name in manager.scripts
    finally:
        saved_path.chmod(stat.S_IWRITE | stat.S_IREAD)
