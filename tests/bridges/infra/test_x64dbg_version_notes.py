# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for x64dbg version extraction from release-notes.md."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.installer import ToolInstaller, ToolVersion
from intellicrack.core.types import ToolName


if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.asyncio
async def test_get_version_x64dbg_uses_release_notes(tmp_path: Path) -> None:
    """Verify get_version(X64DBG) extracts version from release-notes.md.

    Args:
        tmp_path: Pytest temporary path fixture.
    """
    x64dbg_dir = tmp_path / "x64dbg"
    x64dbg_dir.mkdir()
    notes = x64dbg_dir / "release-notes.md"
    notes.write_text("<!-- 2025.08.19 -->\n# August 2025: Bug fixes and stability", encoding="utf-8")

    ti = ToolInstaller(tmp_path)
    version_raw = await ti.get_version(ToolName.X64DBG, x64dbg_dir)

    assert isinstance(version_raw, ToolVersion)
    assert (version_raw.major, version_raw.minor, version_raw.patch) == (2025, 8, 19)
