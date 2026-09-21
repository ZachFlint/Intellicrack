# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates that Intellicrack's third-party licensing obligations hold.

Intellicrack is GPL-3.0-or-later and redistributes third-party software two ways:
the x64dbg plugin SDK is committed under ``tools/x64dbg/pluginsdk`` (a build
dependency ``src/x64dbg-plugin`` links against), and ``packaging/stage.ps1``
bundles fetched tool binaries into ``Intellicrack-Setup.exe``. Both channels carry
obligations that nothing previously enforced: ship the license text, and provide
access to the Corresponding Source.

Four obligations are gated here, each of which was genuinely unmet before:

* The verbatim license texts exist under ``licenses/``.
* x64dbg's text is its **modified** GPL-3.0 carrying the "Treatment of plugins"
  exception. This matters because ``src/x64dbg-plugin`` links ``x64dbg.lib`` and
  is therefore a combined work; that exception is what permits it. Replacing the
  file with stock GPLv3 boilerplate would misstate the terms, so that is failed
  explicitly rather than merely checking the file is non-empty.
* The x64dbg commit recorded in ``tools/x64dbg/commithash.txt`` is the same commit
  the Corresponding Source link points at. GPL-3.0 section 6(d) requires the
  source to correspond to the shipped build, so a bumped SDK with a stale link
  silently breaks compliance.
* The installer actually carries the texts: ``stage.ps1`` stages them and
  ``intellicrack.iss`` installs them. Staging without installing would ship
  binaries with no license text.

These read repository-root files that the sandbox does not mount, so they are
registered ``host_native``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

_LICENSES_DIR: Final[Path] = _REPO_ROOT / "licenses"
_LICENSE_INDEX: Final[Path] = _REPO_ROOT / "THIRD-PARTY-LICENSES.md"
_COMMITHASH: Final[Path] = _REPO_ROOT / "tools" / "x64dbg" / "commithash.txt"
_STAGE_SCRIPT: Final[Path] = _REPO_ROOT / "packaging" / "stage.ps1"
_ISS_SCRIPT: Final[Path] = _REPO_ROOT / "packaging" / "intellicrack.iss"

# Every third-party project whose text must ship. The SDK bundles the last three.
_REQUIRED_LICENSE_DIRS: Final[tuple[str, ...]] = (
    "x64dbg",
    "x64dbg-XEDParse",
    "jansson",
    "lz4",
    "cutter",
    "rizin",
    "radare2",
    "traceevent",
)

# A license file shorter than this is a stub, not a real text.
_MIN_LICENSE_BYTES: Final[int] = 500

# Markers proving x64dbg's text is the modified one, not stock GPLv3.
_X64DBG_MODIFIED_MARKER: Final[str] = "THIS DOCUMENT HAS BEEN MODIFIED"
_X64DBG_PLUGIN_EXCEPTION: Final[str] = "Treatment of plugins"

_FULL_SHA_RE: Final[re.Pattern[str]] = re.compile(r"\b[0-9a-f]{40}\b")


def _read(path: Path) -> str:
    """Read a UTF-8 text file, tolerating a byte-order mark.

    Args:
        path: File to read.

    Returns:
        str: The decoded file contents.
    """
    assert path.is_file(), f"required file missing: {path}"
    return path.read_text(encoding="utf-8-sig")


def test_every_required_license_text_is_vendored() -> None:
    """Real gate: each third-party project's license text ships under ``licenses/``.

    GPL and LGPL both require the license to accompany the work. Deleting a text,
    or leaving behind an empty placeholder, turns this red.
    """
    assert _LICENSES_DIR.is_dir(), f"licenses directory missing: {_LICENSES_DIR}"

    for name in _REQUIRED_LICENSE_DIRS:
        path = _LICENSES_DIR / name / "LICENSE"
        assert path.is_file(), f"license text missing for {name!r}: {path}"
        size = path.stat().st_size
        assert size >= _MIN_LICENSE_BYTES, f"license text for {name!r} is {size} bytes, which is too short to be a real license"


def test_x64dbg_license_is_the_modified_text_with_the_plugin_exception() -> None:
    """Real gate: x64dbg's vendored text is its modified GPL-3.0, not stock GPLv3.

    ``src/x64dbg-plugin`` links ``x64dbg.lib`` and ``x64bridge.lib``, making it a
    combined work with x64dbg. The inserted "Treatment of plugins" clause is what
    permits that. Swapping in an unmodified GPLv3 copy would misstate the terms
    the code is actually offered under, so it fails here.
    """
    text = _read(_LICENSES_DIR / "x64dbg" / "LICENSE")

    assert _X64DBG_MODIFIED_MARKER in text, (
        f"licenses/x64dbg/LICENSE does not contain {_X64DBG_MODIFIED_MARKER!r} -- it appears to have been replaced with stock GPLv3 text"
    )
    assert _X64DBG_PLUGIN_EXCEPTION in text, (
        f"licenses/x64dbg/LICENSE does not contain the {_X64DBG_PLUGIN_EXCEPTION!r} clause, "
        "which is the exception src/x64dbg-plugin depends on"
    )


def test_corresponding_source_link_matches_the_pinned_sdk_commit() -> None:
    """Real gate: the documented source link names the exact vendored SDK commit.

    GPL-3.0 section 6(d) is satisfied by directions to the Corresponding Source for
    *the shipped build*. Bumping the SDK without updating the link would leave the
    documentation pointing at source that does not correspond, so the two are
    anchored to each other here.
    """
    pinned = _read(_COMMITHASH).strip()
    assert _FULL_SHA_RE.fullmatch(pinned), f"commithash.txt does not hold a full 40-char sha: {pinned!r}"

    index = _read(_LICENSE_INDEX)
    assert pinned in index, (
        f"THIRD-PARTY-LICENSES.md does not cite the pinned x64dbg SDK commit {pinned!r}; the Corresponding Source link is stale"
    )


def test_every_vendored_license_is_documented_in_the_index() -> None:
    """Real gate: no vendored license text is left undocumented.

    ``licenses/`` is only useful if the index explains what each text covers.
    Adding a directory without documenting it turns this red.
    """
    index = _read(_LICENSE_INDEX)

    for child in sorted(p for p in _LICENSES_DIR.iterdir() if p.is_dir()):
        assert child.name in index, f"licenses/{child.name}/ exists but THIRD-PARTY-LICENSES.md never mentions it"


def test_installer_both_stages_and_installs_the_license_texts() -> None:
    """Real gate: the installer carries the license texts to the installed tree.

    ``stage.ps1`` building the payload and ``intellicrack.iss`` mapping it into
    ``{app}`` are two halves of one contract. If either half drops the licenses,
    ``Intellicrack-Setup.exe`` ships GPL binaries with no license text, so both
    halves are asserted.
    """
    stage = _read(_STAGE_SCRIPT)
    iss = _read(_ISS_SCRIPT)

    assert "THIRD-PARTY-LICENSES.md" in stage, "packaging/stage.ps1 never stages THIRD-PARTY-LICENSES.md"
    assert "licenses" in stage, "packaging/stage.ps1 never stages the licenses/ tree"

    assert "THIRD-PARTY-LICENSES.md" in iss, "packaging/intellicrack.iss never installs THIRD-PARTY-LICENSES.md"
    assert r"app\licenses\*" in iss, "packaging/intellicrack.iss never installs the licenses/ tree"
