# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Run a Python snippet in a fresh interpreter under a hard timeout.

Gates on "this call must not block" cannot run the call in the test process:
if the regression they guard against comes back, the call never returns and
the whole run hangs. A child interpreter can be abandoned instead, so the
regression fails its test cleanly.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final


if TYPE_CHECKING:
    from collections.abc import Mapping


REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

_INHERITED_ENV: Final[tuple[str, ...]] = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA")


class ChildTimeoutError(AssertionError):
    """The child interpreter did not finish within its timeout."""


def run_child_json(code: str, *, timeout_s: float, extra_env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Run a snippet in a fresh interpreter and decode the JSON it prints last.

    The child sees the repository's ``src`` and root on ``PYTHONPATH`` and only
    a minimal inherited environment, so proxy and cache settings come solely
    from ``extra_env``.

    Args:
        code: Python source; its last line of output must be one JSON object.
        timeout_s: Hard bound on the whole run, interpreter start-up included.
        extra_env: Environment variables to add for the child.

    Returns:
        dict[str, Any]: The decoded JSON object.

    Raises:
        ChildTimeoutError: When the child does not finish within
            ``timeout_s``.
        AssertionError: When the child exits unsuccessfully.
    """
    env = {"PYTHONPATH": f"{REPO_ROOT / 'src'}{os.pathsep}{REPO_ROOT}", "PYTHONIOENCODING": "utf-8"}
    for key in _INHERITED_ENV:
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    env.update(extra_env or {})
    try:
        completed = subprocess.run(
            [sys.executable, "-c", textwrap.dedent(code)],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        message = f"child interpreter did not finish within {timeout_s:g}s"
        raise ChildTimeoutError(message) from exc
    if completed.returncode != 0:
        message = f"child interpreter exited with {completed.returncode}:\n{completed.stderr[-4000:]}"
        raise AssertionError(message)
    decoded: dict[str, Any] = json.loads(completed.stdout.strip().splitlines()[-1])
    return decoded
