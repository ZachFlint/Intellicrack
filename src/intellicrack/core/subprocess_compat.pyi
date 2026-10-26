# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
import subprocess
from collections.abc import Iterable
from subprocess import (
    DEVNULL as DEVNULL,
    PIPE as PIPE,
    run as run,
)

from _typeshed import StrOrBytesPath

CalledProcessError = subprocess.CalledProcessError
CompletedProcess = subprocess.CompletedProcess
Popen = subprocess.Popen
STARTUPINFO = subprocess.STARTUPINFO
SubprocessError = subprocess.SubprocessError
TimeoutExpired = subprocess.TimeoutExpired

CREATE_NEW_CONSOLE: int
CREATE_NEW_PROCESS_GROUP: int
CREATE_NO_WINDOW: int
STARTF_USESHOWWINDOW: int

def list2cmdline(seq: Iterable[StrOrBytesPath]) -> str:
    """Join a program path and its arguments into one Windows command line.

    Each item is quoted and escaped with the Microsoft C runtime parsing rules, so a
    program that splits its command line with those rules receives the same arguments.

    Args:
        seq: Program path followed by its arguments.

    Returns:
        str: The quoted command line.
    """
