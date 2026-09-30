# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The one lock held whenever a handle of this process may be inherited by a child it did not create.

On Windows a child created with ``bInheritHandles`` set and no handle list receives every inheritable handle its parent holds at that
moment, whichever thread made it inheritable and for whichever child. A confined MCP server's pipe ends have to be inheritable while its
process is created; if an unrelated child were created in that window it would receive them too, would learn what the server says and is
told, and would hold the server's standard output open so its exit was never seen.

Every spawn in Intellicrack that makes a handle inheritable holds :data:`INHERITANCE_LOCK` from the moment it does so until the handle is
closed, and every spawn that lets a child inherit without a handle list holds it for the whole spawn, so neither can overlap the other.
:mod:`subprocess` needs no part in this: with ``close_fds`` left at its default it passes a handle list, so its children receive their
own standard handles and nothing else.
"""

from __future__ import annotations

import threading
from typing import Final


INHERITANCE_LOCK: Final[threading.Lock] = threading.Lock()
"""Held while any handle is inheritable for a spawn, and for any spawn that inherits without a handle list."""


__all__ = ["INHERITANCE_LOCK"]
