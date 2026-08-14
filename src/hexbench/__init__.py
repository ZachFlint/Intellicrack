# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Standalone exerciser for the ``intellicrack_hexcore`` Rust extension module.

``hexbench`` is a self-contained web GUI that exposes every public callable of
the compiled hex-editor core so each one can be driven by hand without starting
the full Intellicrack application. Nothing in Intellicrack imports this package;
removing the ``src/hexbench`` directory has no effect on the rest of the tree.
"""

from __future__ import annotations


__all__ = ["__version__"]

__version__ = "1.0.0"
