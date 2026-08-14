# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The script the frozen executable starts from.

A frozen build needs a script to run, and pointing the builder straight at
``__main__`` would not do: the builder would take it as the top-level script
rather than as a module of the package, and ``__file__`` would then resolve one
directory above where the bundled ``static`` tree was placed, so the editor
would start and serve nothing. Importing it from here keeps it a module of the
package, and the same path arithmetic finds the same files frozen or not.

Running this file directly does the same thing as ``python -m hexbench``.
"""

from __future__ import annotations

from hexbench.__main__ import main


__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
