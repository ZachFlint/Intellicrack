# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Script to clean Windows reserved 'nul' files from the project directory."""

import sys
from pathlib import Path


def clean_nul_files() -> None:
    """Recursively find and delete files named 'nul' in the current working directory.

    This is necessary because some Windows build tools can erroneously create these files,
    and standard command-line tools fail to delete them due to 'nul' being a reserved name.
    """
    print("--- Python NUL File Cleaner ---")
    # The batch script ensures this script is run from the project root.
    root_dir = str(Path.cwd())
    print(f"Starting recursive search in: {root_dir}")
    files_deleted = 0

    # Define possible reserved names that could be problematic on Windows
    reserved_names = {
        "nul",
        "NUL",
        "Nul",
        "con",
        "CON",
        "Con",
        "prn",
        "PRN",
        "Prn",
        "aux",
        "AUX",
        "Aux",
        "com1",
        "COM1",
        "Com1",
        "com2",
        "COM2",
        "Com2",
        "com3",
        "COM3",
        "Com3",
        "com4",
        "COM4",
        "Com4",
        "com5",
        "COM5",
        "Com5",
        "com6",
        "COM6",
        "Com6",
        "com7",
        "COM7",
        "Com7",
        "com8",
        "COM8",
        "Com8",
        "com9",
        "COM9",
        "Com9",
        "lpt1",
        "LPT1",
        "Lpt1",
        "lpt2",
        "LPT2",
        "Lpt2",
        "lpt3",
        "LPT3",
        "Lpt3",
        "lpt4",
        "LPT4",
        "Lpt4",
        "lpt5",
        "LPT5",
        "Lpt5",
        "lpt6",
        "LPT6",
        "Lpt6",
        "lpt7",
        "LPT7",
        "Lpt7",
        "lpt8",
        "LPT8",
        "Lpt8",
        "lpt9",
        "LPT9",
        "Lpt9",
    }

    try:
        for entry in Path(root_dir).rglob("*"):
            if entry.is_file() and entry.name in reserved_names:
                nul_path = str(entry)
                prefixed_path = "\\\\?\\" + nul_path

                try:
                    Path(prefixed_path).unlink()
                    print(f"  [OK] Deleted: {nul_path}")
                    files_deleted += 1
                except OSError as e:
                    print(f"  [!!!] FAILED to delete: {nul_path}. Reason: {e}")
    except OSError as e:
        print(f"[!!!] The script failed with an unexpected error: {e}")
        sys.exit(1)

    print(f"\nScan complete. {files_deleted} file(s) deleted.")
    sys.exit(0)


if __name__ == "__main__":
    clean_nul_files()
