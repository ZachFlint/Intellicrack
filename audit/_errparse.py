"""Group basedpyright/ruff error lines by source file for the recovery cleanup."""

from __future__ import annotations

import collections
import re
from pathlib import Path

PATTERN = re.compile(r"tests[\\/][\w\\/.\-]+\.py")

for name, path in [("basedpyright", "/tmp/bpr.txt"), ("ruff", "/tmp/ruff.txt")]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    counts: collections.Counter[str] = collections.Counter()
    for line in text.splitlines():
        if "error" not in line.lower():
            continue
        match = PATTERN.search(line)
        if match:
            counts[match.group(0).replace("\\", "/")] += 1
    print(f"=== {name}: {sum(counts.values())} errors across {len(counts)} files ===")
    for file_path, num in counts.most_common():
        print(f"  {num:2}  {file_path}")
