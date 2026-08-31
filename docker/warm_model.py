# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Pre-download the local-inference test model into the image at build time.

The Intellicrack test sandbox exercises the local PyTorch/transformers
inference path against a small real model
(``TinyLlama/TinyLlama-1.1B-Chat-v1.0``). Downloading that model on first use
requires network access; baking it into the Hugging Face cache at image-build
time (when the build host has network) lets the local-inference tests run
deterministically and quickly. The weights are written under ``HF_HOME`` and
baked into the image. It is invoked from ``docker/Dockerfile.windows``.
"""

from __future__ import annotations

import sys

from huggingface_hub import snapshot_download


_MODEL_ID = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"


def _emit(message: str) -> None:
    """Write a build-progress line to stdout.

    Args:
        message: The line to write (a newline is appended).
    """
    sys.stdout.write(f"{message}\n")


def main() -> int:
    """Download the test model snapshot into the Hugging Face cache.

    Returns:
        int: ``0`` on success.
    """
    local_path = snapshot_download(repo_id=_MODEL_ID)
    _emit(f"cached model {_MODEL_ID} at {local_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
