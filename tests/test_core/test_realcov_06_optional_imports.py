# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for :mod:`intellicrack.core._optional_imports`.

The success path runs the genuine ``importlib.import_module("yara")`` and
asserts the returned object is the real yara module. The failure path drives
the SAME real import machinery to actually fail by installing a real
``MetaPathFinder`` that refuses the ``yara`` name and evicting any cached
module, so ``require_yara`` raises against a genuine ``ImportError`` rather than
a mocked stand-in. The emitted warning is captured from the real logger.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from typing import TYPE_CHECKING

import pytest
from structlog.testing import capture_logs

from intellicrack.core._optional_imports import require_yara
from intellicrack.core.types import SandboxError


if TYPE_CHECKING:
    from collections.abc import Generator, Sequence
    from importlib.machinery import ModuleSpec
    from types import ModuleType


class _BlockYaraFinder:
    """Real ``sys.meta_path`` finder that refuses to import ``yara``.

    Installing this finder ahead of the standard finders forces the genuine
    import machinery to fail for the ``yara`` name, reproducing a real
    deployment where yara-python is not installed without faking the function
    under test.
    """

    def find_spec(
        self,
        name: str,
        path: Sequence[str] | None = None,
        target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        """Return no spec for ``yara`` so the import resolves to a real failure.

        Args:
            name: Fully qualified module name being imported.
            path: Parent package search path (unused for top-level ``yara``).
            target: Existing module object for reloads (unused).

        Returns:
            ModuleSpec | None: ``None`` always; for ``yara`` this blocks the
            import, and for any other name it defers to later finders.

        Raises:
            ModuleNotFoundError: When the requested name is ``yara``, so the
                whole ``sys.meta_path`` chain reports a genuine import failure.
        """
        del path, target
        if name == "yara" or name.startswith("yara."):
            message = "No module named 'yara'"
            raise ModuleNotFoundError(message, name=name)
        return None


def test_require_yara_returns_real_module() -> None:
    """``require_yara`` returns the genuine yara module when it is installed."""
    if importlib.util.find_spec("yara") is None:
        pytest.skip("yara-python is not installed in this environment")
    module = require_yara()
    assert module is importlib.import_module("yara")
    assert module.__name__ == "yara"
    assert hasattr(module, "compile")


@pytest.fixture
def yara_import_blocked() -> Generator[None]:
    """Force the real import machinery to fail for ``yara`` during a test.

    Removes any cached ``yara`` module and installs a real meta-path finder
    that refuses the name, then restores both on teardown so other tests still
    see the genuine module.

    Yields:
        None: Control returns to the test while yara importing is blocked.
    """
    saved = {name: mod for name, mod in sys.modules.items() if name == "yara" or name.startswith("yara.")}
    for name in saved:
        del sys.modules[name]
    finder = _BlockYaraFinder()
    sys.meta_path.insert(0, finder)
    try:
        yield
    finally:
        sys.meta_path.remove(finder)
        sys.modules.update(saved)


@pytest.mark.usefixtures("yara_import_blocked")
def test_require_yara_raises_sandbox_error_on_real_import_failure() -> None:
    """A genuine import failure surfaces as ``SandboxError`` with a warning log."""
    with capture_logs() as captured, pytest.raises(SandboxError) as exc_info:
        require_yara()

    assert "YARA-python" in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, ImportError)

    warnings = [entry for entry in captured if entry.get("event") == "yara_python_not_installed"]
    assert len(warnings) == 1
    assert warnings[0]["log_level"] == "warning"
    assert "yara" in str(warnings[0]["error"])
