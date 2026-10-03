# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate: importing a bridge, the core or the providers package loads neither PyTorch nor Transformers.

``intellicrack.core.config`` reads the provider ids, so every bridge and the
whole of ``intellicrack.core`` import the providers package. That package once
imported its local Transformers provider, model loader and XPU utilities along
with everything else, and those three import PyTorch and Transformers at module
level: a fresh interpreter loaded some 5,500 modules and took about seventeen
seconds on a workstation before it could import one bridge, and on a loaded CI
runner the first-import gates ran past their two-minute limit.

The three submodules' names are now exported lazily. These gates start real
interpreters whose first import is the module under test and require the three
submodules, and the two libraries, to be absent afterwards; and they hold the
lazy exports to behaving like the eager ones did -- same objects, same public
names, same error for a name the package does not export.
"""

from __future__ import annotations

import importlib
from typing import Final

import pytest

import intellicrack.providers as providers_package
from intellicrack.providers.lazy_exports import LAZY_EXPORTS, resolve_lazy_export
from tests._helpers.child_python import run_child_json


_CHILD_TIMEOUT_S: Final[float] = 120.0
_HEAVY_LIBRARIES: Final[tuple[str, ...]] = ("torch", "transformers")
_FIRST_IMPORTS: Final[tuple[str, ...]] = (
    "intellicrack.bridges.base",
    "intellicrack.bridges.hex_editor",
    "intellicrack.core",
    "intellicrack.core.config",
    "intellicrack.providers",
)
_UNKNOWN_NAME: Final[str] = "DefinitelyNotAProviderExport"


def _loaded_after_first_import(module: str) -> dict[str, list[str]]:
    """Import one module first in a fresh interpreter and report what that pulled in.

    Args:
        module: The module the child imports before anything else of Intellicrack's.

    Returns:
        dict[str, list[str]]: Under ``submodules``, the lazily exported
        submodules the import loaded; under ``libraries``, the heavy libraries
        it loaded.
    """
    report = run_child_json(
        f"""
        import importlib
        import json
        import sys

        importlib.import_module({module!r})
        print(json.dumps({{
            "submodules": sorted(name for name in {sorted(set(LAZY_EXPORTS.values()))!r} if name in sys.modules),
            "libraries": sorted(name for name in {_HEAVY_LIBRARIES!r} if name in sys.modules),
        }}))
        """,
        timeout_s=_CHILD_TIMEOUT_S,
    )
    return {key: [str(name) for name in value] for key, value in report.items()}


@pytest.mark.parametrize("module", _FIRST_IMPORTS)
def test_a_first_import_loads_neither_the_torch_backed_submodules_nor_their_libraries(module: str) -> None:
    """A fresh interpreter that imports a bridge, the core or the providers package holds no PyTorch-backed module.

    Falsifiable: with the three submodules imported by the package, every one
    of these first imports loads all three and both libraries.

    Args:
        module: The module the fresh interpreter imports first.
    """
    loaded = _loaded_after_first_import(module)

    assert loaded["submodules"] == [], f"importing {module} loaded {loaded['submodules']}"
    assert loaded["libraries"] == [], f"importing {module} loaded {loaded['libraries']}"


def test_asking_for_a_lazy_export_imports_its_submodule_and_caches_the_result() -> None:
    """The first use of a lazy export in a fresh interpreter imports the submodule that defines it and nothing is resolved twice."""
    report = run_child_json(
        """
        import json
        import sys

        import intellicrack.providers as providers

        module = "intellicrack.providers.local_transformers"
        before = module in sys.modules
        provider = providers.LocalTransformersProvider
        print(json.dumps({
            "before": before,
            "after": module in sys.modules,
            "defined_in": provider.__module__,
            "cached": vars(providers).get("LocalTransformersProvider") is provider,
        }))
        """,
        timeout_s=_CHILD_TIMEOUT_S,
    )

    assert report == {"before": False, "after": True, "defined_in": "intellicrack.providers.local_transformers", "cached": True}


@pytest.mark.parametrize(("name", "module"), sorted(LAZY_EXPORTS.items()))
def test_a_lazy_export_is_the_object_its_submodule_defines(name: str, module: str) -> None:
    """Each lazy export, read from the package, is the very object the submodule defines.

    Args:
        name: The exported name.
        module: The submodule that defines it.
    """
    defined = getattr(importlib.import_module(module), name)

    assert getattr(providers_package, name) is defined
    assert resolve_lazy_export(name) is defined


def test_every_public_name_of_the_package_resolves() -> None:
    """Every name in ``__all__`` can be read from the package, whether it is imported eagerly or lazily."""
    missing = [name for name in providers_package.__all__ if not hasattr(providers_package, name)]

    assert missing == [], f"names in __all__ that the package cannot provide: {missing}"


def test_lazy_exports_are_public_and_listed() -> None:
    """Each lazy export is part of the public API and shows up in ``dir()`` before it has been resolved."""
    assert set(LAZY_EXPORTS) <= set(providers_package.__all__)
    assert set(LAZY_EXPORTS) <= set(dir(providers_package))


def test_a_name_the_package_does_not_export_is_still_an_attribute_error() -> None:
    """The lazy hook does not turn a typo into an import attempt or a different error."""
    with pytest.raises(AttributeError, match=f"no attribute '{_UNKNOWN_NAME}'"):
        _ = getattr(providers_package, _UNKNOWN_NAME)
    with pytest.raises(AttributeError, match=f"no attribute '{_UNKNOWN_NAME}'"):
        _ = resolve_lazy_export(_UNKNOWN_NAME)
