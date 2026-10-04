# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate: importing a bridge, the core or the providers package loads no provider SDK, PyTorch or Transformers.

``intellicrack.core.config`` reads the provider ids, so every bridge and the
whole of ``intellicrack.core`` import the providers package. That package once
imported every provider with it. Each provider module imports its SDK, and the
local Transformers provider imports PyTorch and Transformers: a fresh
interpreter loaded some 5,500 modules and took about seventeen seconds on a
workstation before it could import one bridge, on a loaded CI runner the
first-import gates ran past their two-minute limit, and
``python -m intellicrack --version`` ran past thirty seconds.

Every name the package exports is now resolved on first use. These gates start
real interpreters whose first import is the module under test and require the
SDK-backed submodules, and their libraries, to be absent afterwards; and they
hold the lazy exports to behaving like the eager ones did -- same objects, same
public names, same error for a name the package does not export.
"""

from __future__ import annotations

import importlib
from typing import Final

import pytest

import intellicrack.providers as providers_package
from intellicrack.providers.lazy_exports import LAZY_EXPORTS, resolve_lazy_export
from tests._helpers.child_python import run_child_json


_CHILD_TIMEOUT_S: Final[float] = 120.0
_HEAVY_LIBRARIES: Final[tuple[str, ...]] = ("torch", "transformers", "anthropic", "openai", "google.genai", "huggingface_hub")
_SDK_BACKED_SUBMODULES: Final[tuple[str, ...]] = tuple(
    f"intellicrack.providers.{name}"
    for name in ("anthropic", "google", "grok", "huggingface", "local_transformers", "model_loader", "openai", "xpu_utils")
)
"""The provider submodules that import an SDK, PyTorch or Transformers at module level."""
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
        dict[str, list[str]]: Under ``submodules``, the SDK-backed provider
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
            "submodules": sorted(name for name in {_SDK_BACKED_SUBMODULES!r} if name in sys.modules),
            "libraries": sorted(name for name in {_HEAVY_LIBRARIES!r} if name in sys.modules),
        }}))
        """,
        timeout_s=_CHILD_TIMEOUT_S,
    )
    return {key: [str(name) for name in value] for key, value in report.items()}


@pytest.mark.parametrize("module", _FIRST_IMPORTS)
def test_a_first_import_loads_neither_the_sdk_backed_submodules_nor_their_libraries(module: str) -> None:
    """A fresh interpreter that imports a bridge, the core or the providers package holds no SDK-backed provider module.

    Falsifiable: with any of those submodules imported by the package, every
    one of these first imports loads it and its library.

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


def test_lazy_exports_are_exactly_the_public_names() -> None:
    """The lazy exports and ``__all__`` name the same things, and all of them show up in ``dir()`` before being resolved."""
    assert set(LAZY_EXPORTS) == set(providers_package.__all__)
    assert set(LAZY_EXPORTS) <= set(dir(providers_package))
    assert set(_SDK_BACKED_SUBMODULES) <= set(LAZY_EXPORTS.values())


def test_a_name_the_package_does_not_export_is_still_an_attribute_error() -> None:
    """The lazy hook does not turn a typo into an import attempt or a different error."""
    with pytest.raises(AttributeError, match=f"no attribute '{_UNKNOWN_NAME}'"):
        _ = getattr(providers_package, _UNKNOWN_NAME)
    with pytest.raises(AttributeError, match=f"no attribute '{_UNKNOWN_NAME}'"):
        _ = resolve_lazy_export(_UNKNOWN_NAME)
