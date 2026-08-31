# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for the public ``intellicrack.providers`` package surface.

These tests ensure that internal-only names which have no consumers via
``intellicrack.providers.<name>`` are not re-exported from the package's
``__init__``. The audit identified three such dead re-exports
(``DiscoveryEvent``, ``DtypeOption``, ``ModelConfig``) which leak
implementation details and inflate the documented public API. Callers must
import these directly from the submodule that owns them
(``intellicrack.providers.discovery`` and
``intellicrack.providers.model_loader``).
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from types import ModuleType


_PACKAGE_NAME: str = "intellicrack.providers"
_DEAD_REEXPORTS: tuple[str, ...] = ("DiscoveryEvent", "DtypeOption", "ModelConfig")


def _load_providers_package() -> ModuleType:
    """Return a freshly imported ``intellicrack.providers`` module.

    Returns:
        ModuleType: The package module reloaded so that ``__all__`` and the
            attribute table reflect the current source on disk rather than
            any cached state from earlier tests.
    """
    module = importlib.import_module(_PACKAGE_NAME)
    return importlib.reload(module)


def test_dead_reexports_removed_from_all() -> None:
    """``DiscoveryEvent``/``DtypeOption``/``ModelConfig`` must not be in ``__all__``."""
    providers = _load_providers_package()
    public_api: list[str] = list(getattr(providers, "__all__", []))
    leaked: list[str] = [name for name in _DEAD_REEXPORTS if name in public_api]
    assert not leaked, f"Dead re-exports still present in __all__: {leaked}"


def test_dead_reexports_not_attribute_accessible() -> None:
    """The dead names must not be attributes of the providers package.

    Importing them only to satisfy ``__all__`` would leak them as package
    attributes too, so this test pairs with the ``__all__`` check to keep
    the re-export removed at both surfaces.
    """
    providers = _load_providers_package()
    leaked: list[str] = [name for name in _DEAD_REEXPORTS if hasattr(providers, name)]
    assert not leaked, f"Dead re-exports still attribute-accessible on package: {leaked}"


def test_canonical_sources_still_export_names() -> None:
    """The canonical submodules must continue to expose the dead names.

    The fix only removes the package-level re-export. Internal callers (and
    any external consumer that imports them directly from the owning
    submodule) must still be able to obtain the symbols from their real
    source modules.
    """
    discovery = importlib.import_module(f"{_PACKAGE_NAME}.discovery")
    assert hasattr(discovery, "DiscoveryEvent"), "DiscoveryEvent missing from intellicrack.providers.discovery"
    model_loader = importlib.import_module(f"{_PACKAGE_NAME}.model_loader")
    assert hasattr(model_loader, "DtypeOption"), "DtypeOption missing from intellicrack.providers.model_loader"
    assert hasattr(model_loader, "ModelConfig"), "ModelConfig missing from intellicrack.providers.model_loader"
