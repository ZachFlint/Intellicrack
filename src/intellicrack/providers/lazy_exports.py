# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Exports of :mod:`intellicrack.providers` that are resolved on first use.

The local Transformers provider, the model loader and the XPU utilities import
PyTorch and Transformers at module level. Importing them with the package
loaded both libraries into every process that imports anything under
:mod:`intellicrack.providers` -- which, through ``intellicrack.core.config``,
is every bridge and the whole of :mod:`intellicrack.core`. A fresh interpreter
spent several seconds on a workstation, and more than a minute on a loaded CI
runner, before it could import a single bridge.

The package still exports their names. It resolves each one here the first
time it is asked for, so only a process that really uses a local model pays
for the libraries.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Final


if TYPE_CHECKING:
    from collections.abc import Mapping


_PACKAGE: Final[str] = "intellicrack.providers"
_LOCAL_TRANSFORMERS_MODULE: Final[str] = f"{_PACKAGE}.local_transformers"
_MODEL_LOADER_MODULE: Final[str] = f"{_PACKAGE}.model_loader"
_XPU_UTILS_MODULE: Final[str] = f"{_PACKAGE}.xpu_utils"

LAZY_EXPORTS: Final[Mapping[str, str]] = {
    "LocalTransformersProvider": _LOCAL_TRANSFORMERS_MODULE,
    "LoadedModel": _MODEL_LOADER_MODULE,
    "ModelCache": _MODEL_LOADER_MODULE,
    "clear_global_cache": _MODEL_LOADER_MODULE,
    "estimate_model_memory": _MODEL_LOADER_MODULE,
    "get_global_model_cache": _MODEL_LOADER_MODULE,
    "load_model_for_cpu": _MODEL_LOADER_MODULE,
    "load_model_for_xpu": _MODEL_LOADER_MODULE,
    "set_global_cache_size": _MODEL_LOADER_MODULE,
    "XPUDeviceInfo": _XPU_UTILS_MODULE,
    "check_windows_requirements": _XPU_UTILS_MODULE,
    "clear_xpu_cache": _XPU_UTILS_MODULE,
    "get_optimal_dtype_for_xpu": _XPU_UTILS_MODULE,
    "get_xpu_device_count": _XPU_UTILS_MODULE,
    "get_xpu_device_info": _XPU_UTILS_MODULE,
    "get_xpu_memory_info": _XPU_UTILS_MODULE,
    "initialize_xpu": _XPU_UTILS_MODULE,
    "is_arc_b580": _XPU_UTILS_MODULE,
    "is_xpu_available": _XPU_UTILS_MODULE,
}
"""Each lazily resolved export of the package, and the submodule that defines it."""


def resolve_lazy_export(name: str) -> object:
    """Import the submodule that defines a lazily resolved export and return the export.

    Args:
        name: Attribute name requested from :mod:`intellicrack.providers`.

    Returns:
        object: The export, taken from the submodule that defines it.

    Raises:
        AttributeError: If ``name`` is not a lazily resolved export.
    """
    module_name = LAZY_EXPORTS.get(name)
    if module_name is None:
        msg = f"module {_PACKAGE!r} has no attribute {name!r}"
        raise AttributeError(msg)
    value: object = getattr(importlib.import_module(module_name), name)
    return value
