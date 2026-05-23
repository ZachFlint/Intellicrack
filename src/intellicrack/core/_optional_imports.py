# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Optional third-party module imports for Intellicrack.

This module provides helpers for importing third-party libraries that may not be installed in all environments, with consistent structured
logging and error handling.
"""

import importlib
from types import ModuleType

from intellicrack.core.logging import get_logger
from intellicrack.core.types import SandboxError


_logger = get_logger(__name__)

_ERR_YARA_NOT_AVAILABLE: str = "YARA-python library is not available"


def require_yara() -> ModuleType:
    """Import yara-python or raise SandboxError with structured logging.

    Returns:
        ModuleType: The imported yara module.

    Raises:
        SandboxError: If the yara-python package cannot be imported.
    """
    try:
        return importlib.import_module("yara")
    except ImportError as exc:
        _logger.warning("yara_python_not_installed", error=str(exc))
        raise SandboxError(_ERR_YARA_NOT_AVAILABLE) from exc
