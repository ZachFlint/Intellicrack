"""Package entry point for running Intellicrack as a module.

This enables execution via: python -m intellicrack

Example:
    python -m intellicrack
    python -m intellicrack --version
    python -m intellicrack --help
"""

from __future__ import annotations

import logging
import sys


_logger = logging.getLogger("intellicrack.__main__")


def run() -> None:
    """Execute the Intellicrack application.

    This function serves as the main entry point when the package
    is invoked as a module. It imports and calls the main function
    from the main module, handling any import errors gracefully.
    """
    try:
        from intellicrack.main import main  # noqa: PLC0415
    except ImportError as e:
        _logger.exception("import_failed", extra={"error": str(e)})
        _logger.warning("dependency_check_hint")
        sys.exit(1)

    sys.exit(main())


if __name__ == "__main__":
    run()
