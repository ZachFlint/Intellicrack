"""Test fixtures for 10-meta-suppressions.yml."""

import logging

from intellicrack.core.logging import get_logger

_logger = get_logger(__name__)


def fn_j1_bad() -> None:
    # ruleid: intellicrack-logging-j1-forbidden-noqa-on-logging-rules
    _logger.info("event %s", "arg")  # noqa: G101
    # ruleid: intellicrack-logging-j1-forbidden-noqa-on-logging-rules
    _logger.info("event")  # noqa: LOG015
    try:
        pass
    # ruleid: intellicrack-logging-j1-forbidden-noqa-on-logging-rules
    except Exception:  # noqa: BLE001
        pass
    try:
        pass
    # ruleid: intellicrack-logging-j1-forbidden-noqa-on-logging-rules
    except Exception:  # noqa: TRY400
        _logger.error("x")
        raise


def fn_j1_ok() -> None:
    # ok: intellicrack-logging-j1-forbidden-noqa-on-logging-rules
    _logger.info("event_ok")  # noqa: E501


def fn_j2_bad() -> None:
    # ruleid: intellicrack-logging-j2-logging-disable
    logging.disable(logging.WARNING)


def fn_j2_ok() -> None:
    # ok: intellicrack-logging-j2-logging-disable
    _logger.setLevel(logging.INFO)


def fn_j3_bad() -> None:
    # ruleid: intellicrack-logging-j3-library-level-muting
    _logger.setLevel(logging.ERROR)
    # ruleid: intellicrack-logging-j3-library-level-muting
    _logger.setLevel(logging.CRITICAL)
    # ruleid: intellicrack-logging-j3-library-level-muting
    _logger.setLevel("ERROR")
    # ruleid: intellicrack-logging-j3-library-level-muting
    logging.getLogger("noisy").setLevel(logging.ERROR)


def fn_j3_ok() -> None:
    # ok: intellicrack-logging-j3-library-level-muting
    _logger.setLevel(logging.INFO)
    # ok: intellicrack-logging-j3-library-level-muting
    _logger.setLevel(logging.DEBUG)
