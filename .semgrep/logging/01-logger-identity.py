"""Test fixtures for 01-logger-identity.yml."""

import logging as logging
from logging import getLogger
from intellicrack.core.logging import get_logger


# ruleid: intellicrack-logging-a1-no-stdlib-getlogger
_logger_bad_a1_a = logging.getLogger(__name__)

# ruleid: intellicrack-logging-a1-no-stdlib-getlogger
_logger_bad_a1_b = getLogger(__name__)

# ok: intellicrack-logging-a1-no-stdlib-getlogger
_logger_ok_a1 = get_logger(__name__)


def fn_a2_bad() -> None:
    # ruleid: intellicrack-logging-a2-no-root-logger-calls
    logging.info("anything")
    # ruleid: intellicrack-logging-a2-no-root-logger-calls
    logging.warning("anything")
    # ruleid: intellicrack-logging-a2-no-root-logger-calls
    logging.error("anything")
    # ruleid: intellicrack-logging-a2-no-root-logger-calls
    logging.debug("anything")
    # ruleid: intellicrack-logging-a2-no-root-logger-calls
    logging.exception("anything")
    # ruleid: intellicrack-logging-a2-no-root-logger-calls
    logging.critical("anything")
    # ruleid: intellicrack-logging-a2-no-root-logger-calls
    logging.log(logging.INFO, "anything")


def fn_a2_ok() -> None:
    # ok: intellicrack-logging-a2-no-root-logger-calls
    _logger_ok_a1.info("operation_done")


# ruleid: intellicrack-logging-a3-get-logger-requires-dunder-name
_logger_bad_a3_a = get_logger("bridges.frida")

# ruleid: intellicrack-logging-a3-get-logger-requires-dunder-name
_logger_bad_a3_b = get_logger('literal_name')

# ok: intellicrack-logging-a3-get-logger-requires-dunder-name
_logger_ok_a3 = get_logger(__name__)


class ClassNoInitLogger:
    def do_something(self) -> None:
        # ruleid: intellicrack-logging-a4-module-uses-undefined-self-logger
        self._logger.info("event_a4_bad")


class ClassWithInitLogger:
    def __init__(self) -> None:
        self._logger = get_logger(__name__)

    def do_something(self) -> None:
        # ok: intellicrack-logging-a4-module-uses-undefined-self-logger
        self._logger.info("event_a4_ok")


class ClassWithAnnotatedInitLogger:
    def __init__(self) -> None:
        self._logger: object = get_logger(__name__)

    def do_something(self) -> None:
        # ok: intellicrack-logging-a4-module-uses-undefined-self-logger
        self._logger.debug("event_a4_annotated_ok")


# ruleid: intellicrack-logging-a5-multiple-module-loggers
_logger = get_logger(__name__)
_logger = get_logger(__name__)


# ruleid: intellicrack-logging-a6-logger-must-be-private-module-attr
logger = get_logger(__name__)

# ruleid: intellicrack-logging-a6-logger-must-be-private-module-attr
log = get_logger(__name__)

# ruleid: intellicrack-logging-a6-logger-must-be-private-module-attr
LOGGER = get_logger(__name__)
