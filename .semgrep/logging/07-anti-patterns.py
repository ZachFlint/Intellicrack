"""Test fixtures for 07-anti-patterns.yml."""

import sys
import traceback
import logging

from intellicrack.core.logging import get_logger

_logger = get_logger(__name__)


def fn_g1_bad() -> None:
    # ruleid: intellicrack-logging-g1-print-in-src
    print("hello world")
    # ruleid: intellicrack-logging-g1-print-in-src
    sys.stdout.write("x\n")
    # ruleid: intellicrack-logging-g1-print-in-src
    sys.stderr.write("y\n")


def fn_g1_ok() -> None:
    # ok: intellicrack-logging-g1-print-in-src
    _logger.info("hello_world")


def fn_g2_bad() -> None:
    try:
        raise ValueError("x")
    except ValueError:
        # ruleid: intellicrack-logging-g2-traceback-as-kwarg
        _logger.error("op_failed", traceback_str=traceback.format_exc())


def fn_g2_ok() -> None:
    try:
        raise ValueError("x")
    except ValueError:
        # ok: intellicrack-logging-g2-traceback-as-kwarg
        _logger.exception("op_failed")


def fn_g3_bad() -> None:
    try:
        raise ValueError("x")
    except ValueError as e:
        # ruleid: intellicrack-logging-g3-exception-string-as-event-name
        _logger.error(str(e))
        # ruleid: intellicrack-logging-g3-exception-string-as-event-name
        _logger.error(repr(e))
        # ruleid: intellicrack-logging-g3-exception-string-as-event-name
        _logger.error(type(e).__name__)


def fn_g3_ok() -> None:
    try:
        raise ValueError("x")
    except ValueError as e:
        # ok: intellicrack-logging-g3-exception-string-as-event-name
        _logger.error("op_failed", error=str(e), error_type=type(e).__name__)


def fn_g4_bad(pid: int, addr: int) -> None:
    # ruleid: intellicrack-logging-g4-fstring-in-kwarg-value
    _logger.info("event", summary=f"pid={pid} addr={addr}")


def fn_g4_ok(pid: int, addr: int) -> None:
    # ok: intellicrack-logging-g4-fstring-in-kwarg-value
    _logger.info("event", pid=pid, address=hex(addr))


def fn_g5_bad(lvl: int) -> None:
    # ruleid: intellicrack-logging-g5-dynamic-log-level
    _logger.log(lvl, "something")


def fn_g5_ok() -> None:
    # ok: intellicrack-logging-g5-dynamic-log-level
    _logger.log(logging.INFO, "something")


def fn_g6_bad() -> None:
    try:
        raise Exception("x")
    except Exception as e:
        # ruleid: intellicrack-logging-g6-info-in-bare-except
        _logger.info("op_done", error=str(e))


def fn_g6_ok() -> None:
    try:
        raise ValueError("x")
    except ValueError as e:
        # ok: intellicrack-logging-g6-info-in-bare-except
        _logger.info("op_retryable", error=str(e))


def fn_g7_bad() -> None:
    # ruleid: intellicrack-logging-g7-bare-except-with-log
    try:
        open("x")
    except:
        _logger.exception("x")


def fn_g7_ok() -> None:
    # ok: intellicrack-logging-g7-bare-except-with-log
    try:
        open("x")
    except FileNotFoundError:
        _logger.exception("file_missing")


def fn_g8_bad() -> None:
    # ruleid: intellicrack-logging-g8-kwarg-value-is-none-literal
    _logger.info("event", value=None)


def fn_g8_ok() -> None:
    # ok: intellicrack-logging-g8-kwarg-value-is-none-literal
    _logger.info("event", value="missing")


def fn_g9_bad() -> None:
    # ruleid: intellicrack-logging-g9-kwarg-value-is-empty-collection
    _logger.info("event", items=[])
    # ruleid: intellicrack-logging-g9-kwarg-value-is-empty-collection
    _logger.info("event", mapping={})
    # ruleid: intellicrack-logging-g9-kwarg-value-is-empty-collection
    _logger.info("event", name="")
    # ruleid: intellicrack-logging-g9-kwarg-value-is-empty-collection
    _logger.info("event", tup=())
    # ruleid: intellicrack-logging-g9-kwarg-value-is-empty-collection
    _logger.info("event", items=list())
    # ruleid: intellicrack-logging-g9-kwarg-value-is-empty-collection
    _logger.info("event", items=set())


def fn_g9_ok() -> None:
    # ok: intellicrack-logging-g9-kwarg-value-is-empty-collection
    _logger.info("event", items_count=0)


def fn_g10_bad() -> None:
    try:
        raise ValueError("x")
    except ValueError:
        # ruleid: intellicrack-logging-g10-print-exc-before-log
        traceback.print_exc()
        _logger.error("op_failed")


def fn_g10_ok() -> None:
    try:
        raise ValueError("x")
    except ValueError:
        # ok: intellicrack-logging-g10-print-exc-before-log
        _logger.exception("op_failed")
