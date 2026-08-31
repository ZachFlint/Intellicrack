"""Test fixtures for 05-severity-levels.yml."""

from intellicrack.core.logging import get_logger

_logger = get_logger(__name__)


def fn_e1_bad() -> None:
    try:
        raise ValueError("x")
    except ValueError as e:
        # ruleid: intellicrack-logging-e1-info-inside-except
        _logger.info("attach_failed", error=str(e))


def fn_e1_ok() -> None:
    try:
        raise ValueError("x")
    except ValueError:
        # ok: intellicrack-logging-e1-info-inside-except
        _logger.exception("attach_failed")


def fn_e2_bad() -> None:
    try:
        raise ValueError("x")
    except ValueError as e:
        # ruleid: intellicrack-logging-e2-debug-inside-except
        _logger.debug("attach_failed_debug", error=str(e))


def fn_e3_bad_reraise() -> None:
    try:
        raise ValueError("x")
    except ValueError as e:
        # ruleid: intellicrack-logging-e3-error-on-reraise
        _logger.error("attach_failed", error=str(e))
        raise


def fn_e3_bad_chain() -> None:
    try:
        raise ValueError("x")
    except ValueError as e:
        # ruleid: intellicrack-logging-e3-error-on-reraise
        _logger.error("attach_failed", error=str(e))
        raise RuntimeError("wrapped") from e


def fn_e3_ok_exception_then_raise() -> None:
    try:
        raise ValueError("x")
    except ValueError:
        # ok: intellicrack-logging-e3-error-on-reraise
        _logger.exception("attach_failed")
        raise


def fn_e3_ok_warning_then_raise() -> None:
    try:
        raise ValueError("x")
    except ValueError as e:
        # ok: intellicrack-logging-e3-error-on-reraise
        _logger.warning("attach_retryable", error=str(e))
        raise


def fn_e4_bad() -> None:
    # ruleid: intellicrack-logging-e4-critical-outside-allowlist
    _logger.critical("something_terrible")
    # ruleid: intellicrack-logging-e4-critical-outside-allowlist
    _logger.fatal("totally_dead")


def fn_e4_ok() -> None:
    # ok: intellicrack-logging-e4-critical-outside-allowlist
    _logger.error("attach_failed")


def fn_e5_bad() -> None:
    # ruleid: intellicrack-logging-e5-warning-announces-success
    _logger.warning("process_attached")
    # ruleid: intellicrack-logging-e5-warning-announces-success
    _logger.warning("scan_completed")
    # ruleid: intellicrack-logging-e5-warning-announces-success
    _logger.warning("patch_applied")
    # ruleid: intellicrack-logging-e5-warning-announces-success
    _logger.warning("op_success")


def fn_e5_ok() -> None:
    # ok: intellicrack-logging-e5-warning-announces-success
    _logger.info("process_attached")
    # ok: intellicrack-logging-e5-warning-announces-success
    _logger.warning("attach_retrying")


def fn_e6_bad() -> None:
    # ruleid: intellicrack-logging-e6-debug-on-destructive-op
    _logger.debug("patch_applied")
    # ruleid: intellicrack-logging-e6-debug-on-destructive-op
    _logger.debug("process_killed")
    # ruleid: intellicrack-logging-e6-debug-on-destructive-op
    _logger.debug("file_deleted")
    # ruleid: intellicrack-logging-e6-debug-on-destructive-op
    _logger.debug("memory_written")


def fn_e6_ok() -> None:
    # ok: intellicrack-logging-e6-debug-on-destructive-op
    _logger.info("patch_applied")
    # ok: intellicrack-logging-e6-debug-on-destructive-op
    _logger.debug("memory_read_started")


def fn_e7_bad() -> None:
    # ruleid: intellicrack-logging-e7-info-on-error-event
    _logger.info("attach_failed")
    # ruleid: intellicrack-logging-e7-info-on-error-event
    _logger.info("auth_denied")
    # ruleid: intellicrack-logging-e7-info-on-error-event
    _logger.info("request_timeout")
    # ruleid: intellicrack-logging-e7-info-on-error-event
    _logger.info("binary_not_found")
    # ruleid: intellicrack-logging-e7-info-on-error-event
    _logger.info("op_invalid")


def fn_e7_ok() -> None:
    # ok: intellicrack-logging-e7-info-on-error-event
    _logger.warning("attach_failed")
    # ok: intellicrack-logging-e7-info-on-error-event
    _logger.info("attach_started")
