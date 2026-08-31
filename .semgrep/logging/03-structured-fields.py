"""Test fixtures for 03-structured-fields.yml."""

from intellicrack.core.logging import get_logger

_logger = get_logger(__name__)


def fn_c1_bad() -> None:
    try:
        raise ValueError("x")
    except ValueError as e:
        # ruleid: intellicrack-logging-c1-except-log-missing-error-context
        _logger.info("operation_done")


def fn_c1_ok(pid: int) -> None:
    try:
        raise ValueError("x")
    except ValueError as e:
        # ok: intellicrack-logging-c1-except-log-missing-error-context
        _logger.warning("operation_failed", pid=pid, error=str(e))


def fn_c2_bad_pid(pid: int) -> None:
    # ruleid: intellicrack-logging-c2-missing-function-context-kwargs
    _logger.info("process_op_started")


def fn_c2_bad_binary(binary_path: str) -> None:
    # ruleid: intellicrack-logging-c2-missing-function-context-kwargs
    _logger.info("binary_opened")


def fn_c2_bad_session(session_id: str) -> None:
    # ruleid: intellicrack-logging-c2-missing-function-context-kwargs
    _logger.warning("session_op_failed")


def fn_c2_ok_pid(pid: int) -> None:
    # ok: intellicrack-logging-c2-missing-function-context-kwargs
    _logger.info("process_op_started", pid=pid)


def fn_c2_ok_binary(binary_path: str) -> None:
    # ok: intellicrack-logging-c2-missing-function-context-kwargs
    _logger.info("binary_opened", binary_path=binary_path)


def fn_c3_bad() -> None:
    # ruleid: intellicrack-logging-c3-reserved-logrecord-key
    _logger.info("process_started", name="firefox")
    # ruleid: intellicrack-logging-c3-reserved-logrecord-key
    _logger.info("process_started", message="hello")
    # ruleid: intellicrack-logging-c3-reserved-logrecord-key
    _logger.info("process_started", msg="hello")
    # ruleid: intellicrack-logging-c3-reserved-logrecord-key
    _logger.info("process_started", levelname="INFO")
    # ruleid: intellicrack-logging-c3-reserved-logrecord-key
    _logger.info("process_started", filename="main.py")
    # ruleid: intellicrack-logging-c3-reserved-logrecord-key
    _logger.info("process_started", module="core")
    # ruleid: intellicrack-logging-c3-reserved-logrecord-key
    _logger.info("process_started", thread="t1")
    # ruleid: intellicrack-logging-c3-reserved-logrecord-key
    _logger.info("process_started", args=[1, 2])


def fn_c3_ok() -> None:
    # ok: intellicrack-logging-c3-reserved-logrecord-key
    _logger.info("process_started", process_name="firefox")
    # ok: intellicrack-logging-c3-reserved-logrecord-key
    _logger.info("process_started", tool_name="frida")
    # ok: intellicrack-logging-c3-reserved-logrecord-key
    _logger.info("process_started", exc_info=True)
    # ok: intellicrack-logging-c3-reserved-logrecord-key
    _logger.warning("operation_retrying", stack_info=True)


def fn_c4_bad() -> None:
    try:
        raise ValueError("x")
    except ValueError as e:
        # ruleid: intellicrack-logging-c4-redundant-error-on-exception
        _logger.exception("process_op_failed", error=str(e))
    try:
        raise ValueError("y")
    except ValueError as e:
        # ruleid: intellicrack-logging-c4-redundant-error-on-exception
        _logger.exception("process_op_failed", err=str(e))
    try:
        raise ValueError("z")
    except ValueError as e:
        # ruleid: intellicrack-logging-c4-redundant-error-on-exception
        _logger.exception("process_op_failed", error=repr(e))


def fn_c4_ok(pid: int) -> None:
    try:
        raise ValueError("x")
    except ValueError:
        # ok: intellicrack-logging-c4-redundant-error-on-exception
        _logger.exception("process_op_failed", pid=pid)


def fn_c5_bad() -> None:
    # ruleid: intellicrack-logging-c5-exception-call-outside-except
    _logger.exception("standalone_exception_call")


def fn_c5_ok() -> None:
    try:
        raise ValueError("x")
    except ValueError:
        # ok: intellicrack-logging-c5-exception-call-outside-except
        _logger.exception("process_op_failed")


def fn_c5_ok_else() -> None:
    try:
        raise ValueError("x")
    except ValueError:
        # ok: intellicrack-logging-c5-exception-call-outside-except
        _logger.exception("process_op_failed_else")
    else:
        _logger.info("process_op_ok")


def fn_c5_ok_finally() -> None:
    try:
        raise ValueError("x")
    except ValueError:
        # ok: intellicrack-logging-c5-exception-call-outside-except
        _logger.exception("process_op_failed_finally")
    finally:
        _logger.info("process_op_cleanup")


def fn_c5_ok_else_finally() -> None:
    try:
        raise ValueError("x")
    except ValueError:
        # ok: intellicrack-logging-c5-exception-call-outside-except
        _logger.exception("process_op_failed_else_finally")
    else:
        _logger.info("process_op_ok")
    finally:
        _logger.info("process_op_cleanup")


def fn_c5_ok_multi_except() -> None:
    try:
        raise ValueError("x")
    except ImportError:
        _logger.warning("process_missing_dep")
    except ValueError:
        # ok: intellicrack-logging-c5-exception-call-outside-except
        _logger.exception("process_op_failed_multi")


def fn_c5_ok_tuple_else() -> None:
    try:
        raise ValueError("x")
    except (ValueError, RuntimeError, OSError):
        # ok: intellicrack-logging-c5-exception-call-outside-except
        _logger.exception("process_op_failed_tuple_else")
    else:
        _logger.info("process_op_ok")


def fn_c5_ok_tuple_finally() -> None:
    try:
        raise ValueError("x")
    except (ValueError, RuntimeError, OSError, KeyError):
        # ok: intellicrack-logging-c5-exception-call-outside-except
        _logger.exception("process_op_failed_tuple_finally")
    finally:
        _logger.info("process_op_cleanup")


def fn_c6_bad() -> None:
    try:
        raise ValueError("x")
    except ValueError as e:
        # ruleid: intellicrack-logging-c6-raw-exception-as-kwarg-value
        _logger.warning("op_failed", error=e)
    try:
        raise ValueError("y")
    except ValueError as e:
        # ruleid: intellicrack-logging-c6-raw-exception-as-kwarg-value
        _logger.warning("op_failed", exception=e)


def fn_c6_ok() -> None:
    try:
        raise ValueError("x")
    except ValueError as e:
        # ok: intellicrack-logging-c6-raw-exception-as-kwarg-value
        _logger.warning("op_failed", error=str(e))


def fn_c7_bad(pid: int) -> None:
    # ruleid: intellicrack-logging-c7-duplicated-data-in-event-and-kwargs
    _logger.info(f"pid={pid} attached", pid=pid)


def fn_c8_bad(path: str) -> None:
    # ruleid: intellicrack-logging-c8-non-loggable-value-type
    _logger.info("file_opened", handle=open(path, "rb"))
    # ruleid: intellicrack-logging-c8-non-loggable-value-type
    _logger.info("bytes_sent", payload=bytes(1024))
    # ruleid: intellicrack-logging-c8-non-loggable-value-type
    _logger.info("buf_alloc", buf=bytearray(512))


def fn_c8_ok(path: str) -> None:
    # ok: intellicrack-logging-c8-non-loggable-value-type
    _logger.info("file_opened", path=path, size=1024)
