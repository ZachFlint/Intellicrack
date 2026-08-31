"""Test fixtures for 02-event-names.yml."""

from intellicrack.core.logging import get_logger

_logger = get_logger(__name__)
_EVT_ATTACH = "process_attached"


def fn_b1_bad(pid: int) -> None:
    # ruleid: intellicrack-logging-b1-no-fstring-event-name
    _logger.info(f"attached to pid {pid}")
    # ruleid: intellicrack-logging-b1-no-fstring-event-name
    _logger.warning(f"pid={pid} detached")
    # ruleid: intellicrack-logging-b1-no-fstring-event-name
    _logger.error(f"pid={pid} failed")
    # ruleid: intellicrack-logging-b1-no-fstring-event-name
    _logger.debug(f"pid={pid} debug")
    # ruleid: intellicrack-logging-b1-no-fstring-event-name
    _logger.exception(f"pid={pid} exc")
    # ruleid: intellicrack-logging-b1-no-fstring-event-name
    _logger.critical(f"pid={pid} crit")


def fn_b1_ok(pid: int) -> None:
    # ok: intellicrack-logging-b1-no-fstring-event-name
    _logger.info("process_attached", pid=pid)


def fn_b2_bad(pid: int) -> None:
    # ruleid: intellicrack-logging-b2-no-format-call-event-name
    _logger.info("attached_pid_{}".format(pid))
    # ruleid: intellicrack-logging-b2-no-format-call-event-name
    _logger.error("failed_{}".format(pid))


def fn_b2_ok(pid: int) -> None:
    # ok: intellicrack-logging-b2-no-format-call-event-name
    _logger.info("process_attached", pid=pid)


def fn_b3_bad(pid: int) -> None:
    # ruleid: intellicrack-logging-b3-no-percent-format-event-name
    _logger.info("pid_%s" % pid)
    # ruleid: intellicrack-logging-b3-no-percent-format-event-name
    _logger.warning("pid_%d_attached" % pid)


def fn_b4_bad(event_suffix: str) -> None:
    # ruleid: intellicrack-logging-b4-no-concat-event-name
    _logger.info("prefix_" + event_suffix)
    # ruleid: intellicrack-logging-b4-no-concat-event-name
    _logger.warning(event_suffix + "_suffix")


def fn_b5_bad() -> None:
    # ruleid: intellicrack-logging-b5-no-sentence-event-name
    _logger.info("Failed to attach to the target process because the pid was invalid")
    # ruleid: intellicrack-logging-b5-no-sentence-event-name
    _logger.error("Something went wrong while opening the binary file for writing")


def fn_b5_ok(pid: int) -> None:
    # ok: intellicrack-logging-b5-no-sentence-event-name
    _logger.info("frida_attach_failed", pid=pid)
    # ok: intellicrack-logging-b5-no-sentence-event-name
    _logger.info("binary_open_failed", pid=pid)


def fn_b6_bad() -> None:
    # ruleid: intellicrack-logging-b6-no-generic-event-name
    _logger.error("error")
    # ruleid: intellicrack-logging-b6-no-generic-event-name
    _logger.warning("failed")
    # ruleid: intellicrack-logging-b6-no-generic-event-name
    _logger.info("done")
    # ruleid: intellicrack-logging-b6-no-generic-event-name
    _logger.info("ok")
    # ruleid: intellicrack-logging-b6-no-generic-event-name
    _logger.info("success")
    # ruleid: intellicrack-logging-b6-no-generic-event-name
    _logger.info("start")
    # ruleid: intellicrack-logging-b6-no-generic-event-name
    _logger.info("started")
    # ruleid: intellicrack-logging-b6-no-generic-event-name
    _logger.info("finished")
    # ruleid: intellicrack-logging-b6-no-generic-event-name
    _logger.error("something_went_wrong")
    # ruleid: intellicrack-logging-b6-no-generic-event-name
    _logger.error("unknown")
    # ruleid: intellicrack-logging-b6-no-generic-event-name
    _logger.warning("unexpected")
    # ruleid: intellicrack-logging-b6-no-generic-event-name
    _logger.warning("problem")
    # ruleid: intellicrack-logging-b6-no-generic-event-name
    _logger.warning("issue")


def fn_b6_ok() -> None:
    # ok: intellicrack-logging-b6-no-generic-event-name
    _logger.info("frida_attach_started")
    # ok: intellicrack-logging-b6-no-generic-event-name
    _logger.warning("patch_failed")
    # ok: intellicrack-logging-b6-no-generic-event-name
    _logger.info("scan_completed")


def fn_b7_bad(dynamic_event: str) -> None:
    # ruleid: intellicrack-logging-b7-no-dynamic-event-name
    _logger.info(dynamic_event)
    # ruleid: intellicrack-logging-b7-no-dynamic-event-name
    _logger.info("static_name_" + dynamic_event if dynamic_event else "other")


def fn_b7_ok() -> None:
    # ok: intellicrack-logging-b7-no-dynamic-event-name
    _logger.info(_EVT_ATTACH)
    # ok: intellicrack-logging-b7-no-dynamic-event-name
    _logger.info("scan_completed")


def fn_b8_bad(pid: int) -> None:
    # ruleid: intellicrack-logging-b8-no-format-markers-in-event-name
    _logger.info("pid_is_{pid}")
    # ruleid: intellicrack-logging-b8-no-format-markers-in-event-name
    _logger.info("pid_%s")
    # ruleid: intellicrack-logging-b8-no-format-markers-in-event-name
    _logger.info("addr_%d_attached")


def fn_b9_bad() -> None:
    # ruleid: intellicrack-logging-b9-event-name-redundant-with-level
    _logger.error("error_attach_failed")
    # ruleid: intellicrack-logging-b9-event-name-redundant-with-level
    _logger.warning("warning_low_memory")
    # ruleid: intellicrack-logging-b9-event-name-redundant-with-level
    _logger.debug("debug_probe_hit")


def fn_b9_ok() -> None:
    # ok: intellicrack-logging-b9-event-name-redundant-with-level
    _logger.error("attach_failed")
    # ok: intellicrack-logging-b9-event-name-redundant-with-level
    _logger.warning("low_memory")


def fn_b10_bad() -> None:
    # ruleid: intellicrack-logging-b10-event-name-single-noun
    _logger.info("process")
    # ruleid: intellicrack-logging-b10-event-name-single-noun
    _logger.info("file")
    # ruleid: intellicrack-logging-b10-event-name-single-noun
    _logger.info("memory")


def fn_b10_ok() -> None:
    # ok: intellicrack-logging-b10-event-name-single-noun
    _logger.info("process_attached")
    # ok: intellicrack-logging-b10-event-name-single-noun
    _logger.info("file_opened")
