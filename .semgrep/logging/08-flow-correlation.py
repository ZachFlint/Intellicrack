"""Test fixtures for 08-flow-correlation.yml.

NOTE: Path-scoped rules in this file are evaluated against the
intellicrack source tree layout. The fixture exercises pattern match
shape; full directory-scoped coverage is validated by semgrep's
test harness which treats the fixture file path as its own subject.
"""

from intellicrack.core.logging import get_logger

_logger = get_logger(__name__)


# ruleid: intellicrack-logging-h1-async-def-zero-logs
async def fn_h1_bad_no_log() -> None:
    s1 = 1
    s2 = 2
    s3 = s1 + s2


# ok: intellicrack-logging-h1-async-def-zero-logs
async def fn_h1_ok_has_log() -> None:
    _logger.info("async_op_started")
    s1 = 1
    s2 = 2


def fn_h2_bad() -> None:
    # ruleid: intellicrack-logging-h2-session-create-without-log
    session = Session(owner="tester")


def fn_h2_ok() -> None:
    _logger.info("session_creating")
    # ok: intellicrack-logging-h2-session-create-without-log
    session = Session(owner="tester")


class Session:
    def __init__(self, owner: str) -> None:
        self._logger = get_logger(__name__)
        self._state = "new"
        self._status = "active"

    def do_something(self) -> None:
        # ruleid: intellicrack-logging-h3-state-assignment-without-log
        self._state = "running"

    def do_with_log(self) -> None:
        self._logger.info("session_state_changed", new_state="running")
        # ok: intellicrack-logging-h3-state-assignment-without-log
        self._state = "running"


def fn_h4_bad() -> None:
    # ruleid: intellicrack-logging-h4-retry-loop-no-log
    for attempt in range(3):
        x = attempt + 1


def fn_h4_ok() -> None:
    # ok: intellicrack-logging-h4-retry-loop-no-log
    for attempt in range(3):
        _logger.info("retry_attempt", attempt=attempt)


class FridaBridgeNoInitLog:
    # ruleid: intellicrack-logging-h5-init-without-completion-log
    def __init__(self, host: str) -> None:
        self._host = host
        self._pid = None
        self._script = None
        self._session = None
        self._device = None


class FridaBridgeWithInitLog:
    # ok: intellicrack-logging-h5-init-without-completion-log
    def __init__(self, host: str) -> None:
        self._host = host
        self._pid = None
        self._script = None
        self._session = None
        self._device = None
        self._logger = get_logger(__name__)
        self._logger.info("frida_bridge_initialized", host=host)
