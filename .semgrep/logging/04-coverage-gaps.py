"""Test fixtures for 04-coverage-gaps.yml."""

import asyncio
import contextlib
import os
import shutil
import socket
import subprocess
import urllib.request
from contextlib import contextmanager, asynccontextmanager
from pathlib import Path

import httpx
import requests

from intellicrack.core.logging import get_logger

_logger = get_logger(__name__)


def fn_d1_bad() -> None:
    # ruleid: intellicrack-logging-d1-silent-except-block
    try:
        open("x")
    except FileNotFoundError:
        x = 1


def fn_d1_ok_log() -> None:
    # ok: intellicrack-logging-d1-silent-except-block
    try:
        open("x")
    except FileNotFoundError:
        _logger.exception("file_open_failed")


def fn_d1_ok_reraise() -> None:
    # ok: intellicrack-logging-d1-silent-except-block
    try:
        open("x")
    except FileNotFoundError:
        raise


def fn_d1_ok_reraise_chain() -> None:
    # ok: intellicrack-logging-d1-silent-except-block
    try:
        open("x")
    except FileNotFoundError as e:
        raise RuntimeError("wrap") from e


def fn_d1_ok_suppress() -> None:
    # ok: intellicrack-logging-d1-silent-except-block
    with contextlib.suppress(FileNotFoundError):
        open("x")


def fn_d2_bad() -> None:
    try:
        open("x")
    # ruleid: intellicrack-logging-d2-except-pass
    except FileNotFoundError:
        pass


def fn_d2_ok() -> None:
    try:
        open("x")
    # ok: intellicrack-logging-d2-except-pass
    except FileNotFoundError:
        _logger.exception("file_open_failed")


def fn_d3_bad() -> None:
    for i in range(3):
        try:
            open("x")
        # ruleid: intellicrack-logging-d3-except-continue
        except FileNotFoundError:
            continue


def fn_d4_bad() -> None:
    try:
        open("x")
    # ruleid: intellicrack-logging-d4-except-returns-silent
    except FileNotFoundError:
        return None


def fn_d5_bad(pid: int) -> None:
    # ruleid: intellicrack-logging-d5-raise-without-preceding-log
    raise RuntimeError("uhoh")


def fn_d5_ok_with_log(pid: int) -> None:
    _logger.warning("op_about_to_fail", pid=pid)
    # ok: intellicrack-logging-d5-raise-without-preceding-log
    raise RuntimeError("uhoh")


def fn_d5_ok_in_except() -> None:
    try:
        open("x")
    except FileNotFoundError as e:
        _logger.exception("file_missing")
        # ok: intellicrack-logging-d5-raise-without-preceding-log
        raise RuntimeError("boom") from e


class FridaBridge:
    def __init__(self) -> None:
        self._logger = get_logger(__name__)

    # ruleid: intellicrack-logging-d6-bridge-method-no-entry-log
    def attach_silent(self, pid: int) -> None:
        x = pid + 1

    # ok: intellicrack-logging-d6-bridge-method-no-entry-log
    def attach_logged(self, pid: int) -> None:
        self._logger.info("frida_attach_started", pid=pid)


def fn_d7_bad() -> None:
    # ruleid: intellicrack-logging-d7-subprocess-without-log
    subprocess.Popen(["ls"])


def fn_d7_bad_run() -> None:
    # ruleid: intellicrack-logging-d7-subprocess-without-log
    subprocess.run(["ls"])


def fn_d7_ok() -> None:
    _logger.info("subprocess_spawning", argv=["ls"])
    # ruleid: intellicrack-logging-d7-subprocess-without-log
    subprocess.run(["ls"])


def fn_d8_bad(path: Path) -> None:
    # ruleid: intellicrack-logging-d8-binary-write-without-log
    path.write_bytes(b"x")


def fn_d8_ok(path: Path) -> None:
    _logger.info("file_writing", path=str(path))
    # ruleid: intellicrack-logging-d8-binary-write-without-log
    path.write_bytes(b"x")


def fn_d9_bad(path: str) -> None:
    # ruleid: intellicrack-logging-d9-destructive-op-without-log
    os.remove(path)


def fn_d9_bad_rmtree(path: str) -> None:
    # ruleid: intellicrack-logging-d9-destructive-op-without-log
    shutil.rmtree(path)


def fn_d9_ok(path: str) -> None:
    _logger.info("deleting_file", path=path)
    # ruleid: intellicrack-logging-d9-destructive-op-without-log
    os.remove(path)


def fn_d10_bad() -> None:
    # ruleid: intellicrack-logging-d10-network-call-without-log
    requests.get("https://example.com")


def fn_d10_ok() -> None:
    _logger.info("http_request_starting", url="https://example.com")
    # ruleid: intellicrack-logging-d10-network-call-without-log
    requests.get("https://example.com")


def fn_d11_bad() -> None:
    # ruleid: intellicrack-logging-d11-retry-loop-without-per-attempt-log
    for attempt in range(3):
        x = attempt + 1


def fn_d11_ok() -> None:
    # ok: intellicrack-logging-d11-retry-loop-without-per-attempt-log
    for attempt in range(3):
        _logger.info("retry_attempt", attempt=attempt)


# ruleid: intellicrack-logging-d12-async-function-zero-logs
async def fn_d12_bad_bridge() -> None:
    x = 1


# ok: intellicrack-logging-d12-async-function-zero-logs
async def fn_d12_ok_bridge() -> None:
    _logger.info("async_op_started")


@contextmanager
# ruleid: intellicrack-logging-d13-context-manager-no-entry-exit-log
def cm_d13_bad():
    x = 1
    yield x


@contextmanager
# ok: intellicrack-logging-d13-context-manager-no-entry-exit-log
def cm_d13_ok():
    _logger.info("cm_entered")
    x = 1
    yield x


# ruleid: intellicrack-logging-d14-large-function-zero-logs
def fn_d14_bad() -> None:
    s1 = 1
    s2 = 2
    s3 = 3
    s4 = 4
    s5 = 5
    s6 = 6
    s7 = 7
    s8 = 8
    s9 = 9
    s10 = 10
    s11 = 11
    s12 = 12
    s13 = 13
    s14 = 14
    s15 = 15
    _ = s1 + s15


# ok: intellicrack-logging-d14-large-function-zero-logs
def fn_d14_ok() -> None:
    s1 = 1
    s2 = 2
    s3 = 3
    s4 = 4
    s5 = 5
    s6 = 6
    s7 = 7
    s8 = 8
    s9 = 9
    s10 = 10
    s11 = 11
    s12 = 12
    s13 = 13
    s14 = 14
    s15 = 15
    _logger.info("large_op_complete", size=s1 + s15)
