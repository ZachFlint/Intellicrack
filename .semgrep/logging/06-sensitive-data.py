"""Test fixtures for 06-sensitive-data.yml."""

import os
from os import environ, getenv

import requests

from intellicrack.core.logging import get_logger

_logger = get_logger(__name__)


def fn_f1_bad_password() -> None:
    # ruleid: intellicrack-logging-f1-sensitive-kwarg-name
    _logger.info("login_attempt", password="hunter2")


def fn_f1_bad_token() -> None:
    # ruleid: intellicrack-logging-f1-sensitive-kwarg-name
    _logger.info("auth_ok", token="abc")


def fn_f1_bad_api_key() -> None:
    # ruleid: intellicrack-logging-f1-sensitive-kwarg-name
    _logger.info("provider_configured", api_key="sk-abc")


def fn_f1_bad_authorization() -> None:
    # ruleid: intellicrack-logging-f1-sensitive-kwarg-name
    _logger.info("request_sending", authorization="Bearer xyz")


def fn_f1_bad_credential() -> None:
    # ruleid: intellicrack-logging-f1-sensitive-kwarg-name
    _logger.info("store_access", credential="value")


def fn_f1_bad_cookie() -> None:
    # ruleid: intellicrack-logging-f1-sensitive-kwarg-name
    _logger.info("request_sending", cookie="sid=abc")


def fn_f1_bad_private_key() -> None:
    # ruleid: intellicrack-logging-f1-sensitive-kwarg-name
    _logger.info("ssh_loaded", private_key="-----BEGIN")


def fn_f1_ok() -> None:
    # ok: intellicrack-logging-f1-sensitive-kwarg-name
    _logger.info("auth_ok", token_prefix="abc", token_sha256="deadbeef")
    # ok: intellicrack-logging-f1-sensitive-kwarg-name
    _logger.info("store_access", key_id="openai_api_key")


def fn_f2_bad() -> None:
    # ruleid: intellicrack-logging-f2-logging-environment-variable
    _logger.info("config_loaded", value=os.environ["OPENAI_API_KEY"])
    # ruleid: intellicrack-logging-f2-logging-environment-variable
    _logger.info("config_loaded", value=os.environ.get("TOKEN"))
    # ruleid: intellicrack-logging-f2-logging-environment-variable
    _logger.info("config_loaded", value=os.getenv("SECRET"))
    # ruleid: intellicrack-logging-f2-logging-environment-variable
    _logger.info("config_loaded", value=environ["SECRET"])
    # ruleid: intellicrack-logging-f2-logging-environment-variable
    _logger.info("config_loaded", value=getenv("SECRET"))


def fn_f2_ok() -> None:
    # ok: intellicrack-logging-f2-logging-environment-variable
    _logger.info("config_loaded", var_name="OPENAI_API_KEY")


def fn_f3_bad() -> None:
    req = requests.Request("GET", "https://example.com")
    # ruleid: intellicrack-logging-f3-logging-http-auth-material
    _logger.info("request_sending", headers=req.headers)
    resp = requests.Response()
    # ruleid: intellicrack-logging-f3-logging-http-auth-material
    _logger.info("response_received", cookies=resp.cookies)


def fn_f3_ok() -> None:
    req = requests.Request("GET", "https://example.com")
    # ok: intellicrack-logging-f3-logging-http-auth-material
    _logger.info("request_sending", header_names=list(req.headers.keys()))


def fn_f4_bad() -> None:
    resp = requests.get("https://example.com")
    # ruleid: intellicrack-logging-f4-logging-http-body
    _logger.info("response_received", body=resp.text)
    # ruleid: intellicrack-logging-f4-logging-http-body
    _logger.info("response_received", body=resp.content)
    # ruleid: intellicrack-logging-f4-logging-http-body
    _logger.info("response_received", body=resp.json())


def fn_f4_ok() -> None:
    resp = requests.get("https://example.com")
    # ok: intellicrack-logging-f4-logging-http-body
    _logger.info("response_received", status=resp.status_code, size=len(resp.content))


def fn_f5_bad(data: bytes, buffer: bytearray) -> None:
    # ruleid: intellicrack-logging-f5-logging-raw-bytes-payload
    _logger.info("buf_dump", data=data)
    # ruleid: intellicrack-logging-f5-logging-raw-bytes-payload
    _logger.info("buf_dump", buffer=buffer)
    # ruleid: intellicrack-logging-f5-logging-raw-bytes-payload
    _logger.info("buf_dump", payload=data)


def fn_f5_ok(data: bytes) -> None:
    # ok: intellicrack-logging-f5-logging-raw-bytes-payload
    _logger.info("buf_dump", size=len(data), head_hex=data[:16].hex())


def fn_f6_bad() -> None:
    # ruleid: intellicrack-logging-f6-high-entropy-literal-in-log
    _logger.info("config_set", token="sk-proj-AbCdEf0123456789AbCdEf0123456789AbCdEf")


def fn_f6_ok() -> None:
    # ok: intellicrack-logging-f6-high-entropy-literal-in-log
    _logger.info("config_set", key_id="default_openai")
