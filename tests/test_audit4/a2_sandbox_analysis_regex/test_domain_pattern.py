# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for F-0026: _DOMAIN_PATTERN over-broad hostname matching.

Each test is designed to:
- FAIL with the old regex (which accepted any 2+ letter trailing label),
- PASS with the fixed implementation (TLD allowlist + file-extension denylist).

The tests cover:
- File extensions that must not be accepted as TLDs.
- Real hostname strings that must be accepted.
- Internationalized hostnames in ACE form.
- Adversarial double-extension hostnames.
- extract_iocs integration: domain IOCs must not be produced for filenames.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.sandbox.analysis import extract_iocs
from intellicrack.sandbox.base import ExecutionReport
from intellicrack.sandbox.tld_data import FILE_EXTENSION_TLDS, KNOWN_TLDS


if TYPE_CHECKING:
    from collections.abc import Callable


_analysis_mod = importlib.import_module("intellicrack.sandbox.analysis")
_looks_like_domain: Callable[[str], bool] = getattr(_analysis_mod, "_looks_like_domain")
_has_valid_tld: Callable[[str], bool] = getattr(_analysis_mod, "_has_valid_tld")


def _empty_report(**kwargs: object) -> ExecutionReport:
    """Build a minimal ExecutionReport for IOC extraction tests.

    Args:
        **kwargs: Field overrides applied to the default empty report.

    Returns:
        ExecutionReport: A minimal report with all list fields empty except
            those supplied via kwargs.
    """
    defaults: dict[str, Any] = {
        "result": "success",
        "exit_code": 0,
        "stdout": "",
        "stderr": "",
        "duration_seconds": 1.0,
        "network_activity": [],
        "file_changes": [],
        "registry_changes": [],
        "process_activity": [],
        "api_calls": [],
        "service_changes": [],
        "kernel_objects": [],
        "dll_loads": [],
        "injection_events": [],
        "resource_samples": [],
        "clipboard_events": [],
    }
    defaults.update(kwargs)
    return ExecutionReport(**defaults)


class TestFileExtensionsRejected:
    """File-extension labels must not be matched as valid TLDs."""

    @pytest.mark.parametrize(
        "filename",
        [
            "kernel32.dll",
            "ntdll.dll",
            "payload.exe",
            "setup.cfg",
            "data.bin",
            "notes.txt",
            "script.py",
            "module.so",
            "archive.lib",
            "debug.pdb",
            "config.ini",
            "data.json",
            "settings.xml",
            "output.log",
            "compiled.pyc",
            "object.obj",
            "static.a",
            "driver.sys",
            "native.dylib",
            "bytecode.o",
        ],
    )
    def test_filename_not_matched_as_domain(self, filename: str) -> None:
        """File extension labels must not be recognised as valid TLDs.

        Args:
            filename: A filename string whose extension must not be treated as
                a TLD by _looks_like_domain.
        """
        assert not _looks_like_domain(filename), f"{filename!r} was incorrectly matched as a domain hostname"

    @pytest.mark.parametrize(
        "filename",
        [
            "kernel32.dll",
            "ntdll.dll",
            "payload.exe",
            "setup.cfg",
            "data.bin",
            "notes.txt",
            "script.py",
            "module.so",
        ],
    )
    def test_file_extension_tld_denylist_entry(self, filename: str) -> None:
        """The file-extension denylist must contain the trailing label.

        Args:
            filename: A filename whose extension must appear in FILE_EXTENSION_TLDS.
        """
        ext = filename.rsplit(".", 1)[-1].lower()
        assert ext in FILE_EXTENSION_TLDS, f"Extension {ext!r} from {filename!r} is not in FILE_EXTENSION_TLDS"


class TestRealHostnamesAccepted:
    """Genuine hostnames with valid TLDs must be accepted."""

    @pytest.mark.parametrize(
        "hostname",
        [
            "example.com",
            "mail.google.com",
            "sub.region.co.uk",
            "a.b.c.example.org",
            "update.microsoft.com",
            "cdn.example.net",
            "api.example.io",
            "service.example.info",
            "www.example.co",
            "host.example.ac",
        ],
    )
    def test_real_hostname_is_matched(self, hostname: str) -> None:
        """Valid hostnames with recognised TLDs must be accepted.

        Args:
            hostname: A genuine hostname string that must be accepted by
                _looks_like_domain.
        """
        assert _looks_like_domain(hostname), f"{hostname!r} was not recognised as a valid domain hostname"

    @pytest.mark.parametrize(
        "tld",
        [
            "com",
            "net",
            "org",
            "io",
            "uk",
            "de",
            "fr",
            "ru",
            "cn",
            "info",
        ],
    )
    def test_common_tld_in_allowlist(self, tld: str) -> None:
        """Common TLDs must appear in the KNOWN_TLDS allowlist.

        Args:
            tld: A well-known TLD string that must be present in KNOWN_TLDS.
        """
        assert tld in KNOWN_TLDS, f"Common TLD {tld!r} is missing from KNOWN_TLDS"


class TestInternationalizedHostnames:
    """ACE-encoded internationalized hostnames must be accepted."""

    @pytest.mark.parametrize(
        "hostname",
        [
            "xn--p1ai.xn--p1ai",
            "example.xn--p1ai",
        ],
    )
    def test_ace_hostname_accepted(self, hostname: str) -> None:
        """ACE-encoded internationalized hostnames must be recognised.

        Args:
            hostname: An ACE-encoded hostname string that must be accepted by
                _looks_like_domain.
        """
        assert _looks_like_domain(hostname), f"ACE hostname {hostname!r} was not recognised as a valid domain"

    def test_xn_p1ai_in_tld_allowlist(self) -> None:
        """The xn--p1ai TLD must appear in the KNOWN_TLDS allowlist."""
        assert "xn--p1ai" in KNOWN_TLDS


class TestAdversarialDoubleExtension:
    """Adversarial double-extension hostnames must be rejected."""

    @pytest.mark.parametrize(
        "hostname",
        [
            "sub.example.dll",
            "host.malware.exe",
            "payload.domain.bin",
            "server.host.sys",
            "update.patch.so",
        ],
    )
    def test_double_extension_rejected_as_hostname(self, hostname: str) -> None:
        """Hostnames whose trailing label is a file extension must be rejected.

        Args:
            hostname: A hostname-shaped string ending in a file-extension label
                that must not be accepted as a valid domain.
        """
        assert not _looks_like_domain(hostname), f"{hostname!r} with file-extension TLD was incorrectly accepted as a domain"


class TestHasValidTldFunction:
    """Unit tests for the _has_valid_tld helper function directly."""

    def test_rejects_exe_tld(self) -> None:
        """Candidate with .exe trailing label must be rejected."""
        assert not _has_valid_tld("malware.exe")

    def test_rejects_dll_tld(self) -> None:
        """Candidate with .dll trailing label must be rejected."""
        assert not _has_valid_tld("library.dll")

    def test_rejects_unknown_tld(self) -> None:
        """Candidate with an unrecognised trailing label must be rejected."""
        assert not _has_valid_tld("host.fakeunknownxyz")

    def test_accepts_com_tld(self) -> None:
        """Candidate with .com trailing label must be accepted."""
        assert _has_valid_tld("example.com")

    def test_accepts_org_tld(self) -> None:
        """Candidate with .org trailing label must be accepted."""
        assert _has_valid_tld("example.org")

    def test_accepts_net_tld(self) -> None:
        """Candidate with .net trailing label must be accepted."""
        assert _has_valid_tld("example.net")

    def test_rejects_single_label(self) -> None:
        """Single-label candidate (no dot) must be rejected."""
        assert not _has_valid_tld("localhost")

    def test_case_insensitive_tld(self) -> None:
        """TLD check must be case-insensitive."""
        assert _has_valid_tld("example.COM")
        assert _has_valid_tld("example.Com")
        assert not _has_valid_tld("example.DLL")


class TestExtractIocsIntegration:
    """Integration: extract_iocs must not emit domain IOCs for file paths."""

    def test_dll_path_not_extracted_as_domain(self) -> None:
        """DLL file paths in file_changes must not produce domain IOCs."""
        report = _empty_report(
            file_changes=[
                {
                    "path": "C:\\Windows\\System32\\kernel32.dll",
                    "operation": "read",
                    "timestamp": "2024-01-01T00:00:00",
                    "size": 1024,
                    "old_path": None,
                },
            ],
        )
        iocs = extract_iocs(report)
        domain_values = [ioc["value"] for ioc in iocs if ioc["ioc_type"] == "domain"]
        assert "kernel32.dll" not in domain_values, "kernel32.dll was incorrectly emitted as a domain IOC"

    def test_exe_path_not_extracted_as_domain(self) -> None:
        """EXE file paths in process_activity must not produce domain IOCs."""
        report = _empty_report(
            process_activity=[
                {
                    "pid": 1234,
                    "name": "payload.exe",
                    "operation": "create",
                    "timestamp": "2024-01-01T00:00:00",
                    "path": "C:\\temp\\payload.exe",
                    "command_line": "payload.exe --silent",
                    "parent_pid": None,
                    "exit_code": None,
                },
            ],
        )
        iocs = extract_iocs(report)
        domain_values = [ioc["value"] for ioc in iocs if ioc["ioc_type"] == "domain"]
        assert "payload.exe" not in domain_values, "payload.exe was incorrectly emitted as a domain IOC"

    def test_real_domain_in_registry_extracted(self) -> None:
        """Genuine domains in registry values must still be extracted as IOCs."""
        report = _empty_report(
            registry_changes=[
                {
                    "key": "HKCU\\Software\\Update",
                    "operation": "set",
                    "timestamp": "2024-01-01T00:00:00",
                    "value_name": "Server",
                    "value_type": "REG_SZ",
                    "value_data": "update.example.com",
                },
            ],
        )
        iocs = extract_iocs(report)
        domain_values = [ioc["value"] for ioc in iocs if ioc["ioc_type"] == "domain"]
        assert any(val == "update.example.com" for val in domain_values), "update.example.com was not extracted as a domain IOC"

    def test_txt_filename_in_command_line_not_extracted(self) -> None:
        """Text filenames in command lines must not produce domain IOCs."""
        report = _empty_report(
            process_activity=[
                {
                    "pid": 5678,
                    "name": "cmd.exe",
                    "operation": "create",
                    "timestamp": "2024-01-01T00:00:00",
                    "path": None,
                    "command_line": "type notes.txt && copy data.bin out.log",
                    "parent_pid": None,
                    "exit_code": None,
                },
            ],
        )
        iocs = extract_iocs(report)
        domain_values = [ioc["value"] for ioc in iocs if ioc["ioc_type"] == "domain"]
        for bad in ("notes.txt", "data.bin", "out.log"):
            assert bad not in domain_values, f"{bad!r} was incorrectly emitted as a domain IOC from command line"
