# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for the window-station and desktop grant a confined launch depends on.

A confined server runs with a restricted Low integrity token whose Administrators
group is deny-only. Under a service or an elevated runner the window station and
its desktop grant access only through that group, so the confined child cannot
reach them and dies with ``STATUS_DLL_INIT_FAILED`` while its GUI DLLs
initialize. :func:`grant_window_station_and_desktop` repairs this by granting the
token's own identities. These gates read the real station and desktop access
lists back to prove it grants both the account SID and the logon-session SID, and
that the station grant carries the standard rights an open requests rather than
the station-specific bits alone -- the two properties whose absence let the
child be refused on the hosted runner.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import ClassVar

import pytest

from intellicrack.mcp.sandbox_launch import create_restricted_token, grant_window_station_and_desktop


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="window stations, desktops and restricted tokens are Windows-only Win32 facilities",
)

_DACL_SECURITY_INFORMATION = 0x00000004
_SDDL_REVISION_1 = 1
_TOKEN_USER_CLASS = 1
_TOKEN_GROUPS_CLASS = 2
_SE_GROUP_LOGON_ID = 0xC0000000
_ERROR_INSUFFICIENT_BUFFER = 122
_EXPECTED_STATION_MASK = 0x37F | 0x000F0000


class _SidAndAttributes(ctypes.Structure):
    """Win32 ``SID_AND_ATTRIBUTES``."""

    _fields_: ClassVar = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    """Win32 ``TOKEN_USER``."""

    _fields_: ClassVar = [("User", _SidAndAttributes)]


def _sid_string(sid: int) -> str:
    """Render a security identifier as its SDDL string.

    Args:
        sid: The security identifier, as an address into a live buffer.

    Returns:
        str: The SID in ``S-1-...`` form.

    Raises:
        ctypes.WinError: If the SID could not be converted.
    """
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    out = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(sid), ctypes.byref(out)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return out.value or ""
    finally:
        ctypes.WinDLL("kernel32").LocalFree(out)


def _token_user_sid_string(token: int) -> str:
    """Read the account SID a token runs as.

    Args:
        token: The token to read.

    Returns:
        str: The account SID in SDDL form.

    Raises:
        ctypes.WinError: If the token's user could not be read.
    """
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    needed = wintypes.DWORD(0)
    advapi32.GetTokenInformation(wintypes.HANDLE(token), _TOKEN_USER_CLASS, None, 0, ctypes.byref(needed))
    if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER or not needed.value:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_string_buffer(needed.value)
    if not advapi32.GetTokenInformation(wintypes.HANDLE(token), _TOKEN_USER_CLASS, buffer, needed, ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    return _sid_string(ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents.User.Sid or 0)


def _token_logon_sid_string(token: int) -> str:
    """Read the logon-session SID a token carries.

    Args:
        token: The token to read.

    Returns:
        str: The logon SID in SDDL form.

    Raises:
        ctypes.WinError: If the token's groups could not be read.
        AssertionError: If the token carries no logon SID.
    """
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    needed = wintypes.DWORD(0)
    advapi32.GetTokenInformation(wintypes.HANDLE(token), _TOKEN_GROUPS_CLASS, None, 0, ctypes.byref(needed))
    if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER or not needed.value:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_string_buffer(needed.value)
    if not advapi32.GetTokenInformation(wintypes.HANDLE(token), _TOKEN_GROUPS_CLASS, buffer, needed, ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
    stride = ctypes.sizeof(_SidAndAttributes)
    base = ctypes.alignment(_SidAndAttributes)
    for index in range(count):
        entry = _SidAndAttributes.from_buffer(buffer, base + index * stride)
        if entry.Attributes & _SE_GROUP_LOGON_ID == _SE_GROUP_LOGON_ID:
            return _sid_string(entry.Sid or 0)
    message = "the restricted token carries no logon SID"
    raise AssertionError(message)


def _object_dacl_sddl(handle: int) -> str:
    """Read a window station or desktop's access list as SDDL.

    Args:
        handle: The window station or desktop to read.

    Returns:
        str: The object's DACL in SDDL.

    Raises:
        ctypes.WinError: If the object's security could not be read or converted.
    """
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    info = wintypes.DWORD(_DACL_SECURITY_INFORMATION)
    needed = wintypes.DWORD(0)
    user32.GetUserObjectSecurity(wintypes.HANDLE(handle), ctypes.byref(info), None, 0, ctypes.byref(needed))
    if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER or not needed.value:
        raise ctypes.WinError(ctypes.get_last_error())
    descriptor = ctypes.create_string_buffer(needed.value)
    if not user32.GetUserObjectSecurity(wintypes.HANDLE(handle), ctypes.byref(info), descriptor, needed, ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    out = wintypes.LPWSTR()
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.ULONG),
    ]
    if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor,
        _SDDL_REVISION_1,
        _DACL_SECURITY_INFORMATION,
        ctypes.byref(out),
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return out.value or ""
    finally:
        ctypes.WinDLL("kernel32").LocalFree(out)


class TestWindowStationGrant:
    """The grant reaches both the account and the logon identity, with the rights an open needs."""

    def test_grant_adds_both_identities_with_station_standard_rights(self) -> None:
        """Both SIDs are granted on the station and desktop, and the station grant carries standard rights.

        The account SID and the logon SID must each appear in the station and the
        desktop access lists after the grant: a window station names the logon SID
        in its own entries, so granting only the account would leave the child
        refused. The station entry must carry the standard rights an open requests
        on top of the station-specific bits; granting the station-specific bits
        alone (``0x37f``) is refused on the hosted runner.
        """
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.GetProcessWindowStation.restype = wintypes.HANDLE
        user32.GetThreadDesktop.restype = wintypes.HANDLE
        kernel32.GetCurrentThreadId.restype = wintypes.DWORD

        token = create_restricted_token()
        try:
            user_sid = _token_user_sid_string(token)
            logon_sid = _token_logon_sid_string(token)
            grant_window_station_and_desktop(token)
            station_dacl = _object_dacl_sddl(int(user32.GetProcessWindowStation()))
            desktop_dacl = _object_dacl_sddl(int(user32.GetThreadDesktop(kernel32.GetCurrentThreadId())))
        finally:
            kernel32.CloseHandle(wintypes.HANDLE(token))

        assert user_sid in station_dacl, f"account SID {user_sid} not granted on the station: {station_dacl}"
        assert logon_sid in station_dacl, f"logon SID {logon_sid} not granted on the station: {station_dacl}"
        assert user_sid in desktop_dacl, f"account SID {user_sid} not granted on the desktop: {desktop_dacl}"
        assert logon_sid in desktop_dacl, f"logon SID {logon_sid} not granted on the desktop: {desktop_dacl}"
        expected_ace = f"(A;;0x{_EXPECTED_STATION_MASK:x};;;{logon_sid})"
        assert expected_ace in station_dacl, f"station grant for the logon SID lacks the standard rights: {station_dacl}"
