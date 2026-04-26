# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Sandbox implementations for isolated binary execution.

This package provides sandbox environments for safe execution and behavioral analysis of potentially malicious binaries.
"""

from __future__ import annotations

from intellicrack.sandbox import _log_parsers as log_parsers
from intellicrack.sandbox.base import (
    ApiCall,
    BehaviorMatch,
    ClipboardEvent,
    DllLoadEvent,
    ExecutionReport,
    ExecutionResult,
    FileChange,
    FileOperation,
    InjectionEvent,
    IOCEntry,
    KernelObjectActivity,
    NetworkActivity,
    ProcessActivity,
    ProcessOperation,
    RegistryChange,
    RegistryOperation,
    ResourceSample,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxState,
    SandboxStatus,
    SandboxTimeoutError,
    ServiceChange,
    TimelineEvent,
    validate_file_operation,
    validate_process_operation,
    validate_registry_operation,
)
from intellicrack.sandbox.manager import SandboxInstance, SandboxManager, SandboxType
from intellicrack.sandbox.qemu import AcceleratorType, GuestOS, QEMUConfig, QEMUSandbox
from intellicrack.sandbox.windows import WindowsSandbox


__all__: list[str] = [
    "AcceleratorType",
    "ApiCall",
    "BehaviorMatch",
    "ClipboardEvent",
    "DllLoadEvent",
    "ExecutionReport",
    "ExecutionResult",
    "FileChange",
    "FileOperation",
    "GuestOS",
    "IOCEntry",
    "InjectionEvent",
    "KernelObjectActivity",
    "NetworkActivity",
    "ProcessActivity",
    "ProcessOperation",
    "QEMUConfig",
    "QEMUSandbox",
    "RegistryChange",
    "RegistryOperation",
    "ResourceSample",
    "SandboxBase",
    "SandboxConfig",
    "SandboxError",
    "SandboxInstance",
    "SandboxManager",
    "SandboxState",
    "SandboxStatus",
    "SandboxTimeoutError",
    "SandboxType",
    "ServiceChange",
    "TimelineEvent",
    "WindowsSandbox",
    "log_parsers",
    "validate_file_operation",
    "validate_process_operation",
    "validate_registry_operation",
]
