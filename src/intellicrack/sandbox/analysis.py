# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Post-analysis capabilities for sandbox execution reports.

This module provides host-side post-processing functions that operate on collected ExecutionReport data from sandbox runs, including C2
pattern detection, IOC extraction, timeline generation, behavioral matching, and report diffing.
"""

from __future__ import annotations

import math
import operator
import re
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from intellicrack.core.logging import get_logger
from intellicrack.sandbox.base import (
    BehaviorMatch,
    ExecutionReport,
    IOCEntry,
    NetworkActivity,
    TimelineEvent,
)


_logger = get_logger("sandbox.analysis")

_IPV4_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_URL_PATTERN = re.compile(r"(https?://\S+)")
_MD5_PATTERN = re.compile(r"\b([a-fA-F0-9]{32})\b")
_SHA1_PATTERN = re.compile(r"\b([a-fA-F0-9]{40})\b")
_SHA256_PATTERN = re.compile(r"\b([a-fA-F0-9]{64})\b")
_EMAIL_PATTERN = re.compile(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")
_DOMAIN_PATTERN = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,})\b",
)

_C2_PORTS: frozenset[int] = frozenset(
    {4444, 5555, 8080, 8443, 1337, 31337, 6666, 6667, 9999},
)

_UNSPECIFIED_ADDR = "0.0.0.0"  # noqa: S104

_PRIVATE_IP_PREFIXES: tuple[str, ...] = (
    "10.",
    "127.",
    _UNSPECIFIED_ADDR,
)

_PRIVATE_172_OCTET_MIN = 16
_PRIVATE_172_OCTET_MAX = 31
_IPV4_OCTET_COUNT = 4
_IPV4_OCTET_MAX = 255
_MIN_IPV4_PARTS_FOR_172 = 2

_DOH_PROVIDERS: frozenset[str] = frozenset(
    {"1.1.1.1", "8.8.8.8", "8.8.4.4", "1.0.0.1", "9.9.9.9"},
)

_SYSTEM_DISCOVERY_TOOLS: frozenset[str] = frozenset(
    {"systeminfo.exe", "whoami.exe", "ipconfig.exe", "net.exe", "net1.exe"},
)

_ANTI_DEBUG_APIS: frozenset[str] = frozenset(
    {"IsDebuggerPresent", "NtQueryInformationProcess", "CheckRemoteDebuggerPresent"},
)

_PERSISTENCE_REGISTRY_PATTERNS: tuple[str, ...] = (
    "\\Run\\",
    "\\RunOnce\\",
    "\\CurrentVersion\\Run",
    "\\RunServices\\",
    "\\RunServicesOnce\\",
)

_EXFIL_THRESHOLD_BYTES: int = 1_048_576

_BEACONING_CV_THRESHOLD = 0.3
_BEACONING_MIN_CONNECTIONS = 3
_BEACONING_MIN_INTERVALS = 2
_DGA_ENTROPY_THRESHOLD = 3.5
_DGA_ENTROPY_NORMALIZER = 2.0
_C2_PORT_BASE_CONFIDENCE = 0.5
_C2_PORT_CONFIDENCE_INCREMENT = 0.05
_HTTPS_PORT = 443
_HIGH_FREQ_HTTPS_THRESHOLD = 10
_HIGH_FREQ_HTTPS_NORMALIZER = 50.0
_EXFIL_RATIO_THRESHOLD = 10
_EXFIL_BASE_CONFIDENCE = 0.4
_SLEEP_EVASION_THRESHOLD_MS = 60000
_IOC_CONTEXT_MAX_LEN = 200
_CLIPBOARD_PREVIEW_MAX_LEN = 80


def _is_private_ip(ip: str) -> bool:
    """Check whether an IPv4 address is private or reserved.

    Args:
        ip: The IPv4 address string to check.

    Returns:
        bool: True if the address is private or reserved.
    """
    if ip.startswith(_PRIVATE_IP_PREFIXES):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= _MIN_IPV4_PARTS_FOR_172:
            try:
                second_octet = int(parts[1])
            except ValueError:
                return False
            if _PRIVATE_172_OCTET_MIN <= second_octet <= _PRIVATE_172_OCTET_MAX:
                return True
    return ip.startswith("192.168.")


def _is_valid_ipv4(ip: str) -> bool:
    """Validate that a string is a well-formed IPv4 address.

    Args:
        ip: The string to validate.

    Returns:
        bool: True if the string is a valid IPv4 address.
    """
    parts = ip.split(".")
    if len(parts) != _IPV4_OCTET_COUNT:
        return False
    for part in parts:
        try:
            val = int(part)
        except ValueError:
            return False
        if val < 0 or val > _IPV4_OCTET_MAX:
            return False
    return True


def _looks_like_domain(address: str) -> bool:
    """Determine whether an address looks like a domain name rather than an IP.

    Args:
        address: The address string to evaluate.

    Returns:
        bool: True if the address appears to be a domain name.
    """
    if _IPV4_PATTERN.fullmatch(address):
        return False
    return bool(_DOMAIN_PATTERN.fullmatch(address))


def _shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string.

    Args:
        text: The input string.

    Returns:
        float: The Shannon entropy value.
    """
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


def _extract_identity_key(
    item: dict[str, Any],
    key_fields: list[str],
) -> str:
    """Build an identity key from specified fields of a dict.

    Args:
        item: The dictionary to extract keys from.
        key_fields: The field names to use for the identity key.

    Returns:
        str: A pipe-separated identity key string.
    """
    return "|".join(str(item.get(field_name, "")) for field_name in key_fields)


def _collect_matching_evidence(
    items: list[dict[str, Any]],
    match_field: str,
    pattern: str,
    format_fn: str,
) -> list[str]:
    """Collect evidence strings from items matching a substring pattern.

    Args:
        items: The list of dicts to search.
        match_field: The field name to check for substring match.
        pattern: The lowercase pattern to match against.
        format_fn: A format prefix for the evidence string.

    Returns:
        list[str]: List of formatted evidence strings.
    """
    results: list[str] = []
    for item in items:
        field_val = str(item.get(match_field, ""))
        if pattern in field_val.lower():
            results.append(f"{format_fn}: {field_val}")
    return results


def detect_c2_patterns(
    network_activity: list[NetworkActivity],
) -> list[dict[str, Any]]:
    """Detect command-and-control communication patterns in network activity.

    Analyzes network activity for beaconing behavior, DGA domains, known C2
    ports, and data exfiltration indicators.

    Args:
        network_activity: List of network activity records to analyze.

    Returns:
        list[dict[str, Any]]: List of detected C2 pattern dicts, each with
            keys ``pattern_type``, ``confidence``, ``description``,
            ``indicators``, and ``remote_addresses``.
    """
    _logger.debug("detect_c2_patterns_start", activity_count=len(network_activity))
    patterns: list[dict[str, Any]] = []

    _detect_beaconing(network_activity, patterns)
    _detect_dga_domains(network_activity, patterns)
    _detect_c2_ports(network_activity, patterns)
    _detect_exfiltration_patterns(network_activity, patterns)

    _logger.debug("detect_c2_patterns_complete", patterns_found=len(patterns))
    return patterns


def _detect_beaconing(
    network_activity: list[NetworkActivity],
    patterns: list[dict[str, Any]],
) -> None:
    """Detect periodic beaconing patterns in network connections.

    Args:
        network_activity: List of network activity records.
        patterns: Accumulator list to append detected patterns to.
    """
    connections_by_endpoint: dict[str, list[str]] = defaultdict(list)
    for activity in network_activity:
        endpoint = f"{activity['remote_address']}:{activity['remote_port']}"
        connections_by_endpoint[endpoint].append(activity["timestamp"])

    for endpoint, timestamps in connections_by_endpoint.items():
        if len(timestamps) < _BEACONING_MIN_CONNECTIONS:
            continue
        sorted_ts = sorted(timestamps)
        intervals: list[float] = []
        for i in range(1, len(sorted_ts)):
            try:
                t1 = datetime.fromisoformat(sorted_ts[i - 1])
                t2 = datetime.fromisoformat(sorted_ts[i])
                intervals.append((t2 - t1).total_seconds())
            except (ValueError, TypeError):
                continue

        if len(intervals) < _BEACONING_MIN_INTERVALS:
            continue

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0:
            continue

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        cv = std_dev / mean_interval

        if cv < _BEACONING_CV_THRESHOLD:
            jitter = max(intervals) - min(intervals) if intervals else 0.0
            remote_addr = endpoint.rsplit(":", 1)[0]
            confidence = max(0.0, min(1.0, 1.0 - cv))
            patterns.append({
                "pattern_type": "beaconing",
                "confidence": round(confidence, 3),
                "description": (f"Periodic beaconing detected to {endpoint} with mean interval {mean_interval:.1f}s (CV={cv:.3f})"),
                "indicators": [
                    f"Connection count: {len(timestamps)}",
                    f"Mean interval: {mean_interval:.1f}s",
                    f"Std deviation: {std_dev:.1f}s",
                    f"Coefficient of variation: {cv:.3f}",
                    f"Jitter range: {jitter:.1f}s",
                ],
                "remote_addresses": [remote_addr],
            })


def _detect_dga_domains(
    network_activity: list[NetworkActivity],
    patterns: list[dict[str, Any]],
) -> None:
    """Detect domain generation algorithm patterns via entropy analysis.

    Args:
        network_activity: List of network activity records.
        patterns: Accumulator list to append detected patterns to.
    """
    seen_domains: set[str] = set()
    for activity in network_activity:
        addr = activity["remote_address"]
        if addr in seen_domains:
            continue
        seen_domains.add(addr)
        if not _looks_like_domain(addr):
            continue
        domain_parts = addr.split(".")
        sld = domain_parts[0] if domain_parts else addr
        entropy = _shannon_entropy(sld)
        if entropy > _DGA_ENTROPY_THRESHOLD:
            confidence = min(
                1.0,
                (entropy - _DGA_ENTROPY_THRESHOLD) / _DGA_ENTROPY_NORMALIZER,
            )
            patterns.append({
                "pattern_type": "dga_domain",
                "confidence": round(confidence, 3),
                "description": (f"High-entropy domain detected: {addr} (entropy={entropy:.2f})"),
                "indicators": [
                    f"Domain: {addr}",
                    f"Second-level domain: {sld}",
                    f"Shannon entropy: {entropy:.2f}",
                ],
                "remote_addresses": [addr],
            })


def _detect_c2_ports(
    network_activity: list[NetworkActivity],
    patterns: list[dict[str, Any]],
) -> None:
    """Detect connections to known C2 ports and high-frequency HTTPS.

    Args:
        network_activity: List of network activity records.
        patterns: Accumulator list to append detected patterns to.
    """
    port_connections: dict[int, list[str]] = defaultdict(list)
    for activity in network_activity:
        port = activity["remote_port"]
        port_connections[port].append(activity["remote_address"])

    for port, addresses in port_connections.items():
        if port in _C2_PORTS:
            unique_addrs = list(set(addresses))
            confidence = min(
                1.0,
                _C2_PORT_BASE_CONFIDENCE + len(addresses) * _C2_PORT_CONFIDENCE_INCREMENT,
            )
            patterns.append({
                "pattern_type": "known_c2_port",
                "confidence": round(confidence, 3),
                "description": (f"Connections on known C2 port {port} ({len(addresses)} connection(s))"),
                "indicators": [
                    f"Port: {port}",
                    f"Connection count: {len(addresses)}",
                    f"Unique remote hosts: {len(unique_addrs)}",
                ],
                "remote_addresses": unique_addrs,
            })

        if port == _HTTPS_PORT and len(addresses) >= _HIGH_FREQ_HTTPS_THRESHOLD:
            unique_addrs = list(set(addresses))
            confidence = min(1.0, len(addresses) / _HIGH_FREQ_HTTPS_NORMALIZER)
            patterns.append({
                "pattern_type": "high_frequency_443",
                "confidence": round(confidence, 3),
                "description": (f"High-frequency HTTPS connections ({len(addresses)} connections on port {_HTTPS_PORT})"),
                "indicators": [
                    f"Connection count: {len(addresses)}",
                    f"Unique remote hosts: {len(unique_addrs)}",
                ],
                "remote_addresses": unique_addrs,
            })


def _detect_exfiltration_patterns(
    network_activity: list[NetworkActivity],
    patterns: list[dict[str, Any]],
) -> None:
    """Detect data exfiltration indicators from disproportionate outbound data.

    Args:
        network_activity: List of network activity records.
        patterns: Accumulator list to append detected patterns to.
    """
    for activity in network_activity:
        sent = activity["bytes_sent"]
        received = activity["bytes_received"]
        if sent > 0 and received > 0 and sent > received * _EXFIL_RATIO_THRESHOLD:
            addr = activity["remote_address"]
            confidence = min(1.0, _EXFIL_BASE_CONFIDENCE + (sent / (sent + received)))
            patterns.append({
                "pattern_type": "data_exfiltration",
                "confidence": round(confidence, 3),
                "description": (f"Disproportionate outbound data to {addr}:{activity['remote_port']} (sent={sent}, received={received})"),
                "indicators": [
                    f"Bytes sent: {sent}",
                    f"Bytes received: {received}",
                    f"Ratio: {sent / received:.1f}:1",
                    f"Remote endpoint: {addr}:{activity['remote_port']}",
                ],
                "remote_addresses": [addr],
            })


def extract_iocs(report: ExecutionReport) -> list[IOCEntry]:
    """Extract structured Indicators of Compromise from an execution report.

    Scans network activity, file changes, registry changes, and process
    activity for IP addresses, domains, URLs, hashes, and email addresses.

    Args:
        report: The execution report to extract IOCs from.

    Returns:
        list[IOCEntry]: Deduplicated list of IOC entries.
    """
    _logger.debug("extract_iocs_start")
    seen: set[tuple[str, str]] = set()
    iocs: list[IOCEntry] = []
    now_iso = datetime.now(UTC).isoformat()

    def _add_ioc(
        ioc_type: str,
        value: str,
        source: str,
        context: str,
    ) -> None:
        key = (ioc_type, value)
        if key in seen:
            return
        if ioc_type == "ipv4" and (_is_private_ip(value) or not _is_valid_ipv4(value)):
            return
        seen.add(key)
        iocs.append(
            IOCEntry(
                ioc_type=ioc_type,
                value=value,
                source=source,
                context=context,
                timestamp=now_iso,
            ),
        )

    def _scan_text(text: str, source: str) -> None:
        ctx = text[:_IOC_CONTEXT_MAX_LEN]
        for match in _IPV4_PATTERN.finditer(text):
            _add_ioc("ipv4", match.group(1), source, ctx)
        for match in _URL_PATTERN.finditer(text):
            _add_ioc("url", match.group(1), source, ctx)
        for match in _SHA256_PATTERN.finditer(text):
            _add_ioc("sha256", match.group(1).lower(), source, ctx)
        for match in _SHA1_PATTERN.finditer(text):
            val = match.group(1).lower()
            if ("sha256", val + val[:24]) not in seen:
                _add_ioc("sha1", val, source, ctx)
        for match in _MD5_PATTERN.finditer(text):
            val = match.group(1).lower()
            if ("sha1", val + val[:8]) not in seen and (
                "sha256",
                val + val[:32],
            ) not in seen:
                _add_ioc("md5", val, source, ctx)
        for match in _EMAIL_PATTERN.finditer(text):
            _add_ioc("email", match.group(1), source, ctx)
        for match in _DOMAIN_PATTERN.finditer(text):
            domain = match.group(1)
            if not _IPV4_PATTERN.fullmatch(domain):
                _add_ioc("domain", domain, source, ctx)

    for activity in report.network_activity:
        addr = activity["remote_address"]
        source_desc = f"network:{addr}:{activity['remote_port']}"
        if _is_valid_ipv4(addr):
            _add_ioc("ipv4", addr, "network_activity", source_desc)
        elif _looks_like_domain(addr):
            _add_ioc("domain", addr, "network_activity", source_desc)

    for change in report.file_changes:
        _scan_text(change["path"], "file_changes")

    for change in report.registry_changes:
        _scan_text(change["key"], "registry_changes")
        value_data = change.get("value_data")
        if value_data:
            _scan_text(value_data, "registry_changes")

    for proc in report.process_activity:
        cmd_line = proc.get("command_line")
        if cmd_line:
            _scan_text(cmd_line, "process_activity")
        proc_path = proc.get("path")
        if proc_path:
            _scan_text(proc_path, "process_activity")

    _logger.debug("extract_iocs_complete", ioc_count=len(iocs))
    return iocs


def generate_timeline(
    report: ExecutionReport,
    categories: list[str] | None = None,
) -> list[TimelineEvent]:
    """Generate a unified, sorted timeline from all monitoring streams.

    Merges file changes, registry changes, network activity, process activity,
    API calls, service changes, kernel objects, DLL loads, injection events,
    and clipboard events into a single chronological timeline.

    Args:
        report: The execution report to generate a timeline from.
        categories: Optional list of category names to include. If None, all
            categories are included.

    Returns:
        list[TimelineEvent]: Chronologically sorted list of timeline events.
    """
    _logger.debug(
        "generate_timeline_start",
        filter_categories=categories,
    )
    events: list[TimelineEvent] = []

    category_filter: frozenset[str] | None = frozenset(categories) if categories else None

    def _should_include(category: str) -> bool:
        return category_filter is None or category in category_filter

    if _should_include("file"):
        _timeline_add_file_events(report, events)

    if _should_include("registry"):
        _timeline_add_registry_events(report, events)

    if _should_include("network"):
        _timeline_add_network_events(report, events)

    if _should_include("process"):
        _timeline_add_process_events(report, events)

    if _should_include("api"):
        _timeline_add_api_events(report, events)

    if _should_include("service"):
        _timeline_add_service_events(report, events)

    if _should_include("kernel"):
        _timeline_add_kernel_events(report, events)

    if _should_include("dll"):
        _timeline_add_dll_events(report, events)

    if _should_include("injection"):
        _timeline_add_injection_events(report, events)

    if _should_include("clipboard"):
        _timeline_add_clipboard_events(report, events)

    events.sort(key=operator.itemgetter("timestamp"))

    _logger.debug("generate_timeline_complete", event_count=len(events))
    return events


def _timeline_add_file_events(
    report: ExecutionReport,
    events: list[TimelineEvent],
) -> None:
    """Add file change events to the timeline.

    Args:
        report: The execution report.
        events: Accumulator list for timeline events.
    """
    for change in report.file_changes:
        summary = f"File {change['operation']}: {change['path']}"
        details: dict[str, str] = {
            "path": change["path"],
            "operation": change["operation"],
        }
        old_path = change.get("old_path")
        if old_path:
            details["old_path"] = old_path
            summary += f" (from {old_path})"
        if change.get("size") is not None:
            details["size"] = str(change["size"])
        events.append(
            TimelineEvent(
                timestamp=change["timestamp"],
                category="file",
                summary=summary,
                details=details,
            ),
        )


def _timeline_add_registry_events(
    report: ExecutionReport,
    events: list[TimelineEvent],
) -> None:
    """Add registry change events to the timeline.

    Args:
        report: The execution report.
        events: Accumulator list for timeline events.
    """
    for change in report.registry_changes:
        val_name = change.get("value_name") or "(Default)"
        summary = f"Registry {change['operation']}: {change['key']}\\{val_name}"
        details: dict[str, str] = {
            "key": change["key"],
            "operation": change["operation"],
            "value_name": val_name,
        }
        value_type = change.get("value_type")
        if value_type:
            details["value_type"] = value_type
        value_data = change.get("value_data")
        if value_data:
            details["value_data"] = value_data
        events.append(
            TimelineEvent(
                timestamp=change["timestamp"],
                category="registry",
                summary=summary,
                details=details,
            ),
        )


def _timeline_add_network_events(
    report: ExecutionReport,
    events: list[TimelineEvent],
) -> None:
    """Add network activity events to the timeline.

    Args:
        report: The execution report.
        events: Accumulator list for timeline events.
    """
    for activity in report.network_activity:
        direction = activity["direction"]
        remote = f"{activity['remote_address']}:{activity['remote_port']}"
        summary = f"Network {direction} {activity['protocol'].upper()} connection to {remote}"
        events.append(
            TimelineEvent(
                timestamp=activity["timestamp"],
                category="network",
                summary=summary,
                details={
                    "protocol": activity["protocol"],
                    "direction": direction,
                    "local_address": activity["local_address"],
                    "local_port": str(activity["local_port"]),
                    "remote_address": activity["remote_address"],
                    "remote_port": str(activity["remote_port"]),
                    "bytes_sent": str(activity["bytes_sent"]),
                    "bytes_received": str(activity["bytes_received"]),
                },
            ),
        )


def _timeline_add_process_events(
    report: ExecutionReport,
    events: list[TimelineEvent],
) -> None:
    """Add process activity events to the timeline.

    Args:
        report: The execution report.
        events: Accumulator list for timeline events.
    """
    for proc in report.process_activity:
        summary = f"Process {proc['operation']}: {proc['name']} (PID {proc['pid']})"
        details: dict[str, str] = {
            "pid": str(proc["pid"]),
            "name": proc["name"],
            "operation": proc["operation"],
        }
        proc_path = proc.get("path")
        if proc_path:
            details["path"] = proc_path
        cmd_line = proc.get("command_line")
        if cmd_line:
            details["command_line"] = cmd_line
        if proc.get("parent_pid") is not None:
            details["parent_pid"] = str(proc["parent_pid"])
        if proc.get("exit_code") is not None:
            details["exit_code"] = str(proc["exit_code"])
        events.append(
            TimelineEvent(
                timestamp=proc["timestamp"],
                category="process",
                summary=summary,
                details=details,
            ),
        )


def _timeline_add_api_events(
    report: ExecutionReport,
    events: list[TimelineEvent],
) -> None:
    """Add API call events to the timeline.

    Args:
        report: The execution report.
        events: Accumulator list for timeline events.
    """
    for call in report.api_calls:
        summary = f"API call: {call['api_name']} by {call['process_name']} (PID {call['pid']})"
        events.append(
            TimelineEvent(
                timestamp=call["timestamp"],
                category="api",
                summary=summary,
                details={
                    "api_name": call["api_name"],
                    "module": call["module"],
                    "pid": str(call["pid"]),
                    "process_name": call["process_name"],
                    "arguments": ", ".join(call["arguments"]),
                    "return_value": call["return_value"],
                },
            ),
        )


def _timeline_add_service_events(
    report: ExecutionReport,
    events: list[TimelineEvent],
) -> None:
    """Add service change events to the timeline.

    Args:
        report: The execution report.
        events: Accumulator list for timeline events.
    """
    for svc in report.service_changes:
        summary = f"Service {svc['operation']}: {svc['service_name']} ({svc['display_name']})"
        events.append(
            TimelineEvent(
                timestamp=svc["timestamp"],
                category="service",
                summary=summary,
                details={
                    "service_name": svc["service_name"],
                    "display_name": svc["display_name"],
                    "binary_path": svc["binary_path"],
                    "start_type": svc["start_type"],
                    "operation": svc["operation"],
                },
            ),
        )


def _timeline_add_kernel_events(
    report: ExecutionReport,
    events: list[TimelineEvent],
) -> None:
    """Add kernel object activity events to the timeline.

    Args:
        report: The execution report.
        events: Accumulator list for timeline events.
    """
    for obj in report.kernel_objects:
        summary = f"Kernel object {obj['operation']}: {obj['object_type']} '{obj['name']}' by {obj['process_name']} (PID {obj['pid']})"
        events.append(
            TimelineEvent(
                timestamp=obj["timestamp"],
                category="kernel",
                summary=summary,
                details={
                    "object_type": obj["object_type"],
                    "name": obj["name"],
                    "pid": str(obj["pid"]),
                    "process_name": obj["process_name"],
                    "operation": obj["operation"],
                },
            ),
        )


def _timeline_add_dll_events(
    report: ExecutionReport,
    events: list[TimelineEvent],
) -> None:
    """Add DLL load events to the timeline.

    Args:
        report: The execution report.
        events: Accumulator list for timeline events.
    """
    for dll in report.dll_loads:
        summary = f"DLL loaded: {dll['dll_path']} by PID {dll['pid']} at {dll['base_address']}"
        events.append(
            TimelineEvent(
                timestamp=dll["timestamp"],
                category="dll",
                summary=summary,
                details={
                    "dll_path": dll["dll_path"],
                    "pid": str(dll["pid"]),
                    "process_name": dll["process_name"],
                    "base_address": dll["base_address"],
                    "size": str(dll["size"]),
                },
            ),
        )


def _timeline_add_injection_events(
    report: ExecutionReport,
    events: list[TimelineEvent],
) -> None:
    """Add process injection events to the timeline.

    Args:
        report: The execution report.
        events: Accumulator list for timeline events.
    """
    for inj in report.injection_events:
        summary = (
            f"Process injection: {inj['source_name']} (PID {inj['source_pid']}) "
            f"-> {inj['target_name']} (PID {inj['target_pid']}) "
            f"via {inj['injection_type']}"
        )
        events.append(
            TimelineEvent(
                timestamp=inj["timestamp"],
                category="injection",
                summary=summary,
                details={
                    "source_pid": str(inj["source_pid"]),
                    "source_name": inj["source_name"],
                    "target_pid": str(inj["target_pid"]),
                    "target_name": inj["target_name"],
                    "injection_type": inj["injection_type"],
                    "api_calls": ", ".join(inj["api_calls"]),
                },
            ),
        )


def _timeline_add_clipboard_events(
    report: ExecutionReport,
    events: list[TimelineEvent],
) -> None:
    """Add clipboard activity events to the timeline.

    Args:
        report: The execution report.
        events: Accumulator list for timeline events.
    """
    for clip in report.clipboard_events:
        preview = clip["content_preview"][:_CLIPBOARD_PREVIEW_MAX_LEN]
        summary = f"Clipboard {clip['operation']}: {clip['format']} ({clip['size_bytes']} bytes) by {clip['process_name']}"
        events.append(
            TimelineEvent(
                timestamp=clip["timestamp"],
                category="clipboard",
                summary=summary,
                details={
                    "operation": clip["operation"],
                    "format": clip["format"],
                    "content_preview": preview,
                    "size_bytes": str(clip["size_bytes"]),
                    "pid": str(clip["pid"]),
                    "process_name": clip["process_name"],
                },
            ),
        )


def match_behaviors(
    report: ExecutionReport,
    custom_rules: list[dict[str, Any]] | None = None,
) -> list[BehaviorMatch]:
    """Match behavioral signatures against execution report data.

    Applies built-in MITRE ATT&CK-aligned rules and optional custom rules
    to identify suspicious behaviors in sandbox execution data.

    Args:
        report: The execution report to analyze.
        custom_rules: Optional list of custom rule dicts, each with keys
            ``name``, ``category``, ``severity``, ``description``,
            ``mitre_id``, and ``conditions``.

    Returns:
        list[BehaviorMatch]: List of matched behavioral signatures.
    """
    _logger.debug("match_behaviors_start")
    matches: list[BehaviorMatch] = []

    _match_persistence(report, matches)
    _match_defense_evasion(report, matches)
    _match_command_and_control(report, matches)
    _match_exfiltration(report, matches)
    _match_discovery(report, matches)

    if custom_rules:
        _match_custom_rules(report, custom_rules, matches)

    _logger.debug("match_behaviors_complete", match_count=len(matches))
    return matches


def _match_persistence(
    report: ExecutionReport,
    matches: list[BehaviorMatch],
) -> None:
    """Match persistence-related behavioral signatures.

    Args:
        report: The execution report to analyze.
        matches: Accumulator list for behavior matches.
    """
    matches.extend(
        BehaviorMatch(
            signature_name="Service Creation",
            category="Persistence",
            severity="high",
            description=(f"New service created: {svc['service_name']} ({svc['binary_path']})"),
            evidence=[
                f"Service: {svc['service_name']}",
                f"Display name: {svc['display_name']}",
                f"Binary: {svc['binary_path']}",
                f"Start type: {svc['start_type']}",
            ],
            mitre_attack_id="T1543",
        )
        for svc in report.service_changes
        if svc["operation"].lower() in {"created", "create", "installed", "install"}
    )

    for change in report.registry_changes:
        key_lower = change["key"].lower()
        if any(pat.lower() in key_lower for pat in _PERSISTENCE_REGISTRY_PATTERNS):
            matches.append(
                BehaviorMatch(
                    signature_name="Run Key Persistence",
                    category="Persistence",
                    severity="high",
                    description=f"Registry Run key modification: {change['key']}",
                    evidence=[
                        f"Key: {change['key']}",
                        f"Operation: {change['operation']}",
                        f"Value name: {change.get('value_name') or '(Default)'}",
                        f"Value data: {change.get('value_data') or 'N/A'}",
                    ],
                    mitre_attack_id="T1547",
                ),
            )

    for proc in report.process_activity:
        proc_name = proc["name"].lower()
        if proc_name in {"schtasks.exe", "at.exe"}:
            matches.append(
                BehaviorMatch(
                    signature_name="Scheduled Task Creation",
                    category="Persistence",
                    severity="medium",
                    description=f"Scheduled task utility executed: {proc['name']}",
                    evidence=[
                        f"Process: {proc['name']}",
                        f"PID: {proc['pid']}",
                        f"Command line: {proc.get('command_line') or 'N/A'}",
                    ],
                    mitre_attack_id="T1547",
                ),
            )


def _match_defense_evasion(
    report: ExecutionReport,
    matches: list[BehaviorMatch],
) -> None:
    """Match defense evasion behavioral signatures.

    Args:
        report: The execution report to analyze.
        matches: Accumulator list for behavior matches.
    """
    matches.extend(
        BehaviorMatch(
            signature_name="Process Injection",
            category="Defense Evasion",
            severity="critical",
            description=(f"Process injection detected: {inj['source_name']} -> {inj['target_name']} via {inj['injection_type']}"),
            evidence=[
                f"Source: {inj['source_name']} (PID {inj['source_pid']})",
                f"Target: {inj['target_name']} (PID {inj['target_pid']})",
                f"Type: {inj['injection_type']}",
                f"APIs used: {', '.join(inj['api_calls'])}",
            ],
            mitre_attack_id="T1055",
        )
        for inj in report.injection_events
    )

    anti_debug_evidence: list[str] = [
        f"{call['api_name']} by {call['process_name']} (PID {call['pid']})"
        for call in report.api_calls
        if call["api_name"] in _ANTI_DEBUG_APIS
    ]
    if anti_debug_evidence:
        matches.append(
            BehaviorMatch(
                signature_name="Anti-Debug Techniques",
                category="Defense Evasion",
                severity="medium",
                description="Anti-debugging API calls detected",
                evidence=anti_debug_evidence,
                mitre_attack_id="T1497",
            ),
        )

    sleep_evidence: list[str] = []
    for call in report.api_calls:
        if call["api_name"] == "Sleep" and call["arguments"]:
            try:
                sleep_ms = int(call["arguments"][0])
            except (ValueError, IndexError):
                continue
            if sleep_ms >= _SLEEP_EVASION_THRESHOLD_MS:
                sleep_evidence.append(
                    f"Sleep({sleep_ms}ms) by {call['process_name']} (PID {call['pid']})",
                )
    if sleep_evidence:
        matches.append(
            BehaviorMatch(
                signature_name="Sleep Acceleration Evasion",
                category="Defense Evasion",
                severity="low",
                description="Large Sleep calls detected (possible sandbox evasion)",
                evidence=sleep_evidence,
                mitre_attack_id="T1497",
            ),
        )


def _match_command_and_control(
    report: ExecutionReport,
    matches: list[BehaviorMatch],
) -> None:
    """Match command-and-control behavioral signatures.

    Args:
        report: The execution report to analyze.
        matches: Accumulator list for behavior matches.
    """
    c2_patterns = detect_c2_patterns(report.network_activity)
    matches.extend(
        BehaviorMatch(
            signature_name="Periodic Beaconing",
            category="Command and Control",
            severity="high",
            description=pattern["description"],
            evidence=pattern["indicators"],
            mitre_attack_id="T1071",
        )
        for pattern in c2_patterns
        if pattern["pattern_type"] == "beaconing"
    )

    matches.extend(
        BehaviorMatch(
            signature_name="DNS over HTTPS",
            category="Command and Control",
            severity="medium",
            description=(f"Connection to known DoH provider: {activity['remote_address']}"),
            evidence=[
                f"Provider: {activity['remote_address']}",
                f"Port: {activity['remote_port']}",
                f"Protocol: {activity['protocol']}",
                f"Bytes sent: {activity['bytes_sent']}",
            ],
            mitre_attack_id="T1573",
        )
        for activity in report.network_activity
        if activity["remote_address"] in _DOH_PROVIDERS and activity["remote_port"] == _HTTPS_PORT
    )


def _match_exfiltration(
    report: ExecutionReport,
    matches: list[BehaviorMatch],
) -> None:
    """Match exfiltration behavioral signatures.

    Args:
        report: The execution report to analyze.
        matches: Accumulator list for behavior matches.
    """
    matches.extend(
        BehaviorMatch(
            signature_name="Large Outbound Transfer",
            category="Exfiltration",
            severity="high",
            description=(
                f"Large outbound data transfer: {activity['bytes_sent']} bytes to {activity['remote_address']}:{activity['remote_port']}"
            ),
            evidence=[
                f"Destination: {activity['remote_address']}:{activity['remote_port']}",
                f"Bytes sent: {activity['bytes_sent']}",
                f"Protocol: {activity['protocol']}",
            ],
            mitre_attack_id="T1041",
        )
        for activity in report.network_activity
        if activity["direction"] == "outbound" and activity["bytes_sent"] > _EXFIL_THRESHOLD_BYTES
    )

    clipboard_read_evidence: list[str] = [
        (f"Clipboard read by {clip['process_name']} (PID {clip['pid']}): {clip['format']} ({clip['size_bytes']} bytes)")
        for clip in report.clipboard_events
        if clip["operation"].lower() == "read"
    ]
    if clipboard_read_evidence:
        matches.append(
            BehaviorMatch(
                signature_name="Clipboard Data Access",
                category="Exfiltration",
                severity="medium",
                description="Process read clipboard contents",
                evidence=clipboard_read_evidence,
                mitre_attack_id="T1115",
            ),
        )


def _match_discovery(
    report: ExecutionReport,
    matches: list[BehaviorMatch],
) -> None:
    """Match discovery behavioral signatures.

    Args:
        report: The execution report to analyze.
        matches: Accumulator list for behavior matches.
    """
    discovery_evidence: list[str] = [
        (f"{proc['name']} (PID {proc['pid']}): {proc.get('command_line') or 'N/A'}")
        for proc in report.process_activity
        if proc["name"].lower() in _SYSTEM_DISCOVERY_TOOLS
    ]
    if discovery_evidence:
        matches.append(
            BehaviorMatch(
                signature_name="System Information Discovery",
                category="Discovery",
                severity="low",
                description="System enumeration commands executed",
                evidence=discovery_evidence,
                mitre_attack_id="T1082",
            ),
        )


def _match_custom_rules(
    report: ExecutionReport,
    custom_rules: list[dict[str, Any]],
    matches: list[BehaviorMatch],
) -> None:
    """Match custom behavioral rules against report data.

    Args:
        report: The execution report to analyze.
        custom_rules: List of custom rule dicts.
        matches: Accumulator list for behavior matches.
    """
    for rule in custom_rules:
        rule_name: str = rule.get("name", "Custom Rule")
        rule_category: str = rule.get("category", "Custom")
        rule_severity: str = rule.get("severity", "medium")
        rule_description: str = rule.get("description", "")
        rule_mitre: str = rule.get("mitre_id", "")
        conditions: dict[str, Any] = rule.get("conditions", {})
        evidence_items: list[str] = []

        registry_patterns: list[str] = conditions.get("registry_patterns", [])
        for pattern in registry_patterns:
            evidence_items.extend(
                _collect_matching_evidence(
                    [dict(c) for c in report.registry_changes],
                    "key",
                    pattern.lower(),
                    "Registry match",
                ),
            )

        process_names: list[str] = conditions.get("process_names", [])
        for pname in process_names:
            evidence_items.extend(
                f"Process match: {proc['name']} (PID {proc['pid']})"
                for proc in report.process_activity
                if pname.lower() in proc["name"].lower()
            )

        api_names: list[str] = conditions.get("api_names", [])
        for api_name in api_names:
            evidence_items.extend(
                f"API match: {call['api_name']} by {call['process_name']}"
                for call in report.api_calls
                if api_name.lower() in call["api_name"].lower()
            )

        network_ports: list[int | str] = conditions.get("network_ports", [])
        for port in network_ports:
            port_int = int(port)
            evidence_items.extend(
                f"Network match: port {port_int} to {activity['remote_address']}"
                for activity in report.network_activity
                if activity["remote_port"] == port_int
            )

        if evidence_items:
            matches.append(
                BehaviorMatch(
                    signature_name=rule_name,
                    category=rule_category,
                    severity=rule_severity,
                    description=rule_description,
                    evidence=evidence_items,
                    mitre_attack_id=rule_mitre,
                ),
            )


def diff_reports(
    report_a: ExecutionReport,
    report_b: ExecutionReport,
) -> dict[str, Any]:
    """Compare two execution reports field by field.

    Produces a structured diff showing unique-to-A, unique-to-B, and common
    items for each list field, and side-by-side comparisons for scalar fields.

    Args:
        report_a: The first execution report.
        report_b: The second execution report.

    Returns:
        dict[str, Any]: A diff dict with ``scalars`` and per-field
            ``unique_to_a``, ``unique_to_b``, and ``common`` lists.
    """
    _logger.debug("diff_reports_start")

    result: dict[str, Any] = {
        "scalars": {
            "result": {"a": report_a.result, "b": report_b.result},
            "exit_code": {"a": report_a.exit_code, "b": report_b.exit_code},
            "duration_seconds": {
                "a": report_a.duration_seconds,
                "b": report_b.duration_seconds,
            },
        },
    }

    field_key_map: dict[str, list[str]] = {
        "file_changes": ["path"],
        "registry_changes": ["key", "value_name"],
        "network_activity": ["remote_address", "remote_port"],
        "process_activity": ["name", "command_line"],
        "api_calls": ["api_name", "pid"],
        "service_changes": ["service_name"],
        "kernel_objects": ["object_type", "name"],
        "dll_loads": ["dll_path", "pid"],
        "injection_events": ["source_pid", "target_pid"],
        "resource_samples": ["timestamp"],
        "clipboard_events": ["timestamp", "operation"],
    }

    for field_name, key_fields in field_key_map.items():
        items_a: list[dict[str, Any]] = getattr(report_a, field_name, [])
        items_b: list[dict[str, Any]] = getattr(report_b, field_name, [])

        index_a: dict[str, dict[str, Any]] = {}
        for item in items_a:
            identity = _extract_identity_key(item, key_fields)
            index_a[identity] = item

        index_b: dict[str, dict[str, Any]] = {}
        for item in items_b:
            identity = _extract_identity_key(item, key_fields)
            index_b[identity] = item

        keys_a = set(index_a.keys())
        keys_b = set(index_b.keys())

        unique_to_a = [index_a[k] for k in sorted(keys_a - keys_b)]
        unique_to_b = [index_b[k] for k in sorted(keys_b - keys_a)]
        common = [index_a[k] for k in sorted(keys_a & keys_b)]

        result[field_name] = {
            "unique_to_a": unique_to_a,
            "unique_to_b": unique_to_b,
            "common": common,
        }

    _logger.debug("diff_reports_complete")
    return result
