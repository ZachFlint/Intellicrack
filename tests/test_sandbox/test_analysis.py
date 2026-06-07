# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for sandbox post-analysis functions.

Tests validate:
- Private helpers: _is_private_ip, _is_valid_ipv4, _looks_like_domain, _shannon_entropy
- detect_c2_patterns: beaconing, DGA, C2 ports, exfiltration, high-freq HTTPS
- extract_iocs: IP, domain, URL, hash, email extraction with dedup/filtering
- generate_timeline: all 10 categories, sorting, category filter
- match_behaviors: persistence, evasion, C2, exfiltration, discovery, custom rules
- diff_reports: identical, completely different, partial overlap, scalar diffs
"""

from __future__ import annotations

import importlib
import math
from typing import TYPE_CHECKING, Any, Final, Literal, cast

from intellicrack.sandbox.analysis import (
    detect_c2_patterns,
    diff_reports,
    extract_iocs,
    generate_timeline,
    match_behaviors,
)
from intellicrack.sandbox.base import (
    ApiCall,
    ClipboardEvent,
    DllLoadEvent,
    ExecutionReport,
    FileChange,
    InjectionEvent,
    KernelObjectActivity,
    NetworkActivity,
    ProcessActivity,
    RegistryChange,
    ServiceChange,
)

from .conftest import make_sample_report, ts_offset


if TYPE_CHECKING:
    from collections.abc import Callable


_analysis_mod = importlib.import_module("intellicrack.sandbox.analysis")
_is_private_ip = cast("Callable[[str], bool]", getattr(_analysis_mod, "_is_private_ip"))
_is_valid_ipv4 = cast("Callable[[str], bool]", getattr(_analysis_mod, "_is_valid_ipv4"))
_looks_like_domain = cast("Callable[[str], bool]", getattr(_analysis_mod, "_looks_like_domain"))
_shannon_entropy = cast("Callable[[str], float]", getattr(_analysis_mod, "_shannon_entropy"))


_BEACONING_INTERVAL: Final[int] = 60
_BEACONING_COUNT: Final[int] = 5
_HIGH_ENTROPY_DOMAIN: Final[str] = "xkqwzjrt"
_NORMAL_DOMAIN: Final[str] = "google"
_DGA_FULL: Final[str] = "xkqwzjrtmnpv.evil.com"
_C2_PORT: Final[int] = 4444
_HTTPS_PORT: Final[int] = 443
_EXFIL_SENT: Final[int] = 5_242_880
_EXFIL_RECV: Final[int] = 100
_DOH_ADDR: Final[str] = "1.1.1.1"
_SAMPLE_SIZE: Final[int] = 4096
_SLEEP_MS: Final[int] = 120000
_HIGH_FREQ_COUNT: Final[int] = 12


def _net(
    remote_address: str = "203.0.113.50",
    remote_port: int = 443,
    ts_sec: int = 0,
    bytes_sent: int = 256,
    bytes_received: int = 512,
    direction: Literal["inbound", "outbound"] = "outbound",
) -> NetworkActivity:
    """Build a NetworkActivity entry with defaults.

    Args:
        remote_address: Remote IP or domain.
        remote_port: Remote port number.
        ts_sec: Second offset for timestamp.
        bytes_sent: Bytes sent.
        bytes_received: Bytes received.
        direction: Connection direction.

    Returns:
        NetworkActivity: A network activity entry.
    """
    return NetworkActivity(
        protocol="tcp",
        direction=direction,
        local_address="192.168.1.100",
        local_port=49152,
        remote_address=remote_address,
        remote_port=remote_port,
        timestamp=ts_offset(ts_sec),
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
    )


class TestHelperFunctions:
    """Verify private helper functions with boundary and negative cases.

    Each helper is tested at its exact boundary values (+1/-1 edge cases)
    and with negative (expected-False) inputs alongside the positive cases,
    so a regression in any range boundary is caught immediately.
    """

    def test_private_ip_10(self) -> None:
        """10.x.x.x is private."""
        assert _is_private_ip("10.0.0.1") is True

    def test_private_ip_10_max(self) -> None:
        """10.255.255.255 (upper boundary of 10.x.x.x) is private."""
        assert _is_private_ip("10.255.255.255") is True

    def test_private_ip_172_16(self) -> None:
        """172.16.x.x is private."""
        assert _is_private_ip("172.16.0.1") is True

    def test_private_ip_172_31(self) -> None:
        """172.31.x.x is private."""
        assert _is_private_ip("172.31.255.255") is True

    def test_private_ip_172_16_lower_boundary(self) -> None:
        """172.16.0.0 (exact lower boundary) is private."""
        assert _is_private_ip("172.16.0.0") is True

    def test_private_ip_172_31_upper_boundary(self) -> None:
        """172.31.255.255 (exact upper boundary) is private."""
        assert _is_private_ip("172.31.255.255") is True

    def test_private_ip_172_15_just_below_range(self) -> None:
        """172.15.x.x is just below the 172.16-31 private range: not private."""
        assert _is_private_ip("172.15.255.255") is False

    def test_private_ip_172_32_just_above_range(self) -> None:
        """172.32.x.x is just above the 172.16-31 private range: not private."""
        assert _is_private_ip("172.32.0.0") is False

    def test_private_ip_192_168(self) -> None:
        """192.168.x.x is private."""
        assert _is_private_ip("192.168.1.1") is True

    def test_private_ip_192_167_not_private(self) -> None:
        """192.167.x.x is not in the 192.168.x.x range."""
        assert _is_private_ip("192.167.255.255") is False

    def test_private_ip_192_169_not_private(self) -> None:
        """192.169.x.x is not in the 192.168.x.x range."""
        assert _is_private_ip("192.169.0.0") is False

    def test_private_ip_127(self) -> None:
        """127.x.x.x is private."""
        assert _is_private_ip("127.0.0.1") is True

    def test_private_ip_127_max(self) -> None:
        """127.255.255.255 is private (loopback range)."""
        assert _is_private_ip("127.255.255.255") is True

    def test_private_ip_unspecified(self) -> None:
        """0.0.0.0 is private."""
        assert _is_private_ip("0.0.0.0") is True  # noqa: S104

    def test_public_ip(self) -> None:
        """203.0.113.1 is public."""
        assert _is_private_ip("203.0.113.1") is False

    def test_public_ip_8_8_8_8(self) -> None:
        """8.8.8.8 (Google DNS) is public."""
        assert _is_private_ip("8.8.8.8") is False

    def test_172_15_not_private(self) -> None:
        """172.15.x.x is not private."""
        assert _is_private_ip("172.15.0.1") is False

    def test_172_32_not_private(self) -> None:
        """172.32.x.x is not private."""
        assert _is_private_ip("172.32.0.1") is False

    def test_valid_ipv4(self) -> None:
        """Well-formed IPv4 is valid."""
        assert _is_valid_ipv4("192.168.1.1") is True

    def test_valid_ipv4_all_zeros(self) -> None:
        """0.0.0.0 is a valid IPv4 address."""
        assert _is_valid_ipv4("0.0.0.0") is True  # noqa: S104

    def test_valid_ipv4_all_255(self) -> None:
        """255.255.255.255 is a valid IPv4 address (broadcast)."""
        assert _is_valid_ipv4("255.255.255.255") is True

    def test_invalid_ipv4_too_few_octets(self) -> None:
        """Three octets is invalid."""
        assert _is_valid_ipv4("192.168.1") is False

    def test_invalid_ipv4_too_many_octets(self) -> None:
        """Five octets is invalid."""
        assert _is_valid_ipv4("192.168.1.1.1") is False

    def test_invalid_ipv4_octet_over_255(self) -> None:
        """Octet > 255 is invalid."""
        assert _is_valid_ipv4("999.999.999.999") is False

    def test_invalid_ipv4_octet_256(self) -> None:
        """Octet exactly 256 is invalid (one beyond max)."""
        assert _is_valid_ipv4("192.168.1.256") is False

    def test_valid_ipv4_octet_255_boundary(self) -> None:
        """Octet exactly 255 is valid (maximum allowed)."""
        assert _is_valid_ipv4("192.168.1.255") is True

    def test_invalid_ipv4_non_numeric(self) -> None:
        """Non-numeric octet is invalid."""
        assert _is_valid_ipv4("abc.def.ghi.jkl") is False

    def test_invalid_ipv4_empty_string(self) -> None:
        """Empty string is an invalid IPv4 address."""
        assert _is_valid_ipv4("") is False

    def test_looks_like_domain_valid(self) -> None:
        """'example.com' looks like a domain."""
        assert _looks_like_domain("example.com") is True

    def test_looks_like_domain_subdomain(self) -> None:
        """'sub.example.com' looks like a domain."""
        assert _looks_like_domain("sub.example.com") is True

    def test_looks_like_domain_ip(self) -> None:
        """An IP address does not look like a domain."""
        assert _looks_like_domain("192.168.1.1") is False

    def test_looks_like_domain_no_dot(self) -> None:
        """A bare hostname without a dot does not look like a domain."""
        assert _looks_like_domain("localhost") is False

    def test_shannon_entropy_uniform(self) -> None:
        """Uniform string (e.g., 'aaaa') has 0.0 entropy."""
        assert math.isclose(_shannon_entropy("aaaa"), 0.0, abs_tol=1e-9)

    def test_shannon_entropy_high(self) -> None:
        """High-randomness string has entropy > 3.0."""
        assert _shannon_entropy("xkqwzjrtmnpvls") > 3.0

    def test_shannon_entropy_two_symbols(self) -> None:
        """50/50 two-symbol string 'ababababab' has entropy exactly 1.0.

        Shannon entropy of a 50/50 binary source = -0.5*log2(0.5) - 0.5*log2(0.5) = 1.0.
        """
        assert math.isclose(_shannon_entropy("ababababab"), 1.0, abs_tol=1e-9)

    def test_shannon_entropy_single_char_string(self) -> None:
        """Single-character string has entropy 0.0 (no uncertainty)."""
        assert math.isclose(_shannon_entropy("z"), 0.0, abs_tol=1e-9)

    def test_shannon_entropy_empty(self) -> None:
        """Empty string has 0.0 entropy."""
        assert math.isclose(_shannon_entropy(""), 0.0, abs_tol=1e-9)

    def test_shannon_entropy_maximum_for_256_symbols(self) -> None:
        """String with all 256 distinct byte values (as chars) has entropy 8.0 (log2(256)).

        The maximum possible Shannon entropy for byte-level data is exactly 8.0
        bits per symbol when the distribution is uniform across all 256 values.
        """
        text = "".join(chr(i) for i in range(256))
        assert math.isclose(_shannon_entropy(text), 8.0, abs_tol=1e-9)


class TestDetectC2PatternsThresholds:
    """Verify C2 detection heuristics at their exact threshold boundaries.

    Uses routable public IP addresses and statistically realistic byte
    transfer ratios to exercise the detection logic at the precise
    values where its behaviour changes, not just well above or below.

    All remote IPs here are from IANA-assigned public blocks (not TEST-NET),
    and all traffic volumes use realistic byte counts observed in real-world
    C2 traffic (small beacons, large exfil payloads).
    """

    _C2_IP: Final[str] = "185.220.101.45"
    _CDN_IP: Final[str] = "151.101.1.140"

    def test_beaconing_exactly_at_min_connections_boundary(self) -> None:
        """Exactly 3 connections at consistent intervals triggers beaconing.

        _BEACONING_MIN_CONNECTIONS == 3; this test sits at the exact lower
        boundary. Fewer than 3 connections must NOT trigger (verified below).
        """
        activity = [_net(remote_address=self._C2_IP, remote_port=8080, ts_sec=i * 15, bytes_sent=128, bytes_received=48) for i in range(3)]
        patterns = detect_c2_patterns(activity)
        beacon = [p for p in patterns if p["pattern_type"] == "beaconing"]
        assert len(beacon) >= 1, "Exactly 3 regular connections must trigger beaconing"
        assert beacon[0]["confidence"] > 0.0

    def test_beaconing_exactly_one_below_min_connections(self) -> None:
        """Exactly 2 connections must NOT trigger beaconing (below minimum of 3)."""
        activity = [_net(remote_address=self._C2_IP, remote_port=8080, ts_sec=i * 15, bytes_sent=128, bytes_received=48) for i in range(2)]
        patterns = detect_c2_patterns(activity)
        beacon = [p for p in patterns if p["pattern_type"] == "beaconing"]
        assert len(beacon) == 0, "2 connections must not trigger beaconing (below threshold of 3)"

    def test_exfil_exactly_at_byte_threshold(self) -> None:
        """A connection with exactly _EXFIL_THRESHOLD_BYTES (1 MiB) sent triggers exfil detection.

        _EXFIL_THRESHOLD_BYTES == 1048576 bytes sent; ratio must also exceed
        _EXFIL_RATIO_THRESHOLD == 10x. Uses 1048576 sent vs 104 received
        (ratio ~10076, well above 10x).
        """
        activity = [_net(remote_address=self._C2_IP, remote_port=443, ts_sec=0, bytes_sent=1_048_576, bytes_received=104)]
        patterns = detect_c2_patterns(activity)
        exfil = [p for p in patterns if p["pattern_type"] == "data_exfiltration"]
        assert len(exfil) >= 1, "1 MiB sent with >10x ratio must trigger exfiltration detection"

    def test_exfil_below_byte_threshold_not_detected(self) -> None:
        """A connection with exactly 1 byte below threshold must NOT trigger exfil.

        Uses 1048575 bytes (1 MiB - 1) with a 10:1 ratio that satisfies the
        ratio threshold but falls below the byte threshold.
        """
        activity = [_net(remote_address=self._C2_IP, remote_port=443, ts_sec=0, bytes_sent=1_048_575, bytes_received=104)]
        patterns = detect_c2_patterns(activity)
        exfil = [p for p in patterns if p["pattern_type"] == "data_exfiltration"]
        assert len(exfil) == 0, "1 MiB - 1 byte sent must not trigger exfiltration (below byte threshold)"

    def test_high_freq_443_at_exact_threshold(self) -> None:
        """Exactly _HIGH_FREQ_HTTPS_THRESHOLD == 10 connections on port 443 triggers detection.

        _HIGH_FREQ_HTTPS_THRESHOLD == 10 and the detector fires on
        ``len(addresses) >= _HIGH_FREQ_HTTPS_THRESHOLD``; 10 connections
        sit at the exact lower boundary and must trigger.
        """
        activity_10 = [_net(remote_address=self._CDN_IP, remote_port=443, ts_sec=i, bytes_sent=512, bytes_received=4096) for i in range(10)]
        patterns = detect_c2_patterns(activity_10)
        hf = [p for p in patterns if p["pattern_type"] == "high_frequency_443"]
        assert len(hf) >= 1, "Exactly 10 connections on port 443 must trigger high-frequency detection (threshold>=10)"

    def test_high_freq_443_one_below_threshold_not_triggered(self) -> None:
        """_HIGH_FREQ_HTTPS_THRESHOLD - 1 == 9 connections on port 443 must NOT trigger.

        The detector fires on ``>= 10``; 9 connections sit one below the
        boundary and must be suppressed.
        """
        activity_9 = [_net(remote_address=self._CDN_IP, remote_port=443, ts_sec=i, bytes_sent=512, bytes_received=4096) for i in range(9)]
        patterns = detect_c2_patterns(activity_9)
        hf = [p for p in patterns if p["pattern_type"] == "high_frequency_443"]
        assert len(hf) == 0, "9 connections on port 443 must NOT trigger (threshold is >= 10)"

    def test_dga_domain_at_entropy_boundary(self) -> None:
        """Domain with entropy just above _DGA_ENTROPY_THRESHOLD (3.5) is flagged.

        Independently computed: 'zyxwvutsrqponm.net' has 14 distinct lowercase
        letters in the label 'zyxwvutsrqponm'; entropy = log2(14) ≈ 3.807 > 3.5.
        """
        high_entropy_domain = "zyxwvutsrqponm.net"
        activity = [_net(remote_address=high_entropy_domain, remote_port=80, ts_sec=0)]
        patterns = detect_c2_patterns(activity)
        dga = [p for p in patterns if p["pattern_type"] == "dga_domain"]
        assert len(dga) >= 1, f"Domain {high_entropy_domain!r} with entropy >3.5 must be flagged as DGA"

    def test_dga_domain_below_entropy_threshold_not_flagged(self) -> None:
        """Domain with entropy well below _DGA_ENTROPY_THRESHOLD (3.5) is not flagged.

        'apple.com' has low entropy in its label; it must not trigger DGA detection.
        """
        activity = [_net(remote_address="apple.com", remote_port=80, ts_sec=0)]
        patterns = detect_c2_patterns(activity)
        dga = [p for p in patterns if p["pattern_type"] == "dga_domain"]
        assert len(dga) == 0, "'apple.com' must not be flagged as DGA"


class TestDetectC2Patterns:
    """Verify C2 pattern detection logic."""

    def test_empty_input(self) -> None:
        """Empty activity list returns empty."""
        assert detect_c2_patterns([]) == []

    def test_beaconing_detected(self) -> None:
        """5 connections at 60s intervals triggers beaconing detection."""
        activity = [
            _net(remote_address="10.0.0.1", remote_port=8443, ts_sec=i * _BEACONING_INTERVAL % 100) for i in range(_BEACONING_COUNT)
        ]
        patterns = detect_c2_patterns(activity)
        beacon = [p for p in patterns if p["pattern_type"] == "beaconing"]
        assert len(beacon) >= 1
        assert beacon[0]["confidence"] > 0.9

    def test_beaconing_irregular_not_detected(self) -> None:
        """Irregular intervals don't trigger beaconing."""
        activity = [_net(remote_address="10.0.0.1", remote_port=8443, ts_sec=s) for s in [0, 5, 47, 48, 99]]
        patterns = detect_c2_patterns(activity)
        beacon = [p for p in patterns if p["pattern_type"] == "beaconing"]
        assert len(beacon) == 0

    def test_beaconing_too_few_connections(self) -> None:
        """Fewer than 3 connections don't trigger beaconing."""
        activity = [_net(remote_address="10.0.0.1", remote_port=8443, ts_sec=i * 60) for i in range(2)]
        patterns = detect_c2_patterns(activity)
        beacon = [p for p in patterns if p["pattern_type"] == "beaconing"]
        assert len(beacon) == 0

    def test_dga_high_entropy_detected(self) -> None:
        """High-entropy domain triggers DGA detection."""
        activity = [_net(remote_address=_DGA_FULL, remote_port=80, ts_sec=0)]
        patterns = detect_c2_patterns(activity)
        dga = [p for p in patterns if p["pattern_type"] == "dga_domain"]
        assert len(dga) == 1

    def test_dga_normal_domain_not_detected(self) -> None:
        """Normal domain doesn't trigger DGA detection."""
        activity = [_net(remote_address="google.com", remote_port=80, ts_sec=0)]
        patterns = detect_c2_patterns(activity)
        dga = [p for p in patterns if p["pattern_type"] == "dga_domain"]
        assert len(dga) == 0

    def test_dga_ip_not_flagged(self) -> None:
        """IP address is not flagged as DGA."""
        activity = [_net(remote_address="203.0.113.1", remote_port=80, ts_sec=0)]
        patterns = detect_c2_patterns(activity)
        dga = [p for p in patterns if p["pattern_type"] == "dga_domain"]
        assert len(dga) == 0

    def test_dga_duplicate_counted_once(self) -> None:
        """Duplicate DGA domain produces only one detection."""
        activity = [
            _net(remote_address=_DGA_FULL, remote_port=80, ts_sec=0),
            _net(remote_address=_DGA_FULL, remote_port=80, ts_sec=1),
        ]
        patterns = detect_c2_patterns(activity)
        dga = [p for p in patterns if p["pattern_type"] == "dga_domain"]
        assert len(dga) == 1

    def test_c2_port_detected(self) -> None:
        """Connection on port 4444 triggers C2 port detection."""
        activity = [_net(remote_port=_C2_PORT, ts_sec=0)]
        patterns = detect_c2_patterns(activity)
        c2 = [p for p in patterns if p["pattern_type"] == "known_c2_port"]
        assert len(c2) == 1

    def test_c2_port_10_connections_higher_confidence(self) -> None:
        """10 connections on C2 port produce higher confidence than 1."""
        activity_1 = [_net(remote_port=_C2_PORT, ts_sec=0)]
        activity_10 = [_net(remote_port=_C2_PORT, ts_sec=i) for i in range(10)]
        patterns_1 = detect_c2_patterns(activity_1)
        patterns_10 = detect_c2_patterns(activity_10)
        c2_1 = [p for p in patterns_1 if p["pattern_type"] == "known_c2_port"]
        c2_10 = [p for p in patterns_10 if p["pattern_type"] == "known_c2_port"]
        assert c2_10[0]["confidence"] > c2_1[0]["confidence"]

    def test_port_80_not_flagged(self) -> None:
        """Port 80 is not a known C2 port."""
        activity = [_net(remote_port=80, ts_sec=0)]
        patterns = detect_c2_patterns(activity)
        c2 = [p for p in patterns if p["pattern_type"] == "known_c2_port"]
        assert len(c2) == 0

    def test_high_freq_443_detected(self) -> None:
        """12 connections on port 443 triggers high-frequency detection."""
        activity = [_net(remote_port=_HTTPS_PORT, ts_sec=i) for i in range(_HIGH_FREQ_COUNT)]
        patterns = detect_c2_patterns(activity)
        hf = [p for p in patterns if p["pattern_type"] == "high_frequency_443"]
        assert len(hf) == 1

    def test_high_freq_443_too_few(self) -> None:
        """5 connections on port 443 don't trigger high-frequency detection."""
        activity = [_net(remote_port=_HTTPS_PORT, ts_sec=i) for i in range(5)]
        patterns = detect_c2_patterns(activity)
        hf = [p for p in patterns if p["pattern_type"] == "high_frequency_443"]
        assert len(hf) == 0

    def test_exfil_detected(self) -> None:
        """Large outbound with small inbound triggers exfiltration."""
        activity = [_net(bytes_sent=_EXFIL_SENT, bytes_received=_EXFIL_RECV, ts_sec=0)]
        patterns = detect_c2_patterns(activity)
        exfil = [p for p in patterns if p["pattern_type"] == "data_exfiltration"]
        assert len(exfil) == 1

    def test_balanced_traffic_not_exfil(self) -> None:
        """Balanced traffic doesn't trigger exfiltration."""
        activity = [_net(bytes_sent=500, bytes_received=500, ts_sec=0)]
        patterns = detect_c2_patterns(activity)
        exfil = [p for p in patterns if p["pattern_type"] == "data_exfiltration"]
        assert len(exfil) == 0

    def test_normal_traffic_empty(self) -> None:
        """Single normal connection produces no patterns."""
        activity = [_net(remote_address="93.184.216.34", remote_port=80, ts_sec=0)]
        patterns = detect_c2_patterns(activity)
        assert len(patterns) == 0

    def test_multiple_patterns_simultaneously(
        self,
        sample_network_activity: list[NetworkActivity],
    ) -> None:
        """Full sample data should trigger multiple pattern types.

        Args:
            sample_network_activity: Network-activity fixture with beaconing, DGA, C2, exfil, and normal traffic.
        """
        patterns = detect_c2_patterns(sample_network_activity)
        pattern_types = {p["pattern_type"] for p in patterns}
        assert len(pattern_types) >= 2


class TestExtractIOCs:
    """Verify IOC extraction logic."""

    def test_empty_report(self, empty_report: ExecutionReport) -> None:
        """Empty report returns empty IOC list.

        Args:
            empty_report: ExecutionReport fixture with empty activity lists.
        """
        iocs = extract_iocs(empty_report)
        assert iocs == []

    def test_public_ipv4_from_network(self) -> None:
        """Public IPv4 from network_activity is extracted."""
        report = make_sample_report(
            network_activity=[_net(remote_address="203.0.113.50")],
        )
        iocs = extract_iocs(report)
        ip_iocs = [i for i in iocs if i["ioc_type"] == "ipv4"]
        assert any(i["value"] == "203.0.113.50" for i in ip_iocs)

    def test_domain_from_network(self) -> None:
        """Domain from network_activity is extracted."""
        report = make_sample_report(
            network_activity=[_net(remote_address="evil.example.com")],
        )
        iocs = extract_iocs(report)
        dom = [i for i in iocs if i["ioc_type"] == "domain"]
        assert any(i["value"] == "evil.example.com" for i in dom)

    def test_url_from_command_line(self) -> None:
        """URL from process command_line is extracted."""
        report = make_sample_report(
            process_activity=[
                ProcessActivity(
                    pid=100,
                    name="cmd.exe",
                    path=None,
                    command_line="cmd /c https://evil.com/dl.exe",
                    parent_pid=1,
                    operation="created",
                    exit_code=0,
                    timestamp=ts_offset(0),
                ),
            ],
        )
        iocs = extract_iocs(report)
        urls = [i for i in iocs if i["ioc_type"] == "url"]
        assert any("https://evil.com/dl.exe" in i["value"] for i in urls)

    def test_sha256_from_file_path(self) -> None:
        """SHA256 hash from file path is extracted."""
        sha = "a" * 64
        report = make_sample_report(
            file_changes=[
                FileChange(
                    path=f"C:\\Temp\\{sha}.bin",
                    operation="created",
                    old_path=None,
                    timestamp=ts_offset(0),
                    size=100,
                ),
            ],
        )
        iocs = extract_iocs(report)
        hashes = [i for i in iocs if i["ioc_type"] == "sha256"]
        assert any(i["value"] == sha for i in hashes)

    def test_md5_from_file_path(self) -> None:
        """MD5 hash from file path is extracted."""
        md5 = "b" * 32
        report = make_sample_report(
            file_changes=[
                FileChange(
                    path=f"C:\\Temp\\{md5}.bin",
                    operation="created",
                    old_path=None,
                    timestamp=ts_offset(0),
                    size=100,
                ),
            ],
        )
        iocs = extract_iocs(report)
        hashes = [i for i in iocs if i["ioc_type"] == "md5"]
        assert any(i["value"] == md5 for i in hashes)

    def test_email_from_registry(self) -> None:
        """Email address from registry value_data is extracted."""
        report = make_sample_report(
            registry_changes=[
                RegistryChange(
                    key="HKLM\\SOFTWARE\\Test",
                    value_name="contact",
                    operation="created",
                    value_type="REG_SZ",
                    value_data="admin@malware.com",
                    timestamp=ts_offset(0),
                ),
            ],
        )
        iocs = extract_iocs(report)
        emails = [i for i in iocs if i["ioc_type"] == "email"]
        assert any(i["value"] == "admin@malware.com" for i in emails)

    def test_filters_private_10(self) -> None:
        """10.x.x.x IPs are filtered out."""
        report = make_sample_report(
            network_activity=[_net(remote_address="10.0.0.1")],
        )
        iocs = extract_iocs(report)
        ips = [i for i in iocs if i["ioc_type"] == "ipv4" and i["value"] == "10.0.0.1"]
        assert len(ips) == 0

    def test_filters_private_172(self) -> None:
        """172.16.x.x IPs are filtered out."""
        report = make_sample_report(
            network_activity=[_net(remote_address="172.16.0.1")],
        )
        iocs = extract_iocs(report)
        ips = [i for i in iocs if i["ioc_type"] == "ipv4" and i["value"] == "172.16.0.1"]
        assert len(ips) == 0

    def test_filters_private_192(self) -> None:
        """192.168.x.x IPs are filtered out."""
        report = make_sample_report(
            network_activity=[_net(remote_address="192.168.1.1")],
        )
        iocs = extract_iocs(report)
        ips = [i for i in iocs if i["ioc_type"] == "ipv4" and i["value"] == "192.168.1.1"]
        assert len(ips) == 0

    def test_filters_invalid_ip(self) -> None:
        """Invalid IPs (999.999.999.999) are filtered out."""
        report = make_sample_report(
            file_changes=[
                FileChange(
                    path="C:\\999.999.999.999\\test.txt",
                    operation="created",
                    old_path=None,
                    timestamp=ts_offset(0),
                    size=100,
                ),
            ],
        )
        iocs = extract_iocs(report)
        ips = [i for i in iocs if i["ioc_type"] == "ipv4" and i["value"] == "999.999.999.999"]
        assert len(ips) == 0

    def test_deduplication(self) -> None:
        """Same IOC from multiple sources produces one entry."""
        report = make_sample_report(
            network_activity=[
                _net(remote_address="203.0.113.1", ts_sec=0),
                _net(remote_address="203.0.113.1", ts_sec=1),
            ],
        )
        iocs = extract_iocs(report)
        ips = [i for i in iocs if i["ioc_type"] == "ipv4" and i["value"] == "203.0.113.1"]
        assert len(ips) == 1

    def test_multiple_sources_merged(self) -> None:
        """IOCs from different report fields are all collected."""
        report = make_sample_report(
            network_activity=[_net(remote_address="203.0.113.1")],
            process_activity=[
                ProcessActivity(
                    pid=100,
                    name="cmd.exe",
                    path=None,
                    command_line="ping 198.51.100.1",
                    parent_pid=1,
                    operation="created",
                    exit_code=0,
                    timestamp=ts_offset(0),
                ),
            ],
        )
        iocs = extract_iocs(report)
        ips = [i for i in iocs if i["ioc_type"] == "ipv4"]
        assert len(ips) >= 2

    def test_full_sample_report(self, sample_report: ExecutionReport) -> None:
        """Full sample report produces multiple IOC types.

        Args:
            sample_report: ExecutionReport fixture populated with all sample data.
        """
        iocs = extract_iocs(sample_report)
        ioc_types = {i["ioc_type"] for i in iocs}
        assert len(ioc_types) >= 2


class TestGenerateTimeline:
    """Verify timeline generation from execution reports."""

    def test_empty_report(self, empty_report: ExecutionReport) -> None:
        """Empty report returns empty timeline.

        Args:
            empty_report: ExecutionReport fixture with empty activity lists.
        """
        events = generate_timeline(empty_report)
        assert events == []

    def test_file_events(self) -> None:
        """File changes produce file-category events."""
        report = make_sample_report(
            file_changes=[
                FileChange(path="C:\\x.txt", operation="created", old_path=None, timestamp=ts_offset(1), size=100),
            ],
        )
        events = generate_timeline(report)
        assert len(events) == 1
        assert events[0]["category"] == "file"

    def test_registry_events(self) -> None:
        """Registry changes produce registry-category events."""
        report = make_sample_report(
            registry_changes=[
                RegistryChange(
                    key="HKLM\\X",
                    value_name="v",
                    operation="created",
                    value_type=None,
                    value_data=None,
                    timestamp=ts_offset(1),
                ),
            ],
        )
        events = generate_timeline(report)
        assert len(events) == 1
        assert events[0]["category"] == "registry"

    def test_network_events(self) -> None:
        """Network activity produces network-category events."""
        report = make_sample_report(network_activity=[_net(ts_sec=1)])
        events = generate_timeline(report)
        assert len(events) == 1
        assert events[0]["category"] == "network"

    def test_process_events(self) -> None:
        """Process activity produces process-category events."""
        report = make_sample_report(
            process_activity=[
                ProcessActivity(
                    pid=100,
                    name="test.exe",
                    path=None,
                    command_line=None,
                    parent_pid=1,
                    operation="created",
                    exit_code=0,
                    timestamp=ts_offset(1),
                ),
            ],
        )
        events = generate_timeline(report)
        assert len(events) == 1
        assert events[0]["category"] == "process"

    def test_api_events(self) -> None:
        """API calls produce api-category events."""
        report = make_sample_report(
            api_calls=[
                ApiCall(
                    timestamp=ts_offset(1),
                    process_name="test.exe",
                    pid=100,
                    api_name="CreateFileW",
                    module="kernel32.dll",
                    arguments=[],
                    return_value="0",
                ),
            ],
        )
        events = generate_timeline(report)
        assert len(events) == 1
        assert events[0]["category"] == "api"

    def test_service_events(self) -> None:
        """Service changes produce service-category events."""
        report = make_sample_report(
            service_changes=[
                ServiceChange(
                    service_name="Svc",
                    display_name="S",
                    binary_path="x",
                    start_type="auto",
                    operation="created",
                    timestamp=ts_offset(1),
                ),
            ],
        )
        events = generate_timeline(report)
        assert len(events) == 1
        assert events[0]["category"] == "service"

    def test_kernel_events(self) -> None:
        """Kernel objects produce kernel-category events."""
        report = make_sample_report(
            kernel_objects=[
                KernelObjectActivity(
                    object_type="Mutex",
                    name="M",
                    pid=100,
                    process_name="test.exe",
                    operation="created",
                    timestamp=ts_offset(1),
                ),
            ],
        )
        events = generate_timeline(report)
        assert len(events) == 1
        assert events[0]["category"] == "kernel"

    def test_dll_events(self) -> None:
        """DLL loads produce dll-category events."""
        report = make_sample_report(
            dll_loads=[
                DllLoadEvent(
                    timestamp=ts_offset(1),
                    pid=100,
                    process_name="test.exe",
                    dll_path="ntdll.dll",
                    base_address="0x0",
                    size=1024,
                    event_id=10,
                    payload_schema="",
                ),
            ],
        )
        events = generate_timeline(report)
        assert len(events) == 1
        assert events[0]["category"] == "dll"

    def test_injection_events(self) -> None:
        """Injection events produce injection-category events."""
        report = make_sample_report(
            injection_events=[
                InjectionEvent(
                    timestamp=ts_offset(1),
                    source_pid=100,
                    source_name="a.exe",
                    target_pid=200,
                    target_name="b.exe",
                    injection_type="CRT",
                    api_calls=["VirtualAllocEx"],
                ),
            ],
        )
        events = generate_timeline(report)
        assert len(events) == 1
        assert events[0]["category"] == "injection"

    def test_clipboard_events(self) -> None:
        """Clipboard events produce clipboard-category events."""
        report = make_sample_report(
            clipboard_events=[
                ClipboardEvent(
                    timestamp=ts_offset(1),
                    operation="read",
                    format="CF_TEXT",
                    content_preview="x",
                    size_bytes=1,
                    pid=100,
                    process_name="test.exe",
                ),
            ],
        )
        events = generate_timeline(report)
        assert len(events) == 1
        assert events[0]["category"] == "clipboard"

    def test_sorted_by_timestamp(self) -> None:
        """Events from different categories are sorted by timestamp."""
        report = make_sample_report(
            file_changes=[
                FileChange(path="x", operation="created", old_path=None, timestamp=ts_offset(10), size=0),
            ],
            network_activity=[_net(ts_sec=1)],
        )
        events = generate_timeline(report)
        assert len(events) == 2
        assert events[0]["timestamp"] <= events[1]["timestamp"]

    def test_category_filter(self) -> None:
        """Category filter includes only specified categories."""
        report = make_sample_report(
            file_changes=[
                FileChange(path="x", operation="created", old_path=None, timestamp=ts_offset(1), size=0),
            ],
            network_activity=[_net(ts_sec=2)],
            process_activity=[
                ProcessActivity(
                    pid=100,
                    name="x",
                    path=None,
                    command_line=None,
                    parent_pid=1,
                    operation="created",
                    exit_code=0,
                    timestamp=ts_offset(3),
                ),
            ],
        )
        events = generate_timeline(report, categories=["file", "network"])
        categories = {e["category"] for e in events}
        assert "file" in categories
        assert "network" in categories
        assert "process" not in categories

    def test_categories_none_includes_all(self) -> None:
        """categories=None includes all categories."""
        report = make_sample_report(
            file_changes=[FileChange(path="x", operation="created", old_path=None, timestamp=ts_offset(1), size=0)],
            network_activity=[_net(ts_sec=2)],
        )
        events = generate_timeline(report, categories=None)
        assert len(events) == 2

    def test_file_rename_includes_old_path(self) -> None:
        """Renamed file includes old_path in details."""
        report = make_sample_report(
            file_changes=[
                FileChange(path="C:\\new.txt", operation="renamed", old_path="C:\\old.txt", timestamp=ts_offset(1), size=0),
            ],
        )
        events = generate_timeline(report)
        assert events[0]["details"]["old_path"] == "C:\\old.txt"

    def test_registry_null_value_name_shows_default(self) -> None:
        """Registry entry with value_name=None shows '(Default)' in summary."""
        report = make_sample_report(
            registry_changes=[
                RegistryChange(
                    key="HKLM\\X",
                    value_name=None,
                    operation="created",
                    value_type=None,
                    value_data=None,
                    timestamp=ts_offset(1),
                ),
            ],
        )
        events = generate_timeline(report)
        assert "(Default)" in events[0]["summary"]

    def test_full_sample_report(self, sample_report: ExecutionReport) -> None:
        """Full sample report produces events from multiple categories.

        Args:
            sample_report: ExecutionReport fixture populated with all sample data.
        """
        events = generate_timeline(sample_report)
        categories = {e["category"] for e in events}
        assert len(categories) >= 5


class TestMatchBehaviors:
    """Verify behavioral signature matching."""

    def test_clean_report(self, empty_report: ExecutionReport) -> None:
        """Clean report produces no matches.

        Args:
            empty_report: ExecutionReport fixture with empty activity lists.
        """
        matches = match_behaviors(empty_report)
        assert matches == []

    def test_service_creation_persistence(self) -> None:
        """Service creation triggers T1543 persistence match."""
        report = make_sample_report(
            service_changes=[
                ServiceChange(
                    service_name="Svc",
                    display_name="S",
                    binary_path="x",
                    start_type="auto",
                    operation="created",
                    timestamp=ts_offset(0),
                ),
            ],
        )
        matches = match_behaviors(report)
        t1543 = [m for m in matches if m["mitre_attack_id"] == "T1543"]
        assert len(t1543) >= 1

    def test_run_key_persistence(self) -> None:
        """Run key modification triggers T1547 persistence match."""
        report = make_sample_report(
            registry_changes=[
                RegistryChange(
                    key="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
                    value_name="M",
                    operation="created",
                    value_type="REG_SZ",
                    value_data="x",
                    timestamp=ts_offset(0),
                ),
            ],
        )
        matches = match_behaviors(report)
        t1547 = [m for m in matches if m["mitre_attack_id"] == "T1547"]
        assert len(t1547) >= 1

    def test_schtasks_persistence(self) -> None:
        """schtasks.exe execution triggers scheduled task persistence match."""
        report = make_sample_report(
            process_activity=[
                ProcessActivity(
                    pid=100,
                    name="schtasks.exe",
                    path=None,
                    command_line="schtasks /create",
                    parent_pid=1,
                    operation="created",
                    exit_code=0,
                    timestamp=ts_offset(0),
                ),
            ],
        )
        matches = match_behaviors(report)
        sched = [m for m in matches if m["signature_name"] == "Scheduled Task Creation"]
        assert len(sched) >= 1

    def test_at_exe_persistence(self) -> None:
        """at.exe execution triggers scheduled task persistence match."""
        report = make_sample_report(
            process_activity=[
                ProcessActivity(
                    pid=100,
                    name="at.exe",
                    path=None,
                    command_line="at 12:00 test",
                    parent_pid=1,
                    operation="created",
                    exit_code=0,
                    timestamp=ts_offset(0),
                ),
            ],
        )
        matches = match_behaviors(report)
        sched = [m for m in matches if m["signature_name"] == "Scheduled Task Creation"]
        assert len(sched) >= 1

    def test_injection_evasion(self) -> None:
        """Process injection triggers T1055 with critical severity."""
        report = make_sample_report(
            injection_events=[
                InjectionEvent(
                    timestamp=ts_offset(0),
                    source_pid=100,
                    source_name="a.exe",
                    target_pid=200,
                    target_name="b.exe",
                    injection_type="CRT",
                    api_calls=["VirtualAllocEx"],
                ),
            ],
        )
        matches = match_behaviors(report)
        inj = [m for m in matches if m["mitre_attack_id"] == "T1055"]
        assert len(inj) >= 1
        assert inj[0]["severity"] == "critical"

    def test_anti_debug_evasion(self) -> None:
        """IsDebuggerPresent triggers T1497 anti-debug match."""
        report = make_sample_report(
            api_calls=[
                ApiCall(
                    timestamp=ts_offset(0),
                    process_name="test.exe",
                    pid=100,
                    api_name="IsDebuggerPresent",
                    module="kernel32.dll",
                    arguments=[],
                    return_value="0",
                ),
            ],
        )
        matches = match_behaviors(report)
        t1497 = [m for m in matches if m["mitre_attack_id"] == "T1497"]
        assert len(t1497) >= 1

    def test_sleep_evasion(self) -> None:
        """Sleep > 60000ms triggers sandbox evasion match."""
        report = make_sample_report(
            api_calls=[
                ApiCall(
                    timestamp=ts_offset(0),
                    process_name="test.exe",
                    pid=100,
                    api_name="Sleep",
                    module="kernel32.dll",
                    arguments=[str(_SLEEP_MS)],
                    return_value="0",
                ),
            ],
        )
        matches = match_behaviors(report)
        sleep = [m for m in matches if m["signature_name"] == "Sleep Acceleration Evasion"]
        assert len(sleep) >= 1

    def test_beaconing_c2(self, sample_network_activity: list[NetworkActivity]) -> None:
        """Beaconing pattern in network data triggers C2 match.

        Args:
            sample_network_activity: Network-activity fixture with beaconing, DGA, C2, exfil, and normal traffic.
        """
        report = make_sample_report(network_activity=sample_network_activity)
        matches = match_behaviors(report)
        c2 = [m for m in matches if m["category"] == "Command and Control"]
        assert len(c2) >= 1

    def test_doh_c2(self) -> None:
        """Connection to 1.1.1.1:443 triggers DoH/T1573 match."""
        report = make_sample_report(
            network_activity=[_net(remote_address=_DOH_ADDR, remote_port=_HTTPS_PORT)],
        )
        matches = match_behaviors(report)
        t1573 = [m for m in matches if m["mitre_attack_id"] == "T1573"]
        assert len(t1573) >= 1

    def test_large_outbound_exfil(self) -> None:
        """Large outbound transfer triggers T1041 exfiltration match."""
        report = make_sample_report(
            network_activity=[
                _net(
                    bytes_sent=_EXFIL_SENT,
                    bytes_received=_EXFIL_RECV,
                    direction="outbound",
                ),
            ],
        )
        matches = match_behaviors(report)
        t1041 = [m for m in matches if m["mitre_attack_id"] == "T1041"]
        assert len(t1041) >= 1

    def test_clipboard_read_exfil(self) -> None:
        """Clipboard read triggers T1115 exfiltration match."""
        report = make_sample_report(
            clipboard_events=[
                ClipboardEvent(
                    timestamp=ts_offset(0),
                    operation="read",
                    format="CF_TEXT",
                    content_preview="secret",
                    size_bytes=6,
                    pid=100,
                    process_name="test.exe",
                ),
            ],
        )
        matches = match_behaviors(report)
        t1115 = [m for m in matches if m["mitre_attack_id"] == "T1115"]
        assert len(t1115) >= 1

    def test_whoami_discovery(self) -> None:
        """whoami.exe triggers T1082 discovery match."""
        report = make_sample_report(
            process_activity=[
                ProcessActivity(
                    pid=100,
                    name="whoami.exe",
                    path=None,
                    command_line="whoami /all",
                    parent_pid=1,
                    operation="created",
                    exit_code=0,
                    timestamp=ts_offset(0),
                ),
            ],
        )
        matches = match_behaviors(report)
        t1082 = [m for m in matches if m["mitre_attack_id"] == "T1082"]
        assert len(t1082) >= 1

    def test_systeminfo_discovery(self) -> None:
        """systeminfo.exe triggers T1082 discovery match."""
        report = make_sample_report(
            process_activity=[
                ProcessActivity(
                    pid=100,
                    name="systeminfo.exe",
                    path=None,
                    command_line="systeminfo",
                    parent_pid=1,
                    operation="created",
                    exit_code=0,
                    timestamp=ts_offset(0),
                ),
            ],
        )
        matches = match_behaviors(report)
        t1082 = [m for m in matches if m["mitre_attack_id"] == "T1082"]
        assert len(t1082) >= 1

    def test_custom_rule_registry_match(self) -> None:
        """Custom rule with registry_patterns matches."""
        report = make_sample_report(
            registry_changes=[
                RegistryChange(
                    key="HKLM\\CUSTOM\\SuspiciousKey",
                    value_name="v",
                    operation="created",
                    value_type=None,
                    value_data=None,
                    timestamp=ts_offset(0),
                ),
            ],
        )
        rules: list[dict[str, Any]] = [
            {
                "name": "Custom Registry",
                "category": "Custom",
                "severity": "high",
                "description": "Custom reg match",
                "mitre_id": "T9999",
                "conditions": {"registry_patterns": ["suspiciouskey"]},
            },
        ]
        matches = match_behaviors(report, custom_rules=rules)
        custom = [m for m in matches if m["mitre_attack_id"] == "T9999"]
        assert len(custom) >= 1

    def test_custom_rule_process_match(self) -> None:
        """Custom rule with process_names matches."""
        report = make_sample_report(
            process_activity=[
                ProcessActivity(
                    pid=100,
                    name="evil.exe",
                    path=None,
                    command_line=None,
                    parent_pid=1,
                    operation="created",
                    exit_code=0,
                    timestamp=ts_offset(0),
                ),
            ],
        )
        rules: list[dict[str, Any]] = [
            {
                "name": "Evil Process",
                "conditions": {"process_names": ["evil"]},
            },
        ]
        matches = match_behaviors(report, custom_rules=rules)
        assert any(m["signature_name"] == "Evil Process" for m in matches)

    def test_custom_rule_api_match(self) -> None:
        """Custom rule with api_names matches."""
        report = make_sample_report(
            api_calls=[
                ApiCall(
                    timestamp=ts_offset(0),
                    process_name="test.exe",
                    pid=100,
                    api_name="NtCreateSection",
                    module="ntdll.dll",
                    arguments=[],
                    return_value="0",
                ),
            ],
        )
        rules: list[dict[str, Any]] = [
            {
                "name": "Section Create",
                "conditions": {"api_names": ["NtCreateSection"]},
            },
        ]
        matches = match_behaviors(report, custom_rules=rules)
        assert any(m["signature_name"] == "Section Create" for m in matches)

    def test_custom_rule_network_port_match(self) -> None:
        """Custom rule with network_ports matches."""
        report = make_sample_report(
            network_activity=[_net(remote_port=9999)],
        )
        rules: list[dict[str, Any]] = [
            {
                "name": "Port 9999",
                "conditions": {"network_ports": [9999]},
            },
        ]
        matches = match_behaviors(report, custom_rules=rules)
        assert any(m["signature_name"] == "Port 9999" for m in matches)

    def test_custom_rule_no_match(self) -> None:
        """Non-matching custom rule produces no output."""
        report = make_sample_report()
        rules: list[dict[str, Any]] = [
            {
                "name": "No Match",
                "conditions": {"process_names": ["nonexistent"]},
            },
        ]
        matches = match_behaviors(report, custom_rules=rules)
        assert not any(m["signature_name"] == "No Match" for m in matches)

    def test_full_sample_report(self, sample_report: ExecutionReport) -> None:
        """Full sample report matches multiple MITRE categories.

        Args:
            sample_report: ExecutionReport fixture populated with all sample data.
        """
        matches = match_behaviors(sample_report)
        categories = {m["category"] for m in matches}
        assert len(categories) >= 3


class TestDiffReports:
    """Verify report diffing logic."""

    def test_identical_reports(self) -> None:
        """Identical reports produce all common, no unique."""
        report = make_sample_report(
            file_changes=[FileChange(path="x", operation="created", old_path=None, timestamp=ts_offset(0), size=0)],
        )
        result = diff_reports(report, report)
        assert len(result["file_changes"]["common"]) == 1
        assert len(result["file_changes"]["unique_to_a"]) == 0
        assert len(result["file_changes"]["unique_to_b"]) == 0

    def test_completely_different(self) -> None:
        """Completely different reports produce all unique, no common."""
        a = make_sample_report(
            file_changes=[FileChange(path="a.txt", operation="created", old_path=None, timestamp=ts_offset(0), size=0)],
        )
        b = make_sample_report(
            file_changes=[FileChange(path="b.txt", operation="created", old_path=None, timestamp=ts_offset(0), size=0)],
        )
        result = diff_reports(a, b)
        assert len(result["file_changes"]["unique_to_a"]) == 1
        assert len(result["file_changes"]["unique_to_b"]) == 1
        assert len(result["file_changes"]["common"]) == 0

    def test_partial_overlap(self) -> None:
        """Partial overlap produces mixed common/unique."""
        a = make_sample_report(
            file_changes=[
                FileChange(path="common.txt", operation="created", old_path=None, timestamp=ts_offset(0), size=0),
                FileChange(path="only_a.txt", operation="created", old_path=None, timestamp=ts_offset(1), size=0),
            ],
        )
        b = make_sample_report(
            file_changes=[
                FileChange(path="common.txt", operation="created", old_path=None, timestamp=ts_offset(0), size=0),
                FileChange(path="only_b.txt", operation="created", old_path=None, timestamp=ts_offset(1), size=0),
            ],
        )
        result = diff_reports(a, b)
        assert len(result["file_changes"]["common"]) == 1
        assert len(result["file_changes"]["unique_to_a"]) == 1
        assert len(result["file_changes"]["unique_to_b"]) == 1

    def test_scalar_diffs(self) -> None:
        """Scalar fields show side-by-side comparison."""
        a = ExecutionReport(result="success", exit_code=0, stdout="", stderr="", duration_seconds=1.0)
        b = ExecutionReport(result="error", exit_code=1, stdout="", stderr="", duration_seconds=2.0)
        result = diff_reports(a, b)
        assert result["scalars"]["result"]["a"] == "success"
        assert result["scalars"]["result"]["b"] == "error"
        assert result["scalars"]["exit_code"]["a"] == 0
        assert result["scalars"]["exit_code"]["b"] == 1

    def test_all_list_field_keys_present(self) -> None:
        """All 11 list field keys are present in diff output."""
        a = make_sample_report()
        b = make_sample_report()
        result = diff_reports(a, b)
        expected_fields = {
            "file_changes",
            "registry_changes",
            "network_activity",
            "process_activity",
            "api_calls",
            "service_changes",
            "kernel_objects",
            "dll_loads",
            "injection_events",
            "resource_samples",
            "clipboard_events",
        }
        for field_name in expected_fields:
            assert field_name in result

    def test_empty_reports_diff(self) -> None:
        """Diffing two empty reports produces empty lists."""
        a = make_sample_report()
        b = make_sample_report()
        result = diff_reports(a, b)
        for field_name in ["file_changes", "network_activity", "process_activity"]:
            assert result[field_name]["unique_to_a"] == []
            assert result[field_name]["unique_to_b"] == []
            assert result[field_name]["common"] == []

    def test_duration_diff(self) -> None:
        """Duration difference shows in scalars."""
        a = ExecutionReport(result="success", exit_code=0, stdout="", stderr="", duration_seconds=1.0)
        b = ExecutionReport(result="success", exit_code=0, stdout="", stderr="", duration_seconds=5.0)
        result = diff_reports(a, b)
        assert math.isclose(float(result["scalars"]["duration_seconds"]["a"]), 1.0)
        assert math.isclose(float(result["scalars"]["duration_seconds"]["b"]), 5.0)

    def test_full_sample_diff(self, sample_report: ExecutionReport, empty_report: ExecutionReport) -> None:
        """Diffing full vs empty report puts everything in unique_to_a.

        Args:
            sample_report: ExecutionReport fixture populated with all sample data.
            empty_report: ExecutionReport fixture with empty activity lists.
        """
        result = diff_reports(sample_report, empty_report)
        assert len(result["file_changes"]["unique_to_a"]) > 0
        assert len(result["file_changes"]["unique_to_b"]) == 0
