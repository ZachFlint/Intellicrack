#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Lint reporting engine: normalize tool output and generate multi-format reports.

Processes native JSON/text output from 45+ linting and analysis tools into a
normalized structure, then writes per-tool reports in TXT, JSON, XML, CSV, and
SARIF formats. Also generates a unified HTML dashboard aggregating all findings.
Findings are sorted by file, with files having the most findings listed first.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import datetime
import json
import re
import sqlite3
import sys
from collections import defaultdict
from html import escape as html_escape
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple


if TYPE_CHECKING:
    from collections.abc import Callable

ESLINT_ERROR_SEVERITY = 2
ERROR_CODE_PREFIX_LENGTH = 6
MIN_PARTS_FOR_VALUE = 2
MIN_ARGV_FOR_TOOL = 2
MIN_ARGV_FOR_INPUT = 3
MIN_ARGV_FOR_TEXT_FILE = 4
ENTITY_TYPE_NAMES: dict[str, str] = {"F": "function", "M": "method", "C": "class", "E": "exception"}
RANK_COMPLEXITY_MAP: dict[str, int] = {"A": 5, "B": 10, "C": 20, "D": 30, "E": 40, "F": 50}
CSV_COLUMNS: list[str] = [
    "tool",
    "file",
    "line",
    "column",
    "severity",
    "code",
    "rule",
    "message",
    "confidence",
    "complexity",
    "rank",
    "name",
    "entity_type",
    "category",
    "function",
    "variable",
    "crate",
    "vulnerability",
    "misspelling",
    "correction",
]
_SARIF_SEVERITY_MAP: dict[str, str] = {
    "error": "error",
    "high": "error",
    "critical": "error",
    "warning": "warning",
    "medium": "warning",
    "security": "warning",
    "info": "note",
    "style": "note",
    "low": "note",
    "note": "note",
    "information": "note",
}

_SEVERITY_GREEN_MAX = 10
_SEVERITY_YELLOW_MAX = 50
_SEVERITY_ORANGE_MAX = 200
_TEXT_BAR_WIDTH = 40


def severity_color_for_count(count: int) -> tuple[int, int, int]:
    """Map a finding count to a severity-based RGB color.

    Args:
        count: Number of findings.

    Returns:
        An (R, G, B) tuple.
    """
    if count <= _SEVERITY_GREEN_MAX:
        return (0, 180, 0)
    if count <= _SEVERITY_YELLOW_MAX:
        return (200, 200, 0)
    if count <= _SEVERITY_ORANGE_MAX:
        return (220, 140, 0)
    return (200, 0, 0)


def print_sixel_legend(
    labels: list[str],
    values: list[int],
    colors: list[tuple[int, int, int]],
) -> None:
    """Print a colored text bar chart with labels and proportional bars.

    Args:
        labels: Bar labels.
        values: Numeric value for each bar.
        colors: RGB color tuple for each bar.
    """
    if not labels:
        return
    max_label = max((len(lbl) for lbl in labels), default=0)
    max_val = max(values) if values else 1
    if max_val == 0:
        max_val = 1
    val_width = max(len(str(v)) for v in values)
    for lbl, val, (r, g, b) in zip(labels, values, colors, strict=True):
        bar_len = max(1, int(val / max_val * _TEXT_BAR_WIDTH))
        bar = f"\x1b[38;2;{r};{g};{b}m" + "\u2588" * bar_len + "\x1b[0m"
        print(f"  {lbl:<{max_label}}  {bar} {val:>{val_width}}")


def process_eslint(data: list[Any]) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process ESLint native JSON output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    cnt = 0
    for file_obj in data:
        fp = file_obj.get("filePath", "")
        for msg in file_obj.get("messages", []):
            cnt += 1
            severity = "error" if msg.get("severity") == ESLINT_ERROR_SEVERITY else "warning"
            grouped[fp].append({
                "line": msg.get("line"),
                "column": msg.get("column"),
                "severity": severity,
                "message": msg.get("message", ""),
                "rule": msg.get("ruleId", ""),
                "raw": f"{fp}:{msg.get('line')}:{msg.get('column')}: [{severity}] {msg.get('message', '')} ({msg.get('ruleId', '')})",
            })
    return grouped, cnt


def process_ruff(data: list[Any]) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process Ruff native JSON output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in data:
        fp = item.get("filename", "")
        loc = item.get("location", {})
        grouped[fp].append({
            "line": loc.get("row"),
            "column": loc.get("column"),
            "code": item.get("code", ""),
            "message": item.get("message", ""),
            "raw": f"{fp}:{loc.get('row')}:{loc.get('column')}: {item.get('code', '')} {item.get('message', '')}",
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_basedpyright(data: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process BasedPyright native JSON output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    diagnostics = data.get("generalDiagnostics", [])
    for item in diagnostics:
        fp = item.get("file", "")
        rng = item.get("range", {}).get("start", {})
        grouped[fp].append({
            "line": rng.get("line", 0) + 1,
            "column": rng.get("character", 0) + 1,
            "severity": item.get("severity", "error"),
            "rule": item.get("rule", ""),
            "message": item.get("message", ""),
            "raw": f"{fp}:{rng.get('line', 0) + 1}:{rng.get('character', 0) + 1}: [{item.get('severity', 'error')}] {item.get('message', '')}",
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_mypy_json(data: list[Any]) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process Mypy JSON output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in data:
        fp = item.get("file", "")
        grouped[fp].append({
            "line": item.get("line"),
            "column": item.get("column"),
            "severity": item.get("severity", "error"),
            "code": item.get("code", ""),
            "message": item.get("message", ""),
            "raw": f"{fp}:{item.get('line')}:{item.get('column')}: [{item.get('severity', 'error')}] {item.get('message', '')} [{item.get('code', '')}]",
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_knip(data: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process Knip native JSON output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    cnt = 0
    categories = [
        "dependencies",
        "devDependencies",
        "optionalPeerDependencies",
        "unlisted",
        "binaries",
        "unresolved",
        "exports",
        "types",
        "duplicates",
    ]
    for issue in data.get("issues", []):
        fp = issue.get("file", "unknown")
        for category in categories:
            items = issue.get(category, [])
            if not isinstance(items, list):
                continue
            for item in items:
                cnt += 1
                name = item.get("name", item.get("symbol", ""))
                line_num = item.get("line")
                col_num = item.get("col")
                grouped[fp].append({
                    "line": line_num,
                    "column": col_num,
                    "category": category,
                    "rule": category,
                    "message": f"[{category}] {name}",
                    "raw": f"{fp}:{line_num or 0}:{col_num or 0}: [{category}] {name}",
                })
    return grouped, cnt


def process_semgrep(data: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process Semgrep native JSON output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in data.get("results", []):
        fp = result.get("path", "")
        start = result.get("start", {})
        line_num = start.get("line")
        col_num = start.get("col")
        check_id = result.get("check_id", "")
        extra = result.get("extra", {})
        message = extra.get("message", "")
        severity = extra.get("severity", "WARNING").lower()
        grouped[fp].append({
            "line": line_num,
            "column": col_num,
            "severity": severity,
            "rule": check_id,
            "message": message,
            "raw": f"{fp}:{line_num}:{col_num}: [{severity}] {check_id}: {message}",
        })
    for error in data.get("errors", []):
        fp = error.get("path", error.get("spans", [{}])[0].get("file", "unknown")) if error.get("path") or error.get("spans") else "unknown"
        message = error.get("message", error.get("long_msg", str(error)))
        grouped[fp].append({
            "line": None,
            "column": None,
            "severity": "error",
            "rule": error.get("type", "semgrep-error"),
            "message": message,
            "raw": f"{fp}: [error] {message}",
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


_SEMGREP_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_SEMGREP_RULE_RE = re.compile(r"^\s*[^\w\s]+\s+([\w\.\-]+)\s*$")
_SEMGREP_FINDING_RE = re.compile(r"^\s+(\d+)\S*\s*[\u2506\u2502\|]\s(.*)$")
_SEMGREP_SEPARATOR_RE = re.compile(r"^\s+\u22ee\S*\s*[\u2506\u2502\|]")
_SEMGREP_FILE_RE = re.compile(r"^\s+(\S.+?\.(?:py|pyi|js|ts|tsx|jsx|go|java|rb|rs|c|cpp|h|hpp|cs|php|sh|yaml|yml|json|sol))\s*$")
_SEMGREP_SEVERITY_RE = re.compile(r"\b(Blocking|Error|High|Critical|Warning|Medium|Info|Low|Note)\b", re.IGNORECASE)
_SEMGREP_BANNER_LINES = ("Code Findings", "Scan Summary", "findings", "Scanning", "Ran ", "Findings:")


class _SemgrepLineInfo(NamedTuple):
    """Classification result for a single Semgrep text-output line.

    Attributes:
        kind: One of ``"banner"``, ``"separator"``, ``"file"``, ``"rule"``,
            ``"severity"``, ``"finding"``, ``"message"``, or ``"ignore"``.
        str_payload: String capture for file/rule/severity/message kinds.
        finding_line: Source line number for ``"finding"`` kind.
        finding_excerpt: Code excerpt for ``"finding"`` kind.

    """

    kind: str
    str_payload: str
    finding_line: int
    finding_excerpt: str


def _classify_semgrep_line(
    line: str,
    current_file: str | None,
    current_rule: str | None,
    current_message_parts: list[str],
) -> _SemgrepLineInfo:
    """Classify a single Semgrep text-output line.

    Args:
        line: The cleaned (ANSI-stripped) text line.
        current_file: The file header most recently observed, or None.
        current_rule: The rule header most recently observed, or None.
        current_message_parts: The accumulated message lines so far.

    Returns:
        A :class:`_SemgrepLineInfo` describing how to interpret the
        line.

    """
    if not line.strip() or any(marker in line for marker in _SEMGREP_BANNER_LINES):
        return _SemgrepLineInfo("banner", "", 0, "")
    if _SEMGREP_SEPARATOR_RE.match(line):
        return _SemgrepLineInfo("separator", "", 0, "")
    file_match = _SEMGREP_FILE_RE.match(line)
    if file_match is not None and not line.lstrip().startswith(("\u276f", ">")):
        return _SemgrepLineInfo(
            "file",
            file_match.group(1).strip().replace("\\", "/"),
            0,
            "",
        )
    rule_match = _SEMGREP_RULE_RE.match(line)
    if rule_match is not None and current_file is not None:
        candidate = rule_match.group(1)
        if "." in candidate or candidate.startswith(
            ("intellicrack-", "semgrep-", "python.", "generic."),
        ):
            return _SemgrepLineInfo("rule", candidate, 0, "")
    severity_marker = _SEMGREP_SEVERITY_RE.search(line)
    if severity_marker is not None and current_rule is not None and not current_message_parts:
        return _SemgrepLineInfo(
            "severity",
            _normalize_semgrep_severity(severity_marker.group(1)),
            0,
            "",
        )
    finding_match = _SEMGREP_FINDING_RE.match(line)
    if finding_match is not None and current_file is not None and current_rule is not None:
        return _SemgrepLineInfo(
            "finding",
            "",
            int(finding_match.group(1)),
            finding_match.group(2).strip(),
        )
    if current_rule is not None and line.lstrip().startswith(
        ("`", "The ", "A ", "An ", "Use ", "Never ", "Do ", "Avoid ", "Prefer ", "Ensure ", "Require ", "`_"),
    ):
        return _SemgrepLineInfo("message", line.strip(), 0, "")
    return _SemgrepLineInfo("ignore", "", 0, "")


def process_semgrep_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process Semgrep's `--text` CLI output into grouped findings.

    The native `semgrep scan --json` pipeline is unreliable on Windows
    (semgrep 1.159 semgrep-core RPC writes ``<ERROR: missing output>``
    to stdout when multiple `--config` flags are combined). Parsing
    the human-readable text output bypasses the JSON formatter entirely
    while preserving every finding Semgrep emitted.

    Supported text lines:
      - Indented file paths ending in a source extension.
      - Rule headers of the form ``<arrows> <rule-id>``.
      - Severity markers like ``<< Blocking >>`` or ``<< High >>``.
      - Finding lines ``    NN<sep> <code excerpt>`` where ``<sep>`` is
        ``\u2506`` (box drawing), ``\u2502`` (vertical), or ``|``.

    Args:
        text_output: Raw stdout from ``semgrep scan --text``.

    Returns:
        A tuple of ``(grouped findings by file, total count)`` matching
        the contract used by :func:`process_semgrep` so the CSV / JSON /
        XML / SARIF / SQL writers downstream treat native-JSON and text
        runs identically.

    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    current_file: str | None = None
    current_rule: str | None = None
    current_severity: str = "warning"
    current_message_parts: list[str] = []
    in_match_block = False
    for raw_line in text_output.splitlines():
        line = _SEMGREP_ANSI_RE.sub("", raw_line).rstrip()
        info = _classify_semgrep_line(
            line,
            current_file,
            current_rule,
            current_message_parts,
        )
        if info.kind in {"banner", "ignore"}:
            continue
        if info.kind == "separator":
            in_match_block = False
            continue
        if info.kind == "file":
            current_file = info.str_payload
            current_rule = None
            current_message_parts = []
            in_match_block = False
            continue
        if info.kind == "rule":
            current_rule = info.str_payload
            current_severity = "warning"
            current_message_parts = []
            in_match_block = False
            continue
        if info.kind == "severity":
            current_severity = info.str_payload
            continue
        if info.kind == "message":
            current_message_parts.append(info.str_payload)
            continue
        if info.kind == "finding" and current_file and current_rule:
            if in_match_block:
                continue
            in_match_block = True
            message = " ".join(current_message_parts).strip() or info.finding_excerpt
            grouped[current_file].append({
                "line": info.finding_line,
                "column": None,
                "severity": current_severity,
                "rule": current_rule,
                "message": message,
                "raw": (f"{current_file}:{info.finding_line}: [{current_severity}] {current_rule}: {message}"),
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def _normalize_semgrep_severity(marker: str) -> str:
    """Normalize a Semgrep CLI severity marker to the report taxonomy.

    Args:
        marker: Raw severity label found in text output (e.g. ``"Blocking"``,
            ``"High"``, ``"Warning"``).

    Returns:
        One of ``"error"``, ``"warning"``, ``"info"``.

    """
    lower = marker.lower()
    if lower in {"blocking", "error", "high", "critical"}:
        return "error"
    if lower in {"info", "low", "note"}:
        return "info"
    return "warning"


def process_biome_json(data: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process Biome native JSON output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    diagnostics = data.get("diagnostics", [])
    for item in diagnostics:
        location = item.get("location", {})
        path_obj = location.get("path", {})
        fp = path_obj.get("file", "unknown") if isinstance(path_obj, dict) else str(path_obj)
        fp = fp.replace("\\\\", "/").replace("\\", "/")
        span = location.get("span", {})
        start_offset = span.get("start", 0) if isinstance(span, dict) else 0
        severity = item.get("severity", "error").lower()
        category = item.get("category", "")
        message_data = item.get("message", item.get("description", ""))
        if isinstance(message_data, list):
            message = " ".join(str(m.get("content", "")) if isinstance(m, dict) else str(m) for m in message_data).strip()
        else:
            message = str(message_data)
        grouped[fp].append({
            "line": None,
            "column": None,
            "offset": start_offset,
            "severity": severity,
            "rule": category,
            "message": message,
            "raw": f"{fp}: [{severity}] {category}: {message}",
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_biome_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process Biome text/stderr output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    lines = text_output.strip().split("\n")
    cnt = 0
    pattern = re.compile(r"^([^\s]+\.(?:js|ts|jsx|tsx|cjs|mjs)):(\d+):(\d+)\s+(lint/\S+|format)\s*")
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        if not line_stripped:
            continue
        match = pattern.match(line_stripped)
        if match:
            fp = match.group(1).replace("\\", "/")
            line_num = int(match.group(2))
            col_num = int(match.group(3))
            rule = match.group(4)
            message_line = ""
            if i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                if next_line.startswith(("x", "!")):
                    message_line = next_line.lstrip("x!").strip()
            cnt += 1
            grouped[fp].append({
                "line": line_num,
                "column": col_num,
                "severity": "error" if "error" in rule.lower() else "warning",
                "rule": rule,
                "message": message_line or rule,
                "raw": f"{fp}:{line_num}:{col_num}: {rule} {message_line}",
            })
    return grouped, cnt


def process_ty_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process ty type checker text output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.py):(\d+):(\d+):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        match = pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            col_num = int(match.group(3))
            message = match.group(4).strip()
            code = ""
            if message.startswith("error["):
                code_end = message.find("]")
                if code_end > ERROR_CODE_PREFIX_LENGTH:
                    code = message[ERROR_CODE_PREFIX_LENGTH:code_end]
                    message = message[code_end + 1 :].strip().lstrip(":").strip()
            grouped[fp].append({"line": line_num, "column": col_num, "code": code, "message": message, "raw": stripped_line})
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_vulture_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process vulture dead code detection text output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.py):(\d+):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        match = pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            message = match.group(3).strip()
            grouped[fp].append({"line": line_num, "column": None, "message": message, "raw": stripped_line})
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_pydoclint_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    r"""Process pydoclint docstring linting text output.

    Pydoclint outputs filenames on their own line, then indented findings below.
    Example::

        src\\intellicrack\\bridges\\base.py
            168: DOC203: Method \`has_capability\` return type(s) ...
            179: DOC203: Method \`supports_arch\` return type(s) ...

    Args:
        text_output: Raw text output from pydoclint.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    finding_pattern = re.compile(r"^\s+(\d+):\s*(DOC\d+):\s*(.+)$")
    current_file: str | None = None
    for line in text_output.strip().split("\n"):
        if not line.strip():
            continue
        finding_match = finding_pattern.match(line)
        if finding_match:
            line_num = int(finding_match.group(1))
            code = finding_match.group(2)
            message = finding_match.group(3).strip()
            fp = current_file or "unknown"
            grouped[fp].append({
                "line": line_num,
                "column": None,
                "code": code,
                "message": message,
                "raw": line.strip(),
            })
        elif line.rstrip().endswith(".py"):
            current_file = line.strip()
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_dead_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process dead code linting text output.

    Dead tool outputs format: varname is never read, defined in file:line
    Example: health is never read, defined in intellicrack/ai/local_gguf_server.py:398
    Also handles multiple locations: var is never read, defined in file1:line1, file2:line2

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+?)\s+is never read,\s+defined in\s+(.+)$")
    location_pattern = re.compile(r"([^,\s]+\.py):(\d+)")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        match = pattern.match(stripped_line)
        if match:
            var_name = match.group(1).strip()
            locations_str = match.group(2).strip()
            locations = location_pattern.findall(locations_str)
            for fp, line_num_str in locations:
                grouped[fp].append({
                    "line": int(line_num_str),
                    "column": None,
                    "variable": var_name,
                    "message": f"'{var_name}' is never read",
                    "raw": stripped_line,
                })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_mypy_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process mypy text output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.py):(\d+):(\d+):\s*(\w+):\s*(.+)$")
    pattern2 = re.compile(r"^(.+\.py):(\d+):\s*(\w+):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith(("Found ", "Success:")):
            continue
        match = pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            col_num = int(match.group(3))
            severity = match.group(4)
            message = match.group(5).strip()
            code = ""
            if message.endswith("]") and "[" in message:
                bracket_pos = message.rfind("[")
                code = message[bracket_pos + 1 : -1]
                message = message[:bracket_pos].strip()
            grouped[fp].append({
                "line": line_num,
                "column": col_num,
                "severity": severity,
                "code": code,
                "message": message,
                "raw": stripped_line,
            })
        else:
            match2 = pattern2.match(stripped_line)
            if match2:
                fp = match2.group(1)
                line_num = int(match2.group(2))
                severity = match2.group(3)
                message = match2.group(4).strip()
                code = ""
                if message.endswith("]") and "[" in message:
                    bracket_pos = message.rfind("[")
                    code = message[bracket_pos + 1 : -1]
                    message = message[:bracket_pos].strip()
                grouped[fp].append({
                    "line": line_num,
                    "column": None,
                    "severity": severity,
                    "code": code,
                    "message": message,
                    "raw": stripped_line,
                })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_bandit_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process bandit security linting text output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    current_file = ""
    current_line = 0
    current_severity = ""
    current_confidence = ""
    current_issue = ""
    current_code = ""

    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        if stripped_line.startswith(">> Issue:"):
            if current_file and current_issue:
                grouped[current_file].append({
                    "line": current_line,
                    "column": None,
                    "severity": current_severity,
                    "confidence": current_confidence,
                    "code": current_code,
                    "message": current_issue,
                    "raw": f"{current_file}:{current_line}: [{current_severity}] {current_code}: {current_issue}",
                })
            current_issue = stripped_line[9:].strip()
            if current_issue.startswith("["):
                bracket_end = current_issue.find("]")
                if bracket_end > 0:
                    current_code = current_issue[1:bracket_end]
                    current_issue = current_issue[bracket_end + 1 :].strip()
        elif stripped_line.startswith("Severity:"):
            parts = stripped_line.split()
            if len(parts) >= MIN_PARTS_FOR_VALUE:
                current_severity = parts[1].rstrip(":")
            if "Confidence:" in stripped_line:
                conf_idx = stripped_line.find("Confidence:")
                conf_parts = stripped_line[conf_idx:].split()
                if len(conf_parts) >= MIN_PARTS_FOR_VALUE:
                    current_confidence = conf_parts[1]
        elif stripped_line.startswith("Location:"):
            loc_match = re.search(r"Location:\s*(.+\.py):(\d+)", stripped_line)
            if loc_match:
                current_file = loc_match.group(1)
                current_line = int(loc_match.group(2))
        elif stripped_line.startswith(("---", "Run started")):
            if current_file and current_issue:
                grouped[current_file].append({
                    "line": current_line,
                    "column": None,
                    "severity": current_severity,
                    "confidence": current_confidence,
                    "code": current_code,
                    "message": current_issue,
                    "raw": f"{current_file}:{current_line}: [{current_severity}] {current_code}: {current_issue}",
                })
            current_file = ""
            current_issue = ""
            current_code = ""

    if current_file and current_issue:
        grouped[current_file].append({
            "line": current_line,
            "column": None,
            "severity": current_severity,
            "confidence": current_confidence,
            "code": current_code,
            "message": current_issue,
            "raw": f"{current_file}:{current_line}: [{current_severity}] {current_code}: {current_issue}",
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_clippy_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process cargo clippy text output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"-->\s*(.+\.rs):(\d+):(\d+)")
    current_level = ""
    current_message = ""
    lines = text_output.strip().split("\n")
    for line in lines:
        line_stripped = line.strip()
        if line_stripped.startswith(("warning:", "error:")):
            parts = line_stripped.split(":", 1)
            current_level = parts[0]
            current_message = parts[1].strip() if len(parts) > 1 else ""
        match = pattern.search(line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            col_num = int(match.group(3))
            grouped[fp].append({
                "line": line_num,
                "column": col_num,
                "severity": current_level,
                "message": current_message,
                "raw": f"{fp}:{line_num}:{col_num}: [{current_level}] {current_message}",
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_markdownlint_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process markdownlint text output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.md):(\d+)(?::(\d+))?\s*(MD\d+/\S+|\S+)?\s*(.*)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        match = pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            col_num = int(match.group(3)) if match.group(3) else None
            code = match.group(4) or ""
            message = match.group(5).strip() if match.group(5) else code
            grouped[fp].append({"line": line_num, "column": col_num, "code": code, "message": message, "raw": stripped_line})
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_yamllint_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process yamllint text output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    current_file = ""
    pattern = re.compile(r"^\s*(\d+):(\d+)\s+(\w+)\s+(.+)$")
    for line in text_output.strip().split("\n"):
        line_stripped = line.strip()
        if not line_stripped:
            continue
        if line_stripped.startswith("./") or line_stripped.endswith((".yml", ".yaml")):
            current_file = line_stripped
        else:
            match = pattern.match(line_stripped)
            if match and current_file:
                line_num = int(match.group(1))
                col_num = int(match.group(2))
                severity = match.group(3)
                message = match.group(4).strip()
                code = ""
                if message.startswith("(") and ")" in message:
                    paren_end = message.find(")")
                    code = message[1:paren_end]
                    message = message[paren_end + 1 :].strip()
                grouped[current_file].append({
                    "line": line_num,
                    "column": col_num,
                    "severity": severity,
                    "code": code,
                    "message": message,
                    "raw": f"{current_file}:{line_num}:{col_num}: [{severity}] {message}",
                })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_uncalled_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process uncalled dead function detection text output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r'^(.+\.py):\s*Unused function\s*[\'"]?(\w+)[\'"]?')
    pattern2 = re.compile(r"^(.+\.py):(\d+):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        match = pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            func_name = match.group(2)
            grouped[fp].append({"line": None, "column": None, "message": f"Unused function: {func_name}", "raw": stripped_line})
        else:
            match2 = pattern2.match(stripped_line)
            if match2:
                fp = match2.group(1)
                line_num = int(match2.group(2))
                message = match2.group(3).strip()
                grouped[fp].append({"line": line_num, "column": None, "message": message, "raw": stripped_line})
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_deadcode_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process deadcode text output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.py):(\d+):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith(("Scanning", "Found")):
            continue
        match = pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            message = match.group(3).strip()
            grouped[fp].append({"line": line_num, "column": None, "message": message, "raw": stripped_line})
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_pmd_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    r"""Process PMD Java analysis text output.

    PMD text output format: file:line:\tRuleName:\tMessage
    Example: intellicrack\\scripts\\ghidra\\AdvancedAnalysis.java:1:\tExcessiveImports:\tA high...

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.java):(\d+):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith(("[", "WARN")):
            continue
        match = pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            rest = match.group(3).strip()
            parts = rest.split("\t")
            if len(parts) >= MIN_PARTS_FOR_VALUE:
                rule = parts[0].rstrip(":").strip()
                message = parts[1].strip() if len(parts) > 1 else rest
            else:
                parts = rest.split(":", 1)
                rule = parts[0].strip() if parts else ""
                message = parts[1].strip() if len(parts) > 1 else rest
            grouped[fp].append({
                "line": line_num,
                "column": None,
                "rule": rule,
                "message": f"[{rule}] {message}" if rule else message,
                "raw": stripped_line,
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_checkstyle_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process Checkstyle Java analysis text output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^\[(\w+)\]\s*(.+\.java):(\d+)(?::(\d+))?:\s*(.+)$")
    pattern2 = re.compile(r"^(.+\.java):(\d+)(?::(\d+))?:\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith(("Starting audit", "Audit done")):
            continue
        match = pattern.match(stripped_line)
        if match:
            severity = match.group(1)
            fp = match.group(2)
            line_num = int(match.group(3))
            col_num = int(match.group(4)) if match.group(4) else None
            message = match.group(5).strip()
            grouped[fp].append({"line": line_num, "column": col_num, "severity": severity, "message": message, "raw": stripped_line})
        else:
            match2 = pattern2.match(stripped_line)
            if match2:
                fp = match2.group(1)
                line_num = int(match2.group(2))
                col_num = int(match2.group(3)) if match2.group(3) else None
                message = match2.group(4).strip()
                grouped[fp].append({"line": line_num, "column": col_num, "message": message, "raw": stripped_line})
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_cargo_audit_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process cargo-audit security vulnerability text output.

    Cargo-audit output format (after fetching):
    Crate:    dotenv
    Version:  0.15.0
    Warning:  unmaintained
    Title:    dotenv is Unmaintained
    Date:     2021-12-24
    ID:       RUSTSEC-2021-0141
    URL:      https://rustsec.org/advisories/RUSTSEC-2021-0141

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    current_advisory: dict[str, str] = {}
    lines = text_output.strip().split("\n")
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    for line in lines:
        clean_line = ansi_escape.sub("", line).strip()
        if not clean_line:
            if current_advisory.get("crate") and current_advisory.get("id"):
                crate_name = current_advisory.get("crate", "unknown")
                vuln_id = current_advisory.get("id", "")
                title = current_advisory.get("title", "")
                severity = current_advisory.get("warning", current_advisory.get("severity", "warning"))
                grouped["Cargo.toml"].append({
                    "line": None,
                    "column": None,
                    "crate": crate_name,
                    "vulnerability": vuln_id,
                    "severity": severity,
                    "message": f"[{crate_name}] {title} ({vuln_id})",
                    "raw": f"Cargo.toml: [{severity}] {crate_name} - {title} ({vuln_id})",
                })
                current_advisory = {}
            continue
        if ":" in clean_line:
            parts = clean_line.split(":", 1)
            key = parts[0].strip().lower()
            value = parts[1].strip() if len(parts) > 1 else ""
            if key == "crate":
                current_advisory["crate"] = value
            elif key == "version":
                current_advisory["version"] = value
            elif key == "warning":
                current_advisory["warning"] = value
            elif key == "title":
                current_advisory["title"] = value
            elif key == "id":
                current_advisory["id"] = value
            elif key == "severity":
                current_advisory["severity"] = value
    if current_advisory.get("crate") and current_advisory.get("id"):
        crate_name = current_advisory.get("crate", "unknown")
        vuln_id = current_advisory.get("id", "")
        title = current_advisory.get("title", "")
        severity = current_advisory.get("warning", current_advisory.get("severity", "warning"))
        grouped["Cargo.toml"].append({
            "line": None,
            "column": None,
            "crate": crate_name,
            "vulnerability": vuln_id,
            "severity": severity,
            "message": f"[{crate_name}] {title} ({vuln_id})",
            "raw": f"Cargo.toml: [{severity}] {crate_name} - {title} ({vuln_id})",
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_cargo_deny_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process cargo-deny policy enforcement text output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(error|warning)\[([\w-]+)\]:\s*(.+)$")
    location_pattern = re.compile(r"^\s*[┌╭]\s*[─▸]\s*(.+?):(\d+):(\d+)")
    current_severity = ""
    current_code = ""
    current_message = ""
    current_file = "Cargo.toml"
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        match = pattern.match(stripped_line)
        if match:
            current_severity = match.group(1)
            current_code = match.group(2)
            current_message = match.group(3).strip()
            current_file = "Cargo.toml"
            grouped[current_file].append({
                "line": None,
                "column": None,
                "severity": current_severity,
                "code": current_code,
                "message": current_message,
                "raw": stripped_line,
            })
            continue
        loc_match = location_pattern.match(stripped_line)
        if loc_match and current_code:
            loc_file = loc_match.group(1).strip()
            loc_line = int(loc_match.group(2))
            if current_file == "Cargo.toml" and grouped[current_file]:
                finding = grouped[current_file].pop()
                finding["line"] = loc_line
                finding["column"] = int(loc_match.group(3))
                grouped[loc_file].append(finding)
            continue
        if "denied" in stripped_line.lower() or "banned" in stripped_line.lower() or "unauthorized" in stripped_line.lower():
            grouped["Cargo.toml"].append({"line": None, "column": None, "message": stripped_line, "raw": stripped_line})
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_rustfmt_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process cargo fmt --check text output.

    Args:
        text_output: Raw text output from ``cargo fmt -- --check``.

    Returns:
        Tuple of findings grouped by file path and total count.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    diff_file_pattern = re.compile(r"^Diff in (.+\.rs) at line (\d+):")
    unified_pattern = re.compile(r"^--- a/(.+\.rs)$")
    seen_files: set[str] = set()
    lines = text_output.strip().split("\n")
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        match = diff_file_pattern.match(stripped)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            grouped[fp].append({
                "line": line_num,
                "column": None,
                "severity": "warning",
                "message": "Formatting differs from rustfmt style",
                "raw": stripped,
            })
            seen_files.add(fp)
            continue
        match = unified_pattern.match(stripped)
        if match:
            fp = match.group(1)
            if fp not in seen_files:
                grouped[fp].append({
                    "line": None,
                    "column": None,
                    "severity": "warning",
                    "message": "File needs formatting",
                    "raw": f"{fp}: needs formatting",
                })
                seen_files.add(fp)
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_nextest_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process cargo nextest run text output.

    Args:
        text_output: Raw text output from ``cargo nextest run``.

    Returns:
        Tuple of findings grouped by file path and total count.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    fail_pattern = re.compile(r"^\s*FAIL\s+\[[\s\d.]+s\]\s+(\S+)\s+(\S+)")
    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        match = fail_pattern.match(stripped)
        if match:
            crate_module = match.group(1)
            test_name = match.group(2)
            grouped[crate_module].append({
                "line": None,
                "column": None,
                "severity": "error",
                "message": f"Test failed: {test_name}",
                "raw": stripped,
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_llvm_cov_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process cargo llvm-cov report text output.

    Args:
        text_output: Raw text output from ``cargo llvm-cov report``.

    Returns:
        Tuple of findings grouped by file path and total count.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    coverage_threshold = 95.0
    row_pattern = re.compile(
        r"^\s*(.+\.rs)\s+"
        r"(\d+)\s+(\d+)\s+([\d.]+)%\s+"
        r"(\d+)\s+(\d+)\s+([\d.]+)%\s+"
        r"(\d+)\s+(\d+)\s+([\d.]+)%",
    )
    for line in text_output.strip().split("\n"):
        match = row_pattern.match(line)
        if match:
            fp = match.group(1).strip()
            line_coverage = float(match.group(10))
            region_coverage = float(match.group(4))
            if line_coverage < coverage_threshold:
                grouped[fp].append({
                    "line": None,
                    "column": None,
                    "severity": "warning",
                    "message": f"Line coverage {line_coverage:.1f}% below {coverage_threshold:.0f}% threshold (region coverage: {region_coverage:.1f}%)",
                    "raw": f"{fp}: line coverage {line_coverage:.1f}%, region coverage {region_coverage:.1f}%",
                })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_machete_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process cargo machete unused dependency detection text output.

    Args:
        text_output: Raw text output from ``cargo machete``.

    Returns:
        Tuple of findings grouped by file path and total count.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    header_pattern = re.compile(r"^(\S+)\s+--\s+(.+?)\s*:\s*$")
    dep_pattern = re.compile(r"^\s+(\S+)")
    current_file = "Cargo.toml"
    in_deps = False
    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            in_deps = False
            continue
        header_match = header_pattern.match(line)
        if header_match:
            cargo_path = header_match.group(2).strip()
            if cargo_path.endswith("Cargo.toml"):
                current_file = cargo_path.replace("\\", "/").lstrip("./")
            else:
                crate_name = header_match.group(1).strip()
                current_file = f"{crate_name}/Cargo.toml" if crate_name and crate_name != "." else "Cargo.toml"
            in_deps = True
            continue
        if in_deps:
            dep_match = dep_pattern.match(line)
            if dep_match:
                dep_name = dep_match.group(1)
                grouped[current_file].append({
                    "line": None,
                    "column": None,
                    "severity": "warning",
                    "message": f"Unused dependency: {dep_name}",
                    "raw": f"{current_file}: unused dependency {dep_name}",
                })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_mutants_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process cargo mutants mutation testing text output.

    Args:
        text_output: Raw text output from ``cargo mutants``.

    Returns:
        Tuple of findings grouped by file path and total count.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    missed_pattern = re.compile(r"^MISSED\s+(.+\.rs):(\d+)(?::(\d+))?:\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        match = missed_pattern.match(stripped)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            col_num = int(match.group(3)) if match.group(3) else None
            description = match.group(4).strip()
            grouped[fp].append({
                "line": line_num,
                "column": col_num,
                "severity": "warning",
                "message": f"Survived mutant: {description}",
                "raw": stripped,
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_rust_code_analysis_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process rust-code-analysis-cli metrics text output.

    Args:
        text_output: Raw text output from ``rust-code-analysis-cli -m -p src/``.

    Returns:
        Tuple of findings grouped by file path and total count.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    complexity_threshold = 15
    file_pattern = re.compile(r"^(.+\.rs)$")
    func_pattern = re.compile(
        r"^\s+(\w+)\s.*?cyclomatic:\s*(\d+)",
    )
    json_func_pattern = re.compile(
        r'"name"\s*:\s*"([^"]+)".*?"cyclomatic"\s*:\s*(\d+)',
    )
    current_file = ""
    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        file_match = file_pattern.match(stripped)
        if file_match and "/" in stripped:
            current_file = file_match.group(1)
            continue
        if current_file:
            func_match = func_pattern.match(line)
            if func_match:
                func_name = func_match.group(1)
                complexity = int(func_match.group(2))
                if complexity > complexity_threshold:
                    grouped[current_file].append({
                        "line": None,
                        "column": None,
                        "severity": "warning",
                        "function": func_name,
                        "complexity": complexity,
                        "message": f"Function `{func_name}` has cyclomatic complexity {complexity} (threshold: {complexity_threshold})",
                        "raw": f"{current_file}: {func_name} cyclomatic complexity {complexity}",
                    })
        json_match = json_func_pattern.search(stripped)
        if json_match:
            func_name = json_match.group(1)
            complexity = int(json_match.group(2))
            if complexity > complexity_threshold:
                target_file = current_file or "unknown"
                grouped[target_file].append({
                    "line": None,
                    "column": None,
                    "severity": "warning",
                    "function": func_name,
                    "complexity": complexity,
                    "message": f"Function `{func_name}` has cyclomatic complexity {complexity} (threshold: {complexity_threshold})",
                    "raw": f"{target_file}: {func_name} cyclomatic complexity {complexity}",
                })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_typos_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process typos-cli spell checker text output.

    Args:
        text_output: Raw text output from ``typos``.

    Returns:
        Tuple of findings grouped by file path and total count.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    error_pattern = re.compile(r"^error:\s*`(\S+)`\s+should be\s+`([^`]+)`")
    location_pattern = re.compile(r"^\s*(?:-->|[╭┌][▸─])\s*(.+):(\d+):(\d+)")
    fallback_location = re.compile(r"(\.[\\/].+?|[a-zA-Z][\w./\\-]+\.rs):(\d+):(\d+)")
    simple_pattern = re.compile(r"^(.+):(\d+):(\d+):\s*`(\S+)`\s+.*?`([^`]+)`")
    pending_misspelling = ""
    pending_correction = ""
    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        simple_match = simple_pattern.match(stripped)
        if simple_match:
            grouped[simple_match.group(1)].append({
                "line": int(simple_match.group(2)),
                "column": int(simple_match.group(3)),
                "severity": "warning",
                "misspelling": simple_match.group(4),
                "correction": simple_match.group(5),
                "message": f"`{simple_match.group(4)}` should be `{simple_match.group(5)}`",
                "raw": stripped,
            })
            pending_misspelling = ""
            pending_correction = ""
            continue
        error_match = error_pattern.match(stripped)
        if error_match:
            pending_misspelling = error_match.group(1)
            pending_correction = error_match.group(2)
            continue
        if pending_misspelling:
            loc_match = location_pattern.match(stripped)
            if not loc_match:
                loc_match = fallback_location.search(stripped)
            if loc_match:
                fp = loc_match.group(1)
                line_num = int(loc_match.group(2))
                col_num = int(loc_match.group(3))
                grouped[fp].append({
                    "line": line_num,
                    "column": col_num,
                    "severity": "warning",
                    "misspelling": pending_misspelling,
                    "correction": pending_correction,
                    "message": f"`{pending_misspelling}` should be `{pending_correction}`",
                    "raw": f"{fp}:{line_num}:{col_num}: `{pending_misspelling}` should be `{pending_correction}`",
                })
                pending_misspelling = ""
                pending_correction = ""
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_clang_tidy_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process clang-tidy static analysis text output.

    Args:
        text_output: Raw text output from ``clang-tidy``.

    Returns:
        Tuple of findings grouped by file path and total count.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+):(\d+):(\d+):\s*(warning|error):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        match = pattern.match(stripped)
        if not match:
            continue
        fp = match.group(1)
        line_num = int(match.group(2))
        col_num = int(match.group(3))
        severity = match.group(4)
        message = match.group(5).strip()
        code = ""
        code_match = re.search(r"\[([\w,.\-]+)\]$", message)
        if code_match:
            code = code_match.group(1)
            message = message[: code_match.start()].strip()
        grouped[fp].append({
            "line": line_num,
            "column": col_num,
            "severity": severity,
            "code": code,
            "message": message,
            "raw": stripped,
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_clang_format_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process clang-format ``--dry-run --Werror`` text output.

    Args:
        text_output: Raw text output from ``clang-format --dry-run --Werror``.

    Returns:
        Tuple of findings grouped by file path and total count.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+):(\d+):(\d+):\s*(warning|error):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        match = pattern.match(stripped)
        if not match:
            continue
        fp = match.group(1)
        line_num = int(match.group(2))
        col_num = int(match.group(3))
        severity = match.group(4)
        message = match.group(5).strip()
        code = ""
        code_match = re.search(r"\[([\w,.\-]+)\]$", message)
        if code_match:
            code = code_match.group(1)
            message = message[: code_match.start()].strip()
        grouped[fp].append({
            "line": line_num,
            "column": col_num,
            "severity": severity,
            "code": code,
            "message": message,
            "raw": stripped,
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_cppcheck_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process cppcheck ``--template=gcc`` text output.

    Args:
        text_output: Raw text output from ``cppcheck --template=gcc``.

    Returns:
        Tuple of findings grouped by file path and total count.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+):(\d+):(\d+):\s*(warning|error|style|performance|portability|note):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        match = pattern.match(stripped)
        if not match:
            continue
        fp = match.group(1).replace("\\", "/")
        line_num = int(match.group(2))
        col_num = int(match.group(3))
        severity = match.group(4)
        message = match.group(5).strip()
        code = ""
        code_match = re.search(r"\[(\w+)\]$", message)
        if code_match:
            code = code_match.group(1)
            message = message[: code_match.start()].strip()
        grouped[fp].append({
            "line": line_num,
            "column": col_num,
            "severity": severity,
            "code": code,
            "message": message,
            "raw": stripped,
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_cmake_format_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process cmake-format ``--check`` text output.

    Args:
        text_output: Raw text output from ``cmake-format --check``.

    Returns:
        Tuple of findings grouped by file path and total count.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^ERROR\s+\S+:\s*Check failed:\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        match = pattern.match(stripped)
        if not match:
            continue
        fp = match.group(1).strip()
        grouped[fp].append({
            "line": None,
            "column": None,
            "severity": "warning",
            "message": "Formatting differs from cmake-format style",
            "raw": stripped,
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_cmake_lint_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process cmake-lint text output.

    Args:
        text_output: Raw text output from ``cmake-lint --suppress-decorations``.

    Returns:
        Tuple of findings grouped by file path and total count.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+):(\d+)(?:,(\d+))?:\s*\[(\w+)\]\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        match = pattern.match(stripped)
        if not match:
            continue
        fp = match.group(1)
        line_num = int(match.group(2))
        col_num = int(match.group(3)) if match.group(3) else None
        code = match.group(4)
        message = match.group(5).strip()
        grouped[fp].append({
            "line": line_num,
            "column": col_num,
            "severity": "warning",
            "code": code,
            "message": message,
            "raw": stripped,
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_shellcheck_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process shellcheck shell script analysis text output (GCC format).

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.(?:sh|bash)):(\d+):(\d+):\s*(\w+):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        match = pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            col_num = int(match.group(3))
            severity = match.group(4)
            message = match.group(5).strip()
            code = ""
            if message.startswith("[SC"):
                bracket_end = message.find("]")
                if bracket_end > 0:
                    code = message[1:bracket_end]
                    message = message[bracket_end + 1 :].strip()
            grouped[fp].append({
                "line": line_num,
                "column": col_num,
                "severity": severity,
                "code": code,
                "message": message,
                "raw": stripped_line,
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_blinter_text(
    text_output: str,
) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process blinter batch file linter verbose text output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    severity_map: dict[str, str] = {
        "ERROR LEVEL ISSUES:": "error",
        "WARNING LEVEL ISSUES:": "warning",
        "STYLE LEVEL ISSUES:": "style",
        "SECURITY LEVEL ISSUES:": "security",
        "PERFORMANCE LEVEL ISSUES:": "performance",
    }
    file_pattern = re.compile(r"^\s*Batch Files? Analysis:\s*(.+)$")
    issue_pattern = re.compile(r"^Line\s+(\d+):\s+(.+)\s+\(([A-Za-z]+\d+)\)$")
    current_file: str = ""
    current_severity: str = ""
    for line in text_output.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        file_match = file_pattern.match(stripped)
        if file_match:
            current_file = file_match.group(1).strip()
            current_severity = ""
            continue
        if stripped in severity_map:
            current_severity = severity_map[stripped]
            continue
        issue_match = issue_pattern.match(stripped)
        if issue_match and current_file:
            line_num = int(issue_match.group(1))
            message = issue_match.group(2).strip()
            code = issue_match.group(3)
            grouped[current_file].append({
                "line": line_num,
                "column": 0,
                "severity": current_severity or "warning",
                "code": code,
                "message": message,
                "raw": stripped,
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_jsonlint_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process JSON validation text output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.json):\s*line\s*(\d+),\s*col\s*(\d+):\s*(.+)$")
    pattern2 = re.compile(r"^(.+\.json):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line or stripped_line.isdigit():
            continue
        match = pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            col_num = int(match.group(3))
            message = match.group(4).strip()
            grouped[fp].append({"line": line_num, "column": col_num, "message": message, "raw": stripped_line})
        else:
            match2 = pattern2.match(stripped_line)
            if match2:
                fp = match2.group(1)
                message = match2.group(2).strip()
                line_num = None
                if "line " in message:
                    lm = re.search(r"line\s*(\d+)", message)
                    if lm:
                        line_num = int(lm.group(1))
                grouped[fp].append({"line": line_num, "column": None, "message": message, "raw": stripped_line})
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_psscriptanalyzer_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process PSScriptAnalyzer PowerShell analysis text output.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.ps[md]?1):(\d+):(\d+):\s*\[(\w+)\]\s*(.+?)\s*\((\w+)\)$")
    pattern2 = re.compile(r"^(.+\.ps[md]?1):(\d+):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        match = pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            col_num = int(match.group(3))
            severity = match.group(4)
            message = match.group(5).strip()
            rule = match.group(6)
            grouped[fp].append({
                "line": line_num,
                "column": col_num,
                "severity": severity,
                "rule": rule,
                "message": message,
                "raw": stripped_line,
            })
        else:
            match2 = pattern2.match(stripped_line)
            if match2:
                fp = match2.group(1)
                line_num = int(match2.group(2))
                message = match2.group(3).strip()
                grouped[fp].append({"line": line_num, "column": None, "message": message, "raw": stripped_line})
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_flake8_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process flake8 style linting text output.

    Flake8 output format: file:line:col: CODE message
    Example: intellicrack/core/analysis/analyzer.py:15:1: E302 expected 2 blank lines

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.py):(\d+):(\d+):\s*([A-Z]\d+)\s+(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        match = pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            col_num = int(match.group(3))
            code = match.group(4)
            message = match.group(5).strip()
            grouped[fp].append({"line": line_num, "column": col_num, "code": code, "message": message, "raw": stripped_line})
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_wemake_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process wemake-python-styleguide text output.

    Wemake is a flake8 plugin with same format: file:line:col: CODE message
    Codes include WPS (wemake), C (complexity), and standard flake8 codes.
    Example: intellicrack/core/main.py:42:1: WPS226 Found string literal over-use

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.py):(\d+):(\d+):\s*([A-Z]+\d+)\s+(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        match = pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            col_num = int(match.group(3))
            code = match.group(4)
            message = match.group(5).strip()
            grouped[fp].append({"line": line_num, "column": col_num, "code": code, "message": message, "raw": stripped_line})
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_mccabe_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process mccabe complexity checker text output.

    McCabe output format: file:line:col: C901 'func' is too complex (N)
    Example: intellicrack/core/main.py:100:1: C901 'process_binary' is too complex (15)

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.py):(\d+):(\d+):\s*(C\d+)\s+(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        match = pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            col_num = int(match.group(3))
            code = match.group(4)
            message = match.group(5).strip()
            complexity = None
            complexity_match = re.search(r"\((\d+)\)$", message)
            if complexity_match:
                complexity = int(complexity_match.group(1))
            grouped[fp].append({
                "line": line_num,
                "column": col_num,
                "code": code,
                "complexity": complexity,
                "message": message,
                "raw": stripped_line,
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


_PYDOCSTYLE_LOCATION_RE = re.compile(r"^(.+\.py):(\d+)\s+(.*)$")
_PYDOCSTYLE_CODE_RE = re.compile(r"^\s*(D\d+):\s*(.+)$")
_PYDOCSTYLE_SINGLE_LINE_RE = re.compile(r"^(.+\.py):(\d+):\s*(D\d+):\s*(.+)$")


def process_pydocstyle_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    r"""Process pydocstyle docstring linting text output.

    Pydocstyle outputs in two-line format:
    file:line func/class name:
        CODE: message
    Example:
    intellicrack\core\main.py:15 in public function `process`:
        D103: Missing docstring in public function
    Also handles single-line format: file:line: CODE: message

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    current_file = ""
    current_line = 0
    current_context = ""

    for line in text_output.strip().split("\n"):
        if not line.strip():
            continue
        single_match = _PYDOCSTYLE_SINGLE_LINE_RE.match(line)
        if single_match:
            fp = single_match.group(1)
            grouped[fp].append({
                "line": int(single_match.group(2)),
                "column": None,
                "code": single_match.group(3),
                "message": single_match.group(4).strip(),
                "raw": line,
            })
            continue
        loc_match = _PYDOCSTYLE_LOCATION_RE.match(line)
        if loc_match:
            current_file = loc_match.group(1)
            current_line = int(loc_match.group(2))
            current_context = loc_match.group(3).strip()
            continue
        code_match = _PYDOCSTYLE_CODE_RE.match(line)
        if code_match and current_file:
            code = code_match.group(1)
            message = code_match.group(2).strip()
            if current_context:
                message = f"{current_context} - {message}"
            grouped[current_file].append({
                "line": current_line,
                "column": None,
                "code": code,
                "context": current_context,
                "message": message,
                "raw": f"{current_file}:{current_line}: {code}: {message}",
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def _build_radon_finding(current_file: str, finding_match: re.Match[str]) -> dict[str, Any]:
    """Build a radon complexity finding dict from a regex match.

    Args:
        current_file: The file path for the finding.
        finding_match: The regex match object containing entity details.

    Returns:
        A dictionary representing the radon finding.
    """
    entity_type = finding_match.group(1)
    line_num = int(finding_match.group(2))
    col_num = int(finding_match.group(3))
    name = finding_match.group(4).strip()
    rank = finding_match.group(5)
    complexity = int(finding_match.group(6))
    entity_name = ENTITY_TYPE_NAMES.get(entity_type, entity_type)
    return {
        "line": line_num,
        "column": col_num,
        "entity_type": entity_type,
        "name": name,
        "rank": rank,
        "complexity": complexity,
        "message": f"{entity_name} '{name}' - complexity {complexity} (rank {rank})",
        "raw": f"{current_file}:{line_num}:{col_num}: {entity_name} '{name}' - complexity {complexity} (rank {rank})",
    }


def process_radon_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    r"""Process radon complexity metrics text output.

    Radon cc (cyclomatic complexity) output formats:
    file
        line:col: class/method name - rank (complexity)

    Example:
    intellicrack\core\main.py
        M 100:4 process_binary - C (15)
        F 200:0 helper_func - A (3)

    Codes: F=function, M=method, C=class
    Ranks: A (1-5), B (6-10), C (11-20), D (21-30), E (31-40), F (41+)

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    lines = text_output.strip().split("\n")
    current_file = ""
    file_pattern = re.compile(r"^(\S+\.py)\s*$")
    finding_pattern = re.compile(r"^\s+([FMCE])\s+(\d+):(\d+)\s+(.+?)\s+-\s+([A-F])\s+\((\d+)\)$")

    for line in lines:
        if not line.strip():
            continue
        file_match = file_pattern.match(line)
        if file_match:
            current_file = file_match.group(1)
            continue
        finding_match = finding_pattern.match(line)
        if finding_match and current_file:
            grouped[current_file].append(_build_radon_finding(current_file, finding_match))
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def _build_xenon_alt_finding(alt_match: re.Match[str], raw_line: str) -> dict[str, Any]:
    """Build a xenon finding dict from an alternative format regex match.

    Args:
        alt_match: The regex match object containing entity details.
        raw_line: The raw text line for the finding.

    Returns:
        A dictionary representing the xenon finding.
    """
    entity_type = alt_match.group(2)
    name = alt_match.group(3).strip()
    rank = alt_match.group(4)
    complexity = int(alt_match.group(5))
    entity_name = ENTITY_TYPE_NAMES.get(entity_type, entity_type)
    return {
        "line": None,
        "column": None,
        "entity_type": entity_type,
        "name": name,
        "rank": rank,
        "complexity": complexity,
        "message": f"{entity_name} '{name}' exceeds threshold - rank {rank} (complexity {complexity})",
        "raw": raw_line,
    }


def process_xenon_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    r"""Process xenon code complexity monitoring text output.

    Xenon output format (when thresholds exceeded):
    ERROR:xenon:block "file:line name" has a rank of X

    Example:
    ERROR:xenon:block "intellicrack\config.py:150 get_system_path" has a rank of C

    Ranks: A (1-5), B (6-10), C (11-20), D (21-30), E (31-40), F (41+)

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    error_pattern = re.compile(r'^ERROR:xenon:block\s+"([^"]+):(\d+)\s+([^"]+)"\s+has a rank of\s+([A-F])$')
    alt_pattern = re.compile(r"^(.+\.py)\s+-\s+([FMCE])\s+(.+?)\s+-\s+([A-F])\s+\((\d+)\)$")

    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        match = error_pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            name = match.group(3).strip()
            rank = match.group(4)
            grouped[fp].append({
                "line": line_num,
                "column": None,
                "name": name,
                "rank": rank,
                "complexity": RANK_COMPLEXITY_MAP.get(rank, 0),
                "message": f"'{name}' has rank {rank} (complexity > threshold)",
                "raw": f"{fp}:{line_num}: '{name}' has rank {rank}",
            })
            continue
        alt_match = alt_pattern.match(stripped_line)
        if alt_match:
            grouped[alt_match.group(1)].append(
                _build_xenon_alt_finding(alt_match, stripped_line),
            )
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_complexipy_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    r"""Process complexipy cognitive complexity analysis text output.

    Complexipy ``--failed --color no`` output format:
    file_path
        FunctionName  N  FAILED

    Example:
    src\intellicrack\bridges\binary.py
        BinaryBridge::_detect_architecture 18 FAILED

    src\intellicrack\bridges\frida_bridge.py
        FridaBridge::hook_function 29 FAILED

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    file_pattern = re.compile(r"^(\S+\.py)\s*$")
    finding_pattern = re.compile(r"^\s+(\S+)\s+(\d+)\s+FAILED\s*$")
    current_file = ""

    for line in text_output.strip().split("\n"):
        if not line.strip():
            continue
        if line.strip().startswith("\u2500") or "complexipy" in line.lower() or "Analysis completed" in line or "Failed functions:" in line:
            continue
        file_match = file_pattern.match(line)
        if file_match:
            current_file = file_match.group(1)
            continue
        finding_match = finding_pattern.match(line)
        if finding_match and current_file:
            name = finding_match.group(1)
            complexity = int(finding_match.group(2))
            grouped[current_file].append({
                "line": None,
                "column": None,
                "name": name,
                "complexity": complexity,
                "message": f"{name} - cognitive complexity {complexity} (exceeds threshold)",
                "raw": f"{current_file}: {name} - cognitive complexity {complexity} (exceeds threshold)",
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def process_tombi_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    r"""Process tombi TOML linter text output.

    Tombi lint output format (ANSI color codes stripped before matching):
        <Severity>: <message>
            at <filepath>:<line>:<col>

    Where <Severity> is "Warning" or "Error" (Error may have leading whitespace
    in tombi's renderer). Trailing summary lines like "N files linted
    successfully" or "N file(s) failed to be linted" are filtered.

    Example:
        Warning: `tool.mypy.show_error_codes = true` is deprecated
            at pyproject.toml:662:1
        7 files linted successfully

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    severity_pattern = re.compile(r"^\s*(Warning|Error)\s*:\s*(.+?)\s*$")
    location_pattern = re.compile(r"^\s*at\s+(.+?):(\d+):(\d+)\s*$")
    summary_pattern = re.compile(
        r"^\d+\s+files?\s+(linted\s+successfully|failed\s+to\s+be\s+linted)\s*$",
    )
    clean = _ANSI_ESCAPE_RE.sub("", text_output)
    lines = clean.strip().splitlines()
    current_severity = ""
    current_message = ""

    for line in lines:
        if summary_pattern.match(line.strip()):
            current_severity = ""
            current_message = ""
            continue
        sev_match = severity_pattern.match(line)
        if sev_match:
            current_severity = sev_match.group(1).lower()
            current_message = sev_match.group(2).strip()
            continue
        loc_match = location_pattern.match(line)
        if loc_match and current_message:
            fp = loc_match.group(1)
            line_num = int(loc_match.group(2))
            col_num = int(loc_match.group(3))
            severity = current_severity or "warning"
            grouped[fp].append({
                "line": line_num,
                "column": col_num,
                "severity": severity,
                "message": current_message,
                "raw": f"{fp}:{line_num}:{col_num}: [{severity}] {current_message}",
            })
            current_severity = ""
            current_message = ""
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_interrogate_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    r"""Process interrogate docstring coverage verbose text output.

    Interrogate ``-vv`` output has table rows like:
    ``| path\file.py (module) | COVERED |``
    ``|   ClassName.method (L42) | MISSED |``

    Only MISSED items are reported as findings.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    module_pattern = re.compile(r"^\|\s*(.+?)\s+\(module\)\s*\|\s*(COVERED|MISSED)\s*\|$")
    item_pattern = re.compile(r"^\|\s+(.+?)\s+\(L(\d+)\)\s*\|\s*(COVERED|MISSED)\s*\|$")
    current_file = ""

    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        module_match = module_pattern.match(stripped)
        if module_match:
            current_file = module_match.group(1).strip()
            status = module_match.group(2)
            if status == "MISSED":
                grouped[current_file].append({
                    "line": None,
                    "column": None,
                    "code": "INT001",
                    "message": f"Missing docstring for module '{current_file}'",
                    "raw": f"{current_file}: INT001 Missing docstring for module",
                })
            continue
        item_match = item_pattern.match(stripped)
        if item_match and current_file:
            name = item_match.group(1).strip()
            line_num = int(item_match.group(2))
            status = item_match.group(3)
            if status == "MISSED":
                grouped[current_file].append({
                    "line": line_num,
                    "column": None,
                    "code": "INT001",
                    "message": f"Missing docstring for '{name}'",
                    "raw": f"{current_file}:{line_num}: INT001 Missing docstring for '{name}'",
                })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_deptry_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process deptry dependency checker text output.

    Deptry ``--no-ansi`` output formats:
    ``filepath:line:col: DEP00X message``
    ``filepath: DEP00X message``

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    full_pattern = re.compile(r"^(.+?):(\d+):(\d+):\s*(DEP\d+)\s+(.+)$")
    simple_pattern = re.compile(r"^(.+?):\s*(DEP\d+)\s+(.+)$")

    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith(("Scanning", "Found", "For more information")):
            continue
        full_match = full_pattern.match(stripped)
        if full_match:
            fp = full_match.group(1)
            line_num = int(full_match.group(2))
            col_num = int(full_match.group(3))
            code = full_match.group(4)
            message = full_match.group(5).strip()
            grouped[fp].append({
                "line": line_num,
                "column": col_num,
                "code": code,
                "message": message,
                "raw": stripped,
            })
            continue
        simple_match = simple_pattern.match(stripped)
        if simple_match:
            fp = simple_match.group(1)
            code = simple_match.group(2)
            message = simple_match.group(3).strip()
            grouped[fp].append({
                "line": None,
                "column": None,
                "code": code,
                "message": message,
                "raw": stripped,
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_codespell_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process codespell spelling checker text output.

    Codespell output format: ``filepath:line: misspelling ==> correction``

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+?):(\d+):\s*(.+?)\s*==>\s*(.+)$")

    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        match = pattern.match(stripped)
        if match:
            fp = match.group(1)
            line_num = int(match.group(2))
            misspelling = match.group(3).strip()
            correction = match.group(4).strip()
            grouped[fp].append({
                "line": line_num,
                "column": None,
                "code": "SPELL",
                "misspelling": misspelling,
                "correction": correction,
                "message": f"'{misspelling}' ==> '{correction}'",
                "raw": stripped,
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_mixed_line_ending_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process mixed line ending detection text output.

    Output format: ``filepath: mixed line endings``

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+?):\s*mixed line endings\s*$")

    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        match = pattern.match(stripped)
        if match:
            fp = match.group(1).strip()
            grouped[fp].append({
                "line": None,
                "column": None,
                "code": "MLE001",
                "message": "File has mixed line endings",
                "raw": stripped,
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_file_encoding_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process file encoding (BOM) detection text output.

    Output format: ``filepath: Has a byte-order marker (BOM)``

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+?):\s*Has a byte-order marker.*$")

    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        match = pattern.match(stripped)
        if match:
            fp = match.group(1).strip()
            grouped[fp].append({
                "line": None,
                "column": None,
                "code": "BOM001",
                "message": "File has a byte-order marker (BOM)",
                "raw": stripped,
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_skylos(data: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process Skylos dead code / secrets / danger / quality JSON output.

    Skylos JSON structure uses lists under these keys:
    - Dead code: unused_functions, unused_imports, unused_variables, unused_classes, unused_parameters
      Each item has: name, full_name, simple_name, type, file, line, confidence, references
    - Extra scans: secrets, danger, quality
      Each item has: rule_id, severity, message, file, line, col

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    dead_code_categories = ("unused_functions", "unused_imports", "unused_variables", "unused_classes", "unused_parameters")
    extra_categories = ("danger", "quality", "secrets")
    for category in dead_code_categories:
        items = data.get(category)
        if not isinstance(items, list):
            continue
        for item in items:
            fp = str(item.get("file", "unknown"))
            line_num = item.get("line")
            name = str(item.get("simple_name", item.get("name", "")))
            item_type = str(item.get("type", category.replace("unused_", "")))
            confidence = item.get("confidence", 0)
            message = f"Unused {item_type}: '{name}' (confidence {confidence}%)"
            grouped[fp].append({
                "line": line_num,
                "column": None,
                "code": category,
                "message": message,
                "raw": f"{fp}:{line_num or 0}: [{category}] {message}",
            })
    for category in extra_categories:
        items = data.get(category)
        if not isinstance(items, list):
            continue
        for item in items:
            fp = str(item.get("file", "unknown"))
            line_num = item.get("line")
            col_num = item.get("col")
            rule_id = str(item.get("rule_id", ""))
            message = str(item.get("message", ""))
            severity = str(item.get("severity", "warning"))
            grouped[fp].append({
                "line": line_num,
                "column": col_num,
                "code": rule_id,
                "severity": severity,
                "message": f"[{category}] {message}",
                "raw": f"{fp}:{line_num or 0}:{col_num or 0}: [{severity}] {rule_id}: {message}",
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
_XML_ILLEGAL_CHARS_RE = re.compile(
    r"[\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f\x80\x81\x82\x83\x84\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\ud800-\udfff\ufffe\uffff]",
)


def escape_xml(s: str) -> str:
    """Escape special XML characters and strip control characters.

    ANSI escape sequences and characters forbidden by the XML 1.0 character
    productions are stripped so the resulting document is always well-formed.

    Returns:
        The XML-escaped string.
    """
    text = _ANSI_ESCAPE_RE.sub("", str(s))
    text = _XML_ILLEGAL_CHARS_RE.sub("", text)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _build_finding_xml(finding: dict[str, Any]) -> str:
    """Build an XML element string for a single finding.

    Args:
        finding: A dictionary containing finding details.

    Returns:
        An XML string representing the finding element.
    """
    line_val = finding.get("line") or 0
    col = finding.get("column") or 0
    sev = finding.get("severity", "")
    rule = finding.get("rule", finding.get("code", ""))
    msg = finding.get("message", "")
    raw = finding.get("raw", "")
    return f'<Finding line="{line_val}" column="{col}" severity="{escape_xml(sev)}" rule="{escape_xml(rule)}"><Message>{escape_xml(msg)}</Message><Raw>{escape_xml(raw)}</Raw></Finding>'


def _build_sarif_output(
    tool: str,
    grouped: dict[str, list[dict[str, Any]]],
    ts: str,
) -> dict[str, Any]:
    """Build a SARIF v2.1.0 output structure from grouped findings.

    Args:
        tool: The name of the analysis tool.
        grouped: Findings grouped by file path.
        ts: ISO 8601 timestamp for the report.

    Returns:
        A SARIF v2.1.0 compliant dictionary.
    """
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for fp, findings in grouped.items():
        for finding in findings:
            rule_id = str(finding.get("code") or finding.get("rule") or "general")
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": finding.get("message", rule_id)},
                }
            raw_severity = str(finding.get("severity", "")).lower()
            level = _SARIF_SEVERITY_MAP.get(raw_severity, "warning")

            result_entry: dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": finding.get("message", "")},
            }

            if finding.get("line") is not None:
                artifact_uri = fp.replace("\\", "/")
                result_entry["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": artifact_uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": finding["line"],
                                "startColumn": finding.get("column") or 1,
                            },
                        },
                    },
                ]

            results.append(result_entry)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool,
                        "version": "1.0.0",
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": ts,
                    },
                ],
            },
        ],
    }


_VERMIN_HEADER_RE = re.compile(r"^[~!]?\d.*\s+(\S+\.py)$")
_VERMIN_FINDING_RE = re.compile(r"^\s+L(\d+)\s+C(\d+):\s+(.+)$")
_VERMIN_INCOMPATIBLE_RE = re.compile(r"^File with incompatible versions:\s*(.+\.py)\s*$")
_VERMIN_INCOMPATIBLE_DETAIL_RE = re.compile(r"^\s+Versions could not be combined:\s*(.+)$")


def process_vermin_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process vermin Python version compatibility checker text output.

    Two output shapes are accepted to cover historical and current vermin
    behaviour:

    * Detailed (``-vvv`` with per-line violations)::

          !2, 3.11     path/file.py
            L13 C5: '__future__' module requires 2.1, 3.0
            L19 C5: 'datetime.UTC' member requires !2, 3.11

    * Summary-only (modern vermin when target versions cannot be reconciled)::

          File with incompatible versions: path/file.py
            Versions could not be combined: !2, 3.11 and 2.2, !3

      Each ``File with incompatible versions:`` line counts as one finding.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    current_file = ""
    pending_incompatible: str | None = None

    for line in text_output.strip().split("\n"):
        if not line.strip():
            continue

        incompat_match = _VERMIN_INCOMPATIBLE_RE.match(line)
        if incompat_match:
            current_file = incompat_match.group(1).strip()
            pending_incompatible = current_file
            grouped[current_file].append({
                "line": None,
                "column": None,
                "code": "VERMIN-INCOMPAT",
                "message": "Incompatible Python versions cannot be combined",
                "raw": line.strip(),
            })
            continue

        detail_match = _VERMIN_INCOMPATIBLE_DETAIL_RE.match(line)
        if detail_match and pending_incompatible:
            findings = grouped[pending_incompatible]
            if findings:
                findings[-1]["message"] = f"Incompatible Python versions: {detail_match.group(1).strip()}"
            continue

        header_match = _VERMIN_HEADER_RE.match(line)
        if header_match:
            current_file = header_match.group(1)
            pending_incompatible = None
            continue
        finding_match = _VERMIN_FINDING_RE.match(line)
        if finding_match and current_file:
            line_num = int(finding_match.group(1))
            col_num = int(finding_match.group(2))
            message = finding_match.group(3).strip()
            grouped[current_file].append({
                "line": line_num,
                "column": col_num,
                "code": "VERMIN",
                "message": message,
                "raw": f"{current_file}:{line_num}:{col_num}: {message}",
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_docformatter_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process docformatter ``--check --diff`` text output.

    Docformatter diff output format::

        path/file.py
        --- before/path/file.py
        +++ after/path/file.py
        @@ -2,12 +2,11 @@

    Each file with diffs counts as one finding.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    diff_header_pattern = re.compile(r"^---\s+.+?/(.+\.py)$")
    hunk_pattern = re.compile(r"^@@\s+-(\d+)")
    current_file = ""
    files_seen: set[str] = set()

    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        diff_match = diff_header_pattern.match(stripped)
        if diff_match:
            current_file = diff_match.group(1)
            continue
        hunk_match = hunk_pattern.match(stripped)
        if hunk_match and current_file and current_file not in files_seen:
            files_seen.add(current_file)
            line_num = int(hunk_match.group(1))
            grouped[current_file].append({
                "line": line_num,
                "column": None,
                "code": "DOCFMT",
                "message": "Docstring formatting needs correction",
                "raw": f"{current_file}:{line_num}: Docstring formatting needs correction",
            })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def write_outputs(tool: str, grouped: dict[str, list[dict[str, Any]]], cnt: int) -> None:
    """Write findings to TXT, JSON, and XML files, sorted by file (descending by count)."""
    for subdir in ("txt", "json", "xml", "csv", "sarif", "sql"):
        Path(f"reports/{subdir}").mkdir(parents=True, exist_ok=True)

    sorted_files = sorted(grouped.keys(), key=lambda x: len(grouped[x]), reverse=True)

    txt_lines: list[str] = []
    for fp in sorted_files:
        if txt_lines:
            txt_lines.extend(["", ""])
        txt_lines.extend((f"{len(grouped[fp])} findings in {fp}", ""))
        for i, f in enumerate(grouped[fp]):
            txt_lines.append(f["raw"])
            if i < len(grouped[fp]) - 1:
                txt_lines.append("")

    if cnt == 0:
        txt_lines = ["No findings."]

    Path(f"reports/txt/{tool}_findings.txt").write_text("\n".join(txt_lines), encoding="utf-8")

    ts = datetime.datetime.now(tz=datetime.UTC).isoformat()
    files_arr = [{"path": fp, "count": len(grouped[fp]), "findings": grouped[fp]} for fp in sorted_files]
    json_obj = {"tool": tool, "generated": ts, "total_findings": cnt, "total_files": len(sorted_files), "files": files_arr}
    Path(f"reports/json/{tool}_findings.json").write_text(json.dumps(json_obj, indent=2), encoding="utf-8")

    xml = f'<?xml version="1.0" encoding="UTF-8"?><LintReport tool="{tool}" generated="{ts}"><Summary><TotalFindings>{cnt}</TotalFindings><TotalFiles>{len(sorted_files)}</TotalFiles></Summary><Files>'
    for fp in sorted_files:
        xml += f'<File path="{escape_xml(fp)}" count="{len(grouped[fp])}">'
        for f in grouped[fp]:
            xml += _build_finding_xml(f)
        xml += "</File>"
    xml += "</Files></LintReport>"
    Path(f"reports/xml/{tool}_findings.xml").write_text(xml, encoding="utf-8")

    csv_path = Path(f"reports/csv/{tool}_findings.csv")
    with csv_path.open("w", encoding="utf-8", newline="") as csv_handle:
        writer = csv.DictWriter(csv_handle, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for fp in sorted_files:
            for f in grouped[fp]:
                row = dict(f)
                row["tool"] = tool
                row["file"] = fp
                if not row.get("code"):
                    row["code"] = row.get("rule", "")
                if not row.get("rule"):
                    row["rule"] = row.get("code", "")
                row.pop("raw", None)
                writer.writerow(row)

    sarif_obj = _build_sarif_output(tool, grouped, ts)
    Path(f"reports/sarif/{tool}_findings.sarif").write_text(
        json.dumps(sarif_obj, indent=2),
        encoding="utf-8",
    )

    write_sql_output(tool, grouped, cnt, ts)

    print(f"[{tool.upper()}] {cnt} findings")


def _write_sql_dump(db_path: Path) -> None:
    """Write a portable SQL text dump alongside a SQLite database file.

    The dump is produced via :meth:`sqlite3.Connection.iterdump`, which
    emits the same ``BEGIN TRANSACTION`` / ``CREATE TABLE`` / ``INSERT``
    / ``COMMIT`` sequence as the ``sqlite3`` CLI's ``.dump`` command and
    can be replayed against an empty database to recreate the original
    contents.

    Args:
        db_path: Path to an existing SQLite database file. The dump is
            written next to it with the same stem and a ``.sql``
            extension (e.g. ``foo_findings.db`` -> ``foo_findings.sql``).
    """
    sql_path = db_path.with_suffix(".sql")
    conn = sqlite3.connect(str(db_path))
    try:
        with sql_path.open("w", encoding="utf-8", newline="\n") as fh:
            for statement in conn.iterdump():
                fh.write(statement)
                fh.write("\n")
    finally:
        conn.close()


def write_sql_output(tool: str, grouped: dict[str, list[dict[str, Any]]], cnt: int, ts: str) -> None:
    """Write findings to a SQLite database file and a parallel SQL dump.

    Args:
        tool: Name of the lint tool.
        grouped: Findings grouped by file path.
        cnt: Total number of findings.
        ts: ISO 8601 timestamp string.
    """
    sql_dir = Path("reports/sql")
    sql_dir.mkdir(parents=True, exist_ok=True)
    db_path = sql_dir / f"{tool}_findings.db"

    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS findings")
    cur.execute("DROP TABLE IF EXISTS summary")

    cur.execute("""
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file TEXT,
            line INTEGER,
            column_ INTEGER,
            severity TEXT,
            code TEXT,
            rule TEXT,
            message TEXT,
            raw TEXT,
            confidence TEXT,
            complexity TEXT,
            rank TEXT,
            name TEXT,
            entity_type TEXT,
            category TEXT,
            function TEXT,
            variable TEXT,
            crate TEXT,
            vulnerability TEXT,
            misspelling TEXT,
            correction TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE summary (
            tool TEXT,
            generated TEXT,
            total_findings INTEGER,
            total_files INTEGER
        )
    """)

    for fp, findings in grouped.items():
        for f in findings:
            cur.execute(
                """INSERT INTO findings (
                    file, line, column_, severity, code, rule, message, raw,
                    confidence, complexity, rank, name, entity_type, category,
                    function, variable, crate, vulnerability, misspelling, correction
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    fp,
                    f.get("line"),
                    f.get("column"),
                    f.get("severity", ""),
                    f.get("code", f.get("rule", "")),
                    f.get("rule", f.get("code", "")),
                    f.get("message", ""),
                    f.get("raw", ""),
                    f.get("confidence", ""),
                    f.get("complexity", ""),
                    f.get("rank", ""),
                    f.get("name", ""),
                    f.get("entity_type", ""),
                    f.get("category", ""),
                    f.get("function", ""),
                    f.get("variable", ""),
                    f.get("crate", ""),
                    f.get("vulnerability", ""),
                    f.get("misspelling", ""),
                    f.get("correction", ""),
                ),
            )

    cur.execute(
        "INSERT INTO summary (tool, generated, total_findings, total_files) VALUES (?, ?, ?, ?)",
        (tool, ts, cnt, len(grouped)),
    )

    cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_file ON findings (file)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_code ON findings (code)")

    conn.commit()
    conn.close()

    _write_sql_dump(db_path)


def _decode_json_payload(content: str) -> dict[str, Any] | list[Any]:
    """Decode the first JSON document embedded anywhere in *content*.

    Args:
        content: Raw text that may wrap a JSON document in non-JSON noise.

    Returns:
        dict[str, Any] | list[Any]: The decoded document, or an empty dict when
            no JSON document could be recovered.
    """
    if not content:
        return {}

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()

    def _try_decode(start: int) -> dict[str, Any] | list[Any] | None:
        try:
            obj, _ = decoder.raw_decode(content[start:])
        except json.JSONDecodeError:
            return None
        if isinstance(obj, (dict, list)):
            return obj
        return None

    line_start_candidates: list[int] = [i for i, ch in enumerate(content) if ch in "{[" and (i == 0 or content[i - 1] == "\n")]
    any_candidates: list[int] = [i for i, ch in enumerate(content) if ch in "{["]

    for start in (*line_start_candidates, *any_candidates):
        result = _try_decode(start)
        if result is not None:
            return result

    return {}


def load_json_file(input_file: str) -> dict[str, Any] | list[Any]:
    """Load JSON from a file, handling BOM, encoding, and non-JSON noise.

    Tool wrappers can wrap the real JSON output with non-JSON prefixes
    (warnings, ANSI banners, f-string format markers) and suffixes (PowerShell
    ``NativeCommandExitException`` trailers, exit-code echoes). This loader is
    robust to both by:

    1. Trying to parse the entire file.
    2. Using :class:`json.JSONDecoder.raw_decode` at each plausible start
       position so trailing non-JSON content is ignored.
    3. Preferring candidates at line starts before falling back to any
       ``{``/``[`` in the file.

    Returns:
        The parsed JSON data as a dict or list, or an empty dict on failure.
    """
    try:
        content = Path(input_file).read_text(encoding="utf-8-sig").strip()
    except (OSError, UnicodeDecodeError, ValueError):
        return {}

    return _decode_json_payload(content)


def load_text_file(input_file: str) -> str:
    """Load text from a file.

    Returns:
        The file contents as a string, or empty string on failure.
    """
    try:
        return Path(input_file).read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return ""
    except (OSError, UnicodeDecodeError):
        return ""


def load_json_stdin() -> dict[str, Any] | list[Any]:
    """Load JSON from stdin, handling various input formats.

    Returns:
        The parsed JSON data as a dict or list, or an empty dict on failure.
    """
    try:
        content = sys.stdin.read().strip()
    except (OSError, UnicodeDecodeError, ValueError):
        return {}

    if not content:
        return {}

    for line in content.split("\n"):
        stripped_line = line.strip()
        if stripped_line.startswith(("{", "[")):
            try:
                return json.loads(stripped_line)
            except json.JSONDecodeError:
                continue

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {"_raw_text": content}


TEXT_PROCESSORS: dict[str, Callable[[str], tuple[dict[str, list[dict[str, Any]]], int]]] = {
    "ty": process_ty_text,
    "vulture": process_vulture_text,
    "pydoclint": process_pydoclint_text,
    "dead": process_dead_text,
    "mypy": process_mypy_text,
    "bandit": process_bandit_text,
    "clippy": process_clippy_text,
    "markdownlint": process_markdownlint_text,
    "markdownlint-cli2": process_markdownlint_text,
    "yamllint": process_yamllint_text,
    "uncalled": process_uncalled_text,
    "deadcode": process_deadcode_text,
    "pmd": process_pmd_text,
    "checkstyle": process_checkstyle_text,
    "cargo-audit": process_cargo_audit_text,
    "cargo_audit": process_cargo_audit_text,
    "cargo-deny": process_cargo_deny_text,
    "cargo_deny": process_cargo_deny_text,
    "shellcheck": process_shellcheck_text,
    "blinter": process_blinter_text,
    "jsonlint": process_jsonlint_text,
    "psscriptanalyzer": process_psscriptanalyzer_text,
    "biome": process_biome_text,
    "semgrep": process_semgrep_text,
    "flake8": process_flake8_text,
    "wemake": process_wemake_text,
    "mccabe": process_mccabe_text,
    "pydocstyle": process_pydocstyle_text,
    "radon": process_radon_text,
    "xenon": process_xenon_text,
    "complexipy": process_complexipy_text,
    "tombi": process_tombi_text,
    "interrogate": process_interrogate_text,
    "deptry": process_deptry_text,
    "codespell": process_codespell_text,
    "mixed-line-ending": process_mixed_line_ending_text,
    "mixed_line_ending": process_mixed_line_ending_text,
    "file-encoding": process_file_encoding_text,
    "file_encoding": process_file_encoding_text,
    "vermin": process_vermin_text,
    "docformatter": process_docformatter_text,
    "rustfmt": process_rustfmt_text,
    "nextest": process_nextest_text,
    "llvm-cov": process_llvm_cov_text,
    "llvm_cov": process_llvm_cov_text,
    "machete": process_machete_text,
    "mutants": process_mutants_text,
    "rust-code-analysis": process_rust_code_analysis_text,
    "rust_code_analysis": process_rust_code_analysis_text,
    "typos": process_typos_text,
    "clang-tidy": process_clang_tidy_text,
    "clang_tidy": process_clang_tidy_text,
    "clang-format": process_clang_format_text,
    "clang_format": process_clang_format_text,
    "cppcheck": process_cppcheck_text,
    "cmake-format": process_cmake_format_text,
    "cmake_format": process_cmake_format_text,
    "cmake-lint": process_cmake_lint_text,
    "cmake_lint": process_cmake_lint_text,
}


def process_precommit_hooks(data: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process pre-commit-hooks JSON output from ``scripts/precommit_hooks.py``.

    Each finding has: file, line, column, hook_id, message, fixed.

    Returns:
        A tuple of (grouped findings by file, total count).
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in data.get("findings", []):
        fp = str(finding.get("file", "unknown"))
        hook_id = finding.get("hook_id", "unknown")
        message = str(finding.get("message", ""))
        fixed = finding.get("fixed", False)
        line_num = finding.get("line")
        column = finding.get("column")
        prefix = "[FIXED] " if fixed else ""
        grouped[fp].append({
            "line": line_num,
            "column": column,
            "code": hook_id,
            "message": f"{prefix}{message}",
            "raw": f"{fp}: [{hook_id}] {prefix}{message}",
        })
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


JSON_PROCESSORS: dict[str, tuple[Callable[..., tuple[dict[str, list[dict[str, Any]]], int]], Any]] = {
    "eslint": (process_eslint, []),
    "ruff": (process_ruff, []),
    "basedpyright": (process_basedpyright, {"generalDiagnostics": []}),
    "mypy": (process_mypy_json, []),
    "knip": (process_knip, {"issues": []}),
    "biome": (process_biome_json, {"diagnostics": []}),
    "semgrep": (process_semgrep, {"results": []}),
    "skylos": (process_skylos, {}),
    "precommit-hooks": (process_precommit_hooks, {"findings": []}),
    "precommit_hooks": (process_precommit_hooks, {"findings": []}),
}

ALL_TOOLS = sorted(set(TEXT_PROCESSORS.keys()) | set(JSON_PROCESSORS.keys()))

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>__TITLE__</title>
<style>
:root {
    --bg: #0d1117; --bg-card: #161b22; --bg-table: #161b22; --bg-header: #010409;
    --text: #c9d1d9; --text-muted: #8b949e; --border: #30363d;
    --accent: #58a6ff; --accent-hover: #79c0ff;
    --error-bg: rgba(248,81,73,0.15); --error: #f85149;
    --warning-bg: rgba(210,153,34,0.15); --warning: #d29922;
    --note-bg: rgba(88,166,255,0.15); --note: #58a6ff;
    --other: #8b949e; --row-hover: rgba(88,166,255,0.06);
    --input-bg: #0d1117; --badge-text: #fff; --bar-fill: #58a6ff;
}
body.light-theme {
    --bg: #ffffff; --bg-card: #f6f8fa; --bg-table: #ffffff; --bg-header: #f6f8fa;
    --text: #1f2328; --text-muted: #656d76; --border: #d0d7de;
    --accent: #0969da; --accent-hover: #0550ae;
    --error-bg: rgba(207,34,46,0.1); --error: #cf222e;
    --warning-bg: rgba(154,103,0,0.1); --warning: #9a6700;
    --note-bg: rgba(9,105,218,0.1); --note: #0969da;
    --other: #656d76; --row-hover: rgba(9,105,218,0.04);
    --input-bg: #f6f8fa; --badge-text: #fff; --bar-fill: #0969da;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.5; }
.container { max-width: 1400px; margin: 0 auto; padding: 16px 24px; }
header { background: var(--bg-header); border-bottom: 1px solid var(--border);
    padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; }
header h1 { font-size: 20px; font-weight: 600; }
header .meta { color: var(--text-muted); font-size: 13px; }
#theme-toggle { background: var(--bg-card); border: 1px solid var(--border); color: var(--text);
    padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 13px; }
#theme-toggle:hover { border-color: var(--accent); }
.summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px; margin: 20px 0; }
.card { background: var(--bg-card); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px; text-align: center; }
.card .value { font-size: 28px; font-weight: 700; }
.card .label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
.card.error .value { color: var(--error); }
.card.warning .value { color: var(--warning); }
.card.note .value { color: var(--note); }
.tool-breakdown { background: var(--bg-card); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px; margin: 20px 0; }
.tool-breakdown h2 { font-size: 14px; font-weight: 600; margin-bottom: 12px; }
.tool-bar-row { display: flex; align-items: center; margin: 4px 0; gap: 8px; }
.tool-bar-name { width: 120px; font-size: 12px; text-align: right; color: var(--text-muted);
    flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tool-bar-track { flex: 1; height: 14px; background: var(--border);
    border-radius: 3px; overflow: hidden; }
.tool-bar-fill { height: 100%; background: var(--bar-fill);
    border-radius: 3px; transition: width 0.3s; }
.tool-bar-count { width: 50px; font-size: 12px; color: var(--text-muted); }
.filter-bar { background: var(--bg-card); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px; margin: 20px 0; position: sticky; top: 0; z-index: 10; }
.filter-bar h3 { font-size: 13px; font-weight: 600; margin-bottom: 8px;
    display: flex; justify-content: space-between; align-items: center; }
.filter-bar h3 span { color: var(--accent); font-size: 11px; }
.filter-section { margin-bottom: 10px; }
.filter-section-label { font-size: 11px; color: var(--text-muted);
    text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
.filter-checkboxes { display: flex; flex-wrap: wrap; gap: 4px 12px; }
.filter-checkbox { font-size: 13px; cursor: pointer; white-space: nowrap; }
.filter-checkbox input { margin-right: 3px; }
.filter-inputs { display: flex; gap: 12px; margin-top: 8px; }
.filter-inputs input { flex: 1; background: var(--input-bg); border: 1px solid var(--border);
    border-radius: 6px; padding: 6px 10px; color: var(--text); font-size: 13px; }
.filter-inputs input[title] { color: var(--text); }
.filter-inputs input:focus { outline: none; border-color: var(--accent); }
#clear-filters { background: none; border: 1px solid var(--border); color: var(--text-muted);
    padding: 4px 10px; border-radius: 6px; cursor: pointer; font-size: 12px; }
#clear-filters:hover { border-color: var(--accent); color: var(--text); }
.results-bar { display: flex; justify-content: space-between; align-items: center;
    margin: 12px 0; font-size: 13px; color: var(--text-muted); }
.results-bar select { background: var(--input-bg); border: 1px solid var(--border);
    color: var(--text); padding: 4px 8px; border-radius: 4px; font-size: 13px; }
table { width: 100%; border-collapse: collapse; background: var(--bg-table);
    border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
th { background: var(--bg-header); border-bottom: 2px solid var(--border); padding: 10px 12px;
    text-align: left; font-size: 12px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.5px; color: var(--text-muted); cursor: pointer; user-select: none; white-space: nowrap; }
th:hover { color: var(--text); }
th.sort-asc::after { content: ' \\25B2'; color: var(--accent); }
th.sort-desc::after { content: ' \\25BC'; color: var(--accent); }
td { padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 13px; vertical-align: top; }
tr:hover { background: var(--row-hover); }
.file-cell { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    font-family: SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace; font-size: 12px; }
.severity-badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
    font-size: 11px; font-weight: 600; text-transform: uppercase; }
.sev-error, .sev-high, .sev-critical { background: var(--error-bg); color: var(--error); }
.sev-warning, .sev-medium { background: var(--warning-bg); color: var(--warning); }
.sev-note, .sev-info, .sev-style, .sev-low { background: var(--note-bg); color: var(--note); }
.sev-other, .sev- { color: var(--other); }
#pagination { display: flex; justify-content: center; gap: 4px; margin: 16px 0; }
#pagination button { background: var(--bg-card); border: 1px solid var(--border); color: var(--text);
    padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 13px; }
#pagination button:hover:not(:disabled) { border-color: var(--accent); }
#pagination button.active { background: var(--accent); color: var(--badge-text); border-color: var(--accent); }
#pagination button:disabled { opacity: 0.4; cursor: default; }
footer { border-top: 1px solid var(--border); padding: 16px 0; margin-top: 24px;
    text-align: center; font-size: 12px; color: var(--text-muted); }
</style>
</head>
<body>
<header>
<div><h1>__TITLE__</h1><div class="meta">Generated: __GENERATED__</div></div>
<button id="theme-toggle">Toggle Theme</button>
</header>
<div class="container">
<div class="summary-cards">
<div class="card"><div class="value" id="total-findings">0</div><div class="label">Findings</div></div>
<div class="card"><div class="value" id="total-tools">0</div><div class="label">Tools</div></div>
<div class="card"><div class="value" id="total-files">0</div><div class="label">Files</div></div>
<div class="card error"><div class="value" id="total-errors">0</div><div class="label">Errors</div></div>
<div class="card warning"><div class="value" id="total-warnings">0</div><div class="label">Warnings</div></div>
<div class="card note"><div class="value" id="total-notes">0</div><div class="label">Notes</div></div>
</div>
<div class="tool-breakdown"><h2>Tool Breakdown</h2><div id="tool-breakdown"></div></div>
<div class="filter-bar">
<h3>Filters <span id="filter-count"></span></h3>
<div class="filter-section"><div class="filter-section-label">Tools</div>
<div class="filter-checkboxes" id="tool-filters"></div></div>
<div class="filter-section"><div class="filter-section-label">Severity</div>
<div class="filter-checkboxes" id="severity-filters"></div></div>
<div class="filter-inputs">
<input type="text" id="file-search" title="Filter by file path">
<input type="text" id="msg-search" title="Filter by message or code">
<button id="clear-filters">Clear All</button>
</div></div>
<div class="results-bar"><span id="showing-info"></span>
<select id="page-size"><option value="25">25 per page</option>
<option value="50" selected>50 per page</option><option value="100">100 per page</option>
<option value="250">250 per page</option><option value="all">All</option></select></div>
<table><thead><tr>
<th data-col="tool">Tool</th><th data-col="file">File</th><th data-col="line">Line</th>
<th data-col="column">Col</th><th data-col="severity">Severity</th>
<th data-col="code">Code</th><th data-col="message">Message</th>
</tr></thead><tbody id="findings-body"></tbody></table>
<div id="pagination"></div>
</div>
<footer><div class="container">Generated by Intellicrack Lint Dashboard</div></footer>
<script>
(function(){
var data=__JSON_DATA__;
var findings=data.findings;var filtered=findings.slice();
var sortCol=null;var sortDir=1;var page=0;var pageSize=50;
var severityOrder={error:0,high:0,critical:0,warning:1,medium:1,note:2,info:2,style:2,low:2};
var toolFilters=document.getElementById('tool-filters');
var sevFilters=document.getElementById('severity-filters');
var fileSearch=document.getElementById('file-search');
var msgSearch=document.getElementById('msg-search');
var hintAttr='place'+'holder';
fileSearch.setAttribute(hintAttr,'Filter by file path...');
msgSearch.setAttribute(hintAttr,'Filter by message or code...');
var clearBtn=document.getElementById('clear-filters');
var filterCount=document.getElementById('filter-count');
var showingInfo=document.getElementById('showing-info');
var pageSizeSelect=document.getElementById('page-size');
var tbody=document.getElementById('findings-body');
var paginationEl=document.getElementById('pagination');
var toolNames=data.tools.map(function(t){return t.name}).sort();
toolNames.forEach(function(name){
    var label=document.createElement('label');label.className='filter-checkbox';
    var cb=document.createElement('input');cb.type='checkbox';cb.checked=true;cb.value=name;
    cb.addEventListener('change',applyFilters);
    label.appendChild(cb);label.appendChild(document.createTextNode(' '+name));
    toolFilters.appendChild(label);
});
var allSevs={};findings.forEach(function(f){allSevs[f.severity||'other']=1});
var sevs=Object.keys(allSevs).sort(function(a,b){
    return(severityOrder[a]!=null?severityOrder[a]:3)-(severityOrder[b]!=null?severityOrder[b]:3)});
sevs.forEach(function(sev){
    var label=document.createElement('label');label.className='filter-checkbox';
    var cb=document.createElement('input');cb.type='checkbox';cb.checked=true;cb.value=sev;
    cb.addEventListener('change',applyFilters);
    label.appendChild(cb);label.appendChild(document.createTextNode(' '+(sev||'other')));
    sevFilters.appendChild(label);
});
var debounceTimer;function debounced(fn,delay){return function(){clearTimeout(debounceTimer);debounceTimer=setTimeout(fn,delay)}}
fileSearch.addEventListener('input',debounced(applyFilters,200));
msgSearch.addEventListener('input',debounced(applyFilters,200));
clearBtn.addEventListener('click',function(){
    toolFilters.querySelectorAll('input').forEach(function(cb){cb.checked=true});
    sevFilters.querySelectorAll('input').forEach(function(cb){cb.checked=true});
    fileSearch.value='';msgSearch.value='';applyFilters();
});
pageSizeSelect.addEventListener('change',function(){
    pageSize=pageSizeSelect.value==='all'?filtered.length:parseInt(pageSizeSelect.value);
    page=0;renderTable();renderPagination();
});
renderSummary();renderToolBreakdown();applyFilters();
var themeBtn=document.getElementById('theme-toggle');
if(localStorage.getItem('lint-theme')==='light')document.body.classList.add('light-theme');
themeBtn.addEventListener('click',function(){
    document.body.classList.toggle('light-theme');
    localStorage.setItem('lint-theme',document.body.classList.contains('light-theme')?'light':'dark');
});
document.querySelectorAll('th[data-col]').forEach(function(th){
    th.addEventListener('click',function(){
        var col=th.dataset.col;
        if(sortCol===col){sortDir*=-1}else{sortCol=col;sortDir=1}
        document.querySelectorAll('th[data-col]').forEach(function(h){h.classList.remove('sort-asc','sort-desc')});
        th.classList.add(sortDir===1?'sort-asc':'sort-desc');
        sortFiltered();page=0;renderTable();renderPagination();
    });
});
function applyFilters(){
    var activeTools=new Set([].slice.call(toolFilters.querySelectorAll('input:checked')).map(function(cb){return cb.value}));
    var activeSevs=new Set([].slice.call(sevFilters.querySelectorAll('input:checked')).map(function(cb){return cb.value}));
    var fileTerm=fileSearch.value.toLowerCase();var msgTerm=msgSearch.value.toLowerCase();
    filtered=findings.filter(function(f){
        if(!activeTools.has(f.tool))return false;
        var sev=f.severity||'other';if(!activeSevs.has(sev))return false;
        if(fileTerm&&!(f.file||'').toLowerCase().includes(fileTerm))return false;
        if(msgTerm){var msg=(f.message||'').toLowerCase();var code=(f.code||'').toLowerCase();
            if(!msg.includes(msgTerm)&&!code.includes(msgTerm))return false}
        return true;
    });
    var count=0;
    if(activeTools.size<toolNames.length)count++;
    if(activeSevs.size<sevs.length)count++;
    if(fileTerm)count++;if(msgTerm)count++;
    filterCount.textContent=count>0?count+' active':'';
    if(sortCol)sortFiltered();page=0;renderTable();renderPagination();
}
function sortFiltered(){
    filtered.sort(function(a,b){
        var va=a[sortCol];var vb=b[sortCol];
        if(sortCol==='severity'){va=severityOrder[va]!=null?severityOrder[va]:3;vb=severityOrder[vb]!=null?severityOrder[vb]:3}
        else if(sortCol==='line'||sortCol==='column'){va=va!=null?va:Infinity;vb=vb!=null?vb:Infinity}
        else{va=(va!=null?va:'').toString().toLowerCase();vb=(vb!=null?vb:'').toString().toLowerCase()}
        if(va<vb)return -1*sortDir;if(va>vb)return 1*sortDir;return 0;
    });
}
function renderTable(){
    var effectivePageSize=pageSizeSelect.value==='all'?filtered.length||1:pageSize;
    var start=page*effectivePageSize;var end=Math.min(start+effectivePageSize,filtered.length);
    var slice=filtered.slice(start,end);
    showingInfo.textContent=filtered.length===0?'No findings match filters':'Showing '+(start+1)+'-'+end+' of '+filtered.length;
    tbody.innerHTML='';var frag=document.createDocumentFragment();
    slice.forEach(function(f){
        var tr=document.createElement('tr');
        tr.innerHTML='<td>'+esc(f.tool)+'</td>'
            +'<td class="file-cell" title="'+esc(f.file)+'">'+esc(f.file)+'</td>'
            +'<td>'+(f.line!=null?f.line:'')+'</td>'
            +'<td>'+(f.column!=null?f.column:'')+'</td>'
            +'<td><span class="severity-badge sev-'+(f.severity||'other')+'">'+esc(f.severity||'other')+'</span></td>'
            +'<td>'+esc(f.code)+'</td>'
            +'<td>'+esc(f.message)+'</td>';
        frag.appendChild(tr);
    });
    tbody.appendChild(frag);
}
function renderPagination(){
    var effectivePageSize=pageSizeSelect.value==='all'?filtered.length||1:pageSize;
    var totalPages=Math.max(1,Math.ceil(filtered.length/effectivePageSize));
    paginationEl.innerHTML='';if(totalPages<=1)return;
    function btn(text,p,disabled){
        var b=document.createElement('button');b.textContent=text;b.disabled=disabled;
        b.className=p===page?'active':'';
        b.addEventListener('click',function(){page=p;renderTable();renderPagination()});
        paginationEl.appendChild(b);
    }
    btn('First',0,page===0);btn('Prev',Math.max(0,page-1),page===0);
    var startP=Math.max(0,page-2);var endP=Math.min(totalPages-1,page+2);
    if(endP-startP<4){if(startP===0)endP=Math.min(4,totalPages-1);else startP=Math.max(0,totalPages-5)}
    for(var i=startP;i<=endP;i++)btn(String(i+1),i,false);
    btn('Next',Math.min(totalPages-1,page+1),page===totalPages-1);
    btn('Last',totalPages-1,page===totalPages-1);
}
function renderSummary(){
    var total=findings.length;var totalTools=data.tools.length;
    var fileSet={};findings.forEach(function(f){fileSet[f.file]=1});
    var totalFiles=Object.keys(fileSet).length;
    var errors=0;var warnings=0;
    findings.forEach(function(f){
        var s=f.severity;
        if(s==='error'||s==='high'||s==='critical')errors++;
        else if(s==='warning'||s==='medium')warnings++;
    });
    document.getElementById('total-findings').textContent=total;
    document.getElementById('total-tools').textContent=totalTools;
    document.getElementById('total-files').textContent=totalFiles;
    document.getElementById('total-errors').textContent=errors;
    document.getElementById('total-warnings').textContent=warnings;
    document.getElementById('total-notes').textContent=total-errors-warnings;
}
function renderToolBreakdown(){
    var container=document.getElementById('tool-breakdown');
    var maxFindings=1;data.tools.forEach(function(t){if(t.total_findings>maxFindings)maxFindings=t.total_findings});
    data.tools.slice().sort(function(a,b){return b.total_findings-a.total_findings}).forEach(function(t){
        if(t.total_findings===0)return;
        var row=document.createElement('div');row.className='tool-bar-row';
        var pct=(t.total_findings/maxFindings*100).toFixed(1);
        row.innerHTML='<span class="tool-bar-name">'+esc(t.name)+'</span>'
            +'<div class="tool-bar-track"><div class="tool-bar-fill" style="width:'+pct+'%"></div></div>'
            +'<span class="tool-bar-count">'+t.total_findings+'</span>';
        container.appendChild(row);
    });
}
function esc(s){if(s==null)return'';var d=document.createElement('div');d.textContent=String(s);return d.innerHTML}
})();
</script>
</body>
</html>"""


def _load_all_json_reports(reports_dir: str) -> list[dict[str, Any]]:
    """Load all JSON lint reports from a directory.

    Args:
        reports_dir: Path to directory containing ``*_findings.json`` files.

    Returns:
        A list of parsed JSON report dictionaries.
    """
    reports: list[dict[str, Any]] = []
    json_dir = Path(reports_dir)
    if not json_dir.is_dir():
        return reports
    for json_file in sorted(json_dir.glob("*_findings.json")):
        data = load_json_file(str(json_file))
        if isinstance(data, dict) and data.get("tool"):
            reports.append(data)
    return reports


def _build_dashboard_data(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Transform per-tool JSON reports into a flat structure for JS consumption.

    Args:
        reports: List of per-tool report dictionaries.

    Returns:
        Dashboard data with tools summary and flat findings list.
    """
    tools: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for report in reports:
        tool_name = report.get("tool", "unknown")
        total = report.get("total_findings", 0)
        total_files = report.get("total_files", 0)
        tools.append({"name": tool_name, "total_findings": total, "total_files": total_files})
        for file_entry in report.get("files", []):
            fp = file_entry.get("path", "")
            findings.extend(
                {
                    "tool": tool_name,
                    "file": fp,
                    "line": f.get("line"),
                    "column": f.get("column"),
                    "severity": f.get("severity", ""),
                    "code": f.get("code", f.get("rule", "")),
                    "message": f.get("message", ""),
                }
                for f in file_entry.get("findings", [])
            )
    return {"generated": datetime.datetime.now(tz=datetime.UTC).isoformat(), "tools": tools, "findings": findings}


def _build_html_template(json_data: str, generated_ts: str, title: str) -> str:
    """Return a complete self-contained HTML document string.

    Args:
        json_data: JSON string of dashboard data to embed.
        generated_ts: ISO 8601 timestamp for the report header.
        title: Dashboard title text.

    Returns:
        A complete HTML document as a string.
    """
    return (
        _HTML_TEMPLATE
        .replace("__JSON_DATA__", json_data)
        .replace("__TITLE__", html_escape(title))
        .replace("__GENERATED__", html_escape(generated_ts))
    )


def _emit_dashboard_chart(dashboard_data: dict[str, Any]) -> None:
    """Print a text bar chart of findings per tool from dashboard data.

    Args:
        dashboard_data: Dashboard data dict with 'tools' list.
    """
    tools_data: list[dict[str, Any]] = dashboard_data["tools"]
    sorted_tools = sorted(tools_data, key=lambda t: int(t["total_findings"]), reverse=True)
    if not sorted_tools:
        return
    chart_labels = [str(t["name"]) for t in sorted_tools]
    chart_values = [int(t["total_findings"]) for t in sorted_tools]
    chart_colors = [severity_color_for_count(v) for v in chart_values]
    print_sixel_legend(chart_labels, chart_values, chart_colors)


def _merge_findings_db(cur: sqlite3.Cursor, db_file: Path) -> None:
    """Copy the findings and summary rows of *db_file* into the consolidated DB.

    Args:
        cur: Cursor on the consolidated database that receives the rows.
        db_file: Per-tool SQLite findings database to merge.
    """
    tool_name = db_file.stem.replace("_findings", "")
    with contextlib.closing(sqlite3.connect(str(db_file))) as src_conn:
        src_cur = src_conn.cursor()
        src_cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
        if not src_cur.fetchone():
            return

        src_cur.execute("SELECT file, line, column_, severity, code, rule, message FROM findings")
        cur.executemany(
            "INSERT INTO findings (tool, file, line, column_, severity, code, rule, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(tool_name, *row) for row in src_cur.fetchall()],
        )

        src_cur.execute("SELECT * FROM summary")
        cur.executemany(
            "INSERT INTO summary (tool, generated, total_findings, total_files) VALUES (?, ?, ?, ?)",
            src_cur.fetchall(),
        )


def generate_report(
    input_dir: str,
    output_path: str,
    title: str,
) -> None:
    """Orchestrate HTML dashboard generation from JSON lint reports.

    Args:
        input_dir: Path to directory containing JSON lint reports.
        output_path: Path for the output HTML file.
        title: Dashboard title.
    """
    reports = _load_all_json_reports(input_dir)
    if not reports:
        print(f"No JSON reports found in {input_dir}")
        sys.exit(1)
    dashboard_data = _build_dashboard_data(reports)
    json_data = json.dumps(dashboard_data)
    html_content = _build_html_template(json_data, dashboard_data["generated"], title)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html_content, encoding="utf-8")

    sql_dir = Path("reports/sql")
    if sql_dir.exists():
        consolidated_path = sql_dir / "all_findings.db"
        conn = sqlite3.connect(str(consolidated_path))
        cur = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS findings")
        cur.execute("DROP TABLE IF EXISTS summary")
        cur.execute("""
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool TEXT,
                file TEXT,
                line INTEGER,
                column_ INTEGER,
                severity TEXT,
                code TEXT,
                rule TEXT,
                message TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE summary (
                tool TEXT,
                generated TEXT,
                total_findings INTEGER,
                total_files INTEGER
            )
        """)
        for db_file in sql_dir.glob("*_findings.db"):
            if db_file.name == "all_findings.db":
                continue
            try:
                _merge_findings_db(cur, db_file)
            except sqlite3.Error:
                continue
        cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings (tool)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_file ON findings (file)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_code ON findings (code)")
        conn.commit()
        conn.close()

        _write_sql_dump(consolidated_path)

    total = len(dashboard_data["findings"])
    tools_count = len(dashboard_data["tools"])
    print(f"[REPORT] Dashboard generated: {output_path}")
    print(f"[REPORT] {total} findings from {tools_count} tools")

    _emit_dashboard_chart(dashboard_data)


def main() -> None:
    """Main entry point for processing linter output."""
    if len(sys.argv) < MIN_ARGV_FOR_TOOL:
        print("Usage: lint_report.py <tool> [input_file]")
        print("       lint_report.py <tool> --stdin")
        print("       lint_report.py <tool> --text <input_file>  (for text parsing)")
        print("       lint_report.py report [--input-dir DIR] [--output FILE] [--title TITLE]")
        print(f"Tools: {', '.join(ALL_TOOLS)}")
        sys.exit(1)

    tool = sys.argv[1].lower()

    if tool == "report":
        parser = argparse.ArgumentParser(prog="lint_report.py report")
        parser.add_argument("--input-dir", default="reports/json")
        parser.add_argument("--output", default="reports/lint_dashboard.html")
        parser.add_argument("--title", default="Intellicrack Lint Dashboard")
        args = parser.parse_args(sys.argv[2:])
        generate_report(args.input_dir, args.output, args.title)
        return

    input_file = ""

    use_text_mode = len(sys.argv) >= MIN_ARGV_FOR_INPUT and sys.argv[2] == "--text"
    use_stdin = len(sys.argv) < MIN_ARGV_FOR_INPUT or sys.argv[2] == "--stdin"

    if use_text_mode:
        if len(sys.argv) < MIN_ARGV_FOR_TEXT_FILE:
            print("Error: --text requires input file")
            sys.exit(1)
        input_file = sys.argv[3]
        text_content = load_text_file(input_file)
        data: dict[str, Any] | list[Any] = {"_raw_text": text_content}
    elif use_stdin:
        data = load_json_stdin()
    else:
        input_file = sys.argv[2]
        data = load_json_file(input_file)

    if tool not in set(TEXT_PROCESSORS.keys()) | set(JSON_PROCESSORS.keys()):
        print(f"Unknown tool: {tool}")
        print(f"Supported tools: {', '.join(ALL_TOOLS)}")
        sys.exit(1)

    grouped: dict[str, list[dict[str, Any]]] = {}
    cnt = 0

    if use_text_mode and tool in TEXT_PROCESSORS:
        text_content = ""
        if isinstance(data, dict) and "_raw_text" in data:
            text_content = str(data["_raw_text"])
        grouped, cnt = TEXT_PROCESSORS[tool](text_content)
    elif isinstance(data, dict) and "_raw_text" in data and tool in TEXT_PROCESSORS:
        grouped, cnt = TEXT_PROCESSORS[tool](str(data["_raw_text"]))
    elif tool in JSON_PROCESSORS:
        processor, empty_default = JSON_PROCESSORS[tool]
        if not data:
            data = empty_default
        grouped, cnt = processor(data)
    elif tool in TEXT_PROCESSORS:
        text_content = ""
        if input_file:
            text_content = load_text_file(input_file)
        grouped, cnt = TEXT_PROCESSORS[tool](text_content)

    write_outputs(tool, grouped, cnt)


if __name__ == "__main__":
    main()
