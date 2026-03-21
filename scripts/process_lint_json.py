#!/usr/bin/env python3
"""Process native JSON/text output from linters and convert to standard format.

This script processes output from various linters and produces consistent
findings files in JSON, XML, and TXT formats.
Findings are sorted by file, with files having the most findings listed first.
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any


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


def process_eslint(data: list[Any]) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process ESLint native JSON output."""
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
    """Process Ruff native JSON output."""
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
    """Process BasedPyright native JSON output."""
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
    """Process Mypy JSON output."""
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
    """Process Knip native JSON output."""
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
    """Process Semgrep native JSON output."""
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


def process_biome_json(data: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process Biome native JSON output."""
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
    """Process Biome text/stderr output."""
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
                if next_line.startswith("\u00d7") or next_line.startswith("!"):
                    message_line = next_line.lstrip("\u00d7!").strip()
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
    """Process ty type checker text output."""
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
    """Process vulture dead code detection text output."""
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


def process_darglint_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    r"""Process darglint docstring linting text output.

    Darglint outputs format: file:function:line: CODE: message
    Example: intellicrack\\config.py:_ensure_config_manager_imported:35: DAR201: - return
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.py):([^:]+):(\d+):\s*(\S+):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        match = pattern.match(stripped_line)
        if match:
            fp = match.group(1)
            func_name = match.group(2)
            line_num = int(match.group(3))
            code = match.group(4)
            message = match.group(5).strip()
            grouped[fp].append({
                "line": line_num,
                "column": None,
                "function": func_name,
                "code": code,
                "message": f"[{func_name}] {message}",
                "raw": stripped_line,
            })
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
            fp = current_file if current_file else "unknown"
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
    """Process mypy text output."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.py):(\d+):(\d+):\s*(\w+):\s*(.+)$")
    pattern2 = re.compile(r"^(.+\.py):(\d+):\s*(\w+):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("Found ") or stripped_line.startswith("Success:"):
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
            grouped[fp].append({"line": line_num, "column": col_num, "severity": severity, "code": code, "message": message, "raw": stripped_line})
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
                grouped[fp].append({"line": line_num, "column": None, "severity": severity, "code": code, "message": message, "raw": stripped_line})
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_bandit_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process bandit security linting text output."""
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
        elif stripped_line.startswith("---") or stripped_line.startswith("Run started"):
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
    """Process cargo clippy text output."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"-->\s*(.+\.rs):(\d+):(\d+)")
    current_level = ""
    current_message = ""
    lines = text_output.strip().split("\n")
    for line in lines:
        line_stripped = line.strip()
        if line_stripped.startswith("warning:") or line_stripped.startswith("error:"):
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
    """Process markdownlint text output."""
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
    """Process yamllint text output."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    current_file = ""
    pattern = re.compile(r"^\s*(\d+):(\d+)\s+(\w+)\s+(.+)$")
    for line in text_output.strip().split("\n"):
        line_stripped = line.strip()
        if not line_stripped:
            continue
        if line_stripped.startswith("./") or line_stripped.endswith(".yml") or line_stripped.endswith(".yaml"):
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
    """Process uncalled dead function detection text output."""
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
    """Process deadcode text output."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.py):(\d+):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("Scanning") or stripped_line.startswith("Found"):
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
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(.+\.java):(\d+):\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("[") or stripped_line.startswith("WARN"):
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
    """Process Checkstyle Java analysis text output."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^\[(\w+)\]\s*(.+\.java):(\d+)(?::(\d+))?:\s*(.+)$")
    pattern2 = re.compile(r"^(.+\.java):(\d+)(?::(\d+))?:\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("Starting audit") or stripped_line.startswith("Audit done"):
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
    """Process cargo-deny policy enforcement text output."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pattern = re.compile(r"^(error|warning)\[(\w+)\]:\s*(.+)$")
    for line in text_output.strip().split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        match = pattern.match(stripped_line)
        if match:
            severity = match.group(1)
            code = match.group(2)
            message = match.group(3).strip()
            grouped["Cargo.toml"].append({
                "line": None,
                "column": None,
                "severity": severity,
                "code": code,
                "message": message,
                "raw": stripped_line,
            })
        elif "denied" in stripped_line.lower() or "banned" in stripped_line.lower() or "unauthorized" in stripped_line.lower():
            grouped["Cargo.toml"].append({"line": None, "column": None, "message": stripped_line, "raw": stripped_line})
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_shellcheck_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process shellcheck shell script analysis text output (GCC format)."""
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
            grouped[fp].append({"line": line_num, "column": col_num, "severity": severity, "code": code, "message": message, "raw": stripped_line})
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_blinter_text(
    text_output: str,
) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Process blinter batch file linter verbose text output."""
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
    """Process JSON validation text output."""
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
    """Process PSScriptAnalyzer PowerShell analysis text output."""
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
            grouped[fp].append({"line": line_num, "column": col_num, "severity": severity, "rule": rule, "message": message, "raw": stripped_line})
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
                _build_xenon_alt_finding(alt_match, stripped_line)
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


def process_taplo_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    r"""Process taplo TOML checker text output.

    Taplo check/lint output format:
    error: <message>
      \u250c\u2500 <filepath>:<line>:<col>
      \u2502
    N \u2502 <source line>
      \u2502   ^^^ <hint>

    Example:
    error: invalid TOML
      \u250c\u2500 pyproject.toml:5:10
      \u2502
    5 \u2502 bad = [
      \u2502       ^ unexpected EOF
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    location_pattern = re.compile(r"^\s*\u250c\u2500\s*(.+):(\d+):(\d+)\s*$")
    error_pattern = re.compile(r"^(error|warning):\s*(.+)$")
    lines = text_output.strip().split("\n")
    current_message = ""

    for i, line in enumerate(lines):
        error_match = error_pattern.match(line.strip())
        if error_match:
            current_message = error_match.group(2).strip()
            continue
        loc_match = location_pattern.match(line)
        if loc_match and current_message:
            fp = loc_match.group(1)
            line_num = int(loc_match.group(2))
            col_num = int(loc_match.group(3))
            hint = ""
            for j in range(i + 1, min(i + 5, len(lines))):
                hint_line = lines[j].strip()
                if hint_line.startswith("\u2502"):
                    content = hint_line.lstrip("\u2502").strip()
                    if content.startswith("^") or content.startswith("\u2570") or content.startswith("\u256d"):
                        hint = content.lstrip("^").lstrip("\u2570").lstrip("\u256d").strip()
                        break
            message = f"{current_message}: {hint}" if hint else current_message
            grouped[fp].append({
                "line": line_num,
                "column": col_num,
                "severity": "error",
                "message": message,
                "raw": f"{fp}:{line_num}:{col_num}: [error] {message}",
            })
            current_message = ""
    cnt = sum(len(v) for v in grouped.values())
    return grouped, cnt


def process_interrogate_text(text_output: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    r"""Process interrogate docstring coverage verbose text output.

    Interrogate ``-vv`` output has table rows like:
    ``| path\file.py (module) | COVERED |``
    ``|   ClassName.method (L42) | MISSED |``

    Only MISSED items are reported as findings.
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
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    full_pattern = re.compile(r"^(.+?):(\d+):(\d+):\s*(DEP\d+)\s+(.+)$")
    simple_pattern = re.compile(r"^(.+?):\s*(DEP\d+)\s+(.+)$")

    for line in text_output.strip().split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("Scanning") or stripped.startswith("Found") or stripped.startswith("For more information"):
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


def escape_xml(s: str) -> str:
    """Escape special XML characters."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


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


def write_outputs(tool: str, grouped: dict[str, list[dict[str, Any]]], cnt: int) -> None:
    """Write findings to TXT, JSON, and XML files, sorted by file (descending by count)."""
    for subdir in ("txt", "json", "xml"):
        Path(f"reports/{subdir}").mkdir(parents=True, exist_ok=True)

    sorted_files = sorted(grouped.keys(), key=lambda x: len(grouped[x]), reverse=True)

    txt_lines: list[str] = []
    for fp in sorted_files:
        if txt_lines:
            txt_lines.extend(["", ""])
        txt_lines.append(f"{len(grouped[fp])} findings in {fp}")
        txt_lines.append("")
        for i, f in enumerate(grouped[fp]):
            txt_lines.append(f["raw"])
            if i < len(grouped[fp]) - 1:
                txt_lines.append("")

    if cnt == 0:
        txt_lines = ["No findings."]

    Path(f"reports/txt/{tool}_findings.txt").write_text("\n".join(txt_lines), encoding="utf-8")

    ts = datetime.now().isoformat()
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

    print(f"[{tool.upper()}] {cnt} findings")


def load_json_file(input_file: str) -> dict[str, Any] | list[Any]:
    """Load JSON from a file, handling BOM and encoding issues."""
    try:
        with open(input_file, encoding="utf-8-sig") as f:
            content = f.read().strip()
            if not content:
                return {}
            return json.loads(content)
    except json.JSONDecodeError:
        return {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def load_text_file(input_file: str) -> str:
    """Load text from a file."""
    try:
        with open(input_file, encoding="utf-8-sig") as f:
            return f.read()
    except FileNotFoundError:
        return ""
    except Exception:
        return ""


def load_json_stdin() -> dict[str, Any] | list[Any]:
    """Load JSON from stdin, handling various input formats."""
    try:
        content = sys.stdin.read().strip()
        if not content:
            return {}
        lines = content.split("\n")
        for line in lines:
            stripped_line = line.strip()
            if stripped_line.startswith("{") or stripped_line.startswith("["):
                try:
                    return json.loads(stripped_line)
                except json.JSONDecodeError:
                    continue
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {"_raw_text": content}
    except Exception:
        return {}


TEXT_PROCESSORS: dict[str, Callable[[str], tuple[dict[str, list[dict[str, Any]]], int]]] = {
    "ty": process_ty_text,
    "vulture": process_vulture_text,
    "darglint": process_darglint_text,
    "pydoclint": process_pydoclint_text,
    "dead": process_dead_text,
    "mypy": process_mypy_text,
    "bandit": process_bandit_text,
    "clippy": process_clippy_text,
    "markdownlint": process_markdownlint_text,
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
    "flake8": process_flake8_text,
    "wemake": process_wemake_text,
    "mccabe": process_mccabe_text,
    "pydocstyle": process_pydocstyle_text,
    "radon": process_radon_text,
    "xenon": process_xenon_text,
    "complexipy": process_complexipy_text,
    "taplo": process_taplo_text,
    "interrogate": process_interrogate_text,
    "deptry": process_deptry_text,
    "codespell": process_codespell_text,
    "mixed-line-ending": process_mixed_line_ending_text,
    "mixed_line_ending": process_mixed_line_ending_text,
    "file-encoding": process_file_encoding_text,
    "file_encoding": process_file_encoding_text,
}

JSON_PROCESSORS: dict[str, tuple[Callable[..., tuple[dict[str, list[dict[str, Any]]], int]], Any]] = {
    "eslint": (process_eslint, []),
    "ruff": (process_ruff, []),
    "basedpyright": (process_basedpyright, {"generalDiagnostics": []}),
    "mypy": (process_mypy_json, []),
    "knip": (process_knip, {"issues": []}),
    "biome": (process_biome_json, {"diagnostics": []}),
    "semgrep": (process_semgrep, {"results": []}),
}

ALL_TOOLS = sorted(set(TEXT_PROCESSORS.keys()) | set(JSON_PROCESSORS.keys()))


def main() -> None:
    """Main entry point for processing linter output."""
    if len(sys.argv) < MIN_ARGV_FOR_TOOL:
        print("Usage: process_lint_json.py <tool> [input_file]")
        print("       process_lint_json.py <tool> --stdin")
        print("       process_lint_json.py <tool> --text <input_file>  (for text parsing)")
        print(f"Tools: {', '.join(ALL_TOOLS)}")
        sys.exit(1)

    tool = sys.argv[1].lower()
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
