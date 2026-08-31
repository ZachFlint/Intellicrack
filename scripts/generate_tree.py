#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Intellicrack Directory Tree Generator.

Generates an HTA application that renders the directory tree lazily: the
filesystem is serialized once as a flat JSON node table, then only the root
plus its immediate children are materialized into the DOM at load time. Folders
expand on demand, which keeps mshta's Trident layout engine responsive even on
trees with tens of thousands of entries.
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import subprocess
from pathlib import Path


EXCLUDED_NAMES: frozenset[str] = frozenset({
    ".git",
    ".pixi",
    "node_modules",
    "__pycache__",
    ".ruff_cache",
    ".aider.tags.cache.v4",
    "dist",
    "build",
    ".venv",
    ".mypy_cache",
    ".pytest_cache",
    ".claude",
    ".serena",
    "Intellicrack.egg-info",
})

FILE_ICONS: dict[str, str] = {
    ".py": "[PY]",
    ".js": "[JS]",
    ".json": "[JSON]",
    ".md": "[MD]",
    ".txt": "[TXT]",
    ".html": "[HTML]",
    ".css": "[CSS]",
    ".exe": "[EXE]",
    ".dll": "[DLL]",
    ".so": "[SO]",
    ".java": "[JAVA]",
    ".c": "[C]",
    ".cpp": "[CPP]",
    ".h": "[H]",
    ".rs": "[RS]",
    ".go": "[GO]",
    ".yaml": "[YAML]",
    ".yml": "[YML]",
    ".xml": "[XML]",
    ".svg": "[SVG]",
    ".png": "[PNG]",
    ".jpg": "[JPG]",
    ".jpeg": "[JPEG]",
    ".gif": "[GIF]",
    ".ico": "[ICO]",
    ".zip": "[ZIP]",
    ".rar": "[RAR]",
    ".7z": "[7Z]",
    ".tar": "[TAR]",
    ".gz": "[GZ]",
    ".pdf": "[PDF]",
    ".doc": "[DOC]",
    ".docx": "[DOCX]",
    ".xls": "[XLS]",
    ".xlsx": "[XLSX]",
}

SYNTAX_CLASSES: dict[str, str] = {
    ".py": " python",
    ".js": " javascript",
    ".jsx": " javascript",
    ".json": " json",
}


def get_file_icon(file_path: str) -> str:
    """Return appropriate icon based on file extension.

    Args:
        file_path: Full or relative path to a file.

    Returns:
        str: A string icon representation matching the file type.

    """
    return FILE_ICONS.get(Path(file_path).suffix.lower(), "[FILE]")


def format_size(file_bytes: float) -> str:
    """Format file size in human-readable format.

    Args:
        file_bytes: Number of bytes to format.

    Returns:
        str: Human-readable string representation of file size (e.g., "1.23 MB").

    """
    if file_bytes == 0:
        return "0 B"
    k = 1024.0
    sizes = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    value = float(file_bytes)
    while value >= k and i < len(sizes) - 1:
        value /= k
        i += 1
    return f"{value:.2f} {sizes[i]}"


def _list_dir_sorted(directory: Path) -> list[Path]:
    """Return non-excluded children of ``directory``, folders first then files.

    Args:
        directory: Directory whose entries should be listed.

    Returns:
        list[Path]: Sorted list of child paths, or an empty list if the
        directory cannot be read (e.g. permission denied).

    """
    try:
        entries = [e for e in directory.iterdir() if e.name not in EXCLUDED_NAMES]
    except PermissionError:
        return []
    entries.sort(key=lambda e: (not e.is_dir(), e.name.lower()))
    return entries


def _stat_size(path: Path) -> int:
    """Return the size in bytes of ``path``, or 0 if it cannot be stat'd.

    Args:
        path: Filesystem path to stat.

    Returns:
        int: File size in bytes, or 0 on stat failure.

    """
    try:
        return path.stat().st_size
    except OSError:
        return 0


def scan_directory(root_path: str) -> tuple[list[dict[str, object]], int, int]:
    """Recursively scan ``root_path`` and produce a flat list of node records.

    Each node is a dict with short keys to keep the embedded JSON small:
    ``n`` (name), ``p`` (absolute path), ``t`` (``"d"`` folder / ``"f"``
    file), ``pa`` (parent index, ``-1`` for root), plus ``c`` (list of child
    indices, folders only) or ``s`` (size in bytes, files only).

    Args:
        root_path: Root directory path to scan.

    Returns:
        tuple[list[dict[str, object]], int, int]: A tuple
        ``(nodes, file_count, folder_count)``. ``nodes[0]`` is always the
        root entry; child indices refer into the same list.

    """
    nodes: list[dict[str, object]] = []
    file_count = 0
    folder_count = 0

    def walk(path: str, parent: int) -> int:
        nonlocal file_count, folder_count
        idx = len(nodes)
        p_obj = Path(path)
        name = p_obj.name or path

        if p_obj.is_dir():
            folder_count += 1
            children: list[int] = []
            node: dict[str, object] = {
                "n": name,
                "p": path,
                "t": "d",
                "pa": parent,
                "c": children,
            }
            nodes.append(node)
            children.extend(walk(str(entry), idx) for entry in _list_dir_sorted(p_obj))
        else:
            file_count += 1
            file_node: dict[str, object] = {
                "n": name,
                "p": path,
                "t": "f",
                "pa": parent,
                "s": _stat_size(p_obj),
            }
            nodes.append(file_node)
        return idx

    walk(root_path, -1)
    return nodes, file_count, folder_count


def _embed_json(data: object) -> str:
    """Serialize ``data`` to JSON safe for inline ``<script>`` embedding.

    Args:
        data: Any JSON-serializable Python object.

    Returns:
        str: Compact JSON string with ``</`` sequences neutralized so an
        embedded path or name cannot prematurely terminate the surrounding
        script tag.

    """
    raw = json.dumps(data, separators=(",", ":"), ensure_ascii=True)
    return raw.replace("</", "<\\/")


def _run_system_tree(root_path: str) -> str:
    """Invoke the system ``tree -F`` command and return its stdout.

    Args:
        root_path: Directory to run ``tree`` against.

    Returns:
        str: The tree command's stdout, or an empty string if the binary is
        not available or the invocation failed for any reason.

    """
    tree_bin = shutil.which("tree")
    if tree_bin is None:
        return ""
    try:
        result = subprocess.run(
            [tree_bin, "-F"],
            capture_output=True,
            text=True,
            shell=False,
            cwd=root_path,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        print(f"Warning: Could not generate tree with system command: {e}")
        return ""
    return result.stdout if result.returncode == 0 else ""


def generate_txt_tree(root_path: str, output_file: str) -> None:
    """Generate plain text tree structure file.

    Args:
        root_path: Root directory path to generate tree from.
        output_file: Output file path for the text tree structure.

    """
    print(f"Generating text tree for: {root_path}")

    header_content = f"""INTELLICRACK PROJECT FILE TREE STRUCTURE
========================================

Generated: {datetime.datetime.now(tz=datetime.UTC).strftime("%a, %b %d, %Y %I:%M:%S %p")}
Directory: {root_path}

This document provides a simple text-based tree structure of the Intellicrack project.
For an interactive HTML version with clickable links, see IntellicrackStructure.hta

----------------------------------------

"""

    tree_output = generate_fallback_tree(root_path) if os.name == "nt" else _run_system_tree(root_path) or generate_fallback_tree(root_path)

    with Path(output_file).open("w", encoding="utf-8") as f:
        f.write(header_content)
        f.write(tree_output)

    line_count = tree_output.count("\n")
    print(f"TXT tree generated: {output_file} ({line_count} lines)")


def generate_fallback_tree(root_path: str, prefix: str = "", *, _is_last: bool = True) -> str:
    """Generate tree structure as fallback if tree command fails.

    Args:
        root_path: Root directory path to generate tree from.
        prefix: Prefix string for tree indentation (used in recursion).
        _is_last: Whether this is the last item in the current directory.

    Returns:
        str: String representation of the directory tree structure.

    """
    entries = _list_dir_sorted(Path(root_path))
    parts: list[str] = []
    for i, entry in enumerate(entries):
        is_last_item = i == len(entries) - 1
        connector = "└── " if is_last_item else "├── "
        parts.append(f"{prefix}{connector}{entry.name}")
        if entry.is_dir():
            parts.append("/\n")
            extension = "    " if is_last_item else "│   "
            parts.append(generate_fallback_tree(str(entry), prefix + extension, _is_last=is_last_item))
        else:
            parts.append("\n")
    return "".join(parts)


def generate_hta(root_path: str, output_file: str) -> None:
    """Generate HTA file with a lazy-rendered, clickable directory tree.

    Args:
        root_path: Root directory path to generate HTA for.
        output_file: Output file path for the HTA application.

    """
    print(f"Scanning directory: {root_path}")
    nodes, file_count, folder_count = scan_directory(root_path)

    nodes_json = _embed_json(nodes)
    icons_json = _embed_json(FILE_ICONS)
    syntax_json = _embed_json(SYNTAX_CLASSES)
    root_path_json = _embed_json(root_path)

    hta_content = f"""<!DOCTYPE html>
<html>
<head>
<title>Intellicrack Directory Structure</title>
<HTA:APPLICATION
    ID="IntellicrackTree"
    APPLICATIONNAME="Intellicrack Directory Tree"
    BORDER="thick"
    BORDERSTYLE="normal"
    CAPTION="yes"
    MAXIMIZEBUTTON="yes"
    MINIMIZEBUTTON="yes"
    SHOWINTASKBAR="yes"
    SYSMENU="yes"
    WINDOWSTATE="normal"
    SCROLL="yes"
    NAVIGABLE="yes"
/>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<style>
    body {{
        font-family: 'Consolas', 'Courier New', monospace;
        background: #1e1e1e;
        color: #d4d4d4;
        margin: 0;
        padding: 20px;
        overflow: hidden;
        display: flex;
        flex-direction: column;
        height: 100vh;
        box-sizing: border-box;
    }}

    .main-container {{
        display: flex;
        flex: 1;
        overflow: hidden;
        gap: 20px;
        margin-top: 10px;
    }}

    .tree-pane {{
        flex: 1;
        overflow-y: auto;
        border-right: 1px solid #3c3c3c;
        padding-right: 10px;
    }}

    .preview-pane {{
        flex: 1;
        overflow-y: auto;
        background: #252526;
        padding: 15px;
        border-radius: 5px;
    }}

    #previewContent {{
        white-space: pre-wrap;
        word-wrap: break-word;
        font-size: 13px;
        margin: 0;
    }}

    .action-buttons {{
        margin-top: 10px;
        display: flex;
        gap: 5px;
    }}

    h1 {{
        color: #569cd6;
        border-bottom: 2px solid #569cd6;
        padding-bottom: 10px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }}

    .stats {{
        font-size: 14px;
        color: #808080;
    }}

    .tree {{
        padding: 20px 0;
    }}

    ul {{
        list-style-type: none;
        margin: 0;
        padding-left: 20px;
    }}

    .root-list {{
        padding-left: 0;
    }}

    li {{
        margin: 3px 0;
        position: relative;
    }}

    .item {{
        display: inline-block;
        padding: 2px 5px;
        cursor: pointer;
        border-radius: 3px;
        transition: background-color 0.2s;
        user-select: none;
    }}

    .item:hover {{
        background-color: #2a2a2a;
    }}

    .item.selected {{
        background-color: #37373d;
        border: 1px solid #569cd6;
    }}

    .folder {{
        color: #dcdcaa;
        font-weight: bold;
    }}

    .folder.collapsed:before {{
        content: '\\25B6\\00A0';
        color: #808080;
        display: inline-block;
        width: 15px;
    }}

    .folder.expanded:before {{
        content: '\\25BC\\00A0';
        color: #808080;
        display: inline-block;
        width: 15px;
    }}

    .folder.leaf:before {{
        content: '\\00A0\\00A0\\00A0';
        display: inline-block;
        width: 15px;
    }}

    .file {{
        color: #d4d4d4;
        margin-left: 15px;
    }}

    .python {{ color: #4ec9b0; }}
    .javascript {{ color: #f0db4f; }}
    .json {{ color: #cbcb41; }}

    .size {{
        color: #808080;
        font-size: 0.85em;
        margin-left: 10px;
    }}

    .path-display {{
        background: #2a2a2a;
        padding: 10px;
        margin: 10px 0;
        border-radius: 5px;
        font-size: 12px;
        color: #808080;
        word-break: break-all;
    }}

    .controls {{
        background: #2a2a2a;
        padding: 10px;
        border-radius: 5px;
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 10px;
        flex-wrap: wrap;
    }}

    .controls .spacer {{
        flex: 1;
    }}

    button {{
        background: #569cd6;
        color: white;
        border: none;
        padding: 5px 15px;
        border-radius: 3px;
        cursor: pointer;
        font-family: inherit;
    }}

    button:hover {{
        background: #6ea3d8;
    }}

    .search-box {{
        background: #3c3c3c;
        border: 1px solid #569cd6;
        color: #d4d4d4;
        padding: 5px 10px;
        border-radius: 3px;
        width: 200px;
    }}

    .hidden {{
        display: none !important;
    }}

    .highlight {{
        background-color: #515c6a !important;
        border-radius: 3px;
    }}
</style>
</head>
<body>
<h1>
    Intellicrack Directory Structure
    <span class="stats">{file_count} files, {folder_count} folders</span>
</h1>

<div class="controls">
    <label for="searchBox" style="color: #808080;">Filter:</label>
    <input type="text" class="search-box" id="searchBox" value="" title="Enter filename or partial text to search" onfocus="this.select()">
    <span class="spacer"></span>
    <button id="expandBtn" title="Materializes the full tree - may take a moment for very large trees">Expand All</button>
    <button id="collapseBtn">Collapse All</button>
    <button id="copyBtn">Copy Relative Path</button>
    <button id="refreshBtn">Refresh Tree</button>
</div>

<div class="path-display" id="pathDisplay">Ready - Single-click to preview, double-click to open</div>
<div class="action-buttons">
    <button id="btnCode">Open in Code</button>
    <button id="btnNotepad">Open in Notepad</button>
    <button id="btnTerminal">Terminal Here</button>
</div>

<div class="main-container">
    <div class="tree-pane tree" id="tree"></div>
    <div class="preview-pane">
        <pre id="previewContent">[Select a file to preview]</pre>
    </div>
</div>

<script type="text/javascript">
var ROOT_PATH = {root_path_json};
var NODES = {nodes_json};
var FILE_ICONS = {icons_json};
var SYNTAX_CLASSES = {syntax_json};

var fso = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");
var currentPath = "";
var selectedItem = null;
var spanById = {{}};

function getExt(name) {{
    var dot = name.lastIndexOf(".");
    if (dot < 0) return "";
    return name.substring(dot).toLowerCase();
}}

function iconFor(node) {{
    if (node.t === 'd') return '[DIR]';
    var ext = getExt(node.n);
    return FILE_ICONS[ext] || '[FILE]';
}}

function fmtSize(bytes) {{
    if (!bytes) return "0 B";
    var k = 1024;
    var sizes = ["B", "KB", "MB", "GB", "TB"];
    var i = 0;
    var v = bytes;
    while (v >= k && i < sizes.length - 1) {{ v /= k; i++; }}
    return v.toFixed(2) + " " + sizes[i];
}}

function classifyFolder(node) {{
    var hasChildren = node.c && node.c.length > 0;
    if (!hasChildren) return 'item folder leaf';
    return 'item folder collapsed';
}}

function createItem(id) {{
    var node = NODES[id];
    var li = document.createElement('li');
    li.setAttribute('data-id', '' + id);

    var span = document.createElement('span');
    span.setAttribute('data-path', node.p);
    span.setAttribute('data-id', '' + id);

    if (node.t === 'd') {{
        span.setAttribute('data-type', 'folder');
        span.className = classifyFolder(node);
        span.appendChild(document.createTextNode(iconFor(node) + ' ' + node.n));
    }} else {{
        span.setAttribute('data-type', 'file');
        var ext = getExt(node.n);
        var cls = 'item file' + (SYNTAX_CLASSES[ext] || '');
        span.className = cls;
        span.appendChild(document.createTextNode(iconFor(node) + ' ' + node.n));
        if (node.s) {{
            var sizeSpan = document.createElement('span');
            sizeSpan.className = 'size';
            sizeSpan.appendChild(document.createTextNode('(' + fmtSize(node.s) + ')'));
            span.appendChild(document.createTextNode(' '));
            span.appendChild(sizeSpan);
        }}
    }}

    span.onclick = handleItemClick;
    span.ondblclick = handleItemDoubleClick;
    li.appendChild(span);
    spanById[id] = span;
    return li;
}}

function findChildUl(span) {{
    var next = span.nextSibling;
    while (next && next.nodeType !== 1) next = next.nextSibling;
    if (next && next.tagName === 'UL') return next;
    return null;
}}

function materializeChildren(span) {{
    var existing = findChildUl(span);
    if (existing) return existing;
    var id = parseInt(span.getAttribute('data-id'), 10);
    var node = NODES[id];
    if (node.t !== 'd' || !node.c || node.c.length === 0) return null;
    var li = span.parentNode;
    var ul = document.createElement('ul');
    var frag = document.createDocumentFragment ? document.createDocumentFragment() : null;
    for (var i = 0; i < node.c.length; i++) {{
        var child = createItem(node.c[i]);
        if (frag) frag.appendChild(child); else ul.appendChild(child);
    }}
    if (frag) ul.appendChild(frag);
    li.appendChild(ul);
    return ul;
}}

function expandFolder(span) {{
    if (span.className.indexOf('leaf') !== -1) return;
    var ul = materializeChildren(span);
    if (ul) ul.style.display = 'block';
    span.className = span.className.replace('collapsed', 'expanded');
}}

function collapseFolder(span) {{
    if (span.className.indexOf('leaf') !== -1) return;
    var ul = findChildUl(span);
    if (ul) ul.style.display = 'none';
    span.className = span.className.replace('expanded', 'collapsed');
}}

function toggleFolder(span) {{
    if (span.className.indexOf('leaf') !== -1) return;
    if (span.className.indexOf('expanded') !== -1) {{
        collapseFolder(span);
    }} else {{
        expandFolder(span);
    }}
}}

function findItemAncestor(el) {{
    while (el && (!el.className || ('' + el.className).indexOf('item') === -1)) {{
        el = el.parentNode;
    }}
    return el;
}}

function handleItemClick(event) {{
    event = event || window.event;
    if (event.stopPropagation) {{ event.stopPropagation(); }} else {{ event.cancelBubble = true; }}

    var element = findItemAncestor(event.srcElement || event.target);
    if (!element) return;

    var path = element.getAttribute('data-path');
    var type = element.getAttribute('data-type');

    if (selectedItem) {{
        selectedItem.className = ('' + selectedItem.className).replace(' selected', '');
    }}
    element.className = element.className + ' selected';
    selectedItem = element;

    currentPath = path;
    document.getElementById('pathDisplay').innerHTML = '<strong>Selected:</strong> ' + path;

    if (type === 'folder') {{
        toggleFolder(element);
        document.getElementById('previewContent').innerText = "[Folder selected: " + path + "]";
    }} else if (type === 'file') {{
        try {{
            var file = fso.GetFile(path);
            if (file.Size > 0 && file.Size < 1000000) {{
                var stream = fso.OpenTextFile(path, 1);
                var content = stream.Read(Math.min(file.Size, 15000));
                stream.Close();
                if (file.Size > 15000) content += "\\n\\n... [Preview Truncated] ...";
                document.getElementById('previewContent').innerText = content;
            }} else {{
                document.getElementById('previewContent').innerText = "[File too large or empty for preview. Size: " + file.Size + " bytes]";
            }}
        }} catch(e) {{
            document.getElementById('previewContent').innerText = "[Preview not available for this file type or access denied]";
        }}
    }}
}}

function handleItemDoubleClick(event) {{
    event = event || window.event;
    if (event.stopPropagation) {{ event.stopPropagation(); }} else {{ event.cancelBubble = true; }}

    var element = findItemAncestor(event.srcElement || event.target);
    if (!element) return;

    var path = element.getAttribute('data-path');
    var type = element.getAttribute('data-type');

    if (type === 'file') {{
        openFile(path);
    }} else if (type === 'folder') {{
        openFolder(path);
    }}
}}

function openFile(path) {{
    try {{
        shell.Run('"' + path + '"', 1, false);
    }} catch(e) {{
        try {{
            shell.Run('explorer.exe /select,"' + path + '"', 1, false);
        }} catch(e2) {{
            alert('Cannot open file: ' + path + '\\n' + e.message);
        }}
    }}
}}

function openFolder(path) {{
    try {{
        shell.Run('explorer.exe "' + path + '"', 1, false);
    }} catch(e) {{
        alert('Cannot open folder: ' + path + '\\n' + e.message);
    }}
}}

function openInCode() {{
    if (currentPath) shell.Run('cmd /c code "' + currentPath + '"', 0, false);
}}

function openInNotepad() {{
    if (currentPath) shell.Run('notepad.exe "' + currentPath + '"', 1, false);
}}

function openTerminal() {{
    if (currentPath) {{
        var folder = fso.FileExists(currentPath) ? fso.GetParentFolderName(currentPath) : currentPath;
        shell.Run('pwsh -NoExit -Command "cd \\'' + folder + '\\'"', 1, false);
    }}
}}

function refreshTree() {{
    try {{
        shell.Run('pwsh -c "pixi run python scripts/generate_tree.py"', 0, true);
        window.location.reload();
    }} catch(e) {{
        alert("Failed to refresh: " + e.message);
    }}
}}

function expandAllFrom(id) {{
    var node = NODES[id];
    if (node.t !== 'd' || !node.c || node.c.length === 0) return;
    var span = spanById[id];
    if (!span) return;
    var ul = materializeChildren(span);
    if (ul) ul.style.display = 'block';
    span.className = span.className.replace('collapsed', 'expanded');
    for (var i = 0; i < node.c.length; i++) {{
        expandAllFrom(node.c[i]);
    }}
}}

function expandAll() {{
    expandAllFrom(0);
}}

function collapseAll() {{
    for (var key in spanById) {{
        if (!spanById.hasOwnProperty(key)) continue;
        if (key === '0') continue;
        var s = spanById[key];
        if (s.className && s.className.indexOf('folder') !== -1 && s.className.indexOf('leaf') === -1) {{
            if (s.className.indexOf('expanded') !== -1) {{
                s.className = s.className.replace('expanded', 'collapsed');
            }}
            var ul = findChildUl(s);
            if (ul) ul.style.display = 'none';
        }}
    }}
    var rootSpan = spanById[0];
    if (rootSpan) {{
        if (rootSpan.className.indexOf('collapsed') !== -1) {{
            rootSpan.className = rootSpan.className.replace('collapsed', 'expanded');
        }}
        var rootUl = findChildUl(rootSpan);
        if (rootUl) rootUl.style.display = 'block';
    }}
}}

function ensureAncestorsRendered(id) {{
    var chain = [];
    var cur = id;
    while (cur >= 0) {{
        chain.push(cur);
        cur = NODES[cur].pa;
    }}
    chain.reverse();
    for (var i = 0; i < chain.length - 1; i++) {{
        var ancestorSpan = spanById[chain[i]];
        if (ancestorSpan) {{
            var ul = materializeChildren(ancestorSpan);
            if (ul) ul.style.display = 'block';
            if (ancestorSpan.className.indexOf('collapsed') !== -1) {{
                ancestorSpan.className = ancestorSpan.className.replace('collapsed', 'expanded');
            }}
        }}
    }}
}}

function clearSearchState() {{
    for (var key in spanById) {{
        if (!spanById.hasOwnProperty(key)) continue;
        var s = spanById[key];
        if (s.className.indexOf('highlight') !== -1) {{
            s.className = ('' + s.className).replace(' highlight', '');
        }}
        var li = s.parentNode;
        if (li && li.style.display === 'none') {{
            li.style.display = '';
        }}
    }}
}}

function performSearch() {{
    var query = document.getElementById('searchBox').value;
    clearSearchState();
    if (!query) return;
    var q = query.toLowerCase();

    var onPath = {{}};
    for (var i = 0; i < NODES.length; i++) {{
        if (NODES[i].n.toLowerCase().indexOf(q) === -1) continue;
        onPath[i] = 'match';
        var anc = NODES[i].pa;
        while (anc >= 0 && onPath[anc] !== 'ancestor' && onPath[anc] !== 'match') {{
            onPath[anc] = 'ancestor';
            anc = NODES[anc].pa;
        }}
    }}

    for (var k in onPath) {{
        if (!onPath.hasOwnProperty(k)) continue;
        ensureAncestorsRendered(parseInt(k, 10));
    }}

    for (var key in spanById) {{
        if (!spanById.hasOwnProperty(key)) continue;
        var s = spanById[key];
        var li = s.parentNode;
        if (onPath[key]) {{
            li.style.display = 'list-item';
            if (onPath[key] === 'match' && s.className.indexOf('highlight') === -1) {{
                s.className = s.className + ' highlight';
            }}
        }} else {{
            li.style.display = 'none';
        }}
    }}
}}

function copyPath() {{
    if (currentPath) {{
        try {{
            var relPath = currentPath;
            if (currentPath.toLowerCase().indexOf(ROOT_PATH.toLowerCase()) === 0) {{
                relPath = currentPath.substring(ROOT_PATH.length);
                if (relPath.charAt(0) === '\\\\' || relPath.charAt(0) === '/') {{
                    relPath = relPath.substring(1);
                }}
            }}
            window.clipboardData.setData('Text', relPath);
            document.getElementById('pathDisplay').innerHTML = '<strong>Copied Relative Path:</strong> ' + relPath;
        }} catch(e) {{
            alert('Cannot copy: ' + e.message);
        }}
    }} else {{
        document.getElementById('pathDisplay').innerHTML = 'Select an item first before copying its path';
    }}
}}

function renderRoot() {{
    var rootUl = document.createElement('ul');
    rootUl.className = 'root-list';
    var rootLi = createItem(0);
    rootUl.appendChild(rootLi);
    var rootSpan = spanById[0];
    if (rootSpan && rootSpan.className.indexOf('leaf') === -1) {{
        var ul = materializeChildren(rootSpan);
        if (ul) ul.style.display = 'block';
        rootSpan.className = rootSpan.className.replace('collapsed', 'expanded');
    }}
    var treeEl = document.getElementById('tree');
    treeEl.innerHTML = '';
    treeEl.appendChild(rootUl);
}}

window.onload = function() {{
    renderRoot();
    document.getElementById('expandBtn').onclick = expandAll;
    document.getElementById('collapseBtn').onclick = collapseAll;
    document.getElementById('copyBtn').onclick = copyPath;
    document.getElementById('searchBox').onkeyup = performSearch;
    document.getElementById('refreshBtn').onclick = refreshTree;
    document.getElementById('btnCode').onclick = openInCode;
    document.getElementById('btnNotepad').onclick = openInNotepad;
    document.getElementById('btnTerminal').onclick = openTerminal;
}};
</script>
</body>
</html>"""

    if not hta_content.endswith("\n"):
        hta_content += "\n"
    Path(output_file).write_text(hta_content, encoding="utf-8")

    print(f"HTA file generated successfully: {output_file}")
    print(f"Root path: {root_path}")
    print(f"Processed: {file_count} files, {folder_count} folders")
    print(f"Node table size: {len(nodes_json):,} bytes")
    print("\nDouble-click the HTA file to open")


if __name__ == "__main__":
    root_path = r"D:\Intellicrack"
    hta_output_file = r"D:\Intellicrack\IntellicrackStructure.hta"
    txt_output_file = r"D:\Intellicrack\IntellicrackStructure.txt"

    generate_hta(root_path, hta_output_file)
    generate_txt_tree(root_path, txt_output_file)

    print("\nBoth directory structure files generated successfully!")
