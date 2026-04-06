#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Intellicrack Directory Tree Generator - Fixed Version.

Generates an HTA application with clickable file links using data attributes to avoid escaping issues.
"""

import datetime
import hashlib
import os
import subprocess
from pathlib import Path


def _esc_attr(value: str) -> str:
    """Escape a string for safe use in an HTML attribute value.

    Args:
        value: Raw string to escape.

    Returns:
        HTML-escaped string with quotes escaped.
    """
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")


def _esc_text(value: str) -> str:
    """Escape a string for safe use in HTML text content.

    Args:
        value: Raw string to escape.

    Returns:
        HTML-escaped string.
    """
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def get_file_icon(file_path: str) -> str:
    """Return appropriate icon based on file extension.

    Args:
        file_path: Full or relative path to a file.

    Returns:
        A string icon representation matching the file type.

    """
    ext = Path(file_path).suffix.lower()
    icons = {
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
    return icons.get(ext, "[FILE]")


def scan_directory(root_path: str) -> tuple[str, int, int]:
    """Recursively scan directory and build HTML directly.

    Args:
        root_path: Root directory path to scan.

    Returns:
        A tuple containing the HTML tree structure, file count, and folder count.

    """
    file_count = 0
    folder_count = 0

    def build_html(path: str, level: int = 0) -> str:
        nonlocal file_count, folder_count

        # Generate unique ID for this item
        item_id = hashlib.sha256(path.encode()).hexdigest()[:8]

        html = ""
        name = Path(path).name or path

        if Path(path).is_dir():
            folder_count += 1
            icon = "[DIR]"
            safe_path = _esc_attr(path)
            safe_name = _esc_text(name)
            html += "<li>"
            html += f'<span class="item folder expanded" data-path="{safe_path}" data-id="{item_id}" data-type="folder">'
            html += f"{icon} {safe_name}"
            html += "</span>"

            try:
                items = []
                for entry in Path(path).iterdir():
                    if entry.name in {
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
                    }:
                        continue
                    items.append(str(entry))

                # Sort: directories first, then files
                items.sort(key=lambda x: (not Path(x).is_dir(), x.lower()))

                if items:
                    html += "<ul>"
                    for item_path in items:
                        html += build_html(item_path, level + 1)
                    html += "</ul>"
            except PermissionError:
                pass

            html += "</li>"
        else:
            file_count += 1
            icon = get_file_icon(path)
            ext = Path(path).suffix.lower()
            file_class = "file"

            # Add specific classes for syntax highlighting
            if ext == ".py":
                file_class += " python"
            elif ext in {".js", ".jsx"}:
                file_class += " javascript"
            elif ext == ".json":
                file_class += " json"

            try:
                size = Path(path).stat().st_size
                size_str = format_size(size)
            except (OSError, ValueError, TypeError):
                size_str = ""

            safe_path = _esc_attr(path)
            safe_name = _esc_text(name)
            html += "<li>"
            html += f'<span class="item {file_class}" data-path="{safe_path}" data-id="{item_id}" data-type="file">'
            html += f"{icon} {safe_name}"
            if size_str:
                html += f' <span class="size">({size_str})</span>'
            html += "</span>"
            html += "</li>"

        return html

    html_tree = '<ul class="root-list">' + build_html(root_path) + "</ul>"
    return html_tree, file_count, folder_count


def format_size(file_bytes: int) -> str:
    """Format file size in human-readable format.

    Args:
        file_bytes: Number of bytes to format.

    Returns:
        Human-readable string representation of file size (e.g., "1.23 MB").

    """
    if file_bytes == 0:
        return "0 B"
    k = 1024
    sizes = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while file_bytes >= k and i < len(sizes) - 1:
        file_bytes /= k
        i += 1
    return f"{file_bytes:.2f} {sizes[i]}"


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

    try:
        if os.name == "nt":
            tree_output = generate_fallback_tree(root_path)
        else:
            result = subprocess.run(["tree", "-F"], capture_output=True, text=True, shell=False, cwd=root_path, check=False)
            tree_output = result.stdout if result.returncode == 0 else ""

            if not tree_output:
                tree_output = generate_fallback_tree(root_path)

    except (OSError, subprocess.SubprocessError) as e:
        print(f"Warning: Could not generate tree with system command: {e}")
        tree_output = generate_fallback_tree(root_path)

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
        String representation of the directory tree structure.

    """
    tree_str = ""

    try:
        items = []
        for entry in Path(root_path).iterdir():
            if entry.name in {
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
            }:
                continue
            items.append((entry.name, str(entry)))

        items.sort(key=lambda x: (not Path(x[1]).is_dir(), x[0].lower()))

        for i, (name, path) in enumerate(items):
            is_last_item = i == len(items) - 1
            connector = "└── " if is_last_item else "├── "
            tree_str += f"{prefix}{connector}{name}"

            if Path(path).is_dir():
                tree_str += "/\n"
                extension = "    " if is_last_item else "│   "
                tree_str += generate_fallback_tree(path, prefix + extension, _is_last=is_last_item)
            else:
                tree_str += "\n"
    except PermissionError:
        pass

    return tree_str


def generate_hta(root_path: str, output_file: str) -> None:
    """Generate HTA file with clickable directory tree.

    Args:
        root_path: Root directory path to generate HTA for.
        output_file: Output file path for the HTA application.
    """
    print(f"Scanning directory: {root_path}")
    html_tree, file_count, folder_count = scan_directory(root_path)

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
        content: '▶ ';
        color: #808080;
        display: inline-block;
        width: 15px;
    }}

    .folder.expanded:before {{
        content: '▼ ';
        color: #808080;
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
        position: fixed;
        top: 20px;
        right: 20px;
        background: #2a2a2a;
        padding: 10px;
        border-radius: 5px;
        display: flex;
        gap: 10px;
        z-index: 1000;
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
<div class="controls">
    <label for="searchBox" style="color: #808080; margin-right: 5px;">Filter:</label>
    <input type="text" class="search-box" id="searchBox" value="" title="Enter filename or partial text to search" onfocus="this.select()">
    <button id="expandBtn">Expand All</button>
    <button id="collapseBtn">Collapse All</button>
    <button id="copyBtn">Copy Relative Path</button>
    <button id="refreshBtn">Refresh Tree</button>
</div>

<h1>
    Intellicrack Directory Structure
    <span class="stats">{file_count} files, {folder_count} folders</span>
</h1>

<div class="path-display" id="pathDisplay">Ready - Single-click to preview, double-click to open</div>
<div class="action-buttons">
    <button id="btnCode">Open in Code</button>
    <button id="btnNotepad">Open in Notepad</button>
    <button id="btnTerminal">Terminal Here</button>
</div>

<div class="main-container">
    <div class="tree-pane tree" id="tree">
    {html_tree}
    </div>
    <div class="preview-pane">
        <pre id="previewContent">[Select a file to preview]</pre>
    </div>
</div>

<script type="text/javascript">
var rootPath = "{root_path}";
var fso = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");
var currentPath = "";
var selectedItem = null;

// Initialize event handlers when window loads
window.onload = function() {{
    // Add click handlers to all items using onclick
    var allElements = document.getElementsByTagName('span');
    for (var i = 0; i < allElements.length; i++) {{
        if (allElements[i].className && allElements[i].className.indexOf('item') !== -1) {{
            allElements[i].onclick = handleItemClick;
            allElements[i].ondblclick = handleItemDoubleClick;
        }}
    }}

    // Button handlers using onclick
    document.getElementById('expandBtn').onclick = expandAll;
    document.getElementById('collapseBtn').onclick = collapseAll;
    document.getElementById('copyBtn').onclick = copyPath;
    document.getElementById('searchBox').onkeyup = performSearch;
    document.getElementById('refreshBtn').onclick = refreshTree;

    document.getElementById('btnCode').onclick = openInCode;
    document.getElementById('btnNotepad').onclick = openInNotepad;
    document.getElementById('btnTerminal').onclick = openTerminal;
}};

function handleItemClick(event) {{
    event = event || window.event;
    if (event.stopPropagation) {{
        event.stopPropagation();
    }} else {{
        event.cancelBubble = true;
    }}

    var element = event.srcElement || event.target;
    var path = element.getAttribute('data-path');
    var type = element.getAttribute('data-type');

    // Update selection
    if (selectedItem) {{
        selectedItem.className = selectedItem.className.replace(' selected', '');
    }}
    element.className += ' selected';
    selectedItem = element;

    currentPath = path;
    document.getElementById('pathDisplay').innerHTML = '<strong>Selected:</strong> ' + path;

    // Toggle folder if it's a folder
    if (type === 'folder') {{
        toggleFolder(element);
        document.getElementById('previewContent').innerText = "[Folder selected: " + path + "]";
    }} else if (type === 'file') {{
        try {{
            var file = fso.GetFile(path);
            if (file.Size > 0 && file.Size < 1000000) {{ // Limit preview to files under 1MB
                var stream = fso.OpenTextFile(path, 1);
                var content = stream.Read(Math.min(file.Size, 15000)); // Read up to 15KB
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

function openInCode() {{
    if(currentPath) shell.Run('cmd /c code "' + currentPath + '"', 0, false);
}}

function openInNotepad() {{
    if(currentPath) shell.Run('notepad.exe "' + currentPath + '"', 1, false);
}}

function openTerminal() {{
    if(currentPath) {{
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

function handleItemDoubleClick(event) {{
    event = event || window.event;
    if (event.stopPropagation) {{
        event.stopPropagation();
    }} else {{
        event.cancelBubble = true;
    }}

    var element = event.srcElement || event.target;
    var path = element.getAttribute('data-path');
    var type = element.getAttribute('data-type');

    if (type === 'file') {{
        openFile(path);
    }} else if (type === 'folder') {{
        openFolder(path);
    }}
}}

function toggleFolder(element) {{
    if (element.className.indexOf('expanded') !== -1) {{
        element.className = element.className.replace('expanded', 'collapsed');
        // Find the next UL sibling
        var next = element.nextSibling;
        while (next && next.nodeType !== 1) {{
            next = next.nextSibling;
        }}
        if (next && next.tagName === 'UL') {{
            next.style.display = 'none';
        }}
    }} else {{
        element.className = element.className.replace('collapsed', 'expanded');
        // Find the next UL sibling
        var next = element.nextSibling;
        while (next && next.nodeType !== 1) {{
            next = next.nextSibling;
        }}
        if (next && next.tagName === 'UL') {{
            next.style.display = 'block';
        }}
    }}
}}

function openFile(path) {{
    try {{
        // Try to open with default application
        shell.Run('"' + path + '"', 1, false);
    }} catch(e) {{
        // If that fails, open containing folder and select file
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

function expandAll() {{
    var allElements = document.getElementsByTagName('span');
    for (var i = 0; i < allElements.length; i++) {{
        if (allElements[i].className && allElements[i].className.indexOf('folder') !== -1) {{
            if (allElements[i].className.indexOf('collapsed') !== -1) {{
                allElements[i].className = allElements[i].className.replace('collapsed', 'expanded');
            }}
        }}
    }}
    // Now show all UL elements
    var uls = document.getElementsByTagName('ul');
    for (var i = 0; i < uls.length; i++) {{
        uls[i].style.display = 'block';
    }}
}}

function collapseAll() {{
    var allElements = document.getElementsByTagName('span');
    for (var i = 0; i < allElements.length; i++) {{
        if (allElements[i].className && allElements[i].className.indexOf('folder') !== -1) {{
            if (allElements[i].className.indexOf('expanded') !== -1) {{
                allElements[i].className = allElements[i].className.replace('expanded', 'collapsed');
            }}
        }}
    }}
    // Now hide all UL elements except root
    var uls = document.getElementsByTagName('ul');
    for (var i = 0; i < uls.length; i++) {{
        if (uls[i].className !== 'root-list') {{
            uls[i].style.display = 'none';
        }}
    }}
}}

function copyPath() {{
    if (currentPath) {{
        try {{
            var relPath = currentPath;
            if (currentPath.toLowerCase().indexOf(rootPath.toLowerCase()) === 0) {{
                relPath = currentPath.substring(rootPath.length);
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

function performSearch() {{
    var query = document.getElementById('searchBox').value.toLowerCase();
    var allElements = document.getElementsByTagName('span');
    var items = [];

    // Collect all items
    for (var i = 0; i < allElements.length; i++) {{
        if (allElements[i].className && allElements[i].className.indexOf('item') !== -1) {{
            items.push(allElements[i]);
        }}
    }}

    if (!query) {{
        // Show all items
        for (var i = 0; i < items.length; i++) {{
            items[i].className = items[i].className.replace(' highlight', '');
            items[i].parentElement.style.display = 'list-item';
        }}
        return;
    }}

    // Search and highlight
    for (var i = 0; i < items.length; i++) {{
        var item = items[i];
        var text = item.textContent || item.innerText || '';
        text = text.toLowerCase();

        if (text.indexOf(query) !== -1) {{
            if (item.className.indexOf('highlight') === -1) {{
                item.className += ' highlight';
            }}
            item.parentElement.style.display = 'list-item';

            // Show parent folders
            var parent = item.parentElement;
            while (parent && parent !== document.getElementById('tree')) {{
                parent.style.display = 'block';
                // Find previous sibling that's a folder
                var prev = parent.previousSibling;
                while (prev && prev.nodeType !== 1) {{
                    prev = prev.previousSibling;
                }}
                if (prev && prev.className && prev.className.indexOf('folder') !== -1) {{
                    prev.className = prev.className.replace('collapsed', 'expanded');
                }}
                parent = parent.parentElement;
            }}
        }} else {{
            item.className = item.className.replace(' highlight', '');
            // Don't hide folders that contain matches
            if (item.className.indexOf('folder') === -1 || !hasHighlightedChildren(item)) {{
                item.parentElement.style.display = 'none';
            }}
        }}
    }}
}}

function hasHighlightedChildren(element) {{
    // Find the next UL sibling
    var next = element.nextSibling;
    while (next && next.nodeType !== 1) {{
        next = next.nextSibling;
    }}
    if (next && next.tagName === 'UL') {{
        var children = next.getElementsByTagName('*');
        for (var i = 0; i < children.length; i++) {{
            if (children[i].className && children[i].className.indexOf('highlight') !== -1) {{
                return true;
            }}
        }}
    }}
    return false;
}}
</script>
</body>
</html>"""

    if not hta_content.endswith("\n"):
        hta_content += "\n"
    Path(output_file).write_text(hta_content, encoding="utf-8")

    print(f"HTA file generated successfully: {output_file}")
    print(f"Root path: {root_path}")
    print(f"Processed: {file_count} files, {folder_count} folders")
    print("\nDouble-click the HTA file to open")


if __name__ == "__main__":
    root_path = r"D:\Intellicrack"
    hta_output_file = r"D:\Intellicrack\IntellicrackStructure.hta"
    txt_output_file = r"D:\Intellicrack\IntellicrackStructure.txt"

    generate_hta(root_path, hta_output_file)
    generate_txt_tree(root_path, txt_output_file)

    print("\nBoth directory structure files generated successfully!")
