"""Sphinx configuration for Intellicrack documentation."""
from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from sphinx.application import Sphinx


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "src"))

project = "Intellicrack"
copyright = f"{datetime.now().year}, Zachary Flint"  # noqa: A001
author = "Zachary Flint"
release = "0.1.0a1"
version = "0.1"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "sphinx.ext.napoleon",
    "sphinx.ext.todo",
    "sphinx.ext.coverage",
    "sphinx.ext.githubpages",
    "myst_parser",
    "sphinx_copybutton",
    "sphinx_tabs.tabs",
    "sphinxcontrib.mermaid",
]

autodoc_mock_imports = [
    "PyQt5",
    "PySide6",
    "webview",
    "intellicrack_hexcore",
    "mcp",
    "frida",
    "pefile",
    "lief",
    "capstone",
    "keystone",
    "unicorn",
    "angr",
    "cle",
    "archinfo",
    "claripy",
    "win32api",
    "win32con",
    "win32gui",
    "win32process",
    "win32security",
    "pywintypes",
    "wmi",
    "torch",
    "transformers",
    "accelerate",
    "bitsandbytes",
    "llama_cpp",
    "openai",
    "anthropic",
    "google",
    "huggingface_hub",
    "ghidra_bridge",
    "r2pipe",
    "inotify",
    "inotify_simple",
    "httpx",
    "aiohttp",
    "Crypto",
    "Cryptodome",
    "cryptography",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}
master_doc = "index"
language = "en"
pygments_style = "sphinx"

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
html_theme_options = {
    "navigation_depth": 4,
    "collapse_navigation": False,
    "sticky_navigation": True,
    "includehidden": True,
    "titles_only": False,
    "prev_next_buttons_location": "both",
}

html_context = {
    "display_github": True,
    "github_user": "ZachFlint",
    "github_repo": "Intellicrack",
    "github_version": "main",
    "conf_py_path": "/docs/source/",
}

autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": True,
    "exclude-members": "__weakref__",
    "show-inheritance": True,
    "inherited-members": False,
}

autodoc_typehints = "description"
autodoc_typehints_format = "short"
autodoc_class_signature = "separated"
autodoc_inherit_docstrings = False

suppress_warnings = [
    "autodoc",
    "ref.python",
    "app.add_directive",
    "toc.not_included",
    "autosummary",
]

nitpicky = False
nitpick_ignore = [
    ("py:class", "PyQt6.QtGui.QPaintDevice.PaintDeviceMetric"),
    ("py:class", "PyQt6.QtWidgets.QWidget.RenderFlag"),
    ("py:class", "PyQt6.QtWidgets.QFrame.Shadow"),
    ("py:class", "PyQt6.QtWidgets.QFrame.Shape"),
    ("py:class", "PyQt6.QtWidgets.QFrame.StyleMask"),
]

nitpick_ignore_regex = [
    (r"py:.*", r"PyQt6\..*"),
    (r"py:.*", r"http\.server\..*"),
]

autosummary_generate = True
autosummary_imported_members = False

napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = True
napoleon_use_ivar = True
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_use_keyword = True
napoleon_attr_annotations = True

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "numpy": ("https://numpy.org/doc/stable/", None),
    "pydantic": ("https://docs.pydantic.dev/latest/", None),
}

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "dollarmath",
    "fieldlist",
    "html_admonition",
    "html_image",
    "replacements",
    "smartquotes",
    "substitution",
    "tasklist",
]

todo_include_todos = True
add_module_names = False
python_use_unqualified_type_names = True


def _skip_qt_signals(
    app: Sphinx,
    what: str,
    name: str,
    obj: object,
    skip: bool,
    options: Any,
) -> bool:
    """Skip PyQt/PySide signal members during autodoc member collection.

    The auto-generated ``__doc__`` of a bound or unbound Qt signal contains
    unbalanced reStructuredText inline markup (for example ``*args``), which
    docutils reports as ``Inline emphasis start-string without end-string``.
    Signals carry no meaningful API documentation, so they are omitted.

    Args:
        app: The Sphinx application object.
        what: The type of object the parent docstring belongs to.
        name: The fully qualified name of the member being considered.
        obj: The member object itself.
        skip: Whether autodoc would skip the member by default.
        options: The options given to the parent autodoc directive.

    Returns:
        bool: ``True`` to omit the member; otherwise autodoc's default
        ``skip`` decision.
    """
    if type(obj).__name__ in {"pyqtSignal", "pyqtBoundSignal", "Signal", "SignalInstance"}:
        return True
    return skip


def setup(app: Sphinx) -> dict[str, bool]:
    """Register documentation build hooks for the Intellicrack docs.

    Args:
        app: The Sphinx application object.

    Returns:
        dict[str, bool]: Extension metadata declaring parallel read and write
        safety for the connected hooks.
    """
    app.connect("autodoc-skip-member", _skip_qt_signals)
    return {"parallel_read_safe": True, "parallel_write_safe": True}
