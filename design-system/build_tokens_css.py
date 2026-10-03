# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Build ``tokens.css`` and an offline preview gallery for this design system.

The claude.ai Design System page generates ``tokens.css`` from ``tokens.json``
when the page is viewed, so a local copy of the system has none. This script
writes the same stylesheet next to ``tokens.json``: colour and shadow tokens
per theme, every other token family on ``:root``, a ``--font-<key>`` property
per font stack, a class per type style and an ``@font-face`` per bundled font.

It also writes ``gallery.html``, which loads that stylesheet together with
``components/bundle.css`` and renders every component preview under a theme
switcher. Upload references (``/_blob/<id>``) inside the previews are rewritten
to the matching file under ``assets/`` using the asset records in
``design-system.json``.

Usage::

    python build_tokens_css.py [--root DIR]
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast


_ROOT: Final[Path] = Path(__file__).resolve().parent
_NON_FAMILY_KEYS: Final[frozenset[str]] = frozenset({"name", "version", "meta", "color", "type"})
_THEMED_FAMILIES: Final[frozenset[str]] = frozenset({"shadow"})
_ALIAS: Final[re.Pattern[str]] = re.compile(r"^\{([A-Za-z0-9][A-Za-z0-9_.-]{0,63})\}$")
_BLOB: Final[re.Pattern[str]] = re.compile(r"/_blob/([0-9a-f]{32})")
_MARKER: Final[re.Pattern[str]] = re.compile(r"^<!--\s*@dsCard\b(?P<attrs>[^>]*?)-->\s*$")
_GROUP_ATTR: Final[re.Pattern[str]] = re.compile(r'\bgroup="([^"]*)"')
_HEIGHT_ATTR: Final[re.Pattern[str]] = re.compile(r"\bheight=(\d+)")
_STYLE_PROPERTIES: Final[tuple[tuple[str, str], ...]] = (
    ("fontSize", "font-size"),
    ("lineHeight", "line-height"),
    ("fontWeight", "font-weight"),
    ("letterSpacing", "letter-spacing"),
    ("fontStyle", "font-style"),
)
_FONT_FORMATS: Final[dict[str, str]] = {".woff2": "woff2", ".woff": "woff", ".ttf": "truetype", ".otf": "opentype"}
_COVER: Final[str] = "Cover"
_DEFAULT_CARD_HEIGHT: Final[int] = 120


class DesignSystemError(Exception):
    """Raised when a design-system file is missing or malformed."""


@dataclass(frozen=True, slots=True)
class Preview:
    """One component preview read from ``components/<name>/preview.html``.

    Attributes:
        name: Component folder name.
        group: Gallery group from the ``@dsCard`` marker, empty when absent.
        height: Card height in pixels from the marker.
        body: Preview markup with the marker line removed.
    """

    name: str
    group: str
    height: int
    body: str


def _as_dict(value: object, where: str) -> dict[str, object]:
    """Narrow a parsed JSON value to an object.

    Args:
        value: Parsed JSON value.
        where: Location used in the error message.

    Returns:
        dict[str, object]: The value as a string-keyed mapping.

    Raises:
        DesignSystemError: If the value is not a JSON object.
    """
    if not isinstance(value, dict):
        msg = f"{where}: expected a JSON object"
        raise DesignSystemError(msg)
    return cast("dict[str, object]", value)


def _as_list(value: object, where: str) -> list[object]:
    """Narrow a parsed JSON value to an array.

    Args:
        value: Parsed JSON value.
        where: Location used in the error message.

    Returns:
        list[object]: The value as a list.

    Raises:
        DesignSystemError: If the value is not a JSON array.
    """
    if not isinstance(value, list):
        msg = f"{where}: expected a JSON array"
        raise DesignSystemError(msg)
    return cast("list[object]", value)


def _as_str(value: object, where: str) -> str:
    """Narrow a parsed JSON value to a string.

    Args:
        value: Parsed JSON value.
        where: Location used in the error message.

    Returns:
        str: The value.

    Raises:
        DesignSystemError: If the value is not a string.
    """
    if not isinstance(value, str):
        msg = f"{where}: expected a string"
        raise DesignSystemError(msg)
    return value


def _scalar(value: object, where: str) -> str:
    """Render a token value that is a string or a number as CSS text.

    Args:
        value: Parsed JSON value.
        where: Location used in the error message.

    Returns:
        str: The CSS text for the value.

    Raises:
        DesignSystemError: If the value is neither a string nor a number.
    """
    if isinstance(value, bool):
        msg = f"{where}: booleans are not token values"
        raise DesignSystemError(msg)
    if isinstance(value, int | float):
        return f"{value}"
    return _as_str(value, where)


def _colour(value: str) -> str:
    """Render a colour value, turning an ``{alias}`` into a ``var()`` reference.

    Args:
        value: Colour literal or alias.

    Returns:
        str: CSS colour text.
    """
    alias = _ALIAS.match(value)
    return f"var(--{alias.group(1)})" if alias else value


def _load_json(path: Path) -> object:
    """Read and parse a JSON file.

    Args:
        path: File to read.

    Returns:
        object: The parsed document.

    Raises:
        DesignSystemError: If the file is missing or is not valid JSON.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        msg = f"{path.name} not found in {path.parent}"
        raise DesignSystemError(msg) from exc
    except json.JSONDecodeError as exc:
        msg = f"{path.name}: invalid JSON ({exc.msg} at line {exc.lineno})"
        raise DesignSystemError(msg) from exc


def _theme_ids(color: dict[str, object]) -> list[str]:
    """Read the theme ids in declaration order.

    Args:
        color: The ``color`` family.

    Returns:
        list[str]: Theme ids; the first is the primary theme.

    Raises:
        DesignSystemError: If no theme is declared.
    """
    themes = [
        _as_str(_as_dict(theme, "color.themes[]").get("id"), "color.themes[].id") for theme in _as_list(color.get("themes"), "color.themes")
    ]
    if not themes:
        msg = "color.themes: at least one theme is required"
        raise DesignSystemError(msg)
    return themes


def _collect_themed(
    tokens: list[object],
    family: str,
    themes: list[str],
    blocks: dict[str, list[str]],
) -> None:
    """Add per-theme declarations for a colour-like family.

    A plain string value belongs to the first theme. A per-theme mapping emits
    each theme it names; a theme it omits inherits the first theme's value
    through the ``:root`` cascade, as the page does.

    Args:
        tokens: The family's token list.
        family: Family name, for error messages.
        themes: Theme ids, primary first.
        blocks: Declarations per theme id, extended in place.

    Raises:
        DesignSystemError: If a token names a theme that is not declared.
    """
    for index, raw in enumerate(tokens):
        where = f"{family}.tokens[{index}]"
        token = _as_dict(raw, where)
        name = _as_str(token.get("name"), f"{where}.name")
        value = token.get("value")
        if isinstance(value, str):
            blocks[themes[0]].append(f"  --{name}: {_colour(value)};")
            continue
        for theme_id, theme_value in _as_dict(value, f"{where}.value").items():
            if theme_id not in blocks:
                msg = f"{where}: unknown theme '{theme_id}'"
                raise DesignSystemError(msg)
            blocks[theme_id].append(f"  --{name}: {_colour(_as_str(theme_value, f'{where}.value.{theme_id}'))};")


def _type_rules(type_family: dict[str, object]) -> tuple[list[str], list[str], list[str]]:
    """Build the font-stack properties, type-style classes and font faces.

    Args:
        type_family: The ``type`` section of tokens.json.

    Returns:
        tuple[list[str], list[str], list[str]]: ``:root`` declarations for the
        font stacks, one class rule per type style, and one ``@font-face`` per
        bundled font.
    """
    families = _as_dict(type_family.get("families", {}), "type.families")
    stacks = [f"  --font-{key}: {_as_str(stack, f'type.families.{key}')};" for key, stack in families.items()]

    styles: list[str] = []
    for g_index, raw_group in enumerate(_as_list(type_family.get("groups", []), "type.groups")):
        group = _as_dict(raw_group, f"type.groups[{g_index}]")
        group_family = group.get("family")
        for s_index, raw_style in enumerate(_as_list(group.get("styles", []), f"type.groups[{g_index}].styles")):
            where = f"type.groups[{g_index}].styles[{s_index}]"
            style = _as_dict(raw_style, where)
            family_key = style.get("family", group_family)
            declarations = [f"font-family: var(--font-{_as_str(family_key, f'{where}.family')})"] if family_key else []
            declarations.extend(f"{css}: {_scalar(style[key], f'{where}.{key}')}" for key, css in _STYLE_PROPERTIES if key in style)
            styles.append(f".{_as_str(style.get('name'), f'{where}.name')} {{ {'; '.join(declarations)}; }}")

    faces: list[str] = []
    for f_index, raw_font in enumerate(_as_list(type_family.get("fonts", []), "type.fonts")):
        where = f"type.fonts[{f_index}]"
        font = _as_dict(raw_font, where)
        file = _as_str(font.get("file"), f"{where}.file")
        path = file if "/" in file else f"fonts/{file}"
        fmt = _FONT_FORMATS.get(Path(path).suffix.lower())
        source = f'url("{path}") format("{fmt}")' if fmt else f'url("{path}")'
        faces.append(
            "@font-face { "
            f'font-family: "{_as_str(font.get("family"), f"{where}.family")}"; '
            f"src: {source}; "
            f"font-weight: {_scalar(font.get('weight', '400'), f'{where}.weight')}; "
            f"font-style: {_scalar(font.get('style', 'normal'), f'{where}.style')}; "
            "font-display: swap; }",
        )
    return stacks, styles, faces


def build_tokens_css(tokens: dict[str, object]) -> str:
    """Compile tokens.json into the stylesheet the design-system page serves.

    Args:
        tokens: Parsed tokens.json.

    Returns:
        str: The ``tokens.css`` text.
    """
    color = _as_dict(tokens.get("color"), "color")
    themes = _theme_ids(color)
    blocks: dict[str, list[str]] = {theme: [] for theme in themes}
    _collect_themed(_as_list(color.get("tokens", []), "color.tokens"), "color", themes, blocks)

    root: list[str] = []
    for family, section in tokens.items():
        if family in _NON_FAMILY_KEYS:
            continue
        family_tokens = _as_list(_as_dict(section, family).get("tokens", []), f"{family}.tokens")
        if family in _THEMED_FAMILIES:
            _collect_themed(family_tokens, family, themes, blocks)
            continue
        for index, raw in enumerate(family_tokens):
            where = f"{family}.tokens[{index}]"
            token = _as_dict(raw, where)
            root.append(f"  --{_as_str(token.get('name'), f'{where}.name')}: {_scalar(token.get('value'), f'{where}.value')};")

    stacks, styles, faces = _type_rules(_as_dict(tokens.get("type", {}), "type"))
    root.extend(stacks)

    parts = [f':root, [data-theme="{themes[0]}"] {{\n' + "\n".join(blocks[themes[0]]) + "\n}"]
    parts.extend(f'[data-theme="{theme}"] {{\n' + "\n".join(blocks[theme]) + "\n}" for theme in themes[1:] if blocks[theme])
    parts.append(":root {\n" + "\n".join(root) + "\n}")
    parts.extend(styles)
    parts.extend(faces)
    return "\n\n".join(parts) + "\n"


def asset_paths(index: dict[str, object]) -> dict[str, str]:
    """Map upload ids to their files under ``assets/``.

    Args:
        index: Parsed design-system.json.

    Returns:
        dict[str, str]: Blob id to the relative path ``assets/<Group>/<name>``.
    """
    paths: dict[str, str] = {}
    for group_key, raw_group in _as_dict(index.get("assetGroups", {}), "assetGroups").items():
        group = _as_dict(raw_group, f"assetGroups.{group_key}")
        group_name = _as_str(group.get("name", group_key), f"assetGroups.{group_key}.name")
        for file_key, raw_file in _as_dict(group.get("files", {}), f"assetGroups.{group_key}.files").items():
            record = _as_dict(raw_file, f"assetGroups.{group_key}.files.{file_key}")
            blob = _as_str(record.get("blob"), f"assetGroups.{group_key}.files.{file_key}.blob")
            paths[blob] = f"assets/{group_name}/{_as_str(record.get('name', file_key), 'name')}"
    return paths


def read_previews(components: Path) -> list[Preview]:
    """Read every component preview, cover first, then by group and name.

    Args:
        components: The ``components`` directory.

    Returns:
        list[Preview]: The previews in gallery order.
    """
    previews: list[Preview] = []
    for path in sorted(components.glob("*/preview.html")):
        first, _, rest = path.read_text(encoding="utf-8").partition("\n")
        marker = _MARKER.match(first)
        attrs = marker.group("attrs") if marker else ""
        group = _GROUP_ATTR.search(attrs)
        height = _HEIGHT_ATTR.search(attrs)
        previews.append(
            Preview(
                name=path.parent.name,
                group=group.group(1) if group else "",
                height=int(height.group(1)) if height else _DEFAULT_CARD_HEIGHT,
                body=rest if marker else f"{first}\n{rest}",
            ),
        )
    return sorted(previews, key=lambda p: (p.name != _COVER, p.group.lower(), p.name.lower()))


def localise_uploads(markup: str, paths: dict[str, str], missing: set[str]) -> str:
    """Rewrite ``/_blob/<id>`` references to files under ``assets/``.

    Args:
        markup: Preview markup.
        paths: Blob id to relative asset path.
        missing: Collects ids with no asset record; extended in place.

    Returns:
        str: The markup with every known upload pointed at its local file.
    """

    def replace(match: re.Match[str]) -> str:
        blob = match.group(1)
        if blob in paths:
            return paths[blob]
        missing.add(blob)
        return match.group(0)

    return _BLOB.sub(replace, markup)


def build_gallery(title: str, themes: list[str], previews: list[Preview], paths: dict[str, str], missing: set[str]) -> str:
    """Compose the offline gallery page.

    Args:
        title: Design-system name.
        themes: Theme ids, primary first.
        previews: Previews in gallery order.
        paths: Blob id to relative asset path.
        missing: Collects upload ids that could not be localised.

    Returns:
        str: The ``gallery.html`` text.
    """
    options = "".join(f'<option value="{html.escape(t)}">{html.escape(t)}</option>' for t in themes)
    sections: list[str] = []
    current: str | None = None
    for preview in previews:
        heading = "Cover" if preview.name == _COVER else (preview.group or "Ungrouped")
        if heading != current:
            if current is not None:
                sections.append("</section>")
            sections.append(f'<section><h2 class="g-group">{html.escape(heading)}</h2>')
            current = heading
        sections.append(
            f'<article class="g-card"><h3 class="g-name">{html.escape(preview.name)}</h3>'
            f'<div class="g-frame" style="min-height:{preview.height}px">'
            f"{localise_uploads(preview.body, paths, missing)}</div></article>",
        )
    if current is not None:
        sections.append("</section>")
    safe_title = html.escape(title)
    return (
        "<!doctype html>\n"
        f'<html lang="en" data-theme="{html.escape(themes[0])}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{safe_title} gallery</title>"
        '<link rel="stylesheet" href="tokens.css"><link rel="stylesheet" href="components/bundle.css">'
        '<script src="components/bundle.js"></script>'
        "<style>"
        "body{margin:0;background:#3a3d43;color:#eceff3;font:14px/1.4 system-ui,sans-serif}"
        ".g-bar{position:sticky;top:0;z-index:10;display:flex;align-items:center;gap:12px;"
        "padding:12px 24px;background:#2a2c31;border-bottom:1px solid #50545c}"
        ".g-bar h1{margin:0;font-size:16px}.g-bar label{margin-left:auto}"
        "main{max-width:1040px;margin:0 auto;padding:24px}"
        ".g-group{margin:32px 0 12px;font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#b8bec7}"
        ".g-card{margin:0 0 20px}.g-name{margin:0 0 6px;font-size:13px;font-weight:600}"
        ".g-frame{border:1px solid #50545c;border-radius:6px;overflow:auto}"
        "</style></head><body>"
        f'<header class="g-bar"><h1>{safe_title}</h1>'
        f'<label>Theme <select id="g-theme">{options}</select></label></header>'
        f"<main>{''.join(sections)}</main>"
        "<script>"
        "const s=document.getElementById('g-theme');"
        "s.addEventListener('change',()=>{document.documentElement.dataset.theme=s.value;});"
        "</script></body></html>\n"
    )


def build(root: Path) -> tuple[Path, Path, set[str]]:
    """Write ``tokens.css`` and ``gallery.html`` into a design-system folder.

    Args:
        root: Folder holding tokens.json, design-system.json and components/.

    Returns:
        tuple[Path, Path, set[str]]: The stylesheet path, the gallery path, and
        any upload ids that had no local asset record.
    """
    tokens = _as_dict(_load_json(root / "tokens.json"), "tokens.json")
    index = _as_dict(_load_json(root / "design-system.json"), "design-system.json")

    css_path = root / "tokens.css"
    css_path.write_text(build_tokens_css(tokens), encoding="utf-8")

    themes = _theme_ids(_as_dict(tokens.get("color"), "color"))
    title = _as_str(index.get("title", tokens.get("name", "Design system")), "title")
    missing: set[str] = set()
    gallery = build_gallery(title, themes, read_previews(root / "components"), asset_paths(index), missing)
    gallery_path = root / "gallery.html"
    gallery_path.write_text(gallery, encoding="utf-8")
    return css_path, gallery_path, missing


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point.

    Args:
        argv: Arguments excluding the program name; ``None`` reads ``sys.argv``.

    Returns:
        int: Process exit code, 0 on success and 1 on a malformed system.
    """
    parser = argparse.ArgumentParser(description="Build tokens.css and gallery.html for a design-system folder.")
    parser.add_argument("--root", type=Path, default=_ROOT, help="design-system folder (default: this script's folder)")
    args = parser.parse_args(argv)
    root = cast("Path", args.root)
    try:
        css_path, gallery_path, missing = build(root)
    except DesignSystemError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    sys.stdout.write(f"wrote {css_path}\nwrote {gallery_path}\n")
    for blob in sorted(missing):
        sys.stderr.write(f"warning: no asset record for upload {blob}; left as /_blob/{blob}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
