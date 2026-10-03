# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates that widgets formerly styled inline are now styled by the four theme stylesheets.

The credential source badge, the session tag chips, the sandbox limit spin boxes and the chat markdown view each carried a stylesheet of
their own, which overrode the theme files and froze the widget across a theme switch. They are now selected by object name or by a dynamic
property. These gates build the real widgets, apply every shipped theme through the real :class:`ThemeManager`, and compare what Qt resolved
onto the widget with what the theme's stylesheet declares. A static gate also checks that every ``Class#name`` selector in the stylesheets
names a class the widget carrying that object name really is, since Qt silently ignores a type selector that does not match.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from mcp_types import ElicitRequestFormParams
from PyQt6 import QtWidgets
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication, QLabel, QPushButton, QSpinBox, QWidget

from intellicrack.core.session import Session
from intellicrack.core.types import Message, ToolCall
from intellicrack.mcp.config import McpServerConfig, McpTransportKind, StdioServerSpec
from intellicrack.mcp.consent import DangerousPattern
from intellicrack.providers import ids as provider_ids
from intellicrack.ui.chat import ChatPanel, MessageBubble
from intellicrack.ui.mcp_consent_dialog import McpServerConsentDialog
from intellicrack.ui.mcp_elicitation_dialog import McpElicitationDialog
from intellicrack.ui.panels.sandbox_panel import SandboxPanel
from intellicrack.ui.provider_config import CredentialSource, ProviderSettingsWidget
from intellicrack.ui.resources.icon_manager import IconManager
from intellicrack.ui.resources.resource_helper import get_style_path
from intellicrack.ui.resources.theme_manager import (
    THEME_DARK,
    THEME_DARK2,
    THEME_LIGHT,
    THEME_LIGHT2,
    ThemeManager,
)
from intellicrack.ui.session_manager import TagChipsWidget
from intellicrack.ui.tool_activity import ToolActivityPanel


if TYPE_CHECKING:
    from collections.abc import Generator


_THEMES: tuple[str, ...] = (THEME_DARK, THEME_LIGHT, THEME_DARK2, THEME_LIGHT2)
_UI_ROOT: Path = Path(__file__).resolve().parents[2] / "src" / "intellicrack" / "ui"
_COMMENT: re.Pattern[str] = re.compile(r"/\*.*?\*/", re.DOTALL)
_RULE: re.Pattern[str] = re.compile(r"([^{}]+)\{([^{}]*)\}")
_HEX: re.Pattern[str] = re.compile(r"#[0-9a-fA-F]{6}\b")
_RGBA: re.Pattern[str] = re.compile(r"rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*([0-9.]+)\s*\)")
_OBJECT_NAME_SELECTOR: re.Pattern[str] = re.compile(r"\b(Q[A-Za-z]+)#([A-Za-z_][A-Za-z0-9_]*)")
_SOURCE_KEYS: dict[str, str] = {
    CredentialSource.ENV_FILE: "env_file",
    CredentialSource.ENVIRONMENT: "environment",
    CredentialSource.MANUAL: "manual",
    CredentialSource.NOT_CONFIGURED: "not_configured",
}
_BADGE_OPACITY_TEXT: str = "0.2"
_BADGE_ALPHA: int = 51
_SPIN_CONTENT_MIN_WIDTH: int = 110
_NEW_OBJECT_NAMES: frozenset[str] = frozenset({
    "tagChip",
    "tag_empty_label",
    "sandbox_timeout_spin",
    "sandbox_memory_spin",
    "chat_markdown_view",
    "chat_notice",
    "tool_source_badge",
    "tool_activity_message",
    "mcp_consent_header",
    "mcp_consent_warning",
    "mcp_elicit_header",
    "mcp_elicit_caution",
})
_CHIP_SURFACES: dict[str, str] = {THEME_DARK: "#2d2d30", THEME_LIGHT: "#ffffff"}
_NEW_SELECTORS: tuple[str, ...] = (
    'QLabel#credential_source_label[credentialSource="env_file"]',
    'QLabel#credential_source_label[credentialSource="environment"]',
    'QLabel#credential_source_label[credentialSource="manual"]',
    'QLabel#credential_source_label[credentialSource="not_configured"]',
    "QPushButton#tagChip",
    "QPushButton#tagChip:hover",
    "QLabel#tag_empty_label",
    "QSpinBox#sandbox_timeout_spin",
    "QSpinBox#sandbox_memory_spin",
    "QTextBrowser#chat_markdown_view",
    "QLabel#chat_notice",
    "QLabel#tool_source_badge",
    'QFrame[toolActivityRow="true"]',
    "QLabel#tool_activity_message",
    "QLabel#mcp_consent_header",
    "QLabel#mcp_elicit_header",
    "QLabel#mcp_consent_warning",
    "QLabel#mcp_elicit_caution",
)


def _rules(theme: str) -> dict[str, dict[str, str]]:
    """Parse a shipped theme stylesheet into its rules.

    Args:
        theme: Theme id.

    Returns:
        dict[str, dict[str, str]]: Every individual selector mapped to the declarations that apply to it, later rules overriding earlier.
    """
    text = _COMMENT.sub("", get_style_path(f"{theme}_theme.qss").read_text(encoding="utf-8"))
    rules: dict[str, dict[str, str]] = {}
    for match in _RULE.finditer(text):
        declarations: dict[str, str] = {}
        for declaration in match.group(2).split(";"):
            if ":" in declaration:
                name, value = declaration.split(":", 1)
                declarations[name.strip()] = value.strip()
        for selector in match.group(1).split(","):
            rules.setdefault(" ".join(selector.split()), {}).update(declarations)
    return rules


def _declared(theme: str, selector: str, declaration: str) -> QColor:
    """Read a hex colour a theme stylesheet declares for a selector.

    Args:
        theme: Theme id.
        selector: Exact selector text.
        declaration: Declaration name, e.g. ``"color"``.

    Returns:
        QColor: The declared colour.
    """
    rules = _rules(theme)
    assert selector in rules, f"{theme}_theme.qss has no rule for {selector}"
    assert declaration in rules[selector], f"{theme}_theme.qss {selector} declares no {declaration}"
    found = _HEX.search(rules[selector][declaration])
    assert found is not None, f"{theme}_theme.qss {selector} {declaration} is not a hex colour: {rules[selector][declaration]!r}"
    return QColor(found.group(0))


def _text_color(widget: QWidget) -> QColor:
    """Read the text colour Qt resolved for a widget.

    Args:
        widget: The widget, already built under the theme.

    Returns:
        QColor: The colour of the widget's foreground palette role.
    """
    widget.ensurePolished()
    return widget.palette().color(widget.foregroundRole())


def _fill_color(widget: QWidget) -> QColor:
    """Read the background colour Qt resolved for a widget.

    Args:
        widget: The widget, already built under the theme.

    Returns:
        QColor: The colour of the widget's background palette role.
    """
    widget.ensurePolished()
    return widget.palette().color(widget.backgroundRole())


@pytest.fixture
def manager(qapp: QApplication) -> ThemeManager:
    """Provide a fresh theme manager with the dark theme applied.

    Args:
        qapp: The session ``QApplication``.

    Returns:
        ThemeManager: The singleton, rebuilt for this test.
    """
    del qapp
    ThemeManager.reset_instance()
    fresh = ThemeManager.get_instance()
    assert fresh.apply_theme(THEME_DARK) is True
    return fresh


@pytest.fixture(params=_THEMES)
def theme(request: pytest.FixtureRequest) -> str:
    """Parametrize a test over every shipped theme id.

    Args:
        request: Pytest fixture request carrying the theme id.

    Returns:
        str: The theme id to apply.
    """
    return str(request.param)


@pytest.fixture
def settings(manager: ThemeManager, tmp_path: Path) -> Generator[ProviderSettingsWidget]:
    """Build the real provider settings page.

    Args:
        manager: Fresh theme manager; the page is built under the dark theme.
        tmp_path: Per-test temporary directory holding the provider settings file.

    Yields:
        ProviderSettingsWidget: The page whose credential source badge is under test.
    """
    del manager
    page = ProviderSettingsWidget("openai", config_path=tmp_path / "providers.json")
    yield page
    page.close()
    page.deleteLater()
    QApplication.processEvents()


def _tagged_session() -> Session:
    """Build an in-memory session carrying one tag.

    Returns:
        Session: A session tagged ``"triage"``.
    """
    session = Session.create(provider=provider_ids.OPENAI, model="gpt-4")
    session.add_tag("triage")
    return session


def _stdio_config() -> McpServerConfig:
    """Build a local server configuration for the consent dialog.

    Returns:
        McpServerConfig: An enabled stdio configuration.
    """
    spec = StdioServerSpec(command="powershell", args=("-enc", "AAAA"))
    return McpServerConfig(server_id="srv", kind=McpTransportKind.STDIO, stdio=spec, enabled=True, request_timeout_s=30.0)


class TestStylesheetsDeclareTheNewRules:
    """The rules that replace the inline stylesheets exist in all four theme files."""

    @staticmethod
    def test_all_four_stylesheets_declare_the_same_selectors_including_the_new_rules() -> None:
        """The four theme files stay structurally identical, and the rules that replace the inline styles are in all of them."""
        reference = set(_rules(THEME_DARK))
        missing = sorted(set(_NEW_SELECTORS) - reference)
        assert missing == [], f"dark_theme.qss lacks the rules that replace the inline stylesheets: {missing}"
        for theme_id in _THEMES:
            selectors = set(_rules(theme_id))
            assert selectors == reference, f"{theme_id} differs from dark: {sorted(selectors ^ reference)}"

    @staticmethod
    def test_new_rules_declare_the_same_properties_in_every_theme() -> None:
        """Each new rule sets the same declarations in every theme; only the colour values may differ."""
        for selector in _NEW_SELECTORS:
            reference = sorted(_rules(THEME_DARK)[selector])
            for theme_id in _THEMES:
                assert sorted(_rules(theme_id)[selector]) == reference, f"{selector} declares different properties in {theme_id}"


class TestCredentialSourceBadge:
    """The badge is coloured by the ``credentialSource`` rules of the theme, not by a stylesheet of its own."""

    @staticmethod
    @pytest.mark.parametrize("source", sorted(_SOURCE_KEYS))
    def test_badge_shows_the_stylesheet_colour_for_each_source(
        settings: ProviderSettingsWidget,
        manager: ThemeManager,
        theme: str,
        source: str,
    ) -> None:
        """Each source value selects its own rule, whose colour is also the theme's credential-source entry.

        Args:
            settings: The real provider settings page.
            manager: Fresh theme manager.
            theme: Theme id to switch to after the page exists.
            source: Credential source shown on the badge.
        """
        key = _SOURCE_KEYS[source]
        badge = settings._credential_source_label
        settings._show_credential_source(source)
        assert manager.apply_theme(theme) is True

        selector = f'QLabel#credential_source_label[credentialSource="{key}"]'
        declared = _declared(theme, selector, "color")
        assert not badge.styleSheet(), "the badge must not carry a stylesheet of its own"
        assert badge.text() == source
        assert badge.property("credentialSource") == key
        assert _text_color(badge) == declared
        assert declared == manager.get_credential_source_colors(theme)[key], "stylesheet and palette disagree about this source"

        wash = _RGBA.search(_rules(theme)[selector]["background-color"])
        assert wash is not None, f"{selector} background is not an rgba() wash"
        assert (int(wash.group(1)), int(wash.group(2)), int(wash.group(3))) == (declared.red(), declared.green(), declared.blue())
        assert wash.group(4) == _BADGE_OPACITY_TEXT
        fill = _fill_color(badge)
        assert (fill.red(), fill.green(), fill.blue()) == (declared.red(), declared.green(), declared.blue())
        assert fill.alpha() == _BADGE_ALPHA

    @staticmethod
    def test_badge_recolours_when_the_source_changes(settings: ProviderSettingsWidget) -> None:
        """Changing the source on a live badge re-evaluates the stylesheet, so the colour follows the new value.

        Args:
            settings: The real provider settings page, under the dark theme.
        """
        badge = settings._credential_source_label
        settings._show_credential_source(CredentialSource.ENV_FILE)
        first = _text_color(badge)
        settings._show_credential_source(CredentialSource.NOT_CONFIGURED)
        second = _text_color(badge)
        assert first == _declared(THEME_DARK, 'QLabel#credential_source_label[credentialSource="env_file"]', "color")
        assert second == _declared(THEME_DARK, 'QLabel#credential_source_label[credentialSource="not_configured"]', "color")
        assert first != second

    @staticmethod
    def test_unrecognised_source_uses_the_base_rule(settings: ProviderSettingsWidget, manager: ThemeManager, theme: str) -> None:
        """A source with no rule of its own falls back to the base rule, which is the palette's default entry.

        Args:
            settings: The real provider settings page.
            manager: Fresh theme manager.
            theme: Theme id to apply.
        """
        settings._show_credential_source("a source nobody defined")
        assert manager.apply_theme(theme) is True
        declared = _declared(theme, "QLabel#credential_source_label", "color")
        assert settings._credential_source_label.property("credentialSource") == "default"
        assert _text_color(settings._credential_source_label) == declared
        assert declared == manager.get_credential_source_colors(theme)["default"]

    @staticmethod
    def test_page_without_a_detector_shows_not_configured(settings: ProviderSettingsWidget) -> None:
        """With no detector the badge still gets the themed not-configured styling instead of unstyled text.

        Args:
            settings: The real provider settings page, built without a credential detector.
        """
        settings._update_credential_source_display("")
        badge = settings._credential_source_label
        assert badge.text() == CredentialSource.NOT_CONFIGURED
        assert badge.property("credentialSource") == "not_configured"
        assert not badge.styleSheet()


class TestSessionTagChips:
    """Tag chips and the empty-state label are styled by the theme files and use the shared icon set."""

    @staticmethod
    def test_chip_resolves_the_stylesheet_rule(manager: ThemeManager, theme: str) -> None:
        """An existing chip follows a live theme switch because the application stylesheet styles it.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to switch to after the chip exists.
        """
        widget = TagChipsWidget(session=_tagged_session())
        try:
            chip = widget._chip_buttons["triage"]
            assert manager.apply_theme(theme) is True
            chip.ensurePolished()
            assert not chip.styleSheet(), "the chip must not carry a stylesheet of its own"
            assert chip.inherits("QPushButton")
            palette = chip.palette()
            assert palette.color(QPalette.ColorRole.Button) == _declared(theme, "QPushButton#tagChip", "background-color")
            assert palette.color(QPalette.ColorRole.ButtonText) == _declared(theme, "QPushButton#tagChip", "color")
        finally:
            widget.deleteLater()

    @staticmethod
    def test_base_theme_chip_rule_keeps_the_colours_the_chips_always_had(manager: ThemeManager) -> None:
        """In the base themes the rule is the surface, border, text and accent the chips were drawn with before.

        Args:
            manager: Fresh theme manager.
        """
        for theme_id, surface in _CHIP_SURFACES.items():
            colors = manager.get_analysis_colors(theme_id)
            rule = _rules(theme_id)["QPushButton#tagChip"]
            assert _declared(theme_id, "QPushButton#tagChip", "background-color") == QColor(surface)
            assert _declared(theme_id, "QPushButton#tagChip", "color") == colors["foreground"]
            assert _declared(theme_id, "QPushButton#tagChip", "border") == colors["border"]
            assert rule["border-radius"] == "10px"
            assert rule["padding"] == "2px 8px"
            assert _declared(theme_id, "QPushButton#tagChip:hover", "background-color") == colors["accent"]
            assert _declared(theme_id, "QPushButton#tagChip:hover", "color") == QColor(255, 255, 255)

    @staticmethod
    def test_chip_icon_comes_from_the_icon_manager(manager: ThemeManager) -> None:
        """The remove icon is the shared ``edit_delete`` icon, not a platform standard pixmap.

        Args:
            manager: Fresh theme manager.
        """
        del manager
        widget = TagChipsWidget(session=_tagged_session())
        try:
            chip = widget._chip_buttons["triage"]
            size = chip.iconSize().width()
            expected = IconManager.get_instance().get_icon("edit_delete", size)
            assert not chip.icon().isNull()
            assert chip.icon().cacheKey() == expected.cacheKey()
        finally:
            widget.deleteLater()

    @staticmethod
    def test_chip_icon_falls_back_to_a_rendered_glyph_without_icon_assets(manager: ThemeManager) -> None:
        """When the icon assets are unavailable the chip still shows the manager's Unicode fallback, never nothing.

        Args:
            manager: Fresh theme manager.
        """
        del manager
        IconManager.reset_instance()
        icons = IconManager.get_instance()
        icons.icons_available = False
        try:
            widget = TagChipsWidget(session=_tagged_session())
            try:
                chip = widget._chip_buttons["triage"]
                assert not chip.icon().isNull(), "the chip lost its remove affordance when the icon asset was missing"
                assert chip.icon().cacheKey() == icons.get_icon("edit_delete", chip.iconSize().width()).cacheKey()
            finally:
                widget.deleteLater()
        finally:
            IconManager.reset_instance()

    @staticmethod
    def test_empty_label_is_styled_by_the_theme(manager: ThemeManager, theme: str) -> None:
        """The empty-state label takes the theme's muted colour and italic face from its object-name rule.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to switch to after the label exists.
        """
        widget = TagChipsWidget(session=None)
        try:
            label = widget._empty_label
            assert manager.apply_theme(theme) is True
            assert label.objectName() == "tag_empty_label"
            assert not label.styleSheet()
            assert _text_color(label) == _declared(theme, "QLabel#tag_empty_label", "color")
            assert label.font().italic()
        finally:
            widget.deleteLater()


class TestSandboxLimitSpinBoxes:
    """The spin boxes get their floor from a named theme rule instead of a stylesheet of their own."""

    @staticmethod
    def test_spin_boxes_keep_their_width_under_every_theme(manager: ThemeManager, theme: str) -> None:
        """A panel on screen keeps the spin-box floor through a switch to any shipped theme.

        The generic ``QSpinBox`` rule of every theme declares a narrower ``min-width`` that Qt applies at polish time, replacing any
        minimum set from code, so the floor has to come from a more specific stylesheet rule.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to switch to after the panel is shown.
        """
        panel = SandboxPanel()
        panel.show()
        try:
            assert manager.apply_theme(theme) is True
            QApplication.processEvents()
            generic = QSpinBox()
            generic.ensurePolished()
            for spin, name in ((panel._timeout_spin, "sandbox_timeout_spin"), (panel._memory_limit_spin, "sandbox_memory_spin")):
                assert spin.objectName() == name
                assert not spin.styleSheet(), "the spin box must not carry a stylesheet of its own"
                assert _rules(theme)[f"QSpinBox#{name}"]["min-width"] == f"{_SPIN_CONTENT_MIN_WIDTH}px"
                assert spin.minimumWidth() >= _SPIN_CONTENT_MIN_WIDTH
                assert spin.minimumWidth() > generic.minimumWidth(), "the named rule did not widen the spin box past the generic floor"
            generic.deleteLater()
        finally:
            panel.close()
            panel.deleteLater()


class TestChatSurfaces:
    """The chat markdown view, notice strip and tool provenance badge are styled by the theme files."""

    @staticmethod
    def test_markdown_view_is_transparent_and_frameless_through_its_rule(manager: ThemeManager, theme: str) -> None:
        """The message text is drawn straight onto the bubble: no frame and no background of its own.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to apply.
        """
        assert manager.apply_theme(theme) is True
        bubble = MessageBubble(Message(role="user", content="hi"))
        bubble.resize(420, 120)
        bubble.show()
        try:
            QApplication.processEvents()
            view = bubble.content_label
            assert view.objectName() == "chat_markdown_view"
            assert not view.styleSheet(), "the markdown view must not carry a stylesheet of its own"
            assert view.inherits("QTextBrowser")
            assert view.frameWidth() == 0
            geometry = view.geometry()
            sampled = bubble.grab().toImage().pixelColor(geometry.right() - 2, geometry.bottom() - 1)
            assert sampled == _declared(theme, 'QFrame[role="user"]', "background-color"), (
                "the markdown view painted a background of its own over the bubble"
            )
        finally:
            bubble.close()
            bubble.deleteLater()

    @staticmethod
    def test_third_party_tool_badge_uses_the_warning_colour(manager: ThemeManager, theme: str) -> None:
        """The badge marking a call that went to a third-party server stands out in the theme's warning colour.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to apply.
        """
        assert manager.apply_theme(theme) is True
        call = ToolCall(id="call-1", tool_name="mcp-srv", function_name="mcp-srv.echo", arguments={})
        bubble = MessageBubble(Message(role="assistant", content="", tool_calls=[call]))
        try:
            badge = bubble.findChild(QLabel, "tool_source_badge")
            assert badge is not None, "an MCP tool call must carry a source badge"
            declared = _declared(theme, "QLabel#tool_source_badge", "color")
            assert _text_color(badge) == declared
            assert declared == _declared(theme, 'QLabel[status="warning"]', "color")
            header = bubble.findChild(QLabel, "tool_call_header")
            assert header is not None
            assert _text_color(header) != declared, "test premise: the badge colour differs from the tool header colour"
        finally:
            bubble.deleteLater()

    @staticmethod
    def test_notice_strip_is_styled_by_the_theme(manager: ThemeManager, theme: str) -> None:
        """The notice above the input is a muted strip with its own surface, not plain text on the chat background.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to apply.
        """
        assert manager.apply_theme(theme) is True
        panel = ChatPanel()
        try:
            panel.show_notice("server 'srv' changed a resource")
            notice = panel.findChild(QLabel, "chat_notice")
            assert notice is not None
            assert not notice.styleSheet()
            assert _text_color(notice) == _declared(theme, "QLabel#chat_notice", "color")
            assert _fill_color(notice) == _declared(theme, "QLabel#chat_notice", "background-color")
        finally:
            panel.deleteLater()

    @staticmethod
    def test_running_call_rows_are_styled_by_property(manager: ThemeManager, theme: str) -> None:
        """Rows are selected by a shared property, because each row's object name embeds its call id.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to apply.
        """
        assert manager.apply_theme(theme) is True
        panel = ToolActivityPanel()
        try:
            for call_id in ("a", "b"):
                panel.started(ToolCall(id=call_id, tool_name="hex_editor", function_name="hex_editor.read", arguments={}))
            rows = [panel._rows["a"], panel._rows["b"]]
            assert len({row.objectName() for row in rows}) == len(rows), "test premise: every row has its own object name"
            selector = 'QFrame[toolActivityRow="true"]'
            for row in rows:
                assert row.property("toolActivityRow") == "true"
                assert _fill_color(row) == _declared(theme, selector, "background-color")
                assert _text_color(row.message) == _declared(theme, "QLabel#tool_activity_message", "color")
        finally:
            panel.deleteLater()


class TestMcpDialogs:
    """The consent and elicitation dialogs' headings and cautions are styled by the theme files."""

    @staticmethod
    def test_consent_header_and_flag_warning(manager: ThemeManager, theme: str) -> None:
        """The consent heading is emphasised and the flagged-command warning is a warning panel.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to apply.
        """
        assert manager.apply_theme(theme) is True
        finding = DangerousPattern(token="-enc", reason="encoded command")
        dialog = McpServerConsentDialog(_stdio_config(), "powershell -enc AAAA", [finding])
        try:
            header = dialog.findChild(QLabel, "mcp_consent_header")
            warning = dialog.findChild(QLabel, "mcp_consent_warning")
            assert header is not None
            assert warning is not None
            header.ensurePolished()
            assert header.font().bold()
            assert _text_color(header) == _declared(theme, "QLabel#mcp_consent_header", "color")
            assert _text_color(warning) == _declared(theme, "QLabel#mcp_consent_warning", "color")
            assert _fill_color(warning) == _declared(theme, "QLabel#mcp_consent_warning", "background-color")
            sandbox = dialog.findChild(QLabel, "mcp_consent_sandbox")
            assert sandbox is not None
            assert _text_color(sandbox) != _text_color(warning), "test premise: the warning colour differs from plain dialog text"
        finally:
            dialog.deleteLater()
            QApplication.processEvents()

    @staticmethod
    def test_elicitation_header_and_caution(manager: ThemeManager, theme: str) -> None:
        """The elicitation heading is emphasised and the credential caution is a warning panel.

        Args:
            manager: Fresh theme manager.
            theme: Theme id to apply.
        """
        assert manager.apply_theme(theme) is True
        schema = {"type": "object", "properties": {"name": {"type": "string"}}}
        dialog = McpElicitationDialog("srv", ElicitRequestFormParams(message="Fill this in.", requested_schema=schema))
        try:
            header = dialog.findChild(QLabel, "mcp_elicit_header")
            caution = dialog.findChild(QLabel, "mcp_elicit_caution")
            assert header is not None
            assert caution is not None
            header.ensurePolished()
            assert header.font().bold()
            assert _text_color(caution) == _declared(theme, "QLabel#mcp_elicit_caution", "color")
            assert _fill_color(caution) == _declared(theme, "QLabel#mcp_elicit_caution", "background-color")
        finally:
            dialog.deleteLater()
            QApplication.processEvents()


class _ObjectNameIndex:
    """Which widget classes set which object names, read from the UI source."""

    def __init__(self) -> None:
        """Scan every UI module for ``setObjectName`` calls with a literal name."""
        self._bases: dict[str, list[str]] = {}
        self.owners: dict[str, set[str]] = {}
        self.unresolved: set[str] = set()
        trees = [ast.parse(path.read_text(encoding="utf-8")) for path in sorted(_UI_ROOT.rglob("*.py"))]
        for tree in trees:
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    self._bases[node.name] = [self._name(base) for base in node.bases]
        for tree in trees:
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    attributes: dict[str, str] = {}
                    methods = [item for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))]
                    for method in methods:
                        self._collect_assignments(method, {}, attributes)
                    for method in methods:
                        self._collect_sites(method, node.name, attributes)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._collect_sites(node, None, {})

    @staticmethod
    def _name(node: ast.expr) -> str:
        """Name a class reference.

        Args:
            node: Expression naming a class.

        Returns:
            str: The bare or attribute name, or an empty string for anything else.
        """
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    @staticmethod
    def _literals(node: ast.expr) -> list[str]:
        """Read the object names an argument can evaluate to.

        Args:
            node: The argument of a ``setObjectName`` call.

        Returns:
            list[str]: The string for a literal, both strings for a conditional of literals, otherwise nothing.
        """
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, ast.IfExp):
            return _ObjectNameIndex._literals(node.body) + _ObjectNameIndex._literals(node.orelse)
        return []

    def _collect_assignments(self, scope: ast.AST, local: dict[str, str], attributes: dict[str, str]) -> None:
        """Record which class each variable and ``self`` attribute was constructed from.

        Args:
            scope: Function to read.
            local: Mapping of local variable name to class name, filled in place.
            attributes: Mapping of ``self`` attribute name to class name, filled in place.
        """
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            else:
                continue
            if not isinstance(value, ast.Call):
                continue
            constructed = self._name(value.func)
            for target in targets:
                if isinstance(target, ast.Name):
                    local[target.id] = constructed
                elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                    attributes[target.attr] = constructed

    def _collect_sites(self, scope: ast.AST, owner_class: str | None, attributes: dict[str, str]) -> None:
        """Record the class behind every literal ``setObjectName`` call in a function.

        Args:
            scope: Function to read.
            owner_class: Enclosing class, used when the receiver is ``self``.
            attributes: Mapping of ``self`` attribute name to class name for the enclosing class.
        """
        local: dict[str, str] = {}
        self._collect_assignments(scope, local, dict(attributes))
        for node in ast.walk(scope):
            if not (
                isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "setObjectName" and node.args
            ):
                continue
            receiver = node.func.value
            owner: str | None = None
            if isinstance(receiver, ast.Name):
                owner = owner_class if receiver.id == "self" else local.get(receiver.id)
            elif isinstance(receiver, ast.Attribute) and isinstance(receiver.value, ast.Name) and receiver.value.id == "self":
                owner = attributes.get(receiver.attr)
            for name in self._literals(node.args[0]):
                if owner is None:
                    self.unresolved.add(name)
                else:
                    self.owners.setdefault(name, set()).add(owner)

    def qt_class(self, name: str, seen: frozenset[str] = frozenset()) -> type[QWidget] | None:
        """Resolve a class name to the Qt widget class it is or derives from.

        Args:
            name: A Qt class name or the name of a class defined in the UI package.
            seen: Class names already visited, to stop on a cycle.

        Returns:
            type[QWidget] | None: The Qt widget class, or ``None`` when the name does not lead to one.
        """
        candidate: object = getattr(QtWidgets, name, None)
        if isinstance(candidate, type) and issubclass(candidate, QWidget):
            return candidate
        if name in seen:
            return None
        for base in self._bases.get(name, []):
            resolved = self.qt_class(base, seen | {name})
            if resolved is not None:
                return resolved
        return None


@pytest.fixture(scope="module")
def object_names() -> _ObjectNameIndex:
    """Index the object names the UI source assigns.

    Returns:
        _ObjectNameIndex: The index, built once for the module.
    """
    return _ObjectNameIndex()


class TestSelectorsMatchTheWidgetsTheyName:
    """A ``Class#name`` selector only works when the widget named ``name`` is a ``Class``."""

    @staticmethod
    def test_every_object_name_selector_names_a_class_of_its_widget(object_names: _ObjectNameIndex, theme: str) -> None:
        """Every ``Class#name`` selector in a theme file matches every widget the UI gives that object name.

        Args:
            object_names: Index of the object names the UI source assigns.
            theme: Theme id whose stylesheet is checked.
        """
        text = _COMMENT.sub("", get_style_path(f"{theme}_theme.qss").read_text(encoding="utf-8"))
        selectors = sorted(set(_OBJECT_NAME_SELECTOR.findall(text)))
        uncovered = sorted(_NEW_OBJECT_NAMES - {name for _, name in selectors})
        assert uncovered == [], (
            f"{theme}_theme.qss has no selector for the newly named widgets {uncovered}, so this gate would not cover them"
        )
        problems: list[str] = []
        for selector_class, name in selectors:
            selector_type: object = getattr(QtWidgets, selector_class, None)
            if not (isinstance(selector_type, type) and issubclass(selector_type, QWidget)):
                problems.append(f"{selector_class}#{name}: {selector_class} is not a Qt widget class")
                continue
            owners = object_names.owners.get(name, set())
            if not owners:
                if name not in object_names.unresolved:
                    problems.append(f"{selector_class}#{name}: no widget is ever given this object name")
                continue
            for owner in sorted(owners):
                widget_type = object_names.qt_class(owner)
                if widget_type is None:
                    problems.append(f"{selector_class}#{name}: cannot tell what Qt class {owner} is")
                elif not issubclass(widget_type, selector_type):
                    problems.append(f"{selector_class}#{name}: set on a {owner}, which is a {widget_type.__name__}, not a {selector_class}")
        assert problems == [], "\n".join(problems)

    @staticmethod
    def test_index_resolves_the_new_named_widgets(object_names: _ObjectNameIndex) -> None:
        """The widgets this change named are found by the index, so the gate above really covers them.

        Args:
            object_names: Index of the object names the UI source assigns.
        """
        expected: dict[str, type[QWidget]] = {
            "tagChip": QPushButton,
            "tag_empty_label": QLabel,
            "sandbox_timeout_spin": QSpinBox,
            "sandbox_memory_spin": QSpinBox,
            "chat_markdown_view": QtWidgets.QTextBrowser,
            "credential_source_label": QLabel,
        }
        for name, widget_type in expected.items():
            owners = object_names.owners.get(name, set())
            assert owners, f"no widget is given the object name {name}"
            for owner in owners:
                resolved = object_names.qt_class(owner)
                assert resolved is not None
                assert issubclass(resolved, widget_type), f"{name} is set on a {owner}"
