# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Control flow graph view for Cutter/Rizin function analysis.

Provides QGraphicsView-based rendering of function CFGs parsed from Cutter/Rizin ``agj`` JSON output with hierarchical block layout, colored
edges for branch direction, and interactive block selection.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from typing import Any, Final, cast, override

from PyQt6.QtCore import QPointF, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QFontMetricsF,
    QMouseEvent,
    QPainter,
    QPainterPath,
    QPen,
    QPolygonF,
    QWheelEvent,
)
from PyQt6.QtWidgets import (
    QGraphicsItem,
    QGraphicsPathItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsView,
    QStyleOptionGraphicsItem,
    QTreeWidgetItem,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.resources.font_manager import FontManager
from intellicrack.ui.resources.theme_manager import ThemeManager


_logger = get_logger(__name__)

_BLOCK_PADDING: Final[int] = 10
_BLOCK_MIN_WIDTH: Final[int] = 200
_LINE_HEIGHT: Final[int] = 16
_HEADER_HEIGHT: Final[int] = 22
_LAYER_SPACING_V: Final[int] = 60
_LAYER_SPACING_H: Final[int] = 30
_ARROW_SIZE: Final[int] = 8
_ZOOM_FACTOR: Final[float] = 1.15


def _get_graph_colors() -> dict[str, QColor]:
    """Get theme-aware colors for CFG rendering.

    Returns:
        dict[str, QColor]: Mapping of color names to QColor instances.
    """
    if ThemeManager.get_instance().is_dark_theme():
        return {
            "block_bg": QColor(40, 44, 52),
            "block_border": QColor(80, 85, 95),
            "header_bg": QColor(55, 60, 72),
            "header_text": QColor(220, 220, 220),
            "asm_text": QColor(190, 190, 190),
            "mnemonic_jump": QColor(86, 156, 214),
            "mnemonic_call": QColor(78, 201, 176),
            "mnemonic_ret": QColor(206, 106, 106),
            "edge_true": QColor(80, 200, 80),
            "edge_false": QColor(200, 80, 80),
            "edge_uncond": QColor(150, 150, 150),
            "selected_border": QColor(100, 150, 255),
            "background": QColor(30, 30, 30),
        }
    return {
        "block_bg": QColor(255, 255, 255),
        "block_border": QColor(200, 200, 210),
        "header_bg": QColor(230, 235, 245),
        "header_text": QColor(30, 30, 30),
        "asm_text": QColor(60, 60, 60),
        "mnemonic_jump": QColor(0, 0, 200),
        "mnemonic_call": QColor(0, 128, 128),
        "mnemonic_ret": QColor(180, 50, 50),
        "edge_true": QColor(40, 160, 40),
        "edge_false": QColor(200, 40, 40),
        "edge_uncond": QColor(120, 120, 120),
        "selected_border": QColor(50, 100, 220),
        "background": QColor(248, 248, 248),
    }


_JUMP_MNEMONICS = frozenset({
    "je",
    "jne",
    "jz",
    "jnz",
    "jg",
    "jge",
    "jl",
    "jle",
    "ja",
    "jae",
    "jb",
    "jbe",
    "jo",
    "jno",
    "js",
    "jns",
    "jp",
    "jnp",
    "jmp",
    "jcxz",
    "jecxz",
    "jrcxz",
    "loop",
    "loope",
    "loopne",
})
_CALL_MNEMONICS = frozenset({"call", "syscall"})
_RET_MNEMONICS = frozenset({"ret", "retn", "retf", "iret", "iretd", "iretq"})


class BasicBlockItem(QGraphicsRectItem):
    """Renders a single basic block as a styled rectangle with assembly text."""

    def __init__(
        self,
        block_address: int,
        ops: list[dict[str, Any]],
        parent: QGraphicsItem | None = None,
    ) -> None:
        """Initialize the BasicBlockItem with address and instructions.

        Args:
            block_address: Start address of the block.
            ops: List of instruction dicts from r2 agj output.
            parent: Parent graphics item.
        """
        self.block_address = block_address
        self._ops = ops
        fm = FontManager.get_instance()
        self._font = fm.get_code_font(8)
        self._header_font = fm.get_code_font_bold(8)
        self._colors = _get_graph_colors()

        body_metrics = QFontMetricsF(self._font)
        header_metrics = QFontMetricsF(self._header_font)
        text_width = max(
            (body_metrics.horizontalAdvance(str(op.get("disasm", ""))) for op in ops),
            default=0.0,
        )
        header_width = header_metrics.horizontalAdvance(f"0x{block_address:X}")
        content_width = max(text_width, header_width)
        width = max(float(_BLOCK_MIN_WIDTH), content_width + _BLOCK_PADDING * 2)
        height = float(_HEADER_HEIGHT + len(ops) * _LINE_HEIGHT + _BLOCK_PADDING)

        super().__init__(0, 0, width, height, parent)
        self.setPen(QPen(self._colors["block_border"], 1.5))
        self.setBrush(QBrush(self._colors["block_bg"]))
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, enabled=True)

    def refresh_theme_colors(self) -> None:
        """Re-resolve theme colors and repaint after an application theme change."""
        self._colors = _get_graph_colors()
        self.setPen(QPen(self._colors["block_border"], 1.5))
        self.setBrush(QBrush(self._colors["block_bg"]))
        self.update()

    @override
    def paint(
        self,
        painter: QPainter | None,
        option: QStyleOptionGraphicsItem | None,
        widget: QWidget | None = None,
    ) -> None:
        """Paint the block with header and assembly lines.

        Args:
            painter: Qt painter.
            option: Style options.
            widget: Target widget.
        """
        if painter is None:
            return
        del option, widget
        rect = self.rect()

        colors = self._colors

        if self.isSelected():
            painter.setPen(QPen(colors["selected_border"], 2.0))
        else:
            painter.setPen(QPen(colors["block_border"], 1.5))
        painter.setBrush(QBrush(colors["block_bg"]))
        painter.drawRoundedRect(rect, 4, 4)

        header_rect = QRectF(rect.x(), rect.y(), rect.width(), _HEADER_HEIGHT)
        painter.setBrush(QBrush(colors["header_bg"]))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(header_rect, 4, 4)
        clip_rect = QRectF(rect.x(), rect.y() + 4, rect.width(), _HEADER_HEIGHT - 4)
        painter.drawRect(clip_rect)

        painter.setFont(self._header_font)
        painter.setPen(colors["header_text"])
        painter.drawText(
            header_rect.adjusted(_BLOCK_PADDING, 0, -_BLOCK_PADDING, 0),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            f"0x{self.block_address:X}",
        )

        painter.setFont(self._font)
        y = rect.y() + _HEADER_HEIGHT + 2

        for op in self._ops:
            disasm = str(op.get("disasm", ""))
            mnemonic = disasm.split(maxsplit=1)[0].lower() if disasm else ""

            if mnemonic in _JUMP_MNEMONICS:
                painter.setPen(colors["mnemonic_jump"])
            elif mnemonic in _CALL_MNEMONICS:
                painter.setPen(colors["mnemonic_call"])
            elif mnemonic in _RET_MNEMONICS:
                painter.setPen(colors["mnemonic_ret"])
            else:
                painter.setPen(colors["asm_text"])

            painter.drawText(
                QRectF(rect.x() + _BLOCK_PADDING, y, rect.width() - _BLOCK_PADDING * 2, _LINE_HEIGHT),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                disasm,
            )
            y += _LINE_HEIGHT


class EdgeItem(QGraphicsPathItem):
    """Bezier curve edge between basic blocks with directional arrow."""

    def __init__(
        self,
        start: QPointF,
        end: QPointF,
        edge_type: str = "unconditional",
        parent: QGraphicsItem | None = None,
    ) -> None:
        """Initialize the EdgeItem between two basic blocks.

        Args:
            start: Source point at the bottom center of the source block.
            end: Destination point at the top center of the target block.
            edge_type: Branch type for coloring.
            parent: Parent graphics item.
        """
        super().__init__(parent)
        self.edge_type = edge_type
        colors = _get_graph_colors()

        if edge_type == "true":
            color = colors["edge_true"]
        elif edge_type == "false":
            color = colors["edge_false"]
        else:
            color = colors["edge_uncond"]

        self.setPen(QPen(color, 1.5))

        path = QPainterPath()
        path.moveTo(start)

        mid_y = (start.y() + end.y()) / 2
        ctrl1 = QPointF(start.x(), mid_y)
        ctrl2 = QPointF(end.x(), mid_y)
        path.cubicTo(ctrl1, ctrl2, end)
        self.setPath(path)

        angle = math.atan2(end.y() - ctrl2.y(), end.x() - ctrl2.x())
        arrow_p1 = QPointF(
            end.x() - _ARROW_SIZE * math.cos(angle - math.pi / 6),
            end.y() - _ARROW_SIZE * math.sin(angle - math.pi / 6),
        )
        arrow_p2 = QPointF(
            end.x() - _ARROW_SIZE * math.cos(angle + math.pi / 6),
            end.y() - _ARROW_SIZE * math.sin(angle + math.pi / 6),
        )

        self._arrow = QPolygonF([end, arrow_p1, arrow_p2])
        self._arrow_brush = QBrush(color)

    def refresh_theme_colors(self) -> None:
        """Re-resolve theme colors and repaint after an application theme change."""
        colors = _get_graph_colors()
        if self.edge_type == "true":
            color = colors["edge_true"]
        elif self.edge_type == "false":
            color = colors["edge_false"]
        else:
            color = colors["edge_uncond"]
        self.setPen(QPen(color, 1.5))
        self._arrow_brush = QBrush(color)
        self.update()

    @override
    def paint(
        self,
        painter: QPainter | None,
        option: QStyleOptionGraphicsItem | None,
        widget: QWidget | None = None,
    ) -> None:
        """Paint the edge path and arrowhead.

        Args:
            painter: Qt painter.
            option: Style options.
            widget: Target widget.
        """
        if painter is None:
            return
        super().paint(painter, option, widget)
        painter.setBrush(self._arrow_brush)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPolygon(self._arrow)


class CFGGraphScene(QGraphicsScene):
    """Scene that lays out basic blocks hierarchically from bridge CFG data.

    Accepts two block-dict shapes interchangeably: the Cutter/Rizin ``agj``/``afbj`` shape (``offset``, ``jump``, ``fail``, ``ops``) and the
    Ghidra ``get_basic_blocks`` shape (``start``, ``end``, ``sources``, ``destinations``, ``destination_edges``). Blocks are matched by
    whichever of ``offset``/``start`` is present, and edges are drawn from ``jump``/``fail`` when present, otherwise from
    ``destination_edges``/``destinations``.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the CFGGraphScene instance.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self.block_items: dict[int, BasicBlockItem] = {}

    def load_graph(self, blocks: list[dict[str, Any]]) -> None:
        """Parse basic block dicts and lay them out hierarchically.

        Args:
            blocks: List of basic block dicts, either the Cutter/Rizin
                ``agj``/``afbj`` shape or the Ghidra ``get_basic_blocks``
                shape (see the class docstring for both shapes).
        """
        _logger.debug("graph_loading", block_count=len(blocks))
        self.clear()
        self.block_items.clear()

        if not blocks:
            self.setSceneRect(QRectF())
            return

        block_map = self._build_block_map(blocks)
        layers = self._compute_layers(block_map)
        self._position_layers(layers)
        self._create_edges(block_map)
        self.setSceneRect(self.itemsBoundingRect())
        _logger.debug("graph_loaded", blocks=len(self.block_items), layers=len(layers))

    def _build_block_map(self, blocks: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
        """Build a mapping of offsets to blocks and create scene items.

        Args:
            blocks: Raw block dicts from either the Cutter/Rizin ``agj``/``afbj`` output (keyed by ``offset``) or Ghidra's
                ``get_basic_blocks`` output (keyed by ``start``).

        Returns:
            dict[int, dict[str, Any]]: Mapping of offset to block data.
        """
        block_map: dict[int, dict[str, Any]] = {}
        for block in blocks:
            offset = int(block.get("offset", block.get("start", 0)))
            block_map[offset] = block

        for offset, block in block_map.items():
            ops = block.get("ops", [])
            if not isinstance(ops, list):
                ops = []
            item = BasicBlockItem(offset, cast("list[dict[str, Any]]", ops))
            self.block_items[offset] = item
            self.addItem(item)

        return block_map

    def _position_layers(self, layers: dict[int, list[int]]) -> None:
        """Compute positions for blocks in each layer and apply them.

        Args:
            layers: Mapping of layer index to list of block addresses.
        """
        layer_widths: dict[int, float] = {}
        for layer_idx, addrs in layers.items():
            total_w = sum(self.block_items[a].rect().width() for a in addrs if a in self.block_items)
            total_w += _LAYER_SPACING_H * max(0, len(addrs) - 1)
            layer_widths[layer_idx] = total_w

        max_width = max(layer_widths.values()) if layer_widths else 0
        y_offset = 0.0

        for layer_idx in sorted(layers.keys()):
            addrs = layers[layer_idx]
            layer_w = layer_widths[layer_idx]
            x = (max_width - layer_w) / 2

            for addr in addrs:
                if addr not in self.block_items:
                    continue
                item = self.block_items[addr]
                item.setPos(x, y_offset)
                x += item.rect().width() + _LAYER_SPACING_H

            max_height = max(
                (self.block_items[a].rect().height() for a in addrs if a in self.block_items),
                default=0,
            )
            y_offset += max_height + _LAYER_SPACING_V

    def _create_edges(self, block_map: dict[int, dict[str, Any]]) -> None:
        """Create edge items between blocks based on jump/fail or destination targets.

        Args:
            block_map: Mapping of block address to block data.
        """
        for offset, block in block_map.items():
            if offset not in self.block_items:
                continue
            src_item = self.block_items[offset]
            src_bottom = self._block_bottom_center(src_item)

            jump_target = block.get("jump")
            fail_target = block.get("fail")

            if jump_target is not None or fail_target is not None:
                self._add_r2_style_edges(src_bottom, jump_target, fail_target)
                continue

            self._add_ghidra_style_edges(src_bottom, block)

    def _add_r2_style_edges(
        self,
        src_bottom: QPointF,
        jump_target: object,
        fail_target: object,
    ) -> None:
        """Create edges from Cutter/r2 ``jump``/``fail`` targets.

        Args:
            src_bottom: Bottom-center scene point of the source block.
            jump_target: The ``jump`` (taken-branch) target offset, or ``None``.
            fail_target: The ``fail`` (fallthrough) target offset, or ``None``.
        """
        has_conditional = jump_target is not None and fail_target is not None

        if jump_target is not None and int(cast("int", jump_target)) in self.block_items:
            dst_item = self.block_items[int(cast("int", jump_target))]
            edge_type = "true" if has_conditional else "unconditional"
            self.addItem(EdgeItem(src_bottom, self._block_top_center(dst_item), edge_type))

        if fail_target is not None and int(cast("int", fail_target)) in self.block_items:
            dst_item = self.block_items[int(cast("int", fail_target))]
            self.addItem(EdgeItem(src_bottom, self._block_top_center(dst_item), "false"))

    def _add_ghidra_style_edges(self, src_bottom: QPointF, block: dict[str, Any]) -> None:
        """Create edges from a Ghidra ``get_basic_blocks`` destination list.

        Args:
            src_bottom: Bottom-center scene point of the source block.
            block: Block dict carrying ``destination_edges`` (preferred) or a plain ``destinations`` address list, as documented on
                :meth:`_normalize_ghidra_edges`.
        """
        edges = self._normalize_ghidra_edges(block)
        conditional_count = sum(1 for edge in edges if edge["is_conditional"])

        for edge in edges:
            dest_addr = edge["address"]
            if dest_addr not in self.block_items:
                continue
            dst_item = self.block_items[dest_addr]
            if edge["is_conditional"]:
                edge_type = "true"
            elif edge["is_fallthrough"] and conditional_count:
                edge_type = "false"
            else:
                edge_type = "unconditional"
            self.addItem(EdgeItem(src_bottom, self._block_top_center(dst_item), edge_type))

    @staticmethod
    def _normalize_ghidra_edges(block: dict[str, Any]) -> list[dict[str, Any]]:
        """Normalize a Ghidra block's destination data to a common edge shape.

        Args:
            block: Block dict from :meth:`bridges.ghidra.GhidraBridge.get_basic_blocks`, carrying a ``destination_edges`` list of
                ``{'address': int, 'is_conditional': bool, 'is_fallthrough': bool}`` dicts (preferred, carries real Ghidra flow-type
                data), or a plain ``destinations`` address list as a fallback when flow-type data is unavailable.

        Returns:
            list[dict[str, Any]]: Normalized ``{'address': int, 'is_conditional': bool, 'is_fallthrough': bool}`` dicts.
        """
        edges_raw = block.get("destination_edges")
        if isinstance(edges_raw, list) and edges_raw:
            normalized: list[dict[str, Any]] = []
            for raw_edge in cast("list[dict[str, Any]]", edges_raw):
                address = raw_edge.get("address")
                if address is None:
                    continue
                normalized.append({
                    "address": int(cast("int", address)),
                    "is_conditional": bool(raw_edge.get("is_conditional", False)),
                    "is_fallthrough": bool(raw_edge.get("is_fallthrough", False)),
                })
            return normalized

        dest_raw = block.get("destinations", [])
        if not isinstance(dest_raw, list):
            return []
        return [{"address": int(dest), "is_conditional": False, "is_fallthrough": False} for dest in cast("list[int]", dest_raw)]

    @staticmethod
    def _block_top_center(item: BasicBlockItem) -> QPointF:
        """Compute the top-center scene point of a block item.

        Args:
            item: The block graphics item.

        Returns:
            QPointF: The top-center point of the item in scene coordinates.
        """
        pos = item.pos()
        rect = item.rect()
        return QPointF(pos.x() + rect.width() / 2, pos.y())

    @staticmethod
    def _block_bottom_center(item: BasicBlockItem) -> QPointF:
        """Compute the bottom-center scene point of a block item.

        Args:
            item: The block graphics item.

        Returns:
            QPointF: The bottom-center point of the item in scene coordinates.
        """
        pos = item.pos()
        rect = item.rect()
        return QPointF(pos.x() + rect.width() / 2, pos.y() + rect.height())

    @staticmethod
    def _compute_layers(
        block_map: dict[int, dict[str, Any]],
    ) -> dict[int, list[int]]:
        """Compute hierarchical layers via BFS from the first block.

        Args:
            block_map: Mapping of block address to block data.

        Returns:
            dict[int, list[int]]: Dict mapping layer index to list of block addresses.
        """
        if not block_map:
            return {}

        _logger.debug("layers_computing", block_count=len(block_map))
        all_addrs = set(block_map.keys())
        successors: dict[int, list[int]] = defaultdict(list)
        referenced: set[int] = set()

        for offset, block in block_map.items():
            jump_t = block.get("jump")
            fail_t = block.get("fail")
            if jump_t is not None or fail_t is not None:
                if jump_t is not None and int(cast("int", jump_t)) in all_addrs:
                    successors[offset].append(int(cast("int", jump_t)))
                    referenced.add(int(cast("int", jump_t)))
                if fail_t is not None and int(cast("int", fail_t)) in all_addrs:
                    successors[offset].append(int(cast("int", fail_t)))
                    referenced.add(int(cast("int", fail_t)))
                continue

            for edge in CFGGraphScene._normalize_ghidra_edges(block):
                dest_addr = edge["address"]
                if dest_addr in all_addrs:
                    successors[offset].append(dest_addr)
                    referenced.add(dest_addr)

        roots = [a for a in all_addrs if a not in referenced] or [min(all_addrs)]

        layers: dict[int, list[int]] = defaultdict(list)
        visited: set[int] = set()
        queue: deque[tuple[int, int]] = deque()

        for root in roots:
            queue.append((root, 0))
            visited.add(root)

        while queue:
            addr, layer = queue.popleft()
            layers[layer].append(addr)
            for succ in successors.get(addr, []):
                if succ not in visited:
                    visited.add(succ)
                    queue.append((succ, layer + 1))

        for addr in all_addrs - visited:
            max_layer = max(layers.keys()) if layers else 0
            layers[max_layer + 1].append(addr)

        return dict(layers)


class CFGGraphView(QGraphicsView):
    """Zoomable, pannable graphics view for CFG visualization.

    Emits ``block_clicked`` with the block address when a
    BasicBlockItem is clicked.

    Attributes:
        block_clicked: Signal emitted with block address when a basic block is clicked.
    """

    block_clicked: pyqtSignal = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the CFGGraphView widget.

        Args:
            parent: Parent widget.
        """
        scene = CFGGraphScene()
        super().__init__(scene, parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setBackgroundBrush(QBrush(_get_graph_colors()["background"]))
        ThemeManager.get_instance().theme_changed.connect(self._on_theme_changed)

    def _on_theme_changed(self, resolved_theme: str) -> None:
        """Re-resolve and reapply CFG colors when the application theme changes.

        Connected to :attr:`ThemeManager.theme_changed` so the view background
        and every already-rendered :class:`BasicBlockItem`/:class:`EdgeItem`
        track live theme switches instead of keeping the colors captured at
        construction time.

        Args:
            resolved_theme: The concrete theme now active ("dark" or "light").
        """
        _ = resolved_theme
        self.setBackgroundBrush(QBrush(_get_graph_colors()["background"]))
        scene = self.scene()
        if scene is None:
            return
        for item in scene.items():
            if isinstance(item, (BasicBlockItem, EdgeItem)):
                item.refresh_theme_colors()
        viewport = self.viewport()
        if viewport is not None:
            viewport.update()

    def graph_scene(self) -> CFGGraphScene:
        """Get the typed CFGGraphScene.

        Returns:
            CFGGraphScene: The CFGGraphScene instance.

        Raises:
            TypeError: If the scene is not a CFGGraphScene.
        """
        scene = self.scene()
        if isinstance(scene, CFGGraphScene):
            return scene
        msg = "Scene is not a CFGGraphScene"
        raise TypeError(msg)

    def fit_to_view(self) -> None:
        """Zoom and pan to fit the entire graph in the viewport."""
        scene = self.scene()
        if scene is not None:
            self.fitInView(scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    @override
    def wheelEvent(self, event: QWheelEvent | None) -> None:
        """Zoom with mouse wheel.

        Args:
            event: Wheel event.
        """
        if event is None:
            return
        if event.angleDelta().y() > 0:
            self.scale(_ZOOM_FACTOR, _ZOOM_FACTOR)
        else:
            self.scale(1.0 / _ZOOM_FACTOR, 1.0 / _ZOOM_FACTOR)

    @override
    def mousePressEvent(self, event: QMouseEvent | None) -> None:
        """Handle mouse press and emit block_clicked for block selection.

        Args:
            event: Mouse event.
        """
        super().mousePressEvent(event)
        if event is None:
            return
        item = self.itemAt(event.pos())
        if isinstance(item, BasicBlockItem):
            self.block_clicked.emit(item.block_address)


def _parse_sort_value(text: str) -> int | None:
    """Parse a table cell as an integer for numeric sorting.

    Hexadecimal strings (``0x``/``0X`` prefixed, optionally negative) are parsed
    in base 16; all other non-empty strings are parsed in base 10.

    Args:
        text: The cell text to interpret.

    Returns:
        int | None: The parsed integer value, or None when the text is empty or
        cannot be parsed as an integer.
    """
    stripped = text.strip()
    if not stripped:
        return None
    try:
        if stripped.lower().removeprefix("-").startswith("0x"):
            return int(stripped, 16)
        return int(stripped)
    except ValueError:
        return None


class NumericSortTreeItem(QTreeWidgetItem):
    """QTreeWidgetItem that orders columns by numeric value when possible.

    Function listings render addresses as hexadecimal strings and sizes as decimal strings. The default QTreeWidgetItem comparison is
    lexicographic, so ``0x9`` sorts after ``0x1000`` and ``"100"`` sorts before ``"20"``. This subclass parses both cells of the active sort
    column as integers (base 16 for ``0x`` prefixed text, base 10 otherwise) and compares them numerically, falling back to case-insensitive
    string comparison when either cell is not numeric.
    """

    @override
    def __lt__(self, other: QTreeWidgetItem) -> bool:
        """Compare this item to another by the active sort column.

        Args:
            other: The item to compare against.

        Returns:
            bool: True if this item orders before ``other``.
        """
        tree = self.treeWidget()
        column = tree.sortColumn() if tree is not None else 0
        left_text = self.text(column)
        right_text = other.text(column)
        left_value = _parse_sort_value(left_text)
        right_value = _parse_sort_value(right_text)
        if left_value is not None and right_value is not None:
            return left_value < right_value
        return left_text.casefold() < right_text.casefold()
