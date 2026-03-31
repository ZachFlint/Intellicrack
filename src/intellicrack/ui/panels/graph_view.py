# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""
Control flow graph view for Cutter/Rizin function analysis.

Provides QGraphicsView-based rendering of function CFGs parsed from
Cutter/Rizin ``agj`` JSON output with hierarchical block layout, colored
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
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.resources.font_manager import FontManager
from intellicrack.ui.resources.theme_manager import ThemeManager


_logger = get_logger("ui.panels.graph_view")

_BLOCK_PADDING: Final[int] = 10
_BLOCK_MIN_WIDTH: Final[int] = 200
_LINE_HEIGHT: Final[int] = 16
_HEADER_HEIGHT: Final[int] = 22
_LAYER_SPACING_V: Final[int] = 60
_LAYER_SPACING_H: Final[int] = 30
_ARROW_SIZE: Final[int] = 8
_ZOOM_FACTOR: Final[float] = 1.15


def _get_graph_colors() -> dict[str, QColor]:
    """
    Get theme-aware colors for CFG rendering.

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
    """
    Renders a single basic block as a styled rectangle with assembly text.

    Args:
        block_address: Start address of the block.
        ops: List of instruction dicts from r2 agj (offset, disasm, ...).
        parent: Parent graphics item.
    """

    def __init__(
        self,
        block_address: int,
        ops: list[dict[str, Any]],
        parent: QGraphicsItem | None = None,
    ) -> None:
        self.block_address = block_address
        self._ops = ops
        fm = FontManager.get_instance()
        self._font = fm.get_code_font(8)
        self._header_font = fm.get_code_font_bold(8)
        self._colors = _get_graph_colors()

        text_width = max(len(op.get("disasm", "")) for op in ops) * 7 if ops else 10
        width = max(_BLOCK_MIN_WIDTH, text_width + _BLOCK_PADDING * 2)
        height = _HEADER_HEIGHT + len(ops) * _LINE_HEIGHT + _BLOCK_PADDING

        super().__init__(0, 0, width, height, parent)
        self.setPen(QPen(self._colors["block_border"], 1.5))
        self.setBrush(QBrush(self._colors["block_bg"]))
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, enabled=True)

    @override
    def paint(
        self,
        painter: QPainter | None,
        option: QStyleOptionGraphicsItem | None,
        widget: QWidget | None = None,
    ) -> None:
        """
        Paint the block with header and assembly lines.

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
    """
    Bezier curve edge between basic blocks with directional arrow.

    Args:
        start: Source point (bottom center of source block).
        end: Destination point (top center of target block).
        edge_type: Branch type for coloring.
        parent: Parent graphics item.
    """

    def __init__(
        self,
        start: QPointF,
        end: QPointF,
        edge_type: str = "unconditional",
        parent: QGraphicsItem | None = None,
    ) -> None:
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

    @override
    def paint(
        self,
        painter: QPainter | None,
        option: QStyleOptionGraphicsItem | None,
        widget: QWidget | None = None,
    ) -> None:
        """
        Paint the edge path and arrowhead.

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
    """
    Scene that parses r2 agj output and lays out basic blocks hierarchically.

    Args:
        parent: Parent widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.block_items: dict[int, BasicBlockItem] = {}

    def load_graph(self, blocks: list[dict[str, Any]]) -> None:
        """
        Parse r2 agj blocks and lay them out hierarchically.

        Args:
            blocks: List of basic block dicts from r2 ``agj`` output.
        """
        _logger.debug("graph_loading", block_count=len(blocks))
        self.clear()
        self.block_items.clear()

        if not blocks:
            return

        block_map = self._build_block_map(blocks)
        layers = self._compute_layers(block_map)
        self._position_layers(layers)
        self._create_edges(block_map)
        _logger.debug("graph_loaded", blocks=len(self.block_items), layers=len(layers))

    def _build_block_map(self, blocks: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
        """
        Build a mapping of offsets to blocks and create scene items.

        Args:
            blocks: Raw block dicts from r2 ``agj`` output.

        Returns:
            dict[int, dict[str, Any]]: Mapping of offset to block data.
        """
        block_map: dict[int, dict[str, Any]] = {}
        for block in blocks:
            offset = int(block.get("offset", 0))
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
        """
        Compute positions for blocks in each layer and apply them.

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
        """
        Create edge items between blocks based on jump/fail targets.

        Args:
            block_map: Mapping of block address to block data.
        """
        for offset, block in block_map.items():
            if offset not in self.block_items:
                continue
            src_item = self.block_items[offset]
            src_rect = src_item.rect()
            src_pos = src_item.pos()
            src_bottom = QPointF(
                src_pos.x() + src_rect.width() / 2,
                src_pos.y() + src_rect.height(),
            )

            jump_target = block.get("jump")
            fail_target = block.get("fail")

            has_conditional = jump_target is not None and fail_target is not None

            if jump_target is not None and int(jump_target) in self.block_items:
                dst_item = self.block_items[int(jump_target)]
                dst_pos = dst_item.pos()
                dst_top = QPointF(
                    dst_pos.x() + dst_item.rect().width() / 2,
                    dst_pos.y(),
                )
                edge_type = "true" if has_conditional else "unconditional"
                edge = EdgeItem(src_bottom, dst_top, edge_type)
                self.addItem(edge)

            if fail_target is not None and int(fail_target) in self.block_items:
                dst_item = self.block_items[int(fail_target)]
                dst_pos = dst_item.pos()
                dst_top = QPointF(
                    dst_pos.x() + dst_item.rect().width() / 2,
                    dst_pos.y(),
                )
                edge = EdgeItem(src_bottom, dst_top, "false")
                self.addItem(edge)

    @staticmethod
    def _compute_layers(
        block_map: dict[int, dict[str, Any]],
    ) -> dict[int, list[int]]:
        """
        Compute hierarchical layers via BFS from the first block.

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
            if jump_t is not None and int(jump_t) in all_addrs:
                successors[offset].append(int(jump_t))
                referenced.add(int(jump_t))
            if fail_t is not None and int(fail_t) in all_addrs:
                successors[offset].append(int(fail_t))
                referenced.add(int(fail_t))

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
    """
    Zoomable, pannable graphics view for CFG visualization.

    Emits ``block_clicked`` with the block address when a
    BasicBlockItem is clicked.

    Args:
        parent: Parent widget.

    Attributes:
        block_clicked: Signal emitted with block address when a basic block is clicked.
    """

    block_clicked: pyqtSignal = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        scene = CFGGraphScene()
        super().__init__(scene, parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setBackgroundBrush(QBrush(_get_graph_colors()["background"]))

    def graph_scene(self) -> CFGGraphScene:
        """
        Get the typed CFGGraphScene.

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
        """
        Zoom with mouse wheel.

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
        """
        Handle mouse press and emit block_clicked for block selection.

        Args:
            event: Mouse event.
        """
        super().mousePressEvent(event)
        if event is None:
            return
        item = self.itemAt(event.pos())
        if isinstance(item, BasicBlockItem):
            self.block_clicked.emit(item.block_address)
