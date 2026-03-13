# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Control flow graph view for Cutter/Rizin function analysis.

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
    QFont,
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


_logger = get_logger("ui.panels.graph_view")

_BLOCK_PADDING: Final[int] = 10
_BLOCK_MIN_WIDTH: Final[int] = 200
_LINE_HEIGHT: Final[int] = 16
_HEADER_HEIGHT: Final[int] = 22
_LAYER_SPACING_V: Final[int] = 60
_LAYER_SPACING_H: Final[int] = 30
_ARROW_SIZE: Final[int] = 8
_ZOOM_FACTOR: Final[float] = 1.15

_COLOR_BLOCK_BG = QColor(40, 44, 52)
_COLOR_BLOCK_BORDER = QColor(80, 85, 95)
_COLOR_HEADER_BG = QColor(55, 60, 72)
_COLOR_HEADER_TEXT = QColor(220, 220, 220)
_COLOR_ASM_TEXT = QColor(190, 190, 190)
_COLOR_MNEMONIC_JUMP = QColor(86, 156, 214)
_COLOR_MNEMONIC_CALL = QColor(78, 201, 176)
_COLOR_MNEMONIC_RET = QColor(206, 106, 106)
_COLOR_EDGE_TRUE = QColor(80, 200, 80)
_COLOR_EDGE_FALSE = QColor(200, 80, 80)
_COLOR_EDGE_UNCOND = QColor(150, 150, 150)
_COLOR_SELECTED_BORDER = QColor(100, 150, 255)

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
    """Renders a single basic block as a styled rectangle with assembly text.

    Attributes:
        block_address: Start address of the basic block.
    """

    def __init__(
        self,
        block_address: int,
        ops: list[dict[str, Any]],
        parent: QGraphicsItem | None = None,
    ) -> None:
        """Initialize a basic block item.

        Args:
            block_address: Start address of the block.
            ops: List of instruction dicts from r2 agj (offset, disasm, ...).
            parent: Parent graphics item.
        """
        self.block_address = block_address
        self._ops = ops
        self._font = QFont("JetBrains Mono", 8)
        self._header_font = QFont("JetBrains Mono", 8, QFont.Weight.Bold)

        text_width = max(len(op.get("disasm", "")) for op in ops) * 7 if ops else 10
        width = max(_BLOCK_MIN_WIDTH, text_width + _BLOCK_PADDING * 2)
        height = _HEADER_HEIGHT + len(ops) * _LINE_HEIGHT + _BLOCK_PADDING

        super().__init__(0, 0, width, height, parent)
        self.setPen(QPen(_COLOR_BLOCK_BORDER, 1.5))
        self.setBrush(QBrush(_COLOR_BLOCK_BG))
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)

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

        if self.isSelected():
            painter.setPen(QPen(_COLOR_SELECTED_BORDER, 2.0))
        else:
            painter.setPen(QPen(_COLOR_BLOCK_BORDER, 1.5))
        painter.setBrush(QBrush(_COLOR_BLOCK_BG))
        painter.drawRoundedRect(rect, 4, 4)

        header_rect = QRectF(rect.x(), rect.y(), rect.width(), _HEADER_HEIGHT)
        painter.setBrush(QBrush(_COLOR_HEADER_BG))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(header_rect, 4, 4)
        clip_rect = QRectF(rect.x(), rect.y() + 4, rect.width(), _HEADER_HEIGHT - 4)
        painter.drawRect(clip_rect)

        painter.setFont(self._header_font)
        painter.setPen(_COLOR_HEADER_TEXT)
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
                painter.setPen(_COLOR_MNEMONIC_JUMP)
            elif mnemonic in _CALL_MNEMONICS:
                painter.setPen(_COLOR_MNEMONIC_CALL)
            elif mnemonic in _RET_MNEMONICS:
                painter.setPen(_COLOR_MNEMONIC_RET)
            else:
                painter.setPen(_COLOR_ASM_TEXT)

            painter.drawText(
                QRectF(rect.x() + _BLOCK_PADDING, y, rect.width() - _BLOCK_PADDING * 2, _LINE_HEIGHT),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                disasm,
            )
            y += _LINE_HEIGHT


class EdgeItem(QGraphicsPathItem):
    """Bezier curve edge between basic blocks with directional arrow.

    Attributes:
        edge_type: One of "true", "false", or "unconditional".
    """

    def __init__(
        self,
        start: QPointF,
        end: QPointF,
        edge_type: str = "unconditional",
        parent: QGraphicsItem | None = None,
    ) -> None:
        """Initialize an edge item.

        Args:
            start: Source point (bottom center of source block).
            end: Destination point (top center of target block).
            edge_type: Branch type for coloring.
            parent: Parent graphics item.
        """
        super().__init__(parent)
        self.edge_type = edge_type

        if edge_type == "true":
            color = _COLOR_EDGE_TRUE
        elif edge_type == "false":
            color = _COLOR_EDGE_FALSE
        else:
            color = _COLOR_EDGE_UNCOND

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
    """Scene that parses r2 agj output and lays out basic blocks hierarchically."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the CFG graph scene.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._block_items: dict[int, BasicBlockItem] = {}

    def load_graph(self, blocks: list[dict[str, Any]]) -> None:
        """Parse r2 agj blocks and lay them out hierarchically.

        Args:
            blocks: List of basic block dicts from r2 ``agj`` output.
        """
        self.clear()
        self._block_items.clear()

        if not blocks:
            return

        block_map: dict[int, dict[str, Any]] = {}
        for block in blocks:
            offset = int(block.get("offset", 0))
            block_map[offset] = block

        for offset, block in block_map.items():
            ops = block.get("ops", [])
            if not isinstance(ops, list):
                ops = []
            item = BasicBlockItem(offset, cast("list[dict[str, Any]]", ops))
            self._block_items[offset] = item
            self.addItem(item)

        layers = self._compute_layers(block_map)

        layer_widths: dict[int, float] = {}
        for layer_idx, addrs in layers.items():
            total_w = sum(self._block_items[a].rect().width() for a in addrs if a in self._block_items)
            total_w += _LAYER_SPACING_H * max(0, len(addrs) - 1)
            layer_widths[layer_idx] = total_w

        max_width = max(layer_widths.values()) if layer_widths else 0
        y_offset = 0.0

        for layer_idx in sorted(layers.keys()):
            addrs = layers[layer_idx]
            layer_w = layer_widths[layer_idx]
            x_start = (max_width - layer_w) / 2
            x = x_start

            for addr in addrs:
                if addr not in self._block_items:
                    continue
                item = self._block_items[addr]
                item.setPos(x, y_offset)
                x += item.rect().width() + _LAYER_SPACING_H

            max_height = max(
                (self._block_items[a].rect().height() for a in addrs if a in self._block_items),
                default=0,
            )
            y_offset += max_height + _LAYER_SPACING_V

        self._create_edges(block_map)

    def _create_edges(self, block_map: dict[int, dict[str, Any]]) -> None:
        """Create edge items between blocks based on jump/fail targets.

        Args:
            block_map: Mapping of block address to block data.
        """
        for offset, block in block_map.items():
            if offset not in self._block_items:
                continue
            src_item = self._block_items[offset]
            src_rect = src_item.rect()
            src_pos = src_item.pos()
            src_bottom = QPointF(
                src_pos.x() + src_rect.width() / 2,
                src_pos.y() + src_rect.height(),
            )

            jump_target = block.get("jump")
            fail_target = block.get("fail")

            has_conditional = jump_target is not None and fail_target is not None

            if jump_target is not None and int(jump_target) in self._block_items:
                dst_item = self._block_items[int(jump_target)]
                dst_pos = dst_item.pos()
                dst_top = QPointF(
                    dst_pos.x() + dst_item.rect().width() / 2,
                    dst_pos.y(),
                )
                edge_type = "true" if has_conditional else "unconditional"
                edge = EdgeItem(src_bottom, dst_top, edge_type)
                self.addItem(edge)

            if fail_target is not None and int(fail_target) in self._block_items:
                dst_item = self._block_items[int(fail_target)]
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
        """Compute hierarchical layers via BFS from the first block.

        Args:
            block_map: Mapping of block address to block data.

        Returns:
            Dict mapping layer index to list of block addresses.
        """
        if not block_map:
            return {}

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

        roots = [a for a in all_addrs if a not in referenced]
        if not roots:
            roots = [min(all_addrs)]

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
    """

    block_clicked: pyqtSignal = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the CFG graph view.

        Args:
            parent: Parent widget.
        """
        scene = CFGGraphScene()
        super().__init__(scene, parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setBackgroundBrush(QBrush(QColor(30, 30, 30)))

    def graph_scene(self) -> CFGGraphScene:
        """Get the typed CFGGraphScene.

        Returns:
            The CFGGraphScene instance.
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
    def mousePressEvent(self, event: Any) -> None:
        """Handle mouse press and emit block_clicked for block selection.

        Args:
            event: Mouse event.
        """
        super().mousePressEvent(event)
        item = self.itemAt(event.pos())
        if isinstance(item, BasicBlockItem):
            self.block_clicked.emit(item.block_address)
