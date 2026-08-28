"""
Wireshark-accurate Icon Provider & Vector SVG Asset Resolver for KShark.

Loads the authentic 16x16 & 14x14 SVG vector icons from the Wireshark stock assets
with high-DPI scaling and high-contrast fallbacks.
"""

from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QPen, QBrush, QPolygonF
from PyQt6.QtCore import Qt, QPointF, QRectF
from pathlib import Path
from typing import Optional
import os

STOCK_DIR = Path(__file__).resolve().parent / "icons" / "stock"
ICONS_DIR = Path(__file__).resolve().parent / "icons"


class KSharkIcons:
    """Provides authentic Wireshark vector SVG toolbar & action icons."""

    @classmethod
    def _load_svg(cls, rel_path: str, fallback_icon: Optional[QIcon] = None) -> QIcon:
        svg_file = STOCK_DIR / rel_path
        if svg_file.exists():
            icon = QIcon(str(svg_file))
            if not icon.isNull():
                return icon
        if fallback_icon is not None:
            return fallback_icon
        return QIcon()

    @classmethod
    def get_app_icon(cls) -> QIcon:
        svg_path = ICONS_DIR / "app_icon.svg"
        if svg_path.exists():
            return QIcon(str(svg_path))
        return cls._load_svg("16x16/x-capture-start.svg")

    @classmethod
    def capture_start(cls) -> QIcon:
        """Wireshark Blue Shark Fin Start icon."""
        return cls._load_svg("16x16/x-capture-start.svg")

    @classmethod
    def capture_stop(cls) -> QIcon:
        """Wireshark Red Square Stop icon."""
        return cls._load_svg("16x16/x-capture-stop-red.svg")

    @classmethod
    def capture_restart(cls) -> QIcon:
        """Wireshark Green Reload Circular Arrow icon."""
        return cls._load_svg("16x16/x-capture-restart-turn1.svg")

    @classmethod
    def capture_options(cls) -> QIcon:
        """Wireshark Capture Options Gear icon."""
        return cls._load_svg("16x16/x-capture-options-gear.svg")

    @classmethod
    def file_open(cls) -> QIcon:
        """Open file / folder icon."""
        pix = QPixmap(16, 16)
        pix.fill(Qt.GlobalColor.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        # Folder back tab
        p.setBrush(QBrush(QColor("#0078D7")))
        p.setPen(QPen(QColor("#005A9E"), 1))
        p.drawRoundedRect(1, 2, 8, 4, 1, 1)
        # Folder body
        p.setBrush(QBrush(QColor("#50A8EC")))
        p.setPen(QPen(QColor("#005A9E"), 1))
        p.drawRoundedRect(1, 4, 14, 10, 1, 1)
        # White paper sheet inside
        p.setBrush(QBrush(QColor("#FFFFFF")))
        p.setPen(QPen(QColor("#D0D0D0"), 1))
        p.drawRect(4, 5, 8, 8)
        p.end()
        return QIcon(pix)

    @classmethod
    def file_save(cls) -> QIcon:
        return cls._load_svg("16x16/x-capture-file-save.svg")

    @classmethod
    def file_close(cls) -> QIcon:
        return cls._load_svg("16x16/x-capture-file-close.svg")

    @classmethod
    def file_reload(cls) -> QIcon:
        return cls._load_svg("16x16/x-capture-file-reload.svg")

    @classmethod
    def nav_find(cls) -> QIcon:
        return cls._load_svg("16x16/edit-find.template.svg")

    @classmethod
    def nav_prev(cls) -> QIcon:
        return cls._load_svg("16x16/go-previous.svg")

    @classmethod
    def nav_next(cls) -> QIcon:
        return cls._load_svg("16x16/go-next.svg")

    @classmethod
    def nav_goto(cls) -> QIcon:
        return cls._load_svg("16x16/go-jump.svg")

    @classmethod
    def nav_first(cls) -> QIcon:
        return cls._load_svg("16x16/go-first.svg")

    @classmethod
    def nav_last(cls) -> QIcon:
        return cls._load_svg("16x16/go-last.svg")

    @classmethod
    def autoscroll(cls) -> QIcon:
        """Wireshark arrow pointing to line (Stay Last)."""
        return cls._load_svg("16x16/x-stay-last.svg")

    @classmethod
    def colorize(cls) -> QIcon:
        """Wireshark Colorize Packets color grid."""
        return cls._load_svg("16x16/x-colorize-packets.svg")

    @classmethod
    def resize_columns(cls) -> QIcon:
        return cls._load_svg("16x16/x-resize-columns.svg")

    @classmethod
    def zoom_in(cls) -> QIcon:
        return cls._load_svg("16x16/zoom-in.template.svg")

    @classmethod
    def zoom_out(cls) -> QIcon:
        return cls._load_svg("16x16/zoom-out.template.svg")

    @classmethod
    def zoom_100(cls) -> QIcon:
        return cls._load_svg("16x16/zoom-original.template.svg")

    @classmethod
    def filter_bookmark(cls) -> QIcon:
        """Wireshark display filter green/blue bookmark ribbon."""
        return cls._load_svg("14x14/x-display-filter-bookmark.svg")

    @classmethod
    def filter_bookmark_capture(cls) -> QIcon:
        """Wireshark capture filter bookmark ribbon."""
        return cls._load_svg("14x14/x-capture-filter-bookmark.svg")

    @classmethod
    def filter_clear(cls) -> QIcon:
        """Wireshark clear cross icon."""
        return cls._load_svg("14x14/x-filter-clear.svg")

    @classmethod
    def filter_apply(cls) -> QIcon:
        """Wireshark right arrow apply icon."""
        pix = QPixmap(16, 16)
        pix.fill(Qt.GlobalColor.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(QColor("#2E7D32")))
        p.setPen(Qt.PenStyle.NoPen)
        arrow = QPolygonF([QPointF(4, 3), QPointF(13, 8), QPointF(4, 13)])
        p.drawPolygon(arrow)
        p.end()
        return QIcon(pix)

    @classmethod
    def expert_indicators(cls) -> QIcon:
        """Wireshark expert indicators badge."""
        return cls._load_svg("14x14/x-expert-indicators-all.svg")

    @classmethod
    def shield_critical(cls) -> QIcon:
        """Red shield for critical threats."""
        pix = QPixmap(16, 16)
        pix.fill(Qt.GlobalColor.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(QColor("#FF4444")))
        p.setPen(QPen(QColor("#FFFFFF"), 1))
        shield = QPolygonF([
            QPointF(8, 2), QPointF(14, 4), QPointF(14, 9),
            QPointF(8, 14), QPointF(2, 9), QPointF(2, 4)
        ])
        p.drawPolygon(shield)
        p.end()
        return QIcon(pix)
