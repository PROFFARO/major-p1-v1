"""
KShark Vector SVG & Dynamic QPainter Icon Factory.
Generates pixel-accurate KShark Cloud Teal & Wireshark UI icons.
"""

from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QPen, QBrush, QPolygonF
from PyQt6.QtCore import Qt, QPointF, QRectF, QByteArray
from PyQt6.QtSvg import QSvgRenderer
import xml.etree.ElementTree as ET


class KSharkIcons:
    """Centralized Icon Factory for KShark Desktop Application."""

    @staticmethod
    def _render_svg(svg_str: str, size: int = 16) -> QIcon:
        renderer = QSvgRenderer(QByteArray(svg_str.encode('utf-8')))
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        renderer.render(painter)
        painter.end()
        return QIcon(pixmap)

    @classmethod
    def get_app_icon(cls) -> QIcon:
        """KShark Teal Shark Fin App Icon."""
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Teal Shark Fin
        painter.setBrush(QBrush(QColor("#0E9AA7")))
        painter.setPen(QPen(QColor("#0A2A32"), 2))

        poly = QPolygonF([
            QPointF(12, 54),
            QPointF(24, 22),
            QPointF(52, 10),
            QPointF(42, 38),
            QPointF(54, 54),
        ])
        painter.drawPolygon(poly)

        # Cloud Wave Accent
        painter.setPen(QPen(QColor("#2BC1CF"), 3))
        painter.drawLine(8, 56, 56, 56)

        painter.end()
        return QIcon(pixmap)

    @classmethod
    def capture_start(cls) -> QIcon:
        """KShark Start Capture Shark Fin."""
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M 2,14 Q 5,6 12,2 Q 9,8 14,14 Z" fill="#0E9AA7" stroke="#0A2A32" stroke-width="1.2"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def capture_stop(cls) -> QIcon:
        """Red Square Stop Icon."""
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <rect x="3" y="3" width="10" height="10" rx="1.5" fill="#C92A2A" stroke="#800000" stroke-width="1"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def capture_restart(cls) -> QIcon:
        """Green Circular Restart Icon."""
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M 8,3 A 5,5 0 1,0 13,8 L 11,8 A 3,3 0 1,1 8,5 L 8,7 L 12,4 L 8,1 Z" fill="#0EA773"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def capture_options(cls) -> QIcon:
        """Capture Options Gear Icon."""
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <circle cx="8" cy="8" r="3" fill="none" stroke="#5A7076" stroke-width="2"/>
            <path d="M8,1 L8,3 M8,13 L8,15 M1,8 L3,8 M13,8 L15,8 M3,3 L4.5,4.5 M11.5,11.5 L13,13 M3,13 L4.5,11.5 M11.5,4.5 L13,3" stroke="#5A7076" stroke-width="2" stroke-linecap="round"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def file_open(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M 2,3 L 6,3 L 8,5 L 14,5 L 14,13 L 2,13 Z" fill="#F0C674" stroke="#8C6D1F" stroke-width="1"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def file_save(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M 2,2 L 12,2 L 14,4 L 14,14 L 2,14 Z" fill="#4B6EAF" stroke="#2B4372" stroke-width="1"/>
            <rect x="4" y="2" width="6" height="4" fill="#FFFFFF"/>
            <rect x="4" y="8" width="8" height="5" fill="#FFFFFF"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def file_close(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M 3,3 L 13,13 M 13,3 L 3,13" stroke="#C92A2A" stroke-width="2.5" stroke-linecap="round"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def file_reload(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M 8,2 A 6,6 0 1,0 14,8 L 12,8 A 4,4 0 1,1 8,4 L 8,6 L 12,3 L 8,0 Z" fill="#0E9AA7"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def search_find(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <circle cx="6.5" cy="6.5" r="4.5" fill="none" stroke="#5A7076" stroke-width="2"/>
            <line x1="10" y1="10" x2="14.5" y2="14.5" stroke="#5A7076" stroke-width="2.5" stroke-linecap="round"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def go_previous(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M 12,3 L 4,8 L 12,13 Z" fill="#0EA773"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def go_next(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M 4,3 L 12,8 L 4,13 Z" fill="#0EA773"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def go_first(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <rect x="2" y="3" width="2.5" height="10" fill="#0EA773"/>
            <path d="M 13,3 L 6,8 L 13,13 Z" fill="#0EA773"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def go_last(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M 3,3 L 10,8 L 3,13 Z" fill="#0EA773"/>
            <rect x="11.5" y="3" width="2.5" height="10" fill="#0EA773"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def auto_scroll(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <line x1="8" y1="2" x2="8" y2="11" stroke="#0E9AA7" stroke-width="2"/>
            <path d="M 4,9 L 8,14 L 12,9 Z" fill="#0E9AA7"/>
            <line x1="3" y1="14.5" x2="13" y2="14.5" stroke="#0A2A32" stroke-width="1.5"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def colorize(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <rect x="2" y="2" width="12" height="3" fill="#0EA773"/>
            <rect x="2" y="6.5" width="12" height="3" fill="#2BC1CF"/>
            <rect x="2" y="11" width="12" height="3" fill="#F0C674"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def zoom_in(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <circle cx="6.5" cy="6.5" r="4.5" fill="none" stroke="#5A7076" stroke-width="1.8"/>
            <line x1="10" y1="10" x2="14" y2="14" stroke="#5A7076" stroke-width="2" stroke-linecap="round"/>
            <line x1="4.5" y1="6.5" x2="8.5" y2="6.5" stroke="#0E9AA7" stroke-width="1.8"/>
            <line x1="6.5" y1="4.5" x2="6.5" y2="8.5" stroke="#0E9AA7" stroke-width="1.8"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def zoom_out(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <circle cx="6.5" cy="6.5" r="4.5" fill="none" stroke="#5A7076" stroke-width="1.8"/>
            <line x1="10" y1="10" x2="14" y2="14" stroke="#5A7076" stroke-width="2" stroke-linecap="round"/>
            <line x1="4.5" y1="6.5" x2="8.5" y2="6.5" stroke="#0E9AA7" stroke-width="1.8"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def zoom_100(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <circle cx="6.5" cy="6.5" r="4.5" fill="none" stroke="#5A7076" stroke-width="1.8"/>
            <line x1="10" y1="10" x2="14" y2="14" stroke="#5A7076" stroke-width="2" stroke-linecap="round"/>
            <circle cx="6.5" cy="6.5" r="1.5" fill="#0E9AA7"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def resize_columns(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <line x1="2" y1="2" x2="2" y2="14" stroke="#5A7076" stroke-width="2"/>
            <line x1="14" y1="2" x2="14" y2="14" stroke="#5A7076" stroke-width="2"/>
            <path d="M 6,5 L 3,8 L 6,11 Z M 10,5 L 13,8 L 10,11 Z" fill="#0E9AA7"/>
            <line x1="5" y1="8" x2="11" y2="8" stroke="#0E9AA7" stroke-width="1.5"/>
        </svg>"""
        return cls._render_svg(svg, 16)
