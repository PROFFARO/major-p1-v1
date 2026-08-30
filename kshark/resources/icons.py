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
            <path d="M 2,13.5 C 3,8 6.5,2.5 13.5,2 C 10,6.5 10.5,10.5 13.5,13.5 Z" fill="#2BC1CF" stroke="#0E9AA7" stroke-width="0.8"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def capture_stop(cls) -> QIcon:
        """Red Square Stop Icon."""
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <rect x="3" y="3" width="10" height="10" rx="1.5" fill="#E74C3C" stroke="#C0392B" stroke-width="1"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def capture_restart(cls) -> QIcon:
        """Green Circular Restart Icon."""
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M 8,3 A 5,5 0 1,0 13,8 L 11,8 A 3,3 0 1,1 8,5 L 8,7 L 12,4 L 8,1 Z" fill="#2ECC71"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def capture_options(cls) -> QIcon:
        """Capture Options Gear Icon."""
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <circle cx="8" cy="8" r="5" fill="none" stroke="#8A9EA4" stroke-width="1.6"/>
            <circle cx="8" cy="8" r="2.2" fill="#8A9EA4"/>
            <path d="M 8,1 L 8,3 M 8,13 L 8,15 M 1,8 L 3,8 M 13,8 L 15,8 M 3,3 L 4.5,4.5 M 11.5,11.5 L 13,13 M 3,13 L 4.5,11.5 M 11.5,4.5 L 13,3" stroke="#8A9EA4" stroke-width="1.6" stroke-linecap="round"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def file_open(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M 1.5,3 L 6,3 L 7.5,4.5 L 14.5,4.5 L 14.5,13 L 1.5,13 Z" fill="#F39C12" stroke="#D68910" stroke-width="0.8"/>
            <path d="M 1.5,6 L 14.5,6 L 13,13 L 1.5,13 Z" fill="#F5B041" opacity="0.9"/>
        </svg>"""
        return cls._render_svg(svg, 16)

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
    def tab_tree(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M2,3 L8,3 M2,8 L8,8 M2,13 L8,13 M2,3 L2,13 M8,1 L14,1 L14,5 L8,5 Z M8,6 L14,6 L14,10 L8,10 Z M8,11 L14,11 L14,15 L8,15 Z" stroke="#0E9AA7" stroke-width="1.2" fill="none"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def tab_threat(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M8,1 L14,4 L14,9 C14,13 8,15 8,15 C8,15 2,13 2,9 L2,4 Z" fill="#E74C3C" stroke="#C0392B" stroke-width="1"/>
            <path d="M8,4 L8,9 M8,11 L8,12" stroke="#FFFFFF" stroke-width="1.5" stroke-linecap="round"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def tab_process(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <rect x="3" y="3" width="10" height="10" rx="2" fill="#2ECC71" stroke="#27AE60" stroke-width="1"/>
            <path d="M1,6 L3,6 M1,10 L3,10 M13,6 L15,6 M13,10 L15,10 M6,1 L6,3 M10,1 L10,3 M6,13 L6,15 M10,13 L10,15" stroke="#FFFFFF" stroke-width="1.2"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def tab_metrics(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <rect x="2" y="10" width="3" height="5" fill="#3498DB"/>
            <rect x="6.5" y="6" width="3" height="9" fill="#3498DB"/>
            <rect x="11" y="2" width="3" height="13" fill="#3498DB"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def tab_hex(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <text x="1" y="12" font-family="monospace" font-size="10" font-weight="bold" fill="#0E9AA7">0x</text>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def tab_decoder(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <rect x="2" y="2" width="12" height="12" rx="1.5" fill="none" stroke="#E67E22" stroke-width="1.2"/>
            <path d="M5,5 L11,5 M5,8 L11,8 M5,11 L11,11" stroke="#E67E22" stroke-width="1.2"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def tab_strings(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <text x="3" y="12" font-family="sans-serif" font-size="12" font-weight="bold" fill="#9B59B6">"S"</text>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def tab_code(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M5,4 L2,8 L5,12 M11,4 L14,8 L11,12" stroke="#F1C40F" stroke-width="1.5" fill="none" stroke-linecap="round"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def tab_json(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M3,2 L10,2 L13,5 L13,14 L3,14 Z" fill="#2C3E50" stroke="#7F8C8D" stroke-width="1"/>
            <path d="M5,8 L11,8 M5,11 L9,11" stroke="#BDC3C7" stroke-width="1"/>
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
    def filter_bookmark(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M4,2.5 L12,2.5 L12,14 L8,11.2 L4,14 Z" fill="none" stroke="#2BC1CF" stroke-width="1.5" stroke-linejoin="round"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def filter_history(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M 3.2,5.2 A 5.5,5.5 0 1,1 2.5,8" fill="none" stroke="#2BC1CF" stroke-width="1.5" stroke-linecap="round"/>
            <path d="M 1.5,3.2 L 3.2,5.2 L 5.5,3.8" fill="none" stroke="#2BC1CF" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M 8,5 L 8,8 L 10.5,9.5" fill="none" stroke="#2BC1CF" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def filter_clear(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M4,4 L12,12 M12,4 L4,12" stroke="#E74C3C" stroke-width="2" stroke-linecap="round"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def filter_apply(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M3,8 L11,8 M8,4 L12,8 L8,12" stroke="#2ECC71" stroke-width="2" stroke-linecap="round"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def filter_add(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M8,3 L8,13 M3,8 L13,8" stroke="#0E9AA7" stroke-width="2" stroke-linecap="round"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def go_to_packet(cls) -> QIcon:
        """Exact Wireshark 'Go to specified packet' document pointer icon."""
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <!-- Document Frame -->
            <rect x="3" y="1" width="11" height="14" rx="1.5" fill="#FAFAFA" stroke="#546E7A" stroke-width="1.1"/>
            <!-- Document Lines -->
            <line x1="5.5" y1="3.5" x2="12" y2="3.5" stroke="#37474F" stroke-width="1" stroke-linecap="round"/>
            <line x1="5.5" y1="5.5" x2="12" y2="5.5" stroke="#37474F" stroke-width="1" stroke-linecap="round"/>
            <!-- Highlighted Target Packet / Row (Yellow) -->
            <rect x="7" y="7" width="5.5" height="2" fill="#F1C40F" rx="0.3"/>
            <!-- Bottom Document Lines -->
            <line x1="5.5" y1="10.5" x2="12" y2="10.5" stroke="#37474F" stroke-width="1" stroke-linecap="round"/>
            <line x1="5.5" y1="12.5" x2="12" y2="12.5" stroke="#37474F" stroke-width="1" stroke-linecap="round"/>
            <!-- Green Right-Pointing Arrow -->
            <path d="M 0.8,6.5 L 4,6.5 L 4,4.5 L 7.5,8 L 4,11.5 L 4,9.5 L 0.8,9.5 Z" fill="#2ECC71" stroke="#1E824C" stroke-width="0.7" stroke-linejoin="round"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def go_previous(cls) -> QIcon:
        """Wireshark Go to Previous Packet icon (Green Up Arrow with Top Bar)."""
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <line x1="3" y1="2" x2="13" y2="2" stroke="#546E7A" stroke-width="1.8" stroke-linecap="round"/>
            <path d="M 8,4.5 L 3.5,9.5 L 6.5,9.5 L 6.5,14 L 9.5,14 L 9.5,9.5 L 12.5,9.5 Z" fill="#2ECC71" stroke="#1E824C" stroke-width="0.7" stroke-linejoin="round"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def go_next(cls) -> QIcon:
        """Wireshark Go to Next Packet icon (Green Down Arrow with Bottom Bar)."""
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M 8,11.5 L 3.5,6.5 L 6.5,6.5 L 6.5,2 L 9.5,2 L 9.5,6.5 L 12.5,6.5 Z" fill="#2ECC71" stroke="#1E824C" stroke-width="0.7" stroke-linejoin="round"/>
            <line x1="3" y1="14" x2="13" y2="14" stroke="#546E7A" stroke-width="1.8" stroke-linecap="round"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def go_first(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <rect x="2" y="3" width="2" height="10" fill="#2ECC71" stroke="#1E824C" stroke-width="0.6"/>
            <path d="M 13,3 L 5.5,8 L 13,13 Z" fill="#2ECC71" stroke="#1E824C" stroke-width="0.6"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def go_last(cls) -> QIcon:
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <path d="M 3,3 L 10.5,8 L 3,13 Z" fill="#2ECC71" stroke="#1E824C" stroke-width="0.6"/>
            <rect x="12" y="3" width="2" height="10" fill="#2ECC71" stroke="#1E824C" stroke-width="0.6"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def auto_scroll(cls) -> QIcon:
        """Wireshark Auto-Scroll icon (Document with lines and bottom blue marker)."""
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <rect x="2" y="1" width="12" height="14" rx="1.5" fill="#FAFAFA" stroke="#546E7A" stroke-width="1.1"/>
            <line x1="4.5" y1="3.5" x2="11.5" y2="3.5" stroke="#37474F" stroke-width="1"/>
            <line x1="4.5" y1="5.5" x2="11.5" y2="5.5" stroke="#37474F" stroke-width="1"/>
            <line x1="4.5" y1="7.5" x2="11.5" y2="7.5" stroke="#37474F" stroke-width="1"/>
            <line x1="4.5" y1="9.5" x2="11.5" y2="9.5" stroke="#37474F" stroke-width="1"/>
            <path d="M 5.5,11 L 10.5,11 L 8,13.5 Z" fill="#2980B9"/>
        </svg>"""
        return cls._render_svg(svg, 16)

    @classmethod
    def colorize(cls) -> QIcon:
        """Wireshark Coloring Rules icon (Document with rainbow lines)."""
        svg = """<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <rect x="2" y="1" width="12" height="14" rx="1.5" fill="#FAFAFA" stroke="#546E7A" stroke-width="1.1"/>
            <line x1="4" y1="3.5" x2="12" y2="3.5" stroke="#E74C3C" stroke-width="1.2" stroke-linecap="round"/>
            <line x1="4" y1="5.5" x2="12" y2="5.5" stroke="#2ECC71" stroke-width="1.2" stroke-linecap="round"/>
            <line x1="4" y1="7.5" x2="12" y2="7.5" stroke="#3498DB" stroke-width="1.2" stroke-linecap="round"/>
            <line x1="4" y1="9.5" x2="12" y2="9.5" stroke="#9B59B6" stroke-width="1.2" stroke-linecap="round"/>
            <line x1="4" y1="11.5" x2="12" y2="11.5" stroke="#E67E22" stroke-width="1.2" stroke-linecap="round"/>
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
