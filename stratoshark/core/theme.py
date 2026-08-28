"""
Stratoshark Theme Engine — "Cloud Teal" Official Palette & Wireshark Classic Modes.
Provides pixel-accurate themes, fonts, stylesheets, and dynamic runtime theme switching.
"""

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QColor, QFont, QPalette, QBrush
from PyQt6.QtCore import QObject, pyqtSignal
from typing import Dict, Any


class ThemeManager(QObject):
    """
    Centralized theme manager for Stratoshark.
    Supports Stratoshark Cloud Teal (Light/Dark) and Classic Wireshark palettes.
    """

    themeChanged = pyqtSignal(str)  # Emits current theme name
    _instance = None

    THEME_STRATOSHARK_LIGHT = "stratoshark_light"
    THEME_STRATOSHARK_DARK = "stratoshark_dark"
    THEME_WIRESHARK_CLASSIC = "wireshark_classic"
    THEME_WIRESHARK_DARK = "wireshark_dark"

    def __init__(self):
        super().__init__()
        self._current_theme = self.THEME_STRATOSHARK_DARK

    @classmethod
    def instance(cls) -> 'ThemeManager':
        if cls._instance is None:
            cls._instance = ThemeManager()
        return cls._instance

    @classmethod
    def current_theme(cls) -> str:
        return cls.instance()._current_theme

    @classmethod
    def is_dark(cls) -> bool:
        return "dark" in cls.instance()._current_theme

    def set_theme(self, theme_name: str):
        if theme_name not in (
            self.THEME_STRATOSHARK_LIGHT,
            self.THEME_STRATOSHARK_DARK,
            self.THEME_WIRESHARK_CLASSIC,
            self.THEME_WIRESHARK_DARK,
        ):
            theme_name = self.THEME_STRATOSHARK_DARK

        self._current_theme = theme_name
        app = QApplication.instance()
        if app:
            qss = self.get_stylesheet(theme_name)
            app.setStyleSheet(qss)
        self.themeChanged.emit(theme_name)

    def get_palette_colors(self, theme_name: str = "") -> Dict[str, str]:
        t = theme_name or self._current_theme
        if t == self.THEME_STRATOSHARK_LIGHT:
            return {
                "bg_window": "#F0F4F5",
                "bg_base": "#FFFFFF",
                "bg_alt": "#E8EFF1",
                "fg_text": "#102A30",
                "fg_muted": "#5A7076",
                "brand_primary": "#0E9AA7",
                "brand_deep": "#0A2A32",
                "border": "#D0DCDD",
                "selection_bg": "#0E9AA7",
                "selection_fg": "#FFFFFF",
                "filter_valid_bg": "#D4F4D4",
                "filter_invalid_bg": "#FFD4D4",
                "accent_success": "#0EA773",
                "accent_danger": "#C92A2A",
            }
        elif t == self.THEME_STRATOSHARK_DARK:
            return {
                "bg_window": "#121E22",
                "bg_base": "#182428",
                "bg_alt": "#1F2E34",
                "fg_text": "#D8E8EC",
                "fg_muted": "#8A9EA4",
                "brand_primary": "#2BC1CF",
                "brand_deep": "#03161A",
                "border": "#283C42",
                "selection_bg": "#1A525D",
                "selection_fg": "#FFFFFF",
                "filter_valid_bg": "#133825",
                "filter_invalid_bg": "#4A1818",
                "accent_success": "#2BD49B",
                "accent_danger": "#F05252",
            }
        elif t == self.THEME_WIRESHARK_CLASSIC:
            return {
                "bg_window": "#EFEFEF",
                "bg_base": "#FFFFFF",
                "bg_alt": "#F5F5F5",
                "fg_text": "#000000",
                "fg_muted": "#666666",
                "brand_primary": "#204A87",
                "brand_deep": "#10284A",
                "border": "#CCCCCC",
                "selection_bg": "#3072CC",
                "selection_fg": "#FFFFFF",
                "filter_valid_bg": "#AFF8AF",
                "filter_invalid_bg": "#FFB0AF",
                "accent_success": "#4E9A06",
                "accent_danger": "#CC0000",
            }
        else:  # WIRESHARK_DARK
            return {
                "bg_window": "#1E1E1E",
                "bg_base": "#252526",
                "bg_alt": "#2D2D2D",
                "fg_text": "#CCCCCC",
                "fg_muted": "#888888",
                "brand_primary": "#3B82F6",
                "brand_deep": "#1E3A8A",
                "border": "#3C3C3C",
                "selection_bg": "#2A4068",
                "selection_fg": "#FFFFFF",
                "filter_valid_bg": "#1E3D1E",
                "filter_invalid_bg": "#4D1A1A",
                "accent_success": "#10B981",
                "accent_danger": "#EF4444",
            }

    def get_stylesheet(self, theme_name: str = "") -> str:
        c = self.get_palette_colors(theme_name)
        return f"""
        QMainWindow, QDialog, QWidget {{
            background-color: {c['bg_window']};
            color: {c['fg_text']};
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Ubuntu, "Liberation Sans", sans-serif;
            font-size: 9pt;
        }}

        QMenuBar {{
            background-color: {c['bg_window']};
            color: {c['fg_text']};
            border-bottom: 1px solid {c['border']};
            padding: 2px;
        }}
        QMenuBar::item {{
            background: transparent;
            padding: 4px 8px;
            border-radius: 3px;
        }}
        QMenuBar::item:selected {{
            background-color: {c['selection_bg']};
            color: {c['selection_fg']};
        }}

        QMenu {{
            background-color: {c['bg_window']};
            color: {c['fg_text']};
            border: 1px solid {c['border']};
            padding: 4px;
        }}
        QMenu::item {{
            padding: 4px 24px 4px 12px;
            border-radius: 2px;
        }}
        QMenu::item:selected {{
            background-color: {c['selection_bg']};
            color: {c['selection_fg']};
        }}
        QMenu::separator {{
            height: 1px;
            background-color: {c['border']};
            margin: 4px 6px;
        }}

        QToolBar {{
            background-color: {c['bg_window']};
            border-bottom: 1px solid {c['border']};
            spacing: 2px;
            padding: 2px 4px;
        }}
        QToolButton {{
            background: transparent;
            border: 1px solid transparent;
            border-radius: 3px;
            padding: 3px;
            margin: 1px;
        }}
        QToolButton:hover {{
            background-color: {c['bg_alt']};
            border: 1px solid {c['border']};
        }}
        QToolButton:pressed, QToolButton:checked {{
            background-color: {c['selection_bg']};
            color: {c['selection_fg']};
            border: 1px solid {c['brand_primary']};
        }}

        QTableView, QTreeView, QListView {{
            background-color: {c['bg_base']};
            alternate-background-color: {c['bg_alt']};
            color: {c['fg_text']};
            border: 1px solid {c['border']};
            gridline-color: transparent;
            selection-background-color: {c['selection_bg']};
            selection-color: {c['selection_fg']};
            outline: none;
        }}
        QHeaderView::section {{
            background-color: {c['bg_window']};
            color: {c['fg_text']};
            border: none;
            border-right: 1px solid {c['border']};
            border-bottom: 1px solid {c['border']};
            padding: 3px 6px;
            font-weight: 600;
            font-size: 8.5pt;
        }}

        QSplitter::handle {{
            background-color: {c['border']};
        }}
        QSplitter::handle:horizontal {{
            width: 2px;
        }}
        QSplitter::handle:vertical {{
            height: 2px;
        }}

        QStatusBar {{
            background-color: {c['bg_window']};
            color: {c['fg_muted']};
            border-top: 1px solid {c['border']};
            font-size: 8.5pt;
        }}

        QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {{
            background-color: {c['bg_base']};
            color: {c['fg_text']};
            border: 1px solid {c['border']};
            border-radius: 2px;
            padding: 3px 6px;
        }}
        QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus {{
            border: 1px solid {c['brand_primary']};
        }}

        QScrollBar:vertical {{
            background: {c['bg_window']};
            width: 12px;
            margin: 0px;
        }}
        QScrollBar::handle:vertical {{
            background: {c['border']};
            min-height: 20px;
            border-radius: 4px;
            margin: 2px;
        }}
        QScrollBar::handle:vertical:hover {{
            background: {c['brand_primary']};
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}

        QScrollBar:horizontal {{
            background: {c['bg_window']};
            height: 12px;
            margin: 0px;
        }}
        QScrollBar::handle:horizontal {{
            background: {c['border']};
            min-width: 20px;
            border-radius: 4px;
            margin: 2px;
        }}
        QScrollBar::handle:horizontal:hover {{
            background: {c['brand_primary']};
        }}
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            width: 0px;
        }}

        QDockWidget {{
            titlebar-close-icon: url(none);
            titlebar-normal-icon: url(none);
            font-weight: 600;
        }}
        QDockWidget::title {{
            background-color: {c['bg_window']};
            color: {c['fg_text']};
            padding: 4px 8px;
            border-bottom: 1px solid {c['border']};
        }}
        """


def get_monospace_font(size: int = 9) -> QFont:
    """Returns platform-optimized monospace font for packet and hex views."""
    font = QFont("Monospace", size)
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setFamilies([
        "Liberation Mono",
        "DejaVu Sans Mono",
        "Menlo",
        "Consolas",
        "Courier New",
        "Monospace",
    ])
    return font


def get_ui_font(size: int = 9, bold: bool = False) -> QFont:
    """Returns platform-optimized standard UI font."""
    font = QFont("Sans-Serif", size)
    font.setFamilies([
        "-apple-system",
        "Segoe UI",
        "Ubuntu",
        "Liberation Sans",
        "DejaVu Sans",
        "Sans-Serif",
    ])
    if bold:
        font.setBold(True)
    return font
