"""
KShark Theme Engine — "Cloud Teal" Official Palette & Wireshark Classic Modes.
Provides pixel-accurate themes, fonts, stylesheets, and dynamic runtime theme switching.
"""

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QColor, QFont, QPalette, QBrush
from PyQt6.QtCore import QObject, pyqtSignal
from typing import Dict, Any


class ThemeManager(QObject):
    """
    Centralized theme manager for KShark.
    Provides two unified themes: Wireshark Modern Dark (Global Default) and Wireshark Light.
    """

    themeChanged = pyqtSignal(str)  # Emits current theme name
    _instance = None

    THEME_WIRESHARK_DARK = "wireshark_dark"
    THEME_WIRESHARK_LIGHT = "wireshark_light"

    # Compatibility aliases
    THEME_KSHARK_DARK = THEME_WIRESHARK_DARK
    THEME_KSHARK_LIGHT = THEME_WIRESHARK_LIGHT
    THEME_WIRESHARK_CLASSIC = THEME_WIRESHARK_LIGHT

    def __init__(self):
        super().__init__()
        self._current_theme = self.THEME_WIRESHARK_DARK

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
        if theme_name in ("kshark_light", "wireshark_classic"):
            theme_name = self.THEME_WIRESHARK_LIGHT
        elif theme_name in ("kshark_dark",):
            theme_name = self.THEME_WIRESHARK_DARK

        if theme_name not in (self.THEME_WIRESHARK_DARK, self.THEME_WIRESHARK_LIGHT):
            theme_name = self.THEME_WIRESHARK_DARK

        self._current_theme = theme_name
        app = QApplication.instance()
        if app:
            qss = self.get_stylesheet(theme_name)
            app.setStyleSheet(qss)
        self.themeChanged.emit(theme_name)

    def get_palette_colors(self, theme_name: str = "") -> Dict[str, str]:
        t = theme_name or self._current_theme
        if t in (self.THEME_WIRESHARK_LIGHT, "kshark_light", "wireshark_classic"):
            return {
                "bg_window": "#F1F5F9",
                "bg_base": "#FFFFFF",
                "bg_alt": "#F8FAFC",
                "bg_section": "#F1F5F9",
                "bg_input": "#FFFFFF",
                "fg_text": "#0F172A",
                "fg_muted": "#475569",
                "fg_bright": "#0284C7",
                "brand_primary": "#0284C7",
                "brand_deep": "#0369A1",
                "border": "#CBD5E1",
                "selection_bg": "#BAE6FD",
                "selection_fg": "#0F172A",
                "filter_valid_bg": "#DCFCE7",
                "filter_valid_border": "#86EFAC",
                "filter_invalid_bg": "#FEE2E2",
                "filter_invalid_border": "#FCA5A5",
                "accent_success": "#16A34A",
                "accent_danger": "#DC2626",
                "green_btn": "#16A34A",
                "green_btn_hover": "#15803D",
                "green_btn_border": "#166534",
                "card_threats_bg": "#FEE2E2",
                "card_threats_fg": "#991B1B",
                "card_threats_border": "#FCA5A5",
                "card_warnings_bg": "#FEF3C7",
                "card_warnings_fg": "#92400E",
                "card_warnings_border": "#FCD34D",
                "card_errors_bg": "#FEF9C3",
                "card_errors_fg": "#854D0E",
                "card_errors_border": "#FDE047",
                "card_notes_bg": "#E0F2FE",
                "card_notes_fg": "#0369A1",
                "card_notes_border": "#BAE6FD",
            }
        else:  # WIRESHARK_DARK (Global Default)
            return {
                "bg_window": "#181D20",
                "bg_base": "#1E2429",
                "bg_alt": "#252D33",
                "bg_section": "#141A1D",
                "bg_input": "#111618",
                "fg_text": "#D8E2E6",
                "fg_muted": "#8B9BA2",
                "fg_bright": "#FFFFFF",
                "brand_primary": "#2BC1CF",
                "brand_deep": "#0C4A6E",
                "border": "#2E3A40",
                "selection_bg": "#1E4856",
                "selection_fg": "#FFFFFF",
                "filter_valid_bg": "#143828",
                "filter_valid_border": "#22C55E",
                "filter_invalid_bg": "#4D1B1B",
                "filter_invalid_border": "#EF4444",
                "accent_success": "#22C55E",
                "accent_danger": "#EF4444",
                "green_btn": "#117A4E",
                "green_btn_hover": "#14925E",
                "green_btn_border": "#18A86A",
                "card_threats_bg": "#3A1414",
                "card_threats_fg": "#FF7070",
                "card_threats_border": "#782626",
                "card_warnings_bg": "#3A2510",
                "card_warnings_fg": "#FFA850",
                "card_warnings_border": "#784A1A",
                "card_errors_bg": "#383514",
                "card_errors_fg": "#FFE066",
                "card_errors_border": "#786C1A",
                "card_notes_bg": "#12283A",
                "card_notes_fg": "#66B8FF",
                "card_notes_border": "#1A4D78",
            }

    def get_stylesheet(self, theme_name: str = "") -> str:
        c = self.get_palette_colors(theme_name)
        is_dark = "dark" in (theme_name or self._current_theme)

        tab_bg = c['bg_window']
        tab_selected_bg = c['bg_base']
        tab_fg = c['fg_muted']
        tab_selected_fg = c['brand_primary'] if is_dark else c['fg_text']

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
            color: {c['fg_text']};
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

        QTabWidget::pane {{
            border: 1px solid {c['border']};
            background-color: {c['bg_base']};
            top: -1px;
        }}
        QTabBar::tab {{
            background-color: {tab_bg};
            color: {tab_fg};
            border: 1px solid {c['border']};
            border-bottom: none;
            padding: 4px 10px;
            margin-right: 2px;
            border-top-left-radius: 3px;
            border-top-right-radius: 3px;
            font-weight: bold;
            font-size: 8pt;
        }}
        QTabBar::tab:selected {{
            background-color: {tab_selected_bg};
            color: {tab_selected_fg};
            border-bottom: 1px solid {tab_selected_bg};
        }}
        QTabBar::tab:hover:!selected {{
            background-color: {c['bg_alt']};
            color: {c['fg_text']};
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
            width: 10px;
            margin: 0px;
        }}
        QScrollBar::handle:vertical {{
            background: {c['border']};
            min-height: 20px;
            border-radius: 3px;
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
            height: 10px;
            margin: 0px;
        }}
        QScrollBar::handle:horizontal {{
            background: {c['border']};
            min-width: 20px;
            border-radius: 3px;
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


def get_monospace_font(size: int = 9, bold: bool = False) -> QFont:
    """Returns platform-optimized monospace font for packet and hex views."""
    pt_size = max(6, int(round(size)))
    font = QFont("Monospace", pt_size)
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setFamilies([
        "Liberation Mono",
        "DejaVu Sans Mono",
        "Menlo",
        "Consolas",
        "Courier New",
        "Monospace",
    ])
    if bold:
        font.setBold(True)
    return font


def get_ui_font(size: int = 9, bold: bool = False) -> QFont:
    """Returns platform-optimized standard UI font."""
    pt_size = max(6, int(round(size)))
    font = QFont("Sans-Serif", pt_size)
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

