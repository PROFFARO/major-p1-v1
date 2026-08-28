"""
Wireshark-accurate Theme & Palette Manager for KShark.

Implements Wireshark's exact Tango-based color system, token derivations,
semantic palette roles, light/dark appearance modes, and pixel-accurate Qt6 QSS stylesheets.
"""

from PyQt6.QtGui import QColor, QFont, QPalette, QBrush
from PyQt6.QtCore import Qt, QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication, QWidget
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum


# ─────────────────────────────────────────────────────────────
# 1. Wireshark Canonical Token Definitions (from theme.jsonc)
# ─────────────────────────────────────────────────────────────

class ThemeToken(Enum):
    # Brand
    BrandPrimary = "BrandPrimary"
    BrandDeep = "BrandDeep"

    # Accent
    AccentSuccess = "AccentSuccess"
    AccentWarning = "AccentWarning"
    AccentError = "AccentError"
    AccentInfo = "AccentInfo"

    # Expert Info
    ExpertComment = "ExpertComment"
    ExpertChat = "ExpertChat"
    ExpertNote = "ExpertNote"
    ExpertWarn = "ExpertWarn"
    ExpertError = "ExpertError"
    ExpertForeground = "ExpertForeground"

    # Packets / Event Table Rows
    PacketsSelection = "PacketsSelection"
    PacketsSelectionText = "PacketsSelectionText"
    PacketsInactive = "PacketsInactive"
    PacketsInactiveText = "PacketsInactiveText"
    PacketsMarked = "PacketsMarked"
    PacketsMarkedText = "PacketsMarkedText"
    PacketsIgnored = "PacketsIgnored"
    PacketsIgnoredText = "PacketsIgnoredText"
    PacketsHidden = "PacketsHidden"

    # Display Filter Syntax
    FilterValid = "FilterValid"
    FilterValidBg = "FilterValidBg"
    FilterInvalid = "FilterInvalid"
    FilterInvalidBg = "FilterInvalidBg"
    FilterDeprecated = "FilterDeprecated"
    FilterDeprecatedBg = "FilterDeprecatedBg"
    FilterHistory = "FilterHistory"
    FilterBookmark = "FilterBookmark"
    FilterClear = "FilterClear"
    FilterApply = "FilterApply"

    # Follow Stream / Conversation
    ConversationClient = "ConversationClient"
    ConversationClientText = "ConversationClientText"
    ConversationServer = "ConversationServer"
    ConversationServerText = "ConversationServerText"

    # Chrome & Structural
    WelcomeBannerBg = "WelcomeBannerBg"
    WelcomeBannerText = "WelcomeBannerText"
    FieldBorder = "FieldBorder"
    Separator = "Separator"
    HeaderGradientStart = "HeaderGradientStart"
    HeaderGradientEnd = "HeaderGradientEnd"


# ─────────────────────────────────────────────────────────────
# 2. Token Color Map (Light & Dark Pairs)
# ─────────────────────────────────────────────────────────────

THEME_TOKENS: Dict[ThemeToken, Tuple[str, str]] = {
    # Brand (Light / Dark)
    ThemeToken.BrandPrimary:            ("#204a87", "#5b9ee6"),
    ThemeToken.BrandDeep:               ("#112347", "#0a1828"),

    # Accent
    ThemeToken.AccentSuccess:           ("#73d216", "#8ae234"),
    ThemeToken.AccentWarning:           ("#f57900", "#fcaf3e"),
    ThemeToken.AccentError:             ("#cc0000", "#ef2929"),
    ThemeToken.AccentInfo:              ("#3465a4", "#729fcf"),

    # Expert
    ThemeToken.ExpertComment:           ("#b7f774", "#b7f774"),
    ThemeToken.ExpertChat:              ("#80b7f7", "#80b7f7"),
    ThemeToken.ExpertNote:              ("#a0ffff", "#a0ffff"),
    ThemeToken.ExpertWarn:              ("#f7f253", "#f7f253"),
    ThemeToken.ExpertError:             ("#ff5c5c", "#ff5c5c"),
    ThemeToken.ExpertForeground:        ("#000000", "#000000"),

    # Packets
    ThemeToken.PacketsSelection:        ("#3072cc", "#2a4068"),
    ThemeToken.PacketsSelectionText:    ("#ffffff", "#ffffff"),
    ThemeToken.PacketsInactive:         ("#dcdcdc", "#2e3436"),
    ThemeToken.PacketsInactiveText:     ("#000000", "#eeeeec"),
    ThemeToken.PacketsMarked:           ("#002033", "#002033"),
    ThemeToken.PacketsMarkedText:       ("#ffffff", "#ffffff"),
    ThemeToken.PacketsIgnored:          ("#ffffff", "#1a1a1a"),
    ThemeToken.PacketsIgnoredText:      ("#808080", "#808080"),
    ThemeToken.PacketsHidden:           ("#444444", "#999999"),

    # Filter Syntax
    ThemeToken.FilterValid:             ("#296700", "#3a7a06"),
    ThemeToken.FilterValidBg:           ("#AFF8AF", "#1E3D1E"),
    ThemeToken.FilterInvalid:           ("#5e0000", "#7a1818"),
    ThemeToken.FilterInvalidBg:         ("#FFB0AF", "#4D1A1A"),
    ThemeToken.FilterDeprecated:        ("#8f7a00", "#d4b830"),
    ThemeToken.FilterDeprecatedBg:      ("#FFFA8F", "#3E3B18"),
    ThemeToken.FilterHistory:           ("#555753", "#d3d7cf"),
    ThemeToken.FilterBookmark:          ("#204a87", "#5b9ee6"),
    ThemeToken.FilterClear:             ("#cc0000", "#ef2929"),
    ThemeToken.FilterApply:             ("#296700", "#3a7a06"),

    # Conversation
    ThemeToken.ConversationClient:      ("#fbedcd", "#3a2010"),
    ThemeToken.ConversationClientText:  ("#800000", "#ffb088"),
    ThemeToken.ConversationServer:      ("#edeefb", "#1a1a3a"),
    ThemeToken.ConversationServerText:  ("#000080", "#a0b4ff"),

    # Welcome Banner & Chrome
    ThemeToken.WelcomeBannerBg:         ("#99C2EC", "#204a87"),
    ThemeToken.WelcomeBannerText:       ("#003366", "#FFFFFF"),
    ThemeToken.FieldBorder:             ("#D0D0D0", "#3C3C3C"),
    ThemeToken.Separator:               ("#E0E0E0", "#2D2D2D"),
    ThemeToken.HeaderGradientStart:     ("#112347", "#0a1828"),
    ThemeToken.HeaderGradientEnd:       ("#204a87", "#5b9ee6"),
}

WIRESHARK_COLORS = {
    "filter_valid_bg":          "#AFF8AF",
    "filter_valid_fg":          "#000000",
    "filter_invalid_bg":        "#FFB0AF",
    "filter_invalid_fg":        "#000000",
    "filter_deprecated_bg":     "#FFFA8F",
    "filter_deprecated_fg":     "#000000",
    "dark_filter_valid_bg":     "#1E3D1E",
    "dark_filter_valid_fg":     "#A5D6A7",
    "dark_filter_invalid_bg":   "#4D1A1A",
    "dark_filter_invalid_fg":   "#EF9A9A",
    "dark_filter_deprecated_bg":"#3E3B18",
    "dark_filter_deprecated_fg":"#FFF59D",
}


# Wireshark 14 Rotating Graph Colors (Tango Palette)
GRAPH_COLORS: List[Tuple[str, str]] = [
    ("#2e3436", "#babdb6"),
    ("#204a87", "#729fcf"),
    ("#725000", "#fce94f"),
    ("#4e9a06", "#8ae234"),
    ("#a40000", "#ef2929"),
    ("#5c3566", "#ad7fa8"),
    ("#8c3700", "#fcaf3e"),
    ("#babdb6", "#555753"),
    ("#97c4f0", "#204a87"),
    ("#fce94f", "#725000"),
    ("#8ae234", "#4e9a06"),
    ("#ef2929", "#a40000"),
    ("#ad7fa8", "#5c3566"),
    ("#fcaf3e", "#8c3700"),
]

# Security Classification Colors
SECURITY_COLORS: Dict[str, Tuple[str, str]] = {
    "RANSOMWARE":           ("#FF4444", "#FFFFFF"),
    "KERNEL_ROOTKIT":       ("#B71C1C", "#FFFFFF"),
    "CONTAINER_ESCAPE":     ("#D32F2F", "#FFFFFF"),
    "REVERSE_SHELL":        ("#6A1B9A", "#FFFFFF"),
    "PRIVILEGE_ESCALATION": ("#FF8C00", "#FFFFFF"),
    "DATA_EXFILTRATION":    ("#E65100", "#FFFFFF"),
    "CRYPTO_MINER":         ("#F57F17", "#000000"),
    "BRUTE_FORCE":          ("#FFB300", "#000000"),
    "LOG_TAMPERING":        ("#E53935", "#FFFFFF"),
    "BENIGN":               ("#FFFFFF", "#000000"),
}


# ─────────────────────────────────────────────────────────────
# 3. Fonts Management
# ─────────────────────────────────────────────────────────────

def get_monospace_font(size: int = 9, bold: bool = False) -> QFont:
    """Returns preferred Linux monospace font matching Wireshark packet list."""
    font = QFont("Liberation Mono", int(size))
    if not font.exactMatch():
        font = QFont("DejaVu Sans Mono", int(size))
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setBold(bold)
    return font


def get_ui_font(size: int = 9, bold: bool = False) -> QFont:
    """Returns preferred Linux UI system font."""
    font = QFont("Cantarell", int(size))
    if not font.exactMatch():
        font = QFont("Ubuntu", int(size))
    font.setBold(bold)
    return font


# ─────────────────────────────────────────────────────────────
# 4. Central ThemeManager Singleton & Palette Builder
# ─────────────────────────────────────────────────────────────

class ThemeManager(QObject):
    """
    Central Manager for application-wide Wireshark appearance and palette.
    """

    themeChanged = pyqtSignal()
    _instance: Optional['ThemeManager'] = None
    _is_dark: bool = False

    @classmethod
    def instance(cls) -> 'ThemeManager':
        if cls._instance is None:
            cls._instance = ThemeManager()
        return cls._instance

    @classmethod
    def is_dark(cls) -> bool:
        return cls._is_dark

    @classmethod
    def set_theme(cls, dark: bool = False):
        cls._is_dark = dark
        app = QApplication.instance()
        if app:
            # Apply QPalette
            palette = cls.build_palette(dark)
            app.setPalette(palette)

            # Apply QSS Stylesheet
            stylesheet = cls.get_dark_stylesheet() if dark else cls.get_light_stylesheet()
            app.setStyleSheet(stylesheet)

        inst = cls.instance()
        inst.themeChanged.emit()

    @classmethod
    def color(cls, token: ThemeToken) -> QColor:
        """Returns QColor for given token in current light/dark mode."""
        pair = THEME_TOKENS.get(token, ("#000000", "#FFFFFF"))
        hex_val = pair[1] if cls._is_dark else pair[0]
        return QColor(hex_val)

    @classmethod
    def graph_color(cls, index: int) -> QColor:
        """Returns graph color from 14 rotating Tango palette."""
        pair = GRAPH_COLORS[index % len(GRAPH_COLORS)]
        hex_val = pair[1] if cls._is_dark else pair[0]
        return QColor(hex_val)

    @classmethod
    def build_palette(cls, dark: bool = False) -> QPalette:
        """Builds standard Qt6 QPalette reflecting Wireshark palette roles."""
        palette = QPalette()

        if dark:
            # Dark Window & Base
            palette.setColor(QPalette.ColorRole.Window, QColor("#1E1E1E"))
            palette.setColor(QPalette.ColorRole.WindowText, QColor("#D4D4D4"))
            palette.setColor(QPalette.ColorRole.Base, QColor("#1E1E1E"))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#252526"))
            palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#2D2D2D"))
            palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#E0E0E0"))
            palette.setColor(QPalette.ColorRole.Text, QColor("#D4D4D4"))
            palette.setColor(QPalette.ColorRole.Button, QColor("#2D2D2D"))
            palette.setColor(QPalette.ColorRole.ButtonText, QColor("#D4D4D4"))
            palette.setColor(QPalette.ColorRole.BrightText, QColor("#FFFFFF"))
            palette.setColor(QPalette.ColorRole.Link, QColor("#5B9EE6"))
            palette.setColor(QPalette.ColorRole.Highlight, QColor("#2A4068"))
            palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#FFFFFF"))
            palette.setColor(QPalette.ColorRole.Mid, QColor("#3C3C3C"))
            palette.setColor(QPalette.ColorRole.Midlight, QColor("#454545"))
            palette.setColor(QPalette.ColorRole.Dark, QColor("#121212"))
            palette.setColor(QPalette.ColorRole.Shadow, QColor("#000000"))
        else:
            # Light Window & Base
            palette.setColor(QPalette.ColorRole.Window, QColor("#F0F0F0"))
            palette.setColor(QPalette.ColorRole.WindowText, QColor("#000000"))
            palette.setColor(QPalette.ColorRole.Base, QColor("#FFFFFF"))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#FAFAFA"))
            palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#FFFFDC"))
            palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#000000"))
            palette.setColor(QPalette.ColorRole.Text, QColor("#000000"))
            palette.setColor(QPalette.ColorRole.Button, QColor("#E8E8E8"))
            palette.setColor(QPalette.ColorRole.ButtonText, QColor("#000000"))
            palette.setColor(QPalette.ColorRole.BrightText, QColor("#FFFFFF"))
            palette.setColor(QPalette.ColorRole.Link, QColor("#204A87"))
            palette.setColor(QPalette.ColorRole.Highlight, QColor("#3072CC"))
            palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#FFFFFF"))
            palette.setColor(QPalette.ColorRole.Mid, QColor("#D0D0D0"))
            palette.setColor(QPalette.ColorRole.Midlight, QColor("#E0E0E0"))
            palette.setColor(QPalette.ColorRole.Dark, QColor("#A0A0A0"))
            palette.setColor(QPalette.ColorRole.Shadow, QColor("#707070"))

        return palette

    # ─────────────────────────────────────────────────────────
    # 5. Full Wireshark-Accurate QSS Stylesheets
    # ─────────────────────────────────────────────────────────

    @classmethod
    def get_light_stylesheet(cls) -> str:
        return """
        /* ========================================================= */
        /* Wireshark Classic Light Theme for KShark                   */
        /* ========================================================= */

        QMainWindow {
            background-color: #F0F0F0;
        }

        /* ─── Menu Bar ─────────────────────────────────────────── */
        QMenuBar {
            background-color: #F0F0F0;
            border-bottom: 1px solid #D0D0D0;
            font-size: 9pt;
            padding: 1px 2px;
        }
        QMenuBar::item {
            padding: 3px 8px;
            background: transparent;
            color: #101010;
        }
        QMenuBar::item:selected {
            background-color: #E2E2E2;
            border-radius: 2px;
        }
        QMenuBar::item:pressed {
            background-color: #0078D7;
            color: #FFFFFF;
        }

        /* ─── Dropdown Menus ───────────────────────────────────── */
        QMenu {
            background-color: #FFFFFF;
            border: 1px solid #C0C0C0;
            padding: 3px;
            font-size: 9pt;
        }
        QMenu::item {
            padding: 4px 26px 4px 22px;
            color: #101010;
        }
        QMenu::item:selected {
            background-color: #3072CC;
            color: #FFFFFF;
        }
        QMenu::separator {
            height: 1px;
            background-color: #E5E5E5;
            margin: 3px 6px;
        }

        /* ─── Toolbars ─────────────────────────────────────────── */
        QToolBar {
            background-color: #F8F8F8;
            border-bottom: 1px solid #D8D8D8;
            spacing: 2px;
            padding: 2px 4px;
        }
        QToolBar::separator {
            width: 1px;
            background-color: #D8D8D8;
            margin: 3px 4px;
        }
        QToolButton {
            background: transparent;
            border: 1px solid transparent;
            border-radius: 3px;
            padding: 2px;
            color: #202020;
        }
        QToolButton:hover {
            background-color: #E8E8E8;
            border: 1px solid #C8C8C8;
        }
        QToolButton:pressed {
            background-color: #D0D0D0;
            border: 1px solid #A0A0A0;
        }
        QToolButton:checked {
            background-color: #CDE8FF;
            border: 1px solid #99CCFF;
        }

        /* ─── Display Filter Bar ───────────────────────────────── */
        QLineEdit#filterLineEdit {
            border: 1px solid #D0D0D0;
            border-radius: 2px;
            padding: 3px 6px;
            background-color: #FFFFFF;
            color: #000000;
            font-family: 'Liberation Mono', 'DejaVu Sans Mono', monospace;
            font-size: 9pt;
        }
        QLineEdit#filterLineEdit:focus {
            border: 1px solid #3072CC;
        }

        /* ─── 3-Pane Splitters ─────────────────────────────────── */
        QSplitter::handle {
            background-color: #DCDCDC;
        }
        QSplitter::handle:horizontal {
            width: 3px;
        }
        QSplitter::handle:vertical {
            height: 3px;
        }
        QSplitter::handle:hover {
            background-color: #3072CC;
        }

        /* ─── Event Table View (Packet List) ───────────────────── */
        QTableView {
            background-color: #FFFFFF;
            alternate-background-color: #FAFAFA;
            gridline-color: #ECECEC;
            selection-background-color: #3072CC;
            selection-color: #FFFFFF;
            font-family: 'Liberation Mono', 'DejaVu Sans Mono', monospace;
            font-size: 9pt;
            border: 1px solid #D0D0D0;
        }
        QHeaderView::section {
            background-color: #EAEAEA;
            color: #202020;
            padding: 2px 6px;
            border-top: none;
            border-left: none;
            border-right: 1px solid #D0D0D0;
            border-bottom: 1px solid #C0C0C0;
            font-size: 8.5pt;
            font-weight: normal;
        }
        QHeaderView::section:hover {
            background-color: #DCDCDC;
        }

        /* ─── Event Details Tree ───────────────────────────────── */
        QTreeView {
            background-color: #FFFFFF;
            border: 1px solid #D0D0D0;
            font-family: 'Liberation Mono', 'DejaVu Sans Mono', monospace;
            font-size: 9pt;
            show-decoration-selected: 1;
        }
        QTreeView::item {
            padding: 1px 0;
        }
        QTreeView::item:hover {
            background-color: #F0F6FC;
        }
        QTreeView::item:selected {
            background-color: #3072CC;
            color: #FFFFFF;
        }

        /* ─── Event Bytes View ─────────────────────────────────── */
        QPlainTextEdit#eventByteView {
            background-color: #FFFFFF;
            color: #101010;
            border: 1px solid #D0D0D0;
            font-family: 'Liberation Mono', 'DejaVu Sans Mono', monospace;
            font-size: 9pt;
        }

        /* ─── Status Bar ───────────────────────────────────────── */
        QStatusBar {
            background-color: #E8E8E8;
            border-top: 1px solid #D0D0D0;
            color: #333333;
            font-size: 8.5pt;
            min-height: 22px;
        }
        QStatusBar::item {
            border: none;
        }

        /* ─── Display Filter Toolbar ───────────────────────────── */
        QToolBar#displayFilterToolBar {
            background-color: #F8F8F8;
            border-bottom: 1px solid #D8D8D8;
            padding: 2px 4px;
        }


        /* ─── Dock Widgets ─────────────────────────────────────── */
        QDockWidget {
            font-weight: bold;
            font-size: 8.5pt;
        }
        QDockWidget::title {
            background-color: #E2E2E2;
            padding: 4px;
            border: 1px solid #D0D0D0;
        }

        /* ─── Welcome Page Cards ───────────────────────────────── */
        QFrame#welcomeCard {
            background-color: #FFFFFF;
            border: 1px solid #D0D0D0;
            border-radius: 4px;
        }
        QLabel#welcomePill {
            background-color: #99C2EC;
            color: #003366;
            font-weight: bold;
            font-size: 10pt;
            border-radius: 3px;
            padding: 3px 10px;
        }
        """

    @classmethod
    def get_dark_stylesheet(cls) -> str:
        return """
        /* ========================================================= */
        /* Wireshark Modern Dark Theme for KShark                     */
        /* ========================================================= */

        QMainWindow {
            background-color: #1E1E1E;
            color: #D4D4D4;
        }

        /* ─── Menu Bar ─────────────────────────────────────────── */
        QMenuBar {
            background-color: #252526;
            border-bottom: 1px solid #3C3C3C;
            color: #CCCCCC;
            font-size: 9pt;
            padding: 1px 2px;
        }
        QMenuBar::item {
            padding: 3px 8px;
            background: transparent;
            color: #D4D4D4;
        }
        QMenuBar::item:selected {
            background-color: #333333;
            border-radius: 2px;
        }
        QMenuBar::item:pressed {
            background-color: #094771;
            color: #FFFFFF;
        }

        /* ─── Dropdown Menus ───────────────────────────────────── */
        QMenu {
            background-color: #252526;
            border: 1px solid #454545;
            color: #D4D4D4;
            padding: 3px;
            font-size: 9pt;
        }
        QMenu::item {
            padding: 4px 26px 4px 22px;
            color: #D4D4D4;
        }
        QMenu::item:selected {
            background-color: #094771;
            color: #FFFFFF;
        }
        QMenu::separator {
            height: 1px;
            background-color: #3C3C3C;
            margin: 3px 6px;
        }

        /* ─── Toolbars ─────────────────────────────────────────── */
        QToolBar {
            background-color: #2D2D2D;
            border-bottom: 1px solid #3C3C3C;
            spacing: 2px;
            padding: 2px 4px;
        }
        QToolBar::separator {
            width: 1px;
            background-color: #3C3C3C;
            margin: 3px 4px;
        }
        QToolButton {
            background: transparent;
            border: 1px solid transparent;
            border-radius: 3px;
            padding: 2px;
            color: #CCCCCC;
        }
        QToolButton:hover {
            background-color: #3E3E42;
            border: 1px solid #555555;
        }
        QToolButton:pressed {
            background-color: #094771;
            border: 1px solid #007ACC;
        }
        QToolButton:checked {
            background-color: #264F78;
            border: 1px solid #007ACC;
        }

        /* ─── Display Filter Bar ───────────────────────────────── */
        QLineEdit#filterLineEdit {
            border: 1px solid #3C3C3C;
            border-radius: 2px;
            padding: 3px 6px;
            background-color: #252526;
            color: #D4D4D4;
            font-family: 'Liberation Mono', 'DejaVu Sans Mono', monospace;
            font-size: 9pt;
        }
        QLineEdit#filterLineEdit:focus {
            border: 1px solid #007ACC;
        }

        /* ─── 3-Pane Splitters ─────────────────────────────────── */
        QSplitter::handle {
            background-color: #333333;
        }
        QSplitter::handle:hover {
            background-color: #007ACC;
        }

        /* ─── Event Table View (Packet List) ───────────────────── */
        QTableView {
            background-color: #1E1E1E;
            alternate-background-color: #252526;
            gridline-color: #2D2D2D;
            selection-background-color: #2A4068;
            selection-color: #FFFFFF;
            color: #D4D4D4;
            font-family: 'Liberation Mono', 'DejaVu Sans Mono', monospace;
            font-size: 9pt;
            border: 1px solid #333333;
        }
        QHeaderView::section {
            background-color: #2D2D2D;
            color: #CCCCCC;
            padding: 2px 6px;
            border-top: none;
            border-left: none;
            border-right: 1px solid #3C3C3C;
            border-bottom: 1px solid #3C3C3C;
            font-size: 8.5pt;
        }
        QHeaderView::section:hover {
            background-color: #383838;
        }

        /* ─── Event Details Tree ───────────────────────────────── */
        QTreeView {
            background-color: #1E1E1E;
            border: 1px solid #333333;
            color: #D4D4D4;
            font-family: 'Liberation Mono', 'DejaVu Sans Mono', monospace;
            font-size: 9pt;
            show-decoration-selected: 1;
        }
        QTreeView::item:hover {
            background-color: #2A2D2E;
        }
        QTreeView::item:selected {
            background-color: #2A4068;
            color: #FFFFFF;
        }

        /* ─── Event Bytes View ─────────────────────────────────── */
        QPlainTextEdit#eventByteView {
            background-color: #1E1E1E;
            color: #D4D4D4;
            border: 1px solid #333333;
            font-family: 'Liberation Mono', 'DejaVu Sans Mono', monospace;
            font-size: 9pt;
        }

        /* ─── Status Bar ───────────────────────────────────────── */
        QStatusBar {
            background-color: #252526;
            border-top: 1px solid #3C3C3C;
            color: #CCCCCC;
            font-size: 8.5pt;
            min-height: 22px;
        }
        QStatusBar::item {
            border: none;
        }

        /* ─── Display Filter Toolbar ───────────────────────────── */
        QToolBar#displayFilterToolBar {
            background-color: #252526;
            border-bottom: 1px solid #3C3C3C;
            padding: 2px 4px;
        }


        /* ─── Dock Widgets ─────────────────────────────────────── */
        QDockWidget::title {
            background-color: #2D2D2D;
            color: #CCCCCC;
            padding: 4px;
            border: 1px solid #3C3C3C;
        }

        /* ─── Welcome Page Cards ───────────────────────────────── */
        QFrame#welcomeCard {
            background-color: #252526;
            border: 1px solid #3C3C3C;
            border-radius: 4px;
        }
        QLabel#welcomePill {
            background-color: #204A87;
            color: #FFFFFF;
            font-weight: bold;
            font-size: 10pt;
            border-radius: 3px;
            padding: 3px 10px;
        }
        """
