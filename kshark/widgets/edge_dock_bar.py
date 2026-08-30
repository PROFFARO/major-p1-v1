"""
KShark Edge Dock & Component Restore Bar.
Provides compact edge drawer restore tabs allowing users to minimize any component
and instantly restore or drag it back into the application workspace.
"""

from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QLabel,
    QFrame, QSizePolicy
)
from PyQt6.QtGui import QFont, QColor, QPainter, QBrush, QPen
from PyQt6.QtCore import Qt, pyqtSignal, QSize

from kshark.core.theme import ThemeManager, get_ui_font, get_monospace_font


class EdgeRestoreTabButton(QPushButton):
    """Compact, professional edge restore tab button with status indicator."""

    def __init__(self, text: str, shortcut_hint: str = "", parent=None):
        super().__init__(parent)
        self.tab_text = text
        self.shortcut_hint = shortcut_hint
        self._is_active = False
        self.setFont(get_ui_font(size=7.5, bold=True))
        self.setFixedHeight(22)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        ThemeManager.instance().themeChanged.connect(lambda: self._update_label())
        self._update_label()

    def set_component_active(self, active: bool):
        self._is_active = active
        self._update_label()
        self.update()

    def _update_label(self):
        c = ThemeManager.instance().get_palette_colors()
        bg_base = c.get("bg_base", "#182428")
        bg_alt = c.get("bg_alt", "#1F2E34")
        fg_text = c.get("fg_text", "#D8E8EC")
        fg_muted = c.get("fg_muted", "#8A9EA4")
        brand = c.get("brand_primary", "#2BC1CF")
        border = c.get("border", "#283C42")

        state_symbol = "●" if self._is_active else "○"
        sc = f" [{self.shortcut_hint}]" if self.shortcut_hint else ""
        self.setText(f"{state_symbol} {self.tab_text}{sc}")
        
        if self._is_active:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {bg_base};
                    color: {brand};
                    border: 1px solid {brand};
                    border-radius: 2px;
                    padding: 2px 8px;
                    text-align: left;
                }}
                QPushButton:hover {{
                    background-color: {bg_alt};
                    color: {brand};
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {bg_alt};
                    color: {fg_muted};
                    border: 1px solid {border};
                    border-radius: 2px;
                    padding: 2px 8px;
                    text-align: left;
                }}
                QPushButton:hover {{
                    background-color: {bg_base};
                    color: {fg_text};
                    border-color: {brand};
                }}
            """)


class BottomEdgeRestoreBar(QFrame):
    """Bottom edge drawer strip holding restore tabs for bottom docks and splitter panes."""

    toggleTimelineRequested = pyqtSignal()
    toggleDissectionRequested = pyqtSignal()
    toggleByteViewRequested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(26)
        self._init_ui()
        ThemeManager.instance().themeChanged.connect(self._apply_theme)

    def _init_ui(self):
        c = ThemeManager.instance().get_palette_colors()
        border = c.get("border", "#283C42")
        fg_muted = c.get("fg_muted", "#8A9EA4")
        bg_window = c.get("bg_window", "#121E22")
        self.setStyleSheet(f"background-color: {bg_window}; border-top: 1px solid {border};")
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 2, 6, 2)
        layout.setSpacing(6)

        self.lbl_edge = QLabel("WORKSPACE PANELS:", self)
        self.lbl_edge.setFont(get_monospace_font(size=7, bold=True))
        self.lbl_edge.setStyleSheet(f"color: {fg_muted}; border: none;")
        layout.addWidget(self.lbl_edge)

        self.btn_timeline = EdgeRestoreTabButton("Threat Timeline", "Alt+1", self)
        self.btn_timeline.clicked.connect(self.toggleTimelineRequested.emit)
        layout.addWidget(self.btn_timeline)

        self.btn_dissection = EdgeRestoreTabButton("Dissection Tree", "Alt+3", self)
        self.btn_dissection.clicked.connect(self.toggleDissectionRequested.emit)
        self.btn_dissection.set_component_active(True)
        layout.addWidget(self.btn_dissection)

        self.btn_byte = EdgeRestoreTabButton("Hex & Byte Inspector", "Alt+4", self)
        self.btn_byte.clicked.connect(self.toggleByteViewRequested.emit)
        self.btn_byte.set_component_active(True)
        layout.addWidget(self.btn_byte)

        layout.addStretch(1)

    def _apply_theme(self):
        c = ThemeManager.instance().get_palette_colors()
        border = c.get("border", "#283C42")
        fg_muted = c.get("fg_muted", "#8A9EA4")
        bg_window = c.get("bg_window", "#121E22")
        self.setStyleSheet(f"background-color: {bg_window}; border-top: 1px solid {border};")
        self.lbl_edge.setStyleSheet(f"color: {fg_muted}; border: none;")


class RightEdgeRestoreBar(QFrame):
    """Right vertical edge strip for AI Copilot and forensic side-drawers."""

    toggleCopilotRequested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(28)
        self._init_ui()
        ThemeManager.instance().themeChanged.connect(self._apply_theme)

    def _init_ui(self):
        c = ThemeManager.instance().get_palette_colors()
        border = c.get("border", "#283C42")
        bg_window = c.get("bg_window", "#121E22")
        self.setStyleSheet(f"background-color: {bg_window}; border-left: 1px solid {border};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(2, 6, 2, 6)
        layout.setSpacing(6)

        self.btn_copilot = QPushButton("C\nO\nP\nI\nL\nO\nT", self)
        self.btn_copilot.setFont(get_monospace_font(size=7.5, bold=True))
        self.btn_copilot.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_copilot.setToolTip("AI Security Copilot (Alt+2) — Click to Restore / Minimize")
        layout.addWidget(self.btn_copilot)
        self.btn_copilot.clicked.connect(self.toggleCopilotRequested.emit)
        self._apply_theme()
        layout.addStretch(1)

    def _apply_theme(self):
        c = ThemeManager.instance().get_palette_colors()
        border = c.get("border", "#283C42")
        bg_alt = c.get("bg_alt", "#1F2E34")
        bg_window = c.get("bg_window", "#121E22")
        brand = c.get("brand_primary", "#2BC1CF")
        self.setStyleSheet(f"background-color: {bg_window}; border-left: 1px solid {border};")
        self.btn_copilot.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg_alt};
                color: {brand};
                border: 1px solid {border};
                border-radius: 2px;
                padding: 6px 2px;
            }}
            QPushButton:hover {{
                background-color: {c['bg_base']};
                border-color: {brand};
                color: {brand};
            }}
        """)

    def set_copilot_active(self, active: bool):
        c = ThemeManager.instance().get_palette_colors()
        bg_base = c.get("bg_base", "#182428")
        bg_alt = c.get("bg_alt", "#1F2E34")
        brand = c.get("brand_primary", "#2BC1CF")
        fg_muted = c.get("fg_muted", "#8A9EA4")
        fg_text = c.get("fg_text", "#D8E8EC")
        border = c.get("border", "#283C42")

        if active:
            self.btn_copilot.setStyleSheet(f"""
                QPushButton {{
                    background-color: {bg_base};
                    color: {brand};
                    border: 1px solid {brand};
                    border-radius: 2px;
                    padding: 6px 2px;
                }}
                QPushButton:hover {{
                    background-color: {bg_alt};
                    color: {brand};
                }}
            """)
        else:
            self.btn_copilot.setStyleSheet(f"""
                QPushButton {{
                    background-color: {bg_alt};
                    color: {fg_muted};
                    border: 1px solid {border};
                    border-radius: 2px;
                    padding: 6px 2px;
                }}
                QPushButton:hover {{
                    background-color: {bg_base};
                    border-color: {brand};
                    color: {fg_text};
                }}
            """)

