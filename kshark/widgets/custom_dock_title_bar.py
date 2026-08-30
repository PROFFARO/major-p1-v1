"""
Custom Title Bar for KShark Dock Widgets.
Features Minimize [-], Float/Dock [⤢], and Close [✕] buttons for professional IDE panel management.
"""

from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel, QPushButton, QDockWidget
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import Qt, pyqtSignal

from kshark.core.theme import ThemeManager, get_ui_font, get_monospace_font


class KSharkDockTitleBar(QWidget):
    """Clean, high-density custom title bar for QDockWidget panels."""

    minimizeClicked = pyqtSignal()

    def __init__(self, dock_widget: QDockWidget, title: str, parent=None):
        super().__init__(parent)
        self.dock_widget = dock_widget
        self.title_text = title
        self._init_ui()
        ThemeManager.instance().themeChanged.connect(self._apply_theme)
        self._apply_theme()

    def _init_ui(self):
        self.setFixedHeight(26)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 2, 6, 2)
        layout.setSpacing(4)

        # Title Label
        self.lbl_title = QLabel(self.title_text, self)
        self.lbl_title.setFont(get_ui_font(size=8, bold=True))
        layout.addWidget(self.lbl_title)

        layout.addStretch(1)

        # 1. Minimize Button [-]
        self.btn_min = QPushButton("—", self)
        self.btn_min.setFont(get_monospace_font(size=7.5, bold=True))
        self.btn_min.setToolTip("Minimize to Edge Drawer Tab")
        self.btn_min.clicked.connect(self._on_minimize)
        layout.addWidget(self.btn_min)

        # 2. Float / Dock Button [⤢]
        self.btn_float = QPushButton("⤢", self)
        self.btn_float.setFont(get_ui_font(size=8))
        self.btn_float.setToolTip("Toggle Floating Window")
        self.btn_float.clicked.connect(self._toggle_floating)
        layout.addWidget(self.btn_float)

        # 3. Close Button [✕]
        self.btn_close = QPushButton("✕", self)
        self.btn_close.setFont(get_ui_font(size=7.5))
        self.btn_close.setToolTip("Close Panel")
        self.btn_close.clicked.connect(self.dock_widget.close)
        layout.addWidget(self.btn_close)

    def _apply_theme(self):
        c = ThemeManager.instance().get_palette_colors()
        is_dark = ThemeManager.is_dark()
        bg = "#16262D" if is_dark else c["bg_window"]
        border = c["border"]
        brand = c["brand_primary"]
        fg_muted = c["fg_muted"]
        bg_alt = c["bg_alt"]
        fg_text = c["fg_text"]

        self.setStyleSheet(f"background-color: {bg}; border-bottom: 1px solid {border};")
        self.lbl_title.setStyleSheet(f"color: {brand}; border: none; background: transparent;")

        btn_style = f"""
            QPushButton {{
                background-color: transparent;
                color: {fg_muted};
                border: 1px solid transparent;
                border-radius: 2px;
                font-family: monospace;
                font-size: 8pt;
                font-weight: bold;
                min-width: 18px;
                max-width: 18px;
                min-height: 18px;
                max-height: 18px;
                padding: 0;
            }}
            QPushButton:hover {{
                background-color: {bg_alt};
                color: {fg_text};
                border-color: {border};
            }}
        """
        self.btn_min.setStyleSheet(btn_style)
        self.btn_float.setStyleSheet(btn_style)
        self.btn_close.setStyleSheet(f"""
            {btn_style}
            QPushButton:hover {{
                background-color: #E74C3C;
                color: #FFFFFF;
                border-color: #C0392B;
            }}
        """)

    def _on_minimize(self):
        self.minimizeClicked.emit()
        self.dock_widget.hide()

    def _toggle_floating(self):
        self.dock_widget.setFloating(not self.dock_widget.isFloating())
