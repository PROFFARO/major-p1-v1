"""
Stratoshark Main Status Bar — Event Counters, EPS, Active Filter, and Profile Status.
Direct port of ui/stratoshark/stratoshark_main_status_bar.cpp.
"""

from PyQt6.QtWidgets import QStatusBar, QLabel, QWidget, QHBoxLayout, QPushButton
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtCore import Qt

from stratoshark.core.theme import ThemeManager, get_monospace_font


class MainStatusBar(QStatusBar):
    """
    Stratoshark Main Status Bar.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("stratosharkStatusBar")

        self.threat_count = 0
        self.eps = 0.0

        self._init_ui()

    def _init_ui(self):
        # 1. Protection Badge (Left)
        self.lbl_protected = QLabel("  🛡️ Protected  ", self)
        self.lbl_protected.setStyleSheet("background-color: #0EA773; color: white; border-radius: 3px; font-weight: bold;")
        self.addWidget(self.lbl_protected)

        # 2. Main Status Message
        self.lbl_message = QLabel("Ready to capture kernel events", self)
        self.addWidget(self.lbl_message, stretch=1)

        # 3. Permanent Widgets (Right)
        # EPS
        self.lbl_eps = QLabel("0.0 EPS", self)
        self.lbl_eps.setFont(get_monospace_font(size=8))
        self.lbl_eps.setStyleSheet("color: #0E9AA7; font-weight: bold; padding: 0 8px;")
        self.addPermanentWidget(self.lbl_eps)

        # Packets Count
        self.lbl_packets = QLabel("Events: 0  Displayed: 0 (100.0%)", self)
        self.lbl_packets.setFont(get_monospace_font(size=8))
        self.lbl_packets.setStyleSheet("padding: 0 8px;")
        self.addPermanentWidget(self.lbl_packets)

        # Profile
        self.btn_profile = QPushButton("Profile: Default", self)
        self.btn_profile.setFlat(True)
        self.btn_profile.setStyleSheet("padding: 0 6px; font-weight: 500;")
        self.addPermanentWidget(self.btn_profile)

    def set_status_message(self, text: str, is_error: bool = False):
        colors = ThemeManager.instance().get_palette_colors()
        fg = colors["accent_danger"] if is_error else colors["fg_text"]
        self.lbl_message.setStyleSheet(f"color: {fg};")
        self.lbl_message.setText(text)

    def update_stats(self, total: int, displayed: int, threats: int = 0, eps: float = 0.0):
        self.threat_count = threats
        self.eps = eps

        pct = (displayed / total * 100.0) if total > 0 else 100.0
        self.lbl_packets.setText(f"Events: {total:,}  Displayed: {displayed:,} ({pct:.1f}%)")
        self.lbl_eps.setText(f"{eps:.1f} EPS")

        if threats > 0:
            self.lbl_protected.setText(f"  🚨 {threats} Threat(s)  ")
            self.lbl_protected.setStyleSheet("background-color: #C92A2A; color: white; border-radius: 3px; font-weight: bold;")
        else:
            self.lbl_protected.setText("  🛡️ Protected  ")
            self.lbl_protected.setStyleSheet("background-color: #0EA773; color: white; border-radius: 3px; font-weight: bold;")
