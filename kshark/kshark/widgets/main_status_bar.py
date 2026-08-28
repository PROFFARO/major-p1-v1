"""
Wireshark-accurate Main Status Bar for KShark.

Sections:
  1. Expert Information Badge (Shield icon with Threat Alert count)
  2. Status Message Label (Informational & filter feedback)
  3. Throughput Gauge (EPS: Events Per Second)
  4. Packet / Event Counter (Packets: X | Displayed: Y | Threats: Z)
  5. Profile Switcher (Profile: Default)
"""

from PyQt6.QtWidgets import QStatusBar, QLabel, QToolButton, QWidget, QHBoxLayout
from PyQt6.QtGui import QIcon, QColor
from PyQt6.QtCore import Qt, pyqtSignal

from kshark.resources.icons import KSharkIcons


class MainStatusBar(QStatusBar):
    """
    Multi-section status bar adhering to Wireshark status bar design.
    """

    expertInfoClicked = pyqtSignal()
    profileChangeRequested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.total_events = 0
        self.displayed_events = 0
        self.threat_count = 0
        self.eps = 0.0

        self._init_ui()

    def _init_ui(self):
        # 1. Expert Info Pill / Badge
        self.expert_btn = QToolButton(self)
        self.expert_btn.setIcon(KSharkIcons.shield_critical())
        self.expert_btn.setText(" 0 Threats")
        self.expert_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.expert_btn.setStyleSheet("""
            QToolButton {
                background-color: #2E7D32;
                color: #FFFFFF;
                border-radius: 3px;
                padding: 1px 6px;
                font-weight: bold;
                font-size: 8pt;
            }
        """)
        self.expert_btn.clicked.connect(self.expertInfoClicked.emit)
        self.addWidget(self.expert_btn)

        # 2. Main Informational Message Label
        self.info_label = QLabel("Ready", self)
        self.info_label.setStyleSheet("padding-left: 8px; font-size: 8.5pt;")
        self.addWidget(self.info_label, stretch=1)

        # 3. Throughput (EPS) Permanent Widget
        self.eps_label = QLabel("0.0 EPS", self)
        self.eps_label.setStyleSheet("padding: 0 8px; font-weight: bold; color: #007ACC; font-size: 8.5pt;")
        self.addPermanentWidget(self.eps_label)

        # 4. Event & Packet Counter Permanent Widget
        self.counter_label = QLabel("Packets: 0  Displayed: 0 (100.0%)", self)
        self.counter_label.setStyleSheet("padding: 0 10px; font-size: 8.5pt;")
        self.addPermanentWidget(self.counter_label)

        # 5. Configuration Profile Permanent Widget
        self.profile_btn = QToolButton(self)
        self.profile_btn.setText("Profile: Default")
        self.profile_btn.setStyleSheet("padding: 0 6px; font-size: 8pt;")
        self.profile_btn.clicked.connect(self.profileChangeRequested.emit)
        self.addPermanentWidget(self.profile_btn)

    def set_status_message(self, message: str, is_error: bool = False):
        """Sets informational status message."""
        self.info_label.setText(message)
        if is_error:
            self.info_label.setStyleSheet("padding-left: 8px; font-size: 8.5pt; color: #D32F2F; font-weight: bold;")
        else:
            self.info_label.setStyleSheet("padding-left: 8px; font-size: 8.5pt;")

    def update_stats(self, total: int, displayed: int, threats: int, eps: float = 0.0):
        """Updates event counts and expert threat badge."""
        self.total_events = total
        self.displayed_events = displayed
        self.threat_count = threats
        self.eps = eps

        # Update EPS
        self.eps_label.setText(f"{self.eps:.1f} EPS")

        # Update Counters
        pct = (displayed / total * 100.0) if total > 0 else 100.0
        self.counter_label.setText(f"Packets: {total:,}  Displayed: {displayed:,} ({pct:.1f}%)")

        # Update Threat Badge
        if threats > 0:
            self.expert_btn.setText(f" {threats} Threats")
            self.expert_btn.setStyleSheet("""
                QToolButton {
                    background-color: #D32F2F;
                    color: #FFFFFF;
                    border-radius: 3px;
                    padding: 1px 6px;
                    font-weight: bold;
                    font-size: 8pt;
                }
            """)
        else:
            self.expert_btn.setText(" Protected")
            self.expert_btn.setStyleSheet("""
                QToolButton {
                    background-color: #2E7D32;
                    color: #FFFFFF;
                    border-radius: 3px;
                    padding: 1px 6px;
                    font-weight: bold;
                    font-size: 8pt;
                }
            """)
