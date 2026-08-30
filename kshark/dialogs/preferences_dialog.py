"""
KShark Preferences & Configuration Profiles Dialog.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QTabWidget, QWidget, QLineEdit, QFormLayout
)
from PyQt6.QtCore import Qt

from kshark.core.theme import ThemeManager
from kshark.core.settings import KSharkSettings


class PreferencesDialog(QDialog):
    """
    KShark Preferences Dialog.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("KShark · Preferences")
        self.resize(560, 360)
        self.settings = KSharkSettings()
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        tabs = QTabWidget(self)

        # Tab 1: Appearance & Themes
        t1 = QWidget()
        l1 = QFormLayout(t1)
        l1.setContentsMargins(16, 16, 16, 16)
        l1.setSpacing(12)

        self.combo_theme = QComboBox(self)
        self.combo_theme.addItem("KShark Cloud Teal (Dark)", ThemeManager.THEME_KSHARK_DARK)
        self.combo_theme.addItem("KShark Cloud Teal (Light)", ThemeManager.THEME_KSHARK_LIGHT)
        self.combo_theme.addItem("Wireshark Classic (Light)", ThemeManager.THEME_WIRESHARK_CLASSIC)
        self.combo_theme.addItem("Wireshark Modern (Dark)", ThemeManager.THEME_WIRESHARK_DARK)

        # Select active
        cur = ThemeManager.current_theme()
        for idx in range(self.combo_theme.count()):
            if self.combo_theme.itemData(idx) == cur:
                self.combo_theme.setCurrentIndex(idx)
                break

        l1.addRow("Appearance Theme:", self.combo_theme)

        # Profile selection
        self.combo_profile = QComboBox(self)
        self.combo_profile.addItems(["Default (Linux Syscalls & eBPF)", "CloudTrail (AWS Cloud Logs)", "Kubernetes (Container Pods)"])
        l1.addRow("Active Configuration Profile:", self.combo_profile)

        tabs.addTab(t1, "Appearance & Profiles")

        # Tab 2: eBPF & Agent Connection
        t2 = QWidget()
        l2 = QFormLayout(t2)
        l2.setContentsMargins(16, 16, 16, 16)
        l2.setSpacing(12)

        self.ws_input = QLineEdit(self.settings.get_agent_ws_url(), self)
        l2.addRow("eBPF Agent WebSocket URL:", self.ws_input)

        tabs.addTab(t2, "eBPF Subsystems")

        layout.addWidget(tabs, stretch=1)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch(1)

        btn_apply = QPushButton("OK", self)
        btn_apply.setDefault(True)
        btn_apply.clicked.connect(self._on_apply)
        btn_layout.addWidget(btn_apply)

        btn_cancel = QPushButton("Cancel", self)
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(btn_cancel)

        layout.addLayout(btn_layout)

    def _on_apply(self):
        theme_key = self.combo_theme.currentData()
        ThemeManager.instance().set_theme(theme_key)
        self.settings.set_theme(theme_key)
        self.settings.set_agent_ws_url(self.ws_input.text().strip())
        self.accept()
