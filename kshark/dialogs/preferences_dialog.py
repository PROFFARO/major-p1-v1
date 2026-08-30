"""
KShark Preferences & Configuration Profiles Dialog.

Structured tabs:
1. Appearance & Display (Themes, Font Size, Auto-Scroll)
2. Configuration Profiles (Active profile selector, Create, Delete)
3. Buffer & Capture Defaults (Max buffer size, default filter)
4. Telemetry & Agent Connection (WebSocket URL)
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QTabWidget, QWidget, QLineEdit, QFormLayout, QSpinBox, QCheckBox,
    QInputDialog, QMessageBox
)
from PyQt6.QtCore import Qt

from kshark.core.theme import ThemeManager, get_monospace_font, get_ui_font
from kshark.core.settings import KSharkSettings


class PreferencesDialog(QDialog):
    """
    KShark Global Preferences & Configuration Profiles Dialog.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("KShark · Preferences")
        self.resize(600, 400)
        self.settings = KSharkSettings()
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        tabs = QTabWidget(self)
        tabs.setFont(get_ui_font(size=8, bold=True))

        # ── Tab 1: Appearance & Display ──
        t1 = QWidget()
        l1 = QFormLayout(t1)
        l1.setContentsMargins(16, 16, 16, 16)
        l1.setSpacing(12)

        self.combo_theme = QComboBox(self)
        self.combo_theme.setFont(get_ui_font(size=8.5))
        self.combo_theme.addItem("Wireshark Dark (Default)", ThemeManager.THEME_WIRESHARK_DARK)
        self.combo_theme.addItem("Wireshark Light", ThemeManager.THEME_WIRESHARK_LIGHT)

        cur = ThemeManager.current_theme()
        for idx in range(self.combo_theme.count()):
            if self.combo_theme.itemData(idx) == cur:
                self.combo_theme.setCurrentIndex(idx)
                break
        l1.addRow("Appearance Theme:", self.combo_theme)

        self.spin_font_size = QSpinBox(self)
        self.spin_font_size.setFont(get_monospace_font(size=8.5))
        self.spin_font_size.setRange(6, 24)
        self.spin_font_size.setValue(self.settings.get_font_size())
        self.spin_font_size.setSuffix(" pt")
        l1.addRow("Dissection Table Font Size:", self.spin_font_size)

        self.chk_auto_scroll = QCheckBox("Automatically scroll event list to latest packet during live capture", self)
        self.chk_auto_scroll.setFont(get_ui_font(size=8))
        self.chk_auto_scroll.setChecked(self.settings.get_auto_scroll())
        l1.addRow("Auto-Scroll:", self.chk_auto_scroll)

        tabs.addTab(t1, "Appearance & Display")

        # ── Tab 2: Configuration Profiles ──
        t2 = QWidget()
        l2 = QVBoxLayout(t2)
        l2.setContentsMargins(16, 16, 16, 16)
        l2.setSpacing(10)

        f2 = QFormLayout()
        f2.setSpacing(10)

        self.combo_profile = QComboBox(self)
        self.combo_profile.setFont(get_ui_font(size=8.5))
        self._reload_profiles()
        f2.addRow("Active Profile:", self.combo_profile)
        l2.addLayout(f2)

        prof_btns = QHBoxLayout()
        prof_btns.setSpacing(8)

        btn_new_prof = QPushButton("＋ New Profile...", self)
        btn_new_prof.setFont(get_ui_font(size=8))
        btn_new_prof.clicked.connect(self._create_profile)
        prof_btns.addWidget(btn_new_prof)

        btn_del_prof = QPushButton("－ Delete Profile", self)
        btn_del_prof.setFont(get_ui_font(size=8))
        btn_del_prof.clicked.connect(self._delete_profile)
        prof_btns.addWidget(btn_del_prof)

        prof_btns.addStretch(1)
        l2.addLayout(prof_btns)
        l2.addStretch(1)

        tabs.addTab(t2, "Configuration Profiles")

        # ── Tab 3: Capture & Buffer Defaults ──
        t3 = QWidget()
        l3 = QFormLayout(t3)
        l3.setContentsMargins(16, 16, 16, 16)
        l3.setSpacing(12)

        self.spin_buffer = QSpinBox(self)
        self.spin_buffer.setFont(get_monospace_font(size=8.5))
        self.spin_buffer.setRange(1000, 1000000)
        self.spin_buffer.setSingleStep(5000)
        self.spin_buffer.setValue(self.settings.get_max_buffer_events())
        self.spin_buffer.setSuffix(" events")
        l3.addRow("Max In-Memory Event Capacity:", self.spin_buffer)

        self.edit_default_filter = QLineEdit(self.settings.get_default_filter(), self)
        self.edit_default_filter.setFont(get_monospace_font(size=8.5))
        self.edit_default_filter.setPlaceholderText("e.g. threat.name != 'BENIGN'")
        l3.addRow("Default Display Filter on Startup:", self.edit_default_filter)

        tabs.addTab(t3, "Capture & Buffer")

        # ── Tab 4: Telemetry Agent & eBPF ──
        t4 = QWidget()
        l4 = QFormLayout(t4)
        l4.setContentsMargins(16, 16, 16, 16)
        l4.setSpacing(12)

        self.ws_input = QLineEdit(self.settings.get_agent_ws_url(), self)
        self.ws_input.setFont(get_monospace_font(size=8.5))
        l4.addRow("eBPF Agent WebSocket URL:", self.ws_input)

        tabs.addTab(t4, "eBPF Subsystems")

        layout.addWidget(tabs, stretch=1)

        # ── Action Buttons ──
        btn_layout = QHBoxLayout()
        btn_layout.addStretch(1)

        btn_apply = QPushButton("OK", self)
        btn_apply.setFont(get_ui_font(size=8, bold=True))
        btn_apply.setDefault(True)
        btn_apply.clicked.connect(self._on_apply)
        btn_layout.addWidget(btn_apply)

        btn_cancel = QPushButton("Cancel", self)
        btn_cancel.setFont(get_ui_font(size=8))
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(btn_cancel)

        layout.addLayout(btn_layout)

    def _reload_profiles(self):
        self.combo_profile.clear()
        profiles = self.settings.get_profiles()
        active = self.settings.get_active_profile()
        self.combo_profile.addItems(profiles)
        idx = self.combo_profile.findText(active)
        if idx >= 0:
            self.combo_profile.setCurrentIndex(idx)

    def _create_profile(self):
        name, ok = QInputDialog.getText(self, "New Profile", "Enter configuration profile name:")
        if ok and name.strip():
            clean_name = name.strip()
            profiles = self.settings.get_profiles()
            if clean_name not in profiles:
                profiles.append(clean_name)
                self.settings.set_profiles(profiles)
                self.settings.set_active_profile(clean_name)
                self._reload_profiles()

    def _delete_profile(self):
        current = self.combo_profile.currentText()
        if "Default" in current:
            QMessageBox.warning(self, "Cannot Delete", "The default profile cannot be deleted.")
            return
        profiles = self.settings.get_profiles()
        if current in profiles and len(profiles) > 1:
            profiles.remove(current)
            self.settings.set_profiles(profiles)
            self.settings.set_active_profile(profiles[0])
            self._reload_profiles()

    def _on_apply(self):
        theme_key = self.combo_theme.currentData()
        ThemeManager.instance().set_theme(theme_key)
        self.settings.set_theme(theme_key)
        new_font_size = self.spin_font_size.value()
        self.settings.set_font_size(new_font_size)
        parent = self.parent()
        if parent is not None and hasattr(parent, "apply_font_size"):
            parent.apply_font_size(new_font_size)
        auto_scroll_val = self.chk_auto_scroll.isChecked()
        self.settings.set_auto_scroll(auto_scroll_val)
        if parent is not None and hasattr(parent, "auto_scroll"):
            parent.auto_scroll = auto_scroll_val
            if hasattr(parent, "toolbar") and hasattr(parent.toolbar, "act_autoscroll"):
                parent.toolbar.act_autoscroll.setChecked(auto_scroll_val)
        self.settings.set_active_profile(self.combo_profile.currentText())
        self.settings.set_max_buffer_events(self.spin_buffer.value())
        self.settings.set_default_filter(self.edit_default_filter.text().strip())
        self.settings.set_agent_ws_url(self.ws_input.text().strip())
        self.accept()
