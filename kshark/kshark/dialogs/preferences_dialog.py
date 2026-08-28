"""
Preferences Dialog for KShark (Wireshark Preferences Equivalent).
"""

from PyQt6.QtWidgets import (
    QDialog, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, 
    QLabel, QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QCheckBox, 
    QDialogButtonBox, QPushButton, QFileDialog
)
from PyQt6.QtCore import Qt

from kshark.core.settings import KSharkSettings
from kshark.core.theme import ThemeManager


class PreferencesDialog(QDialog):
    """
    Wireshark-styled multi-tab Preferences Dialog.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("KShark · Preferences")
        self.resize(650, 480)
        self.settings = KSharkSettings()

        self._init_ui()
        self._load_values()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        self.tabs = QTabWidget(self)

        # Tab 1: Appearance & UI
        self.tab_appearance = QWidget()
        app_layout = QFormLayout(self.tab_appearance)
        app_layout.setContentsMargins(16, 16, 16, 16)
        app_layout.setSpacing(12)

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light (Wireshark Classic)", "Dark (Modern SOC)", "System Default"])
        app_layout.addRow("Theme Mode:", self.theme_combo)

        self.font_spin = QSpinBox()
        self.font_spin.setRange(7, 18)
        self.font_spin.setValue(9)
        app_layout.addRow("Monospace Font Size:", self.font_spin)

        self.tabs.addTab(self.tab_appearance, "Appearance")

        # Tab 2: Live Ingestion & Agent
        self.tab_capture = QWidget()
        cap_layout = QFormLayout(self.tab_capture)
        cap_layout.setContentsMargins(16, 16, 16, 16)
        cap_layout.setSpacing(12)

        self.ws_url_edit = QLineEdit()
        cap_layout.addRow("Agent WebSocket URL:", self.ws_url_edit)

        self.rest_url_edit = QLineEdit()
        cap_layout.addRow("Agent REST Base URL:", self.rest_url_edit)

        self.tabs.addTab(self.tab_capture, "Agent & Ingestion")

        # Tab 3: ML Detection Engine & Thresholds
        self.tab_engine = QWidget()
        eng_layout = QFormLayout(self.tab_engine)
        eng_layout.setContentsMargins(16, 16, 16, 16)
        eng_layout.setSpacing(12)

        self.window_sec_spin = QDoubleSpinBox()
        self.window_sec_spin.setRange(1.0, 30.0)
        self.window_sec_spin.setValue(5.0)
        self.window_sec_spin.setSuffix(" seconds")
        eng_layout.addRow("Sliding Feature Window:", self.window_sec_spin)

        self.conf_thresh_spin = QDoubleSpinBox()
        self.conf_thresh_spin.setRange(0.10, 1.00)
        self.conf_thresh_spin.setValue(0.70)
        self.conf_thresh_spin.setSingleStep(0.05)
        eng_layout.addRow("ML Alert Confidence Threshold:", self.conf_thresh_spin)

        self.tabs.addTab(self.tab_engine, "Detection Engine")

        # Tab 4: LLM Security Copilot
        self.tab_llm = QWidget()
        llm_layout = QFormLayout(self.tab_llm)
        llm_layout.setContentsMargins(16, 16, 16, 16)
        llm_layout.setSpacing(12)

        self.llm_provider_combo = QComboBox()
        self.llm_provider_combo.addItems(["Auto-Detect", "NVIDIA Nemotron", "Google Gemini", "OpenAI GPT-4o", "Ollama (Local)"])
        llm_layout.addRow("LLM Provider:", self.llm_provider_combo)

        self.llm_model_edit = QLineEdit()
        llm_layout.addRow("Model Name:", self.llm_model_edit)

        self.llm_key_edit = QLineEdit()
        self.llm_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        llm_layout.addRow("API Key:", self.llm_key_edit)

        self.tabs.addTab(self.tab_llm, "LLM Security Copilot")

        layout.addWidget(self.tabs)

        # Bottom OK / Cancel Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self._save_and_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _load_values(self):
        # Appearance
        theme_mode = self.settings.get_theme_mode()
        if theme_mode == "dark":
            self.theme_combo.setCurrentIndex(1)
        elif theme_mode == "system":
            self.theme_combo.setCurrentIndex(2)
        else:
            self.theme_combo.setCurrentIndex(0)
        self.font_spin.setValue(self.settings.get_font_size())

        # Agent
        self.ws_url_edit.setText(self.settings.get_agent_ws_url())
        self.rest_url_edit.setText(self.settings.get_agent_rest_base())

        # LLM
        self.llm_model_edit.setText(self.settings.get_llm_model())
        self.llm_key_edit.setText(self.settings.get_llm_api_key())

    def _save_and_accept(self):
        # Save Appearance
        idx = self.theme_combo.currentIndex()
        mode = "dark" if idx == 1 else ("system" if idx == 2 else "light")
        self.settings.set_theme_mode(mode)
        self.settings.set_font_size(self.font_spin.value())
        ThemeManager.set_theme(dark=(mode == "dark"))

        # Save Agent
        self.settings.set_agent_ws_url(self.ws_url_edit.text().strip())
        self.settings.set_agent_rest_base(self.rest_url_edit.text().strip())

        # Save LLM
        self.settings.set_llm_config(
            provider=self.llm_provider_combo.currentText(),
            model=self.llm_model_edit.text().strip(),
            api_key=self.llm_key_edit.text().strip()
        )

        self.accept()
