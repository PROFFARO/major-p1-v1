"""
Stratoshark Copilot Dock — Local LLM Security Analyst Platform.
"""

from PyQt6.QtWidgets import (
    QDockWidget, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel, QScrollArea
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import pyqtSignal, Qt

from stratoshark.core.theme import get_ui_font, get_monospace_font


class CopilotDock(QDockWidget):
    """
    Stratoshark AI Security Copilot Analyst Dock.
    """

    copilotQuerySubmitted = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__("AI Security Copilot", parent)
        self.setObjectName("copilotDock")
        self.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea)
        self._init_ui()

    def _init_ui(self):
        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # Conversation History
        self.history_view = QTextEdit(self)
        self.history_view.setReadOnly(True)
        self.history_view.setFont(get_ui_font(size=9))
        self.history_view.setHtml("""
            <div style='color: #0E9AA7; font-weight: bold;'>🤖 Stratoshark Security Copilot Online</div>
            <div style='color: #8A9EA4; font-size: 8.5pt;'>Analyzing live kernel system calls, eBPF telemetry, and threat markers.</div>
            <hr style='border: 0; border-top: 1px solid #283C42;'/>
        """)
        layout.addWidget(self.history_view, stretch=1)

        # Prompt Input
        input_layout = QHBoxLayout()
        self.input_field = QLineEdit(self)
        self.input_field.setPlaceholderText("Ask Copilot about active events or threats...")
        self.input_field.returnPressed.connect(self._on_submit)
        input_layout.addWidget(self.input_field, stretch=1)

        self.btn_send = QPushButton("Ask", self)
        self.btn_send.clicked.connect(self._on_submit)
        input_layout.addWidget(self.btn_send)

        layout.addLayout(input_layout)
        self.setWidget(container)

    def _on_submit(self):
        text = self.input_field.text().strip()
        if not text:
            return

        self.input_field.clear()
        self.history_view.append(f"<div style='margin-top: 6px;'><b>👤 You:</b> {text}</div>")
        self.history_view.append("<div style='color: #8A9EA4; font-style: italic;'>Analyzing kernel telemetry...</div>")
        self.copilotQuerySubmitted.emit(text)

    def append_copilot_response(self, prompt: str, response: str):
        # Remove thinking placeholder and append response
        self.history_view.append(f"<div style='margin-top: 4px; color: #0EA773;'><b>🤖 Copilot:</b> {response}</div><br/>")
        sb = self.history_view.verticalScrollBar()
        sb.setValue(sb.maximum())
