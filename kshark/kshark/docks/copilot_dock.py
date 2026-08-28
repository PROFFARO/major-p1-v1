"""
Dockable LLM Security Analyst Copilot Panel for KShark.

Provides interactive SOC AI investigation, threat summarization, and remediation runbooks.
"""

from PyQt6.QtWidgets import (
    QDockWidget, QWidget, QVBoxLayout, QHBoxLayout, QTextBrowser, 
    QLineEdit, QPushButton, QLabel, QToolButton
)
from PyQt6.QtGui import QIcon, QFont
from PyQt6.QtCore import Qt, pyqtSignal
from typing import Dict, Any, Optional


class CopilotDock(QDockWidget):
    """
    Dockable LLM Security Copilot Analyst Panel.
    """

    copilotQuerySubmitted = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__("AI Security Analyst Copilot", parent)
        self.setObjectName("copilotDock")
        self.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea | Qt.DockWidgetArea.BottomDockWidgetArea)

        self._init_ui()

    def _init_ui(self):
        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # 1. Header Info Bar
        info_bar = QHBoxLayout()
        self.status_lbl = QLabel("● Copilot Online (NVIDIA Nemotron / Gemini)", self)
        self.status_lbl.setStyleSheet("color: #2E7D32; font-weight: bold; font-size: 8.5pt;")
        info_bar.addWidget(self.status_lbl)
        info_bar.addStretch(1)

        clear_btn = QToolButton(self)
        clear_btn.setText("Clear Chat")
        clear_btn.setStyleSheet("font-size: 8pt;")
        clear_btn.clicked.connect(self._clear_chat)
        info_bar.addWidget(clear_btn)
        layout.addLayout(info_bar)

        # 2. Rich Chat History Browser
        self.chat_browser = QTextBrowser(self)
        self.chat_browser.setOpenExternalLinks(True)
        self.chat_browser.setStyleSheet("""
            QTextBrowser {
                background-color: #FFFFFF;
                border: 1px solid #D0D0D0;
                border-radius: 4px;
                padding: 6px;
                font-size: 9pt;
            }
        """)
        self._append_system_message("Welcome to KShark AI Security Copilot. Click any event and choose 'Investigate with Copilot' or type a query below.")
        layout.addWidget(self.chat_browser, stretch=1)

        # 3. Quick Action Forensic Buttons
        quick_layout = QHBoxLayout()
        quick_layout.setSpacing(4)

        btn_triage = QPushButton("⚡ Triage Recent Threats")
        btn_triage.setStyleSheet("font-size: 8pt; padding: 3px 6px;")
        btn_triage.clicked.connect(lambda: self.submit_query("Analyze the most recent threats detected and summarize their MITRE ATT&CK techniques."))
        quick_layout.addWidget(btn_triage)

        btn_remediation = QPushButton("🛡️ Remediation Runbook")
        btn_remediation.setStyleSheet("font-size: 8pt; padding: 3px 6px;")
        btn_remediation.clicked.connect(lambda: self.submit_query("Generate an incident remediation runbook for all critical/high threats recorded."))
        quick_layout.addWidget(btn_remediation)

        layout.addLayout(quick_layout)

        # 4. Prompt Input Bar
        input_layout = QHBoxLayout()
        self.input_field = QLineEdit(self)
        self.input_field.setPlaceholderText("Ask AI Analyst about kernel anomalies, PIDs, or runbooks...")
        self.input_field.returnPressed.connect(self._on_submit)
        input_layout.addWidget(self.input_field, stretch=1)

        self.send_btn = QPushButton("Send", self)
        self.send_btn.setStyleSheet("""
            QPushButton {
                background-color: #007ACC;
                color: #FFFFFF;
                border-radius: 3px;
                padding: 4px 12px;
                font-weight: bold;
            }
        """)
        self.send_btn.clicked.connect(self._on_submit)
        input_layout.addWidget(self.send_btn)

        layout.addLayout(input_layout)
        self.setWidget(container)

    def _on_submit(self):
        prompt = self.input_field.text().strip()
        if not prompt:
            return
        self.input_field.clear()
        self.submit_query(prompt)

    def submit_query(self, prompt: str):
        """Appends user query to chat and emits signal to backend bridge."""
        self._append_user_message(prompt)
        self._append_system_message("<i>Analyzing telemetry context with AI Copilot...</i>")
        self.copilotQuerySubmitted.emit(prompt)

    def handle_response(self, prompt: str, response: str):
        """Displays completed LLM Copilot response."""
        # Format markdown response into clean HTML
        html_response = response.replace("\n", "<br>")
        self._append_copilot_message(html_response)

    def investigate_event(self, event: Dict[str, Any]):
        """Initiates one-click investigation for a specific event."""
        pid = event.get("pid", 0)
        comm = event.get("comm", "unknown")
        threat = event.get("threat_name") or event.get("threat_type") or "BENIGN"
        syscall = event.get("syscall") or f"sys_{event.get('syscall_id', '')}"
        file_p = event.get("file_path") or event.get("filename") or ""

        prompt = (
            f"Investigate suspicious event: PID {pid} ({comm}), Threat: {threat}, "
            f"Syscall: {syscall}, Target: {file_p}. Assess risk, MITRE technique, and suggest remediation."
        )
        self.submit_query(prompt)

    def _append_user_message(self, text: str):
        self.chat_browser.append(f"<p style='color: #007ACC; font-weight: bold;'>👤 Analyst:</p><p style='margin-left: 10px;'>{text}</p><hr>")

    def _append_copilot_message(self, text: str):
        self.chat_browser.append(f"<p style='color: #2E7D32; font-weight: bold;'>🤖 Security Copilot:</p><div style='margin-left: 10px; line-height: 1.4;'>{text}</div><hr>")

    def _append_system_message(self, text: str):
        self.chat_browser.append(f"<p style='color: #777777; font-size: 8.5pt;'>{text}</p>")

    def _clear_chat(self):
        self.chat_browser.clear()
        self._append_system_message("Chat cleared.")
