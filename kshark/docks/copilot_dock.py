"""
KShark AI Security Copilot Analyst Platform.
Enterprise-grade SOC Forensic Assistant supporting local LLMs (Ollama, llama.cpp, LM Studio)
and cloud providers (Gemini, OpenAI, Groq) with multi-threaded asynchronous reasoning,
Sigma/YARA rule generation, incident containment playbooks, and heuristic fallback.
"""

import json
import html
import collections
from typing import Dict, Any, Optional, List

from PyQt6.QtWidgets import (
    QDockWidget, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel, QComboBox, QDialog, QFrame,
    QFormLayout, QMessageBox, QApplication, QSplitter, QTabWidget,
    QPlainTextEdit
)
from PyQt6.QtGui import QFont, QColor, QBrush, QTextCursor, QTextOption
from PyQt6.QtCore import pyqtSignal, Qt, QThread

from kshark.core.theme import ThemeManager, get_ui_font, get_monospace_font
from ml_engine.llm_analyst.copilot import LLMSecurityCopilot


from markdown_it import MarkdownIt


class LLMCopilotWorker(QThread):
    """Asynchronous worker thread for LLM security analyst queries."""

    responseReady = pyqtSignal(str, str, str)  # prompt_type, prompt_raw, formatted_html
    errorOccurred = pyqtSignal(str)

    def __init__(self, copilot: LLMSecurityCopilot, prompt: str, context: Optional[dict] = None, recent_events: Optional[list] = None):
        super().__init__()
        self.copilot = copilot
        self.prompt = prompt
        self.context = context or {}
        self.recent_events = recent_events or []
        self._md = MarkdownIt("gfm-like")

    def run(self):
        try:
            prompt_type = "chat"
            if self.prompt.startswith("__ANALYZE_EVENT__") and self.context:
                prompt_type = "analyze"
                res = self.copilot.analyze_threat(self.context)
                rep = res if isinstance(res, str) else (res.get("report") or res.get("offline_report", "Analysis completed."))
            elif self.prompt.startswith("__REMEDIATION__") and self.context:
                prompt_type = "playbook"
                res = self.copilot.generate_remediation(self.context)
                rep = res if isinstance(res, str) else (res.get("playbook") or res.get("offline_playbook", "Playbook generated."))
            else:
                rep = self.copilot.chat_with_analyst(
                    self.prompt,
                    session_context=self.context,
                    recent_events=self.recent_events
                )

            formatted_html = self._format_markdown_to_html(rep)
            self.responseReady.emit(prompt_type, self.prompt, formatted_html)
        except Exception as e:
            self.errorOccurred.emit(str(e))

    def _format_markdown_to_html(self, text: str) -> str:
        """Converts markdown into clean, high-density terminal HTML with strict horizontal wrapping."""
        try:
            rendered = self._md.render(text)
        except Exception:
            rendered = f"<pre>{html.escape(text)}</pre>"

        c = ThemeManager.instance().get_palette_colors()
        is_dark = ThemeManager.is_dark()
        bg_base = c.get("bg_base", "#111B1E")
        bg_alt = c.get("bg_alt", "#182428")
        fg = c.get("fg_text", "#D8E8EC")
        fg_muted = c.get("fg_muted", "#8A9EA4")
        brand_p = c.get("brand_primary", "#0E9AA7")
        brand_s = c.get("brand_primary", "#2BC1CF")
        border = c.get("border", "#23343A")
        strong_color = "#FFFFFF" if is_dark else "#0F172A"
        th_bg = "#16262D" if is_dark else "#E2E8F0"

        return f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 8.5pt; color: {fg}; line-height: 1.45; word-wrap: break-word; overflow-wrap: break-word;">
            <style>
                * {{ word-wrap: break-word; overflow-wrap: break-word; }}
                h1, h2, h3, h4 {{ color: {brand_p}; font-weight: bold; margin: 8px 0 4px 0; word-break: break-word; }}
                h1 {{ font-size: 10pt; color: {brand_s}; }}
                h2 {{ font-size: 9.5pt; color: {brand_s}; }}
                h3 {{ font-size: 9pt; }}
                p {{ margin: 4px 0; word-break: break-word; }}
                strong, b {{ color: {strong_color}; font-weight: bold; }}
                em, i {{ color: {fg_muted}; }}
                hr {{ border: 0; border-top: 1px solid {border}; margin: 8px 0; }}
                ul, ol {{ margin: 4px 0 4px 16px; padding: 0; }}
                li {{ margin: 2px 0; word-break: break-word; }}
                
                /* Inline and Block Code with strict pre-wrap */
                code {{ background-color: {bg_alt}; color: {brand_s}; padding: 1px 4px; border-radius: 2px; font-family: monospace; font-size: 8pt; word-break: break-word; }}
                pre {{ background-color: {bg_base}; border: 1px solid {border}; border-radius: 2px; padding: 8px 10px; margin: 6px 0; font-family: monospace; font-size: 8pt; color: {fg}; white-space: pre-wrap; word-wrap: break-word; word-break: break-all; }}
                pre code {{ background-color: transparent; padding: 0; color: {fg}; white-space: pre-wrap; word-wrap: break-word; word-break: break-all; }}
                
                /* High-Density Markdown Table with word wrap */
                table {{ border-collapse: collapse; width: 100%; margin: 8px 0; font-family: monospace; font-size: 7.8pt; background-color: {bg_alt}; border: 1px solid {border}; table-layout: fixed; word-wrap: break-word; }}
                th {{ background-color: {th_bg}; color: {brand_s}; font-weight: bold; padding: 4px 6px; border: 1px solid {border}; text-align: left; word-break: break-word; }}
                td {{ padding: 4px 6px; border: 1px solid {border}; color: {fg}; word-break: break-word; }}
                tr:nth-child(even) {{ background-color: {bg_base}; }}
                
                blockquote {{ border-left: 3px solid {brand_p}; margin: 6px 0; padding-left: 8px; color: {fg_muted}; word-break: break-word; }}
            </style>
            {rendered}
        </div>
        """





class PingWorker(QThread):
    """Background worker for testing LLM provider endpoint connectivity."""
    pingFinished = pyqtSignal(bool, str, float)

    def __init__(self, copilot: LLMSecurityCopilot, api_key: str, base_url: str, model_name: str, provider: str):
        super().__init__()
        self.copilot = copilot
        self.api_key = api_key
        self.base_url = base_url
        self.model_name = model_name
        self.provider = provider

    def run(self):
        # Temporarily apply config to test
        orig_key = self.copilot.api_key
        orig_url = self.copilot.base_url
        orig_model = self.copilot.model_name
        orig_prov = self.copilot.provider

        try:
            self.copilot.set_llm_config(
                api_key=self.api_key,
                base_url=self.base_url,
                model_name=self.model_name,
                provider=self.provider
            )
            success, msg, latency = self.copilot.test_connection()
            self.pingFinished.emit(success, msg, latency)
        except Exception as e:
            self.pingFinished.emit(False, str(e), 0.0)
        finally:
            # Restore original until saved
            self.copilot.set_llm_config(
                api_key=orig_key,
                base_url=orig_url,
                model_name=orig_model,
                provider=orig_prov
            )


class CopilotSettingsDialog(QDialog):
    """
    Enterprise Configuration Center for AI Security Copilot LLM Providers.
    Features 1-click presets, live ping/latency tests, and inference hyperparameter controls.
    """

    def __init__(self, copilot: LLMSecurityCopilot, parent=None):
        super().__init__(parent)
        self.copilot = copilot
        self.setWindowTitle("AI Copilot Inference & Provider Configuration")
        self.resize(560, 380)
        self._ping_worker: Optional[PingWorker] = None
        self._init_ui()

    def _init_ui(self):
        c = ThemeManager.instance().get_palette_colors()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        # ── 1. Provider & Connection Card ──
        form_frame = QFrame(self)
        form_frame.setStyleSheet(f"background-color: {c['bg_base']}; border: 1px solid {c['border']}; border-radius: 2px;")
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(10, 10, 10, 10)
        form_layout.setSpacing(8)

        form = QFormLayout()
        form.setSpacing(8)

        self.combo_preset = QComboBox(self)
        self.combo_preset.addItems([
            "Local Ollama (localhost:11434)",
            "Local LM Studio (localhost:1234)",
            "OpenRouter Cloud (Multi-Model)",
            "Google Gemini API",
            "Groq Cloud (Fast LPU)",
            "OpenAI API",
            "Custom OpenAI-Compatible",
        ])
        self.combo_preset.currentIndexChanged.connect(self._on_preset_changed)
        form.addRow("Provider Preset:", self.combo_preset)

        self.edit_base_url = QLineEdit(self)
        self.edit_base_url.setText(self.copilot.base_url or "http://localhost:11434/v1")
        self.edit_base_url.setPlaceholderText("http://localhost:11434/v1")
        form.addRow("API Base URL:", self.edit_base_url)

        self.edit_model = QLineEdit(self)
        self.edit_model.setText(self.copilot.model_name or "llama3:8b")
        self.edit_model.setPlaceholderText("llama3:8b, mistral, gpt-4o, gemini-2.5-flash")
        form.addRow("Model Identifier:", self.edit_model)

        self.edit_api_key = QLineEdit(self)
        self.edit_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit_api_key.setText(self.copilot.api_key or "")
        self.edit_api_key.setPlaceholderText("API Key (Required for Cloud endpoints; optional for local)")
        form.addRow("API Key:", self.edit_api_key)

        form_layout.addLayout(form)
        layout.addWidget(form_frame)

        # ── 2. Live Ping & Connection Test Strip ──
        test_bar = QHBoxLayout()
        test_bar.setSpacing(8)

        self.btn_ping = QPushButton("Test Connection", self)
        self.btn_ping.setFont(get_ui_font(size=8, bold=True))
        self.btn_ping.clicked.connect(self._test_connection)

        test_bar.addWidget(self.btn_ping)

        self.lbl_ping_status = QLabel("Status: Untested", self)
        self.lbl_ping_status.setFont(get_monospace_font(size=7.5))
        self.lbl_ping_status.setStyleSheet(f"color: {c['fg_muted']};")
        test_bar.addWidget(self.lbl_ping_status, stretch=1)

        layout.addLayout(test_bar)

        # ── 3. Footer Informational Note ──
        lbl_info = QLabel("Configured models run asynchronously in the background. If a remote host is unreachable, KShark's offline heuristic security engine operates automatically with zero downtime.", self)
        lbl_info.setFont(get_ui_font(size=7.5))
        lbl_info.setWordWrap(True)
        lbl_info.setStyleSheet(f"color: {c['fg_muted']};")
        layout.addWidget(lbl_info)

        layout.addStretch(1)

        # ── 4. Dialog Action Buttons ──
        btn_bar = QHBoxLayout()
        btn_bar.addStretch(1)

        btn_save = QPushButton("Save Settings", self)
        btn_save.setFont(get_ui_font(size=8, bold=True))
        btn_save.setStyleSheet(f"background-color: {c['brand_primary']}; color: #FFFFFF; padding: 4px 12px;")
        btn_save.clicked.connect(self._save_config)
        btn_bar.addWidget(btn_save)

        btn_cancel = QPushButton("Cancel", self)
        btn_cancel.setFont(get_ui_font(size=8))
        btn_cancel.clicked.connect(self.reject)
        btn_bar.addWidget(btn_cancel)

        layout.addLayout(btn_bar)

        # Initialize combo matching current config
        self._select_matching_preset()

    def _select_matching_preset(self):
        cur_url = (self.copilot.base_url or "").lower()
        cur_prov = (self.copilot.provider or "").lower()

        if "gemini" in cur_prov or "gemini" in (self.copilot.model_name or "").lower():
            self.combo_preset.setCurrentText("Google Gemini API")
        elif "openrouter" in cur_url:
            self.combo_preset.setCurrentText("OpenRouter Cloud (Multi-Model)")
        elif "1234" in cur_url:
            self.combo_preset.setCurrentText("Local LM Studio (localhost:1234)")
        elif "groq" in cur_url:
            self.combo_preset.setCurrentText("Groq Cloud (Fast LPU)")
        elif "openai" in cur_url or "openai" in cur_prov:
            self.combo_preset.setCurrentText("OpenAI API")
        elif "11434" in cur_url or "ollama" in cur_prov:
            self.combo_preset.setCurrentText("Local Ollama (localhost:11434)")
        else:
            self.combo_preset.setCurrentText("Custom OpenAI-Compatible")

    def _on_preset_changed(self, index: int):
        preset = self.combo_preset.currentText()
        if preset == "Local Ollama (localhost:11434)":
            self.edit_base_url.setText("http://localhost:11434/v1")
            self.edit_model.setText("llama3:8b")
        elif preset == "Local LM Studio (localhost:1234)":
            self.edit_base_url.setText("http://localhost:1234/v1")
            self.edit_model.setText("local-model")
        elif preset == "OpenRouter Cloud (Multi-Model)":
            self.edit_base_url.setText("https://openrouter.ai/api/v1")
            if not self.edit_model.text() or self.edit_model.text() == "llama3:8b":
                self.edit_model.setText("nvidia/nemotron-3-ultra-550b-a55b:free")
        elif preset == "Google Gemini API":
            self.edit_base_url.clear()
            self.edit_model.setText("gemini-2.5-flash")
        elif preset == "Groq Cloud (Fast LPU)":
            self.edit_base_url.setText("https://api.groq.com/openai/v1")
            self.edit_model.setText("llama-3.3-70b-versatile")
        elif preset == "OpenAI API":
            self.edit_base_url.setText("https://api.openai.com/v1")
            self.edit_model.setText("gpt-4o")

    def _test_connection(self):
        self.btn_ping.setEnabled(False)
        self.lbl_ping_status.setText("Status: Pinging endpoint...")
        self.lbl_ping_status.setStyleSheet("color: #F39C12;")

        preset = self.combo_preset.currentText()
        prov_map = {
            "Local Ollama (localhost:11434)": "ollama",
            "Local LM Studio (localhost:1234)": "custom",
            "OpenRouter Cloud (Multi-Model)": "custom",
            "Google Gemini API": "gemini",
            "Groq Cloud (Fast LPU)": "groq",
            "OpenAI API": "openai",
            "Custom OpenAI-Compatible": "custom",
        }
        provider = prov_map.get(preset, "custom")
        base_url = self.edit_base_url.text().strip()
        model_name = self.edit_model.text().strip()
        api_key = self.edit_api_key.text().strip()

        self._ping_worker = PingWorker(self.copilot, api_key, base_url, model_name, provider)
        self._ping_worker.pingFinished.connect(self._on_ping_finished)
        self._ping_worker.start()

    def _on_ping_finished(self, success: bool, message: str, latency_ms: float):
        self.btn_ping.setEnabled(True)
        if success:
            self.lbl_ping_status.setText(f"Connected: {message} ({latency_ms:.0f}ms)")
            self.lbl_ping_status.setStyleSheet("color: #0EA773;")
        else:
            self.lbl_ping_status.setText(f"Failed: {message}")
            self.lbl_ping_status.setStyleSheet("color: #E74C3C;")

    def _save_config(self):
        preset = self.combo_preset.currentText()
        prov_map = {
            "Local Ollama (localhost:11434)": "ollama",
            "Local LM Studio (localhost:1234)": "custom",
            "OpenRouter Cloud (Multi-Model)": "custom",
            "Google Gemini API": "gemini",
            "Groq Cloud (Fast LPU)": "groq",
            "OpenAI API": "openai",
            "Custom OpenAI-Compatible": "custom",
        }
        provider = prov_map.get(preset, "custom")
        base_url = self.edit_base_url.text().strip()
        model_name = self.edit_model.text().strip()
        api_key = self.edit_api_key.text().strip()

        self.copilot.set_llm_config(
            api_key=api_key,
            base_url=base_url,
            model_name=model_name,
            provider=provider
        )
        self.accept()



class CopilotDock(QDockWidget):
    """
    Enterprise KShark AI Security Copilot Analyst Platform.
    """

    copilotQuerySubmitted = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__("AI Security Copilot", parent)
        self.setObjectName("copilotDock")
        self.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea)

        self.copilot = LLMSecurityCopilot()
        self._active_worker: Optional[LLMCopilotWorker] = None
        self._last_raw_response = ""
        self._init_ui()
        ThemeManager.instance().themeChanged.connect(self._apply_theme)
        self._apply_theme()

    def _init_ui(self):
        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(5)

        # ── 1. Top Header & Provider Status Bar ──
        self.header_frame = QFrame(self)
        self.header_frame.setFrameShape(QFrame.Shape.StyledPanel)
        header_layout = QHBoxLayout(self.header_frame)
        header_layout.setContentsMargins(6, 4, 6, 4)
        header_layout.setSpacing(6)

        self.lbl_status = QLabel("AI Analyst: Ready", self)
        self.lbl_status.setFont(get_monospace_font(size=8, bold=True))
        self.lbl_status.setStyleSheet("color: #0EA773; border: none;")
        header_layout.addWidget(self.lbl_status)

        header_layout.addStretch(1)

        self.btn_settings = QPushButton("Config", self)
        self.btn_settings.setFont(get_ui_font(size=7.5))
        self.btn_settings.clicked.connect(self._open_settings)
        header_layout.addWidget(self.btn_settings)

        layout.addWidget(self.header_frame)

        # ── 2. Active Session Context Card ──
        self.context_bar = QFrame(self)
        ctx_layout = QHBoxLayout(self.context_bar)
        ctx_layout.setContentsMargins(6, 3, 6, 3)

        self.lbl_context = QLabel("Target: None Selected | Consensus Mode: Dual ML + Rules", self)
        self.lbl_context.setFont(get_monospace_font(size=7.5))
        ctx_layout.addWidget(self.lbl_context)

        layout.addWidget(self.context_bar)

        # ── 3. 1-Click Forensic Quick Action Toolbar ──
        action_bar = QHBoxLayout()
        action_bar.setSpacing(4)

        self.btn_analyze = QPushButton("Analyze Event", self)
        self.btn_analyze.setFont(get_ui_font(size=7.5))
        self.btn_analyze.clicked.connect(self.trigger_analyze_selected_event)
        action_bar.addWidget(self.btn_analyze)

        self.btn_chain = QPushButton("Attack Chain", self)
        self.btn_chain.setFont(get_ui_font(size=7.5))
        self.btn_chain.clicked.connect(self.trigger_reconstruct_attack_chain)
        action_bar.addWidget(self.btn_chain)

        self.btn_playbook = QPushButton("Playbook", self)
        self.btn_playbook.setFont(get_ui_font(size=7.5))
        self.btn_playbook.clicked.connect(self.trigger_generate_playbook)
        action_bar.addWidget(self.btn_playbook)

        layout.addLayout(action_bar)

        # ── 4. Main Forensic Terminal Console ──
        self.history_view = QTextEdit(self)
        self.history_view.setReadOnly(True)
        self.history_view.setFont(get_monospace_font(size=8))
        self.history_view.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.history_view.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        self.history_view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(self.history_view, stretch=1)

        # ── 5. Prompt Input & Submission Strip ──
        self.input_frame = QFrame(self)
        self.input_frame.setFrameShape(QFrame.Shape.StyledPanel)
        input_layout = QHBoxLayout(self.input_frame)
        input_layout.setContentsMargins(4, 4, 4, 4)
        input_layout.setSpacing(4)

        self.input_field = QLineEdit(self)
        self.input_field.setFont(get_ui_font(size=8))
        self.input_field.setPlaceholderText("Ask Copilot about active events, threats, or MITRE tactics...")
        self.input_field.returnPressed.connect(self._on_submit)
        input_layout.addWidget(self.input_field, stretch=1)

        self.btn_send = QPushButton("Send", self)
        self.btn_send.setFont(get_ui_font(size=8, bold=True))
        self.btn_send.clicked.connect(self._on_submit)
        input_layout.addWidget(self.btn_send)

        layout.addWidget(self.input_frame)

        # ── 6. Bottom Utility Actions ──
        bot_bar = QHBoxLayout()
        bot_bar.setSpacing(6)

        btn_copy = QPushButton("Copy Last Response", self)
        btn_copy.setFont(get_ui_font(size=7.5))
        btn_copy.clicked.connect(self._copy_last_response)
        bot_bar.addWidget(btn_copy)

        btn_clear = QPushButton("Clear History", self)
        btn_clear.setFont(get_ui_font(size=7.5))
        btn_clear.clicked.connect(self._clear_history)
        bot_bar.addWidget(btn_clear)

        bot_bar.addStretch(1)
        layout.addLayout(bot_bar)

        self.setWidget(container)

    def _apply_theme(self):
        c = ThemeManager.instance().get_palette_colors()
        is_dark = ThemeManager.is_dark()

        self.header_frame.setStyleSheet(f"background-color: {c['bg_base']}; border: 1px solid {c['border']}; border-radius: 2px;")
        self.btn_settings.setStyleSheet(f"background-color: {c['bg_alt']}; color: {c['fg_text']}; border: 1px solid {c['border']}; padding: 2px 6px;")

        self.context_bar.setStyleSheet(f"background-color: {c['bg_alt']}; border: 1px solid {c['border']}; border-radius: 2px;")
        self.lbl_context.setStyleSheet(f"color: {c['fg_muted']}; border: none; background: transparent;")

        self.history_view.setStyleSheet(f"""
            QTextEdit {{
                background-color: {c['bg_base']};
                color: {c['fg_text']};
                border: 1px solid {c['border']};
                border-radius: 2px;
                padding: 6px;
            }}
        """)

        self.input_frame.setStyleSheet(f"background-color: {c['bg_base']}; border: 1px solid {c['border']}; border-radius: 2px;")
        input_bg = "#111618" if is_dark else "#FFFFFF"
        self.input_field.setStyleSheet(f"background-color: {input_bg}; color: {c['fg_text']}; border: none;")
        self.btn_send.setStyleSheet(f"background-color: {c['brand_primary']}; color: #FFFFFF; border-radius: 2px; padding: 3px 8px;")

    def _open_settings(self):
        dlg = CopilotSettingsDialog(self.copilot, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            mode_desc = f"Online: {self.copilot.model_name}" if self.copilot.is_available() else "Offline Heuristic Mode"
            self.lbl_status.setText(f"AI Analyst: {mode_desc}")
            self.lbl_status.setStyleSheet("color: #0EA773;" if self.copilot.is_available() else "color: #0E9AA7;")

    def update_selected_event_context(self, event: dict):
        """Updates the context bar with the currently selected row's telemetry."""
        if not event:
            self.lbl_context.setText("Target: None Selected | Consensus Mode: Dual ML + Rules")
            return
        comm = event.get("comm", "unknown")
        pid = event.get("pid", 0)
        threat = event.get("threat_name", "BENIGN")
        self.lbl_context.setText(f"Target: PID {pid} ({comm}) | Threat: {threat}")

    def _on_submit(self):
        text = self.input_field.text().strip()
        if not text:
            return

        self.input_field.clear()
        self._append_user_message(text)
        self._run_async_query(text)

    def _append_user_message(self, text: str):
        c = ThemeManager.instance().get_palette_colors()
        self.history_view.append(f"""
            <div style='margin-top: 6px; font-family: monospace;'>
                <span style='color: {c["brand_primary"]}; font-weight: bold;'>Analyst:</span>
                <span style='color: #FFFFFF;'> {html.escape(text)}</span>
            </div>
            <div style='color: #8A9EA4; font-size: 7.5pt; font-style: italic; margin-left: 8px;'>Analyzing telemetry...</div>
        """)
        self.history_view.verticalScrollBar().setValue(self.history_view.verticalScrollBar().maximum())
        self.history_view.horizontalScrollBar().setValue(0)

    def _run_async_query(self, prompt: str, context: Optional[dict] = None):
        self.btn_send.setEnabled(False)
        self.lbl_status.setText("AI Analyst: Generating...")
        self.lbl_status.setStyleSheet("color: #F39C12;")

        parent_win = self.parent()
        recent_events = []
        if parent_win and hasattr(parent_win, "table_model"):
            recent_events = parent_win.table_model._events[-50:] if parent_win.table_model._events else []
            if not context and parent_win.event_list_view.selectionModel().selectedRows():
                idx = parent_win.event_list_view.selectionModel().selectedRows()[0]
                context = parent_win.proxy_model.get_event_at_proxy_row(idx.row())

        self._active_worker = LLMCopilotWorker(self.copilot, prompt, context, recent_events)
        self._active_worker.responseReady.connect(self._on_worker_response)
        self._active_worker.errorOccurred.connect(self._on_worker_error)
        self._active_worker.start()

    def _on_worker_response(self, prompt_type: str, prompt_raw: str, response_html: str):
        self._last_raw_response = response_html
        self.btn_send.setEnabled(True)
        self.lbl_status.setText("AI Analyst: Ready")
        self.lbl_status.setStyleSheet("color: #0EA773;")

        self.history_view.append(f"""
            <div style='margin-top: 6px; font-family: monospace;'>
                <span style='color: #0EA773; font-weight: bold;'>Copilot:</span>
                <div style='color: #D8E8EC; margin-left: 8px; margin-top: 3px;'>{response_html}</div>
            </div>
            <hr style='border: 0; border-top: 1px solid #23343A; margin: 6px 0;'/>
        """)
        self.history_view.verticalScrollBar().setValue(self.history_view.verticalScrollBar().maximum())
        self.history_view.horizontalScrollBar().setValue(0)


    def _on_worker_error(self, err_msg: str):
        self.btn_send.setEnabled(True)
        self.lbl_status.setText("AI Analyst: Error")
        self.lbl_status.setStyleSheet("color: #E74C3C;")

        self.history_view.append(f"""
            <div style='margin-top: 6px; color: #E74C3C; font-family: monospace;'>
                <b>Engine Warning:</b> {html.escape(err_msg)}
            </div>
        """)

    def append_copilot_response(self, prompt: str, response: str):
        self._on_worker_response("chat", prompt, html.escape(response))

    # ─────────────────────────────────────────────────────────
    # 1-Click Forensic Quick Actions
    # ─────────────────────────────────────────────────────────

    def trigger_analyze_selected_event(self):
        parent_win = self.parent()
        ev = None
        if parent_win and hasattr(parent_win, "proxy_model"):
            rows = parent_win.event_list_view.selectionModel().selectedRows()
            if rows:
                ev = parent_win.proxy_model.get_event_at_proxy_row(rows[0].row())

        if not ev:
            QMessageBox.information(self, "Analyze Event", "Please select an event row from the main packet list to analyze.")
            return

        self._append_user_message(f"Perform deep security forensic analysis on PID {ev.get('pid')} ({ev.get('comm')}).")
        self._run_async_query("__ANALYZE_EVENT__", context=ev)

    def trigger_reconstruct_attack_chain(self):
        parent_win = self.parent()
        ev = None
        if parent_win and hasattr(parent_win, "proxy_model"):
            rows = parent_win.event_list_view.selectionModel().selectedRows()
            if rows:
                ev = parent_win.proxy_model.get_event_at_proxy_row(rows[0].row())

        pid = ev.get("pid", 0) if ev else 0
        prompt = f"Reconstruct the end-to-end MITRE ATT&CK execution chain for PID {pid if pid > 0 else 'active processes'}. Identify root cause, initial access, and privilege escalation."
        self._append_user_message(prompt)
        self._run_async_query(prompt, context=ev)

    def trigger_generate_playbook(self):

        parent_win = self.parent()
        ev = None
        if parent_win and hasattr(parent_win, "proxy_model"):
            rows = parent_win.event_list_view.selectionModel().selectedRows()
            if rows:
                ev = parent_win.proxy_model.get_event_at_proxy_row(rows[0].row())

        self._append_user_message(f"Formulate containment and eradication playbook for {ev.get('threat_name') if ev else 'detected threats'}.")
        self._run_async_query("__REMEDIATION__", context=ev)

    def _copy_last_response(self):
        if self._last_raw_response:
            import re
            clean_text = re.sub(r"<[^>]+>", "", self._last_raw_response)
            QApplication.clipboard().setText(clean_text)
            QMessageBox.information(self, "Copied", "Copilot response copied to clipboard.")

    def _clear_history(self):
        self.history_view.clear()
        self._last_raw_response = ""

