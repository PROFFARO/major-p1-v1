"""
KShark Event Comment & Forensic Notes Dialog.

Allows cyber security engineers, incident responders, and analysts to attach
investigation notes, verdict tags, and triage commentary to any packet/event.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit,
    QLineEdit, QComboBox, QMessageBox, QApplication
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt
from typing import Dict, Any, Optional

from kshark.core.theme import ThemeManager, get_monospace_font, get_ui_font


class EditCommentDialog(QDialog):
    """
    Dialog for adding or editing forensic comments on a captured telemetry event.
    """

    def __init__(self, event_num: int, current_comment: str = "", event_summary: str = "", parent=None):
        super().__init__(parent)
        self.event_num = event_num
        self.comment_text = current_comment
        self.event_summary = event_summary

        self.setWindowTitle(f"KShark · Edit Event Comment — Event #{event_num}")
        self.resize(520, 320)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Header Info
        lbl_info = QLabel(f"<b>Event #{self.event_num}</b>: <code>{self.event_summary}</code>", self)
        lbl_info.setFont(get_ui_font(size=8.5))
        layout.addWidget(lbl_info)

        lbl_prompt = QLabel("Analyst Forensic Note / Triage Verdict:", self)
        lbl_prompt.setFont(get_ui_font(size=8, bold=True))
        layout.addWidget(lbl_prompt)

        # Editor
        self.editor = QTextEdit(self)
        self.editor.setFont(get_monospace_font(size=9))
        self.editor.setPlaceholderText("Enter forensic notes, incident classification, or investigation tags (e.g. [FALSE POSITIVE], [MALICIOUS C2], [LATERAL MOVEMENT])...")
        self.editor.setPlainText(self.comment_text)
        layout.addWidget(self.editor, stretch=1)

        # Quick Tag Buttons
        tag_bar = QHBoxLayout()
        tag_bar.setSpacing(6)

        lbl_quick = QLabel("Quick Tags:", self)
        lbl_quick.setFont(get_ui_font(size=8))
        tag_bar.addWidget(lbl_quick)

        tags = ["[MALICIOUS]", "[SUSPICIOUS]", "[FALSE POSITIVE]", "[VERIFIED BENIGN]", "[CONTAINED]"]
        for tag in tags:
            btn = QPushButton(tag, self)
            btn.setFont(get_monospace_font(size=7.5))
            btn.setFixedHeight(20)
            btn.clicked.connect(lambda _, t=tag: self._insert_tag(t))
            tag_bar.addWidget(btn)

        tag_bar.addStretch(1)
        layout.addLayout(tag_bar)

        # Action Buttons
        bot_bar = QHBoxLayout()
        bot_bar.setSpacing(8)

        btn_clear = QPushButton("Clear Comment", self)
        btn_clear.setFont(get_ui_font(size=8))
        btn_clear.clicked.connect(lambda: self.editor.clear())
        bot_bar.addWidget(btn_clear)

        bot_bar.addStretch(1)

        btn_save = QPushButton("Save Comment", self)
        btn_save.setFont(get_ui_font(size=8, bold=True))
        btn_save.setDefault(True)
        btn_save.clicked.connect(self._on_save)
        bot_bar.addWidget(btn_save)

        btn_cancel = QPushButton("Cancel", self)
        btn_cancel.setFont(get_ui_font(size=8))
        btn_cancel.clicked.connect(self.reject)
        bot_bar.addWidget(btn_cancel)

        layout.addLayout(bot_bar)

    def _insert_tag(self, tag: str):
        cur = self.editor.toPlainText().strip()
        if cur:
            self.editor.setPlainText(f"{tag} {cur}")
        else:
            self.editor.setPlainText(tag)

    def _on_save(self):
        self.comment_text = self.editor.toPlainText().strip()
        self.accept()

    def get_comment(self) -> str:
        return self.comment_text
