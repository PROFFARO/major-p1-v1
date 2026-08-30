"""
KShark Multi-Format Byte & Hex Dump Viewer.
Supports 5 viewing modes (Hex+ASCII, Raw Text, Structured JSON, C-Array, Base64),
range highlighting, text selection, and forensic binary inspection.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPlainTextEdit, QMenu,
    QComboBox, QLabel, QApplication, QMessageBox
)
from PyQt6.QtGui import QTextCursor, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import Qt, pyqtSignal
import json
import base64
from typing import Optional, Dict, Any, List

from kshark.core.theme import get_monospace_font
from kshark.dialogs.byte_hasher_dialog import ByteHasherDialog


class EventByteView(QWidget):
    """
    KShark multi-format raw byte inspection widget.
    """

    MODE_HEX_ASCII = "Hex + ASCII Dump"
    MODE_RAW_TEXT = "Raw Text"
    MODE_JSON = "Structured JSON"
    MODE_C_ARRAY = "C-Array Payload"
    MODE_BASE64 = "Base64 Stream"

    MODES = [MODE_HEX_ASCII, MODE_RAW_TEXT, MODE_JSON, MODE_C_ARRAY, MODE_BASE64]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._raw_bytes: bytes = b""
        self._current_event: Optional[Dict[str, Any]] = None
        self._current_mode = self.MODE_HEX_ASCII
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        # Header toolbar for byte view
        bar = QHBoxLayout()
        bar.setContentsMargins(4, 2, 4, 2)
        bar.setSpacing(6)

        lbl = QLabel("Format:")
        lbl.setStyleSheet("font-weight: bold; color: #888888;")
        self.combo_mode = QComboBox()
        self.combo_mode.addItems(self.MODES)
        self.combo_mode.currentTextChanged.connect(self._on_mode_changed)

        self.lbl_len = QLabel("0 bytes")
        self.lbl_len.setStyleSheet("color: #0E9AA7; font-weight: bold;")

        bar.addWidget(lbl)
        bar.addWidget(self.combo_mode)
        bar.addStretch()
        bar.addWidget(self.lbl_len)

        layout.addLayout(bar)

        # Text editor pane
        self.editor = QPlainTextEdit()
        self.editor.setObjectName("eventByteView")
        self.editor.setReadOnly(True)
        self.editor.setFont(get_monospace_font(size=9))
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.editor.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.editor.customContextMenuRequested.connect(self._show_context_menu)

        layout.addWidget(self.editor)

    def setFont(self, font: QFont):
        super().setFont(font)
        if hasattr(self, "editor"):
            self.editor.setFont(font)

    def set_event_data(self, event: Optional[Dict[str, Any]]):
        self._current_event = event
        if not event:
            self._raw_bytes = b""
            self.editor.clear()
            self.lbl_len.setText("0 bytes")
            return

        try:
            json_str = json.dumps(event, indent=2)
            self._raw_bytes = json_str.encode("utf-8")
        except Exception:
            self._raw_bytes = str(event).encode("utf-8")

        self.lbl_len.setText(f"{len(self._raw_bytes):,} bytes")
        self._render_view()

    def _on_mode_changed(self, mode: str):
        self._current_mode = mode
        self._render_view()

    def _render_view(self):
        if not self._raw_bytes:
            self.editor.clear()
            return

        if self._current_mode == self.MODE_HEX_ASCII:
            lines = self._generate_hexdump(self._raw_bytes)
            self.editor.setPlainText("\n".join(lines))
        elif self._current_mode == self.MODE_RAW_TEXT:
            try:
                self.editor.setPlainText(self._raw_bytes.decode("utf-8", "replace"))
            except Exception:
                self.editor.setPlainText(str(self._raw_bytes))
        elif self._current_mode == self.MODE_JSON:
            if self._current_event:
                self.editor.setPlainText(json.dumps(self._current_event, indent=2))
            else:
                self.editor.setPlainText("{}")
        elif self._current_mode == self.MODE_C_ARRAY:
            lines = self._generate_c_array(self._raw_bytes)
            self.editor.setPlainText(lines)
        elif self._current_mode == self.MODE_BASE64:
            b64 = base64.b64encode(self._raw_bytes).decode("ascii")
            self.editor.setPlainText(b64)

    def _generate_hexdump(self, data: bytes) -> list:
        lines = []
        n = len(data)
        for offset in range(0, n, 16):
            chunk = data[offset:offset+16]
            offset_str = f"{offset:08x}"
            hex_parts = [f"{b:02x}" for b in chunk]
            while len(hex_parts) < 16:
                hex_parts.append("  ")
            hex_left = " ".join(hex_parts[:8])
            hex_right = " ".join(hex_parts[8:])
            hex_str = f"{hex_left}  {hex_right}"
            ascii_chars = [chr(b) if 32 <= b <= 126 else "." for b in chunk]
            ascii_str = "".join(ascii_chars)
            lines.append(f"{offset_str}  {hex_str}  {ascii_str}")
        return lines

    def _generate_c_array(self, data: bytes) -> str:
        lines = [f"// KShark payload capture ({len(data)} bytes)", "const unsigned char payload[] = {"]
        for offset in range(0, len(data), 12):
            chunk = data[offset:offset+12]
            hex_items = [f"0x{b:02x}" for b in chunk]
            lines.append("    " + ", ".join(hex_items) + ",")
        lines.append("};")
        return "\n".join(lines)

    def _show_context_menu(self, pos):
        menu = QMenu(self)

        # 1. View As Submenu
        m_view = menu.addMenu("View As")
        for mode in self.MODES:
            act = m_view.addAction(mode)
            act.setCheckable(True)
            act.setChecked(mode == self._current_mode)
            act.triggered.connect(lambda checked, m=mode: self.combo_mode.setCurrentText(m))

        menu.addSeparator()

        # 2. Copy Options
        m_copy = menu.addMenu("Copy")
        sel_text = self.editor.textCursor().selectedText()
        if sel_text:
            m_copy.addAction("Copy Selected Text", lambda: QApplication.clipboard().setText(sel_text))
        m_copy.addAction("Copy Entire Hex Dump", lambda: QApplication.clipboard().setText(self.editor.toPlainText()))
        m_copy.addAction("Copy as C-Array", lambda: QApplication.clipboard().setText(self._generate_c_array(self._raw_bytes)))
        m_copy.addAction("Copy as Base64", lambda: QApplication.clipboard().setText(base64.b64encode(self._raw_bytes).decode("ascii")))

        menu.addSeparator()

        # 3. Hashes & Forensic Inspector
        menu.addAction("Compute Hashes & Entropy...", self._open_hasher_dialog)

        menu.exec(self.editor.viewport().mapToGlobal(pos))

    def _open_hasher_dialog(self):
        if not self._raw_bytes:
            QMessageBox.information(self, "No Data", "No event byte stream selected.")
            return
        dlg = ByteHasherDialog(self._raw_bytes, self)
        dlg.exec()
