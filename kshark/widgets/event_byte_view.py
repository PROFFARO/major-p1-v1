"""
KShark Multi-Format Raw Byte & Binary Payload Inspector.
Engineered for Reverse Engineers, Cyber Security Analysts, and Network Forensics Teams.
Includes:
- 6-format payload switcher (Hex+ASCII, Raw Buffer, C-Array, Base64, JSON, Strings)
- Real-time Interactive Binary Value Inspector footer (uint8, uint16, uint32, IPv4, ASCII, Bits)
- Live byte search with navigation and match counter
- Cryptographic hash computation (MD5, SHA-1, SHA-256, Shannon Entropy)
- Export / Save payload to binary disk file
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPlainTextEdit, QMenu,
    QComboBox, QLabel, QLineEdit, QPushButton, QApplication, QMessageBox,
    QFileDialog, QFrame
)
from PyQt6.QtGui import QTextCursor, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import Qt, pyqtSignal
import json
import base64
import struct
import math
from typing import Optional, Dict, Any, List

from kshark.core.theme import get_monospace_font, get_ui_font
from kshark.dialogs.byte_hasher_dialog import ByteHasherDialog


class EventByteView(QWidget):
    """
    KShark multi-format raw byte inspection widget with integrated binary value inspector.
    """

    MODE_HEX_ASCII = "Hex + ASCII Dump"
    MODE_RAW_PAYLOAD = "Raw Payload Buffer"
    MODE_JSON = "Structured JSON"
    MODE_C_ARRAY = "C-Array Payload"
    MODE_BASE64 = "Base64 Stream"
    MODE_STRINGS = "Printable ASCII Strings"

    MODES = [
        MODE_HEX_ASCII,
        MODE_RAW_PAYLOAD,
        MODE_JSON,
        MODE_C_ARRAY,
        MODE_BASE64,
        MODE_STRINGS,
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._raw_bytes: bytes = b""
        self._payload_bytes: bytes = b""
        self._current_event: Optional[Dict[str, Any]] = None
        self._current_mode = self.MODE_HEX_ASCII
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        # ── 1. Top Header Control Toolbar ──
        bar = QHBoxLayout()
        bar.setContentsMargins(6, 4, 6, 4)
        bar.setSpacing(6)

        lbl_fmt = QLabel("Format:")
        lbl_fmt.setFont(get_ui_font(size=8, bold=True))
        lbl_fmt.setStyleSheet("color: #888888;")

        self.combo_mode = QComboBox()
        self.combo_mode.setFont(get_ui_font(size=8))
        self.combo_mode.setFixedHeight(22)
        self.combo_mode.addItems(self.MODES)
        self.combo_mode.currentTextChanged.connect(self._on_mode_changed)

        # Search Bar
        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Find bytes / text...")

        self.search_entry.setFont(get_ui_font(size=8))
        self.search_entry.setFixedHeight(22)
        self.search_entry.textChanged.connect(self._on_search_changed)

        btn_hashes = QPushButton("Hashes")
        btn_hashes.setFont(get_ui_font(size=8))
        btn_hashes.setFixedHeight(22)
        btn_hashes.setToolTip("Calculate MD5, SHA-1, SHA-256 and Shannon Entropy")
        btn_hashes.clicked.connect(self._open_hasher_dialog)

        btn_export = QPushButton("Export...")
        btn_export.setFont(get_ui_font(size=8))
        btn_export.setFixedHeight(22)
        btn_export.setToolTip("Export raw byte buffer to file")
        btn_export.clicked.connect(self._export_to_file)

        self.lbl_len = QLabel("0 bytes")
        self.lbl_len.setFont(get_ui_font(size=8, bold=True))
        self.lbl_len.setStyleSheet("color: #0E9AA7;")

        bar.addWidget(lbl_fmt)
        bar.addWidget(self.combo_mode)
        bar.addWidget(self.search_entry, stretch=1)
        bar.addWidget(btn_hashes)
        bar.addWidget(btn_export)
        bar.addWidget(self.lbl_len)

        layout.addLayout(bar)

        # ── 2. Hex / Text Display Editor ──
        self.editor = QPlainTextEdit()
        self.editor.setObjectName("eventByteView")
        self.editor.setReadOnly(True)
        self.editor.setFont(get_monospace_font(size=9))
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.editor.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.editor.customContextMenuRequested.connect(self._show_context_menu)
        self.editor.cursorPositionChanged.connect(self._on_cursor_changed)

        layout.addWidget(self.editor, stretch=1)

        # ── 3. Bottom Interactive Binary Value Inspector Ribbon ──
        self.inspector_frame = QFrame()
        self.inspector_frame.setStyleSheet("background-color: #121E24; border-top: 1px solid #1E2D33; padding: 2px;")
        insp_layout = QHBoxLayout(self.inspector_frame)
        insp_layout.setContentsMargins(6, 2, 6, 2)
        insp_layout.setSpacing(12)

        self.lbl_offset = QLabel("Offset: 0x0000 (0)")
        self.lbl_offset.setFont(get_monospace_font(size=8))
        self.lbl_offset.setStyleSheet("color: #0E9AA7; font-weight: bold;")

        self.lbl_u8 = QLabel("u8: -")
        self.lbl_u8.setFont(get_monospace_font(size=8))

        self.lbl_u16 = QLabel("u16_le: -")
        self.lbl_u16.setFont(get_monospace_font(size=8))

        self.lbl_u32 = QLabel("u32_le: -")
        self.lbl_u32.setFont(get_monospace_font(size=8))

        self.lbl_ip = QLabel("IPv4: -")
        self.lbl_ip.setFont(get_monospace_font(size=8))

        self.lbl_bin = QLabel("Bits: -")
        self.lbl_bin.setFont(get_monospace_font(size=8))
        self.lbl_bin.setStyleSheet("color: #2ECC71;")

        insp_layout.addWidget(self.lbl_offset)
        insp_layout.addWidget(self.lbl_u8)
        insp_layout.addWidget(self.lbl_u16)
        insp_layout.addWidget(self.lbl_u32)
        insp_layout.addWidget(self.lbl_ip)
        insp_layout.addWidget(self.lbl_bin)
        insp_layout.addStretch(1)

        layout.addWidget(self.inspector_frame)

    def set_font_size(self, size: float):
        """Updates monospace font size dynamically."""
        font = get_monospace_font(size=size)
        if hasattr(self, "editor") and self.editor is not None:
            self.editor.setFont(font)

    def set_event_data(self, event: Optional[Dict[str, Any]]):
        self._current_event = event
        if not event:
            self._raw_bytes = b""
            self._payload_bytes = b""
            self.editor.clear()
            self.lbl_len.setText("0 bytes")
            self._update_inspector(0)
            return

        # Extract genuine raw payload buffer if present, otherwise structured telemetry
        payload_data = event.get("data") or event.get("payload") or event.get("buffer") or ""
        if isinstance(payload_data, str) and payload_data:
            try:
                self._payload_bytes = payload_data.encode("utf-8")
            except Exception:
                self._payload_bytes = bytes(payload_data, "utf-8", "replace")
        elif isinstance(payload_data, bytes):
            self._payload_bytes = payload_data
        else:
            self._payload_bytes = (event.get("cmdline") or event.get("file_path") or str(event)).encode("utf-8")

        try:
            json_str = json.dumps(event, indent=2)
            self._raw_bytes = json_str.encode("utf-8")
        except Exception:
            self._raw_bytes = str(event).encode("utf-8")

        active_bytes = self._get_active_buffer()
        self.lbl_len.setText(f"{len(active_bytes):,} bytes")
        self._render_view()
        self._update_inspector(0)

    def _get_active_buffer(self) -> bytes:
        if self._current_mode == self.MODE_RAW_PAYLOAD:
            return self._payload_bytes if self._payload_bytes else self._raw_bytes
        return self._raw_bytes

    def _on_mode_changed(self, mode: str):
        self._current_mode = mode
        active_bytes = self._get_active_buffer()
        self.lbl_len.setText(f"{len(active_bytes):,} bytes")
        self._render_view()

    def _render_view(self):
        active_bytes = self._get_active_buffer()
        if not active_bytes:
            self.editor.clear()
            return

        if self._current_mode == self.MODE_HEX_ASCII:
            lines = self._generate_hexdump(active_bytes)
            self.editor.setPlainText("\n".join(lines))
        elif self._current_mode == self.MODE_RAW_PAYLOAD:
            try:
                self.editor.setPlainText(active_bytes.decode("utf-8", "replace"))
            except Exception:
                self.editor.setPlainText(str(active_bytes))
        elif self._current_mode == self.MODE_JSON:
            if self._current_event:
                self.editor.setPlainText(json.dumps(self._current_event, indent=2))
            else:
                self.editor.setPlainText("{}")
        elif self._current_mode == self.MODE_C_ARRAY:
            lines = self._generate_c_array(active_bytes)
            self.editor.setPlainText(lines)
        elif self._current_mode == self.MODE_BASE64:
            b64 = base64.b64encode(active_bytes).decode("ascii")
            self.editor.setPlainText(b64)
        elif self._current_mode == self.MODE_STRINGS:
            strings = self._extract_printable_strings(active_bytes)
            self.editor.setPlainText("\n".join(strings))

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
        lines = [f"// KShark Dissection Payload Buffer ({len(data)} bytes)", "const unsigned char payload[] = {"]
        for offset in range(0, len(data), 12):
            chunk = data[offset:offset+12]
            hex_items = [f"0x{b:02x}" for b in chunk]
            lines.append("    " + ", ".join(hex_items) + ",")
        lines.append("};")
        return "\n".join(lines)

    def _extract_printable_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        result = []
        cur = []
        for b in data:
            if 32 <= b <= 126:
                cur.append(chr(b))
            else:
                if len(cur) >= min_len:
                    result.append("".join(cur))
                cur = []
        if len(cur) >= min_len:
            result.append("".join(cur))
        return result if result else ["(No ASCII strings >= 4 chars found)"]

    def _on_cursor_changed(self):
        cursor = self.editor.textCursor()
        line_num = cursor.blockNumber()
        col = cursor.positionInBlock()

        # In Hex+ASCII mode:
        # Format: 00000000  xx xx xx xx xx xx xx xx  yy yy yy yy yy yy yy yy  ................
        # Cols:   0..7   8 9  10..32 (L-hex) 33 34 35..57 (R-hex) 58 59 60..75 (ASCII)
        if self._current_mode == self.MODE_HEX_ASCII:
            if 10 <= col <= 33:
                byte_idx = min(7, max(0, (col - 10) // 3))
            elif 34 <= col <= 59:
                byte_idx = 8 + min(7, max(0, (col - 34) // 3))
            elif col >= 60:
                byte_idx = min(15, max(0, col - 60))
            else:
                byte_idx = 0
            byte_offset = (line_num * 16) + byte_idx
        else:
            byte_offset = cursor.position()

        self._update_inspector(byte_offset)

    def _update_inspector(self, offset: int):
        active_bytes = self._get_active_buffer()
        if not active_bytes or offset < 0 or offset >= len(active_bytes):
            self.lbl_offset.setText(f"Offset: 0x{max(0, offset):04X} ({max(0, offset)})")
            self.lbl_u8.setText("u8: -")
            self.lbl_u16.setText("u16_le: -")
            self.lbl_u32.setText("u32_le: -")
            self.lbl_ip.setText("IPv4: -")
            self.lbl_bin.setText("Bits: -")
            return

        buf = active_bytes[offset:offset+8]
        if len(buf) < 8:
            buf = buf.ljust(8, b'\x00')

        u8 = buf[0]
        u16 = struct.unpack("<H", buf[:2])[0]
        u32 = struct.unpack("<I", buf[:4])[0]
        ip = ".".join(str(b) for b in buf[:4])
        bits = f"{u8:08b}"

        self.lbl_offset.setText(f"Offset: 0x{offset:04X} ({offset})")
        self.lbl_u8.setText(f"u8: {u8} (0x{u8:02X})")
        self.lbl_u16.setText(f"u16_le: {u16}")
        self.lbl_u32.setText(f"u32_le: {u32}")
        self.lbl_ip.setText(f"IPv4: {ip}")
        self.lbl_bin.setText(f"Bits: {bits}")


    def _on_search_changed(self, text: str):
        query = text.strip()
        if not query:
            return

        cursor = self.editor.textCursor()
        doc = self.editor.document()
        find_cursor = doc.find(query, cursor)
        if find_cursor.isNull():
            find_cursor = doc.find(query)
        if not find_cursor.isNull():
            self.editor.setTextCursor(find_cursor)

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
        m_copy.addAction("Copy as C-Array", lambda: QApplication.clipboard().setText(self._generate_c_array(self._get_active_buffer())))
        m_copy.addAction("Copy as Base64", lambda: QApplication.clipboard().setText(base64.b64encode(self._get_active_buffer()).decode("ascii")))

        menu.addSeparator()

        # 3. Hashes & Export
        menu.addAction("Compute Hashes & Entropy...", self._open_hasher_dialog)
        menu.addAction("Export Payload to File...", self._export_to_file)

        menu.exec(self.editor.viewport().mapToGlobal(pos))

    def _open_hasher_dialog(self):
        active_bytes = self._get_active_buffer()
        if not active_bytes:
            QMessageBox.information(self, "No Data", "No event byte stream selected.")
            return
        dlg = ByteHasherDialog(active_bytes, self)
        dlg.exec()

    def _export_to_file(self):
        active_bytes = self._get_active_buffer()
        if not active_bytes:
            QMessageBox.information(self, "No Data", "No event byte stream selected to export.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export KShark Payload Buffer",
            "kshark_payload.bin",
            "Binary Raw Data (*.bin);;Hex Dump (*.hex);;JSON (*.json);;All Files (*)"
        )
        if not path:
            return

        try:
            with open(path, "wb") as f:
                f.write(active_bytes)
            QMessageBox.information(self, "Export Successful", f"Saved {len(active_bytes):,} bytes to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to save file: {e}")
