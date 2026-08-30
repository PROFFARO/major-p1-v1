"""
KShark Byte & Binary Payload Inspector Pane (Right Forensic Component).
Features a 5-tab interface for Reverse Engineers, Security Analysts, and Network Admins:
1. Hex Dump — 3-column Wireshark dump with syntax highlighting & live cursor inspection
2. Value Decoder — Multi-type decoder table (int8, int16, int32, int64, float, IPv4, Unix Time)
3. Extracted Strings — String triage for C2 domains, passwords, URLs, and file paths
4. C-Array Payload — Exploit & shellcode byte literal generator
5. JSON Telemetry — Structured JSON data tree
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QPlainTextEdit, QTextEdit,
    QLabel, QLineEdit, QPushButton, QHeaderView, QTableWidget,
    QTableWidgetItem, QFrame, QApplication, QMessageBox, QMenu, QFileDialog
)
from PyQt6.QtGui import QTextCursor, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import Qt, pyqtSignal
from typing import Optional, Dict, Any, List
import json
import base64
import struct
import math

from kshark.core.theme import ThemeManager, get_ui_font, get_monospace_font
from kshark.dialogs.byte_hasher_dialog import ByteHasherDialog
from kshark.resources.icons import KSharkIcons


class BytePayloadInspectorPane(QWidget):
    """
    Modular 5-Tab Byte & Binary Payload Inspection Pane.
    """

    minimizeRequested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._raw_bytes: bytes = b""
        self._payload_bytes: bytes = b""
        self._current_event: Optional[Dict[str, Any]] = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Tab Widget with clean vector icons
        self.tabs = QTabWidget(self)
        self.tabs.setObjectName("byteTabs")
        self.tabs.setFont(get_ui_font(size=8, bold=True))

        # Corner Minimize Button
        corner_widget = QWidget(self)
        c_layout = QHBoxLayout(corner_widget)
        c_layout.setContentsMargins(0, 0, 4, 0)
        btn_min = QPushButton("—", corner_widget)
        btn_min.setFixedSize(18, 18)
        btn_min.setFont(get_monospace_font(size=7.5, bold=True))
        btn_min.setToolTip("Minimize Byte Inspector Pane (Alt+4)")
        btn_min.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #8A9EA4;
                border: 1px solid transparent;
                border-radius: 2px;
                padding: 0;
            }
            QPushButton:hover {
                background-color: #16262D;
                color: #FFFFFF;
                border-color: #23343A;
            }
        """)
        btn_min.clicked.connect(self.minimizeRequested.emit)
        c_layout.addWidget(btn_min)
        self.tabs.setCornerWidget(corner_widget, Qt.Corner.TopRightCorner)

        # ── Tab 1: Hex Dump ──

        tab_hex = QWidget()
        l_hex = QVBoxLayout(tab_hex)
        l_hex.setContentsMargins(4, 4, 4, 4)
        l_hex.setSpacing(4)

        # Search toolbar
        bar = QHBoxLayout()
        bar.setContentsMargins(2, 2, 2, 2)
        bar.setSpacing(6)

        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Find bytes / text in buffer...")
        self.search_entry.setFont(get_ui_font(size=8))
        self.search_entry.setFixedHeight(22)
        self.search_entry.textChanged.connect(self._on_search_changed)

        btn_hashes = QPushButton("Hashes")
        btn_hashes.setFont(get_ui_font(size=8))
        btn_hashes.setFixedHeight(22)
        btn_hashes.clicked.connect(self._open_hasher_dialog)

        btn_export = QPushButton("Export...")
        btn_export.setFont(get_ui_font(size=8))
        btn_export.setFixedHeight(22)
        btn_export.clicked.connect(self._export_to_file)

        self.lbl_len = QLabel("0 bytes")
        self.lbl_len.setFont(get_ui_font(size=8, bold=True))
        self.lbl_len.setStyleSheet("color: #0E9AA7;")

        bar.addWidget(self.search_entry, stretch=1)
        bar.addWidget(btn_hashes)
        bar.addWidget(btn_export)
        bar.addWidget(self.lbl_len)
        l_hex.addLayout(bar)

        self.hex_editor = QPlainTextEdit()
        self.hex_editor.setObjectName("eventByteView")
        self.hex_editor.setReadOnly(True)
        self.hex_editor.setFont(get_monospace_font(size=9))
        self.hex_editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.hex_editor.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.hex_editor.customContextMenuRequested.connect(self._show_hex_context_menu)
        self.hex_editor.cursorPositionChanged.connect(self._on_cursor_changed)
        l_hex.addWidget(self.hex_editor)

        self.tabs.addTab(tab_hex, KSharkIcons.tab_hex(), "Hex Dump")

        # ── Tab 2: Value Decoder ──
        tab_decode = QWidget()
        l_decode = QVBoxLayout(tab_decode)
        l_decode.setContentsMargins(6, 6, 6, 6)
        l_decode.setSpacing(6)

        self.decode_table = QTableWidget()
        self.decode_table.setColumnCount(3)
        self.decode_table.setHorizontalHeaderLabels(["Data Type", "Little-Endian (x86)", "Big-Endian (Network)"])
        self.decode_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.decode_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.decode_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.decode_table.setFont(get_monospace_font(size=8))
        l_decode.addWidget(self.decode_table)

        self.tabs.addTab(tab_decode, KSharkIcons.tab_decoder(), "Value Decoder")

        # ── Tab 3: Extracted Strings ──
        tab_strings = QWidget()
        l_strings = QVBoxLayout(tab_strings)
        l_strings.setContentsMargins(6, 6, 6, 6)
        l_strings.setSpacing(6)

        self.strings_table = QTableWidget()
        self.strings_table.setColumnCount(3)
        self.strings_table.setHorizontalHeaderLabels(["Offset", "Length", "Extracted ASCII / UTF-8 String"])
        self.strings_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.strings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.strings_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.strings_table.setFont(get_monospace_font(size=8))
        l_strings.addWidget(self.strings_table)

        self.tabs.addTab(tab_strings, KSharkIcons.tab_strings(), "Extracted Strings")

        # ── Tab 4: C-Array Payload ──
        tab_c = QWidget()
        l_c = QVBoxLayout(tab_c)
        l_c.setContentsMargins(6, 6, 6, 6)
        l_c.setSpacing(6)

        btn_copy_c = QPushButton("Copy C-Array Payload")
        btn_copy_c.setFont(get_ui_font(size=8))
        btn_copy_c.setFixedHeight(24)
        btn_copy_c.clicked.connect(lambda: (QApplication.clipboard().setText(self.c_editor.toPlainText()), QMessageBox.information(self, "Copied", "C-Array payload copied to clipboard!")))
        l_c.addWidget(btn_copy_c)

        self.c_editor = QPlainTextEdit()
        self.c_editor.setReadOnly(True)
        self.c_editor.setFont(get_monospace_font(size=9))
        l_c.addWidget(self.c_editor)

        self.tabs.addTab(tab_c, KSharkIcons.tab_code(), "C-Array Payload")

        # ── Tab 5: JSON Telemetry ──
        tab_json = QWidget()
        l_json = QVBoxLayout(tab_json)
        l_json.setContentsMargins(6, 6, 6, 6)
        l_json.setSpacing(6)

        btn_copy_json = QPushButton("Copy JSON")
        btn_copy_json.setFont(get_ui_font(size=8))
        btn_copy_json.setFixedHeight(24)
        btn_copy_json.clicked.connect(lambda: (QApplication.clipboard().setText(self.json_editor.toPlainText()), QMessageBox.information(self, "Copied", "JSON telemetry copied to clipboard!")))
        l_json.addWidget(btn_copy_json)

        self.json_editor = QPlainTextEdit()
        self.json_editor.setReadOnly(True)
        self.json_editor.setFont(get_monospace_font(size=9))
        l_json.addWidget(self.json_editor)

        self.tabs.addTab(tab_json, KSharkIcons.tab_json(), "JSON Telemetry")

        layout.addWidget(self.tabs)

        # ── Bottom Live Interactive Ribbon ──
        self.inspector_frame = QFrame()
        insp_layout = QHBoxLayout(self.inspector_frame)
        insp_layout.setContentsMargins(8, 3, 8, 3)
        insp_layout.setSpacing(12)

        self.lbl_offset = QLabel("Offset: 0x0000 (0)")
        self.lbl_offset.setFont(get_monospace_font(size=8))

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

        insp_layout.addWidget(self.lbl_offset)
        insp_layout.addWidget(self.lbl_u8)
        insp_layout.addWidget(self.lbl_u16)
        insp_layout.addWidget(self.lbl_u32)
        insp_layout.addWidget(self.lbl_ip)
        insp_layout.addWidget(self.lbl_bin)
        insp_layout.addStretch(1)

        layout.addWidget(self.inspector_frame)
        self._apply_theme()
        ThemeManager.instance().themeChanged.connect(self._apply_theme)

    def _apply_theme(self):
        c = ThemeManager.instance().get_palette_colors()
        is_dark = ThemeManager.is_dark()
        bg_frame = "#121E24" if is_dark else "#FFFFFF"
        self.inspector_frame.setStyleSheet(f"background-color: {bg_frame}; border-top: 1px solid {c['border']}; padding: 2px;")
        self.lbl_offset.setStyleSheet(f"color: {c['brand_primary']}; font-weight: bold;")
        self.lbl_bin.setStyleSheet(f"color: {c['accent_success']};")
        self.lbl_len.setStyleSheet(f"color: {c['brand_primary']}; font-weight: bold;")
        for lbl in (self.lbl_u8, self.lbl_u16, self.lbl_u32, self.lbl_ip):
            lbl.setStyleSheet(f"color: {c['fg_text']};")

    def clear(self):
        """Clears all byte views and decoded data."""
        self.set_event_data(None)

    def set_font_size(self, size: float):
        """Updates monospace font size dynamically across hex editor and tables."""
        font = get_monospace_font(size=size)
        self.setFont(font)

    def setFont(self, font: QFont):
        super().setFont(font)
        if hasattr(self, "hex_editor"):
            self.hex_editor.setFont(font)
        if hasattr(self, "decode_table"):
            self.decode_table.setFont(font)
        if hasattr(self, "strings_table"):
            self.strings_table.setFont(font)
        if hasattr(self, "entropy_table"):
            self.entropy_table.setFont(font)
        if hasattr(self, "asn1_view"):
            self.asn1_view.setFont(font)

    def highlight_byte_range(self, offset: int, length: int):
        """Highlights the byte range in the Hex Editor view and centers cursor."""
        if not hasattr(self, "hex_editor") or not self._raw_bytes:
            return

        if offset < 0 or length <= 0:
            self.hex_editor.setExtraSelections([])
            return

        total_len = len(self._raw_bytes)
        if offset >= total_len:
            return

        clamped_len = min(length, total_len - offset)
        doc = self.hex_editor.document()
        is_dark = ThemeManager.is_dark()

        extra_selections = []
        fmt_hex = QTextCharFormat()
        fmt_hex.setBackground(QColor("#1A404D" if is_dark else "#BAE6FD"))
        fmt_hex.setForeground(QColor("#2BC1CF" if is_dark else "#0369A1"))
        fmt_hex.setFontWeight(QFont.Weight.Bold)

        fmt_ascii = QTextCharFormat()
        fmt_ascii.setBackground(QColor("#1A404D" if is_dark else "#BAE6FD"))
        fmt_ascii.setForeground(QColor("#2BC1CF" if is_dark else "#0369A1"))

        first_cursor = None

        for b_idx in range(offset, offset + clamped_len):
            line_num = b_idx // 16
            col_in_line = b_idx % 16

            if col_in_line < 8:
                char_pos_hex = 10 + col_in_line * 3
            else:
                char_pos_hex = 10 + 8 * 3 + 1 + (col_in_line - 8) * 3

            char_pos_ascii = 61 + col_in_line

            block = doc.findBlockByLineNumber(line_num)
            if block.isValid():
                block_start = block.position()

                sel_hex = QTextEdit.ExtraSelection()
                sel_hex.format = fmt_hex
                cursor_hex = QTextCursor(doc)
                cursor_hex.setPosition(block_start + char_pos_hex)
                cursor_hex.setPosition(block_start + char_pos_hex + 2, QTextCursor.MoveMode.KeepAnchor)
                sel_hex.cursor = cursor_hex
                extra_selections.append(sel_hex)

                sel_ascii = QTextEdit.ExtraSelection()
                sel_ascii.format = fmt_ascii
                cursor_ascii = QTextCursor(doc)
                cursor_ascii.setPosition(block_start + char_pos_ascii)
                cursor_ascii.setPosition(block_start + char_pos_ascii + 1, QTextCursor.MoveMode.KeepAnchor)
                sel_ascii.cursor = cursor_ascii
                extra_selections.append(sel_ascii)

                if first_cursor is None:
                    first_cursor = cursor_hex

        self.hex_editor.setExtraSelections(extra_selections)
        if first_cursor:
            self.hex_editor.setTextCursor(first_cursor)
            self.hex_editor.centerCursor()

        self._update_inspector(offset)


    def set_event_data(self, event: Optional[Dict[str, Any]]):

        self._current_event = event
        if not event:
            self._raw_bytes = b""
            self._payload_bytes = b""
            self.hex_editor.clear()
            self.c_editor.clear()
            self.json_editor.clear()
            self.decode_table.setRowCount(0)
            self.strings_table.setRowCount(0)
            self.lbl_len.setText("0 bytes")
            self._update_inspector(0)
            return

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

        self.lbl_len.setText(f"{len(self._raw_bytes):,} bytes")

        # Hex Dump
        lines = self._generate_hexdump(self._raw_bytes)
        self.hex_editor.setPlainText("\n".join(lines))

        # C-Array
        self.c_editor.setPlainText(self._generate_c_array(self._raw_bytes))

        # JSON
        self.json_editor.setPlainText(json.dumps(event, indent=2))

        # Strings Table
        self._populate_strings_table(self._raw_bytes)

        # Inspector
        self._update_inspector(0)
        self._populate_decode_table(0)

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
        lines = [f"// KShark Dissection Payload ({len(data)} bytes)", "const unsigned char payload[] = {"]
        for offset in range(0, len(data), 12):
            chunk = data[offset:offset+12]
            hex_items = [f"0x{b:02x}" for b in chunk]
            lines.append("    " + ", ".join(hex_items) + ",")
        lines.append("};")
        return "\n".join(lines)

    def _populate_strings_table(self, data: bytes, min_len: int = 4):
        rows = []
        cur = []
        cur_offset = 0

        for idx, b in enumerate(data):
            if 32 <= b <= 126:
                if not cur:
                    cur_offset = idx
                cur.append(chr(b))
            else:
                if len(cur) >= min_len:
                    rows.append((cur_offset, len(cur), "".join(cur)))
                cur = []
        if len(cur) >= min_len:
            rows.append((cur_offset, len(cur), "".join(cur)))

        self.strings_table.setRowCount(len(rows))
        for r_idx, (offset, length, string_val) in enumerate(rows):
            self.strings_table.setItem(r_idx, 0, QTableWidgetItem(f"0x{offset:04X}"))
            self.strings_table.setItem(r_idx, 1, QTableWidgetItem(str(length)))
            self.strings_table.setItem(r_idx, 2, QTableWidgetItem(string_val))

    def _on_cursor_changed(self):
        cursor = self.hex_editor.textCursor()
        line_num = cursor.blockNumber()
        col = cursor.positionInBlock()

        # In Hex+ASCII mode:
        # Cols: 0..7 (offset), 8..9 (sp), 10..33 (L-hex), 34..59 (R-hex), 60..76 (ASCII)
        if 10 <= col <= 33:
            byte_idx = min(7, max(0, (col - 10) // 3))
        elif 34 <= col <= 59:
            byte_idx = 8 + min(7, max(0, (col - 34) // 3))
        elif col >= 60:
            byte_idx = min(15, max(0, col - 60))
        else:
            byte_idx = 0

        byte_offset = (line_num * 16) + byte_idx

        self._update_inspector(byte_offset)
        self._populate_decode_table(byte_offset)

    def _update_inspector(self, offset: int):
        if not self._raw_bytes or offset < 0 or offset >= len(self._raw_bytes):
            self.lbl_offset.setText(f"Offset: 0x{max(0, offset):04X} ({max(0, offset)})")
            self.lbl_u8.setText("u8: -")
            self.lbl_u16.setText("u16_le: -")
            self.lbl_u32.setText("u32_le: -")
            self.lbl_ip.setText("IPv4: -")
            self.lbl_bin.setText("Bits: -")
            return


        buf = self._raw_bytes[offset:offset+8]
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

    def _populate_decode_table(self, offset: int):
        if not self._raw_bytes or offset < 0:
            return

        buf = self._raw_bytes[offset:offset+8]
        if len(buf) < 8:
            buf = buf.ljust(8, b'\x00')

        rows = []
        u8 = buf[0]
        i8 = struct.unpack("b", bytes([buf[0]]))[0]
        rows.append(("8-bit Integer (Unsigned / Signed)", f"{u8} (0x{u8:02X})", f"{i8}"))

        u16_le = struct.unpack("<H", buf[:2])[0]
        u16_be = struct.unpack(">H", buf[:2])[0]
        rows.append(("16-bit Integer", f"{u16_le} (0x{u16_le:04X})", f"{u16_be} (0x{u16_be:04X})"))

        u32_le = struct.unpack("<I", buf[:4])[0]
        u32_be = struct.unpack(">I", buf[:4])[0]
        rows.append(("32-bit Integer", f"{u32_le} (0x{u32_le:08X})", f"{u32_be} (0x{u32_be:08X})"))

        u64_le = struct.unpack("<Q", buf[:8])[0]
        u64_be = struct.unpack(">Q", buf[:8])[0]
        rows.append(("64-bit Integer", f"{u64_le}", f"{u64_be}"))

        try:
            f32_le = struct.unpack("<f", buf[:4])[0]
            f32_be = struct.unpack(">f", buf[:4])[0]
            rows.append(("32-bit Float", f"{f32_le:.6f}", f"{f32_be:.6f}"))
        except Exception:
            pass

        ip_le = ".".join(str(b) for b in buf[:4])
        rows.append(("IPv4 Address", ip_le, ip_le))

        self.decode_table.setRowCount(len(rows))
        for r_idx, (t_name, le_val, be_val) in enumerate(rows):
            self.decode_table.setItem(r_idx, 0, QTableWidgetItem(t_name))
            self.decode_table.setItem(r_idx, 1, QTableWidgetItem(le_val))
            self.decode_table.setItem(r_idx, 2, QTableWidgetItem(be_val))

    def _on_search_changed(self, text: str):
        query = text.strip()
        if not query:
            return

        cursor = self.hex_editor.textCursor()
        doc = self.hex_editor.document()
        find_cursor = doc.find(query, cursor)
        if find_cursor.isNull():
            find_cursor = doc.find(query)
        if not find_cursor.isNull():
            self.hex_editor.setTextCursor(find_cursor)

    def _show_hex_context_menu(self, pos):
        menu = QMenu(self)
        sel_text = self.hex_editor.textCursor().selectedText()

        if sel_text:
            menu.addAction("Copy Selected Text", lambda: QApplication.clipboard().setText(sel_text))
        menu.addAction("Copy Entire Hex Dump", lambda: QApplication.clipboard().setText(self.hex_editor.toPlainText()))
        menu.addAction("Copy as C-Array", lambda: QApplication.clipboard().setText(self._generate_c_array(self._raw_bytes)))
        menu.addAction("Copy as Base64", lambda: QApplication.clipboard().setText(base64.b64encode(self._raw_bytes).decode("ascii")))

        menu.addSeparator()
        menu.addAction("Compute Hashes & Entropy...", self._open_hasher_dialog)
        menu.addAction("Export Payload to File...", self._export_to_file)

        menu.exec(self.hex_editor.viewport().mapToGlobal(pos))

    def _open_hasher_dialog(self):
        if not self._raw_bytes:
            QMessageBox.information(self, "No Data", "No event byte stream selected.")
            return
        dlg = ByteHasherDialog(self._raw_bytes, self)
        dlg.exec()

    def _export_to_file(self):
        if not self._raw_bytes:
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
                f.write(self._raw_bytes)
            QMessageBox.information(self, "Export Successful", f"Saved {len(self._raw_bytes):,} bytes to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to save file: {e}")
