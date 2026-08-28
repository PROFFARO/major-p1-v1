"""
Wireshark-accurate Hex / ASCII Raw Byte Viewer for KShark.

Displays 3-column structured memory & JSON payload dump:
  Offset (8 hex) | Hex bytes (16 bytes in 8-byte groups) | ASCII characters
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QPlainTextEdit, QTextEdit
from PyQt6.QtGui import QTextCursor, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import Qt
import json
from typing import Optional, Dict, Any

from kshark.core.theme import get_monospace_font


class EventByteView(QPlainTextEdit):
    """
    Wireshark-styled raw byte viewer.
    Renders raw event serialized payload with offset, hex, and printable ASCII.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("eventByteView")
        self.setReadOnly(True)
        self.setFont(get_monospace_font(size=9))
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._raw_bytes: bytes = b""

    def set_event_data(self, event: Optional[Dict[str, Any]]):
        """Formats event dictionary into 16-byte aligned Hex dump + ASCII representation."""
        self.clear()
        if not event:
            self._raw_bytes = b""
            return

        try:
            # Serialize event dictionary into formatted JSON byte stream
            json_str = json.dumps(event, indent=2)
            self._raw_bytes = json_str.encode("utf-8")
        except Exception:
            self._raw_bytes = str(event).encode("utf-8")

        lines = self._generate_hexdump(self._raw_bytes)
        self.setPlainText("\n".join(lines))

    def _generate_hexdump(self, data: bytes) -> list:
        """Generates Wireshark-style 3-column hex dump lines."""
        lines = []
        n = len(data)

        for offset in range(0, n, 16):
            chunk = data[offset:offset+16]

            # 1. Offset: 8 hex digits
            offset_str = f"{offset:08x}"

            # 2. Hex Dump: 16 bytes, grouped into two 8-byte halves
            hex_parts = []
            for b in chunk:
                hex_parts.append(f"{b:02x}")

            # Pad to 16 bytes for alignment
            while len(hex_parts) < 16:
                hex_parts.append("  ")

            hex_left = " ".join(hex_parts[:8])
            hex_right = " ".join(hex_parts[8:])
            hex_str = f"{hex_left}  {hex_right}"

            # 3. ASCII Representation: printable characters or '.'
            ascii_chars = []
            for b in chunk:
                if 32 <= b <= 126:
                    ascii_chars.append(chr(b))
                else:
                    ascii_chars.append(".")
            ascii_str = "".join(ascii_chars)

            lines.append(f"{offset_str}  {hex_str}  {ascii_str}")

        return lines

    def highlight_byte_range(self, start_byte: int, length: int):
        """Highlights a specific byte range in both the hex and ASCII columns."""
        if start_byte < 0 or length <= 0 or not self._raw_bytes:
            return

        # Clear existing selections
        cursor = self.textCursor()
        cursor.select(QTextCursor.SelectionType.Document)
        fmt_normal = QTextCharFormat()
        cursor.setCharFormat(fmt_normal)

        # Apply highlight format
        fmt_highlight = QTextCharFormat()
        fmt_highlight.setBackground(QColor("#0078D7"))
        fmt_highlight.setForeground(QColor("#FFFFFF"))

        # Calculate character offsets in the formatted text
        # (Each line is: 8 (offset) + 2 (spaces) + 23 (left hex) + 2 (gap) + 23 (right hex) + 2 (gap) + 16 (ascii) = 76 chars)
        line_len = 77  # including newline

        for b_idx in range(start_byte, min(start_byte + length, len(self._raw_bytes))):
            row = b_idx // 16
            col = b_idx % 16

            # Hex char position
            hex_col_offset = 10 + (col * 3 if col < 8 else 24 + 2 + (col - 8) * 3)
            char_pos = row * line_len + hex_col_offset

            cursor.setPosition(char_pos)
            cursor.movePosition(QTextCursor.MoveOperation.Right, QTextCursor.MoveMode.KeepAnchor, 2)
            cursor.mergeCharFormat(fmt_highlight)

            # ASCII char position
            ascii_col_offset = 10 + 23 + 2 + 23 + 2 + col
            ascii_pos = row * line_len + ascii_col_offset
            cursor.setPosition(ascii_pos)
            cursor.movePosition(QTextCursor.MoveOperation.Right, QTextCursor.MoveMode.KeepAnchor, 1)
            cursor.mergeCharFormat(fmt_highlight)
