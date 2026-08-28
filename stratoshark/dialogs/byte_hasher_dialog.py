"""
Stratoshark Byte Hasher & Value Inspector Dialog.
Calculates cryptographic hashes (MD5, SHA-1, SHA-256, Entropy) and decodes byte representations.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFormLayout, QGroupBox, QLineEdit, QApplication, QMessageBox,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt
import hashlib
import math
import struct
from typing import Optional

from stratoshark.core.theme import get_monospace_font

class ByteHasherDialog(QDialog):
    """
    Forensic Hasher and Binary Value Inspector.
    """

    def __init__(self, data: bytes, parent=None):
        super().__init__(parent)
        self.data = data
        self.setWindowTitle(f"Byte Hasher & Binary Inspector ({len(data):,} bytes)")
        self.resize(680, 460)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # 1. Hashes Box
        grp_hash = QGroupBox("Cryptographic Hashes & Entropy")
        f_hash = QFormLayout(grp_hash)

        md5 = hashlib.md5(self.data).hexdigest()
        sha1 = hashlib.sha1(self.data).hexdigest()
        sha256 = hashlib.sha256(self.data).hexdigest()
        entropy = self._calculate_entropy(self.data)

        edit_md5 = QLineEdit(md5)
        edit_md5.setReadOnly(True)
        edit_md5.setFont(get_monospace_font(size=9))

        edit_sha1 = QLineEdit(sha1)
        edit_sha1.setReadOnly(True)
        edit_sha1.setFont(get_monospace_font(size=9))

        edit_sha256 = QLineEdit(sha256)
        edit_sha256.setReadOnly(True)
        edit_sha256.setFont(get_monospace_font(size=9))

        lbl_entropy = QLabel(f"<b>{entropy:.4f} bits / byte</b> (Max: 8.0 — {'High Entropy / Encrypted' if entropy > 7.0 else 'Standard Text / Code'})")

        f_hash.addRow("MD5:", edit_md5)
        f_hash.addRow("SHA-1:", edit_sha1)
        f_hash.addRow("SHA-256:", edit_sha256)
        f_hash.addRow("Shannon Entropy:", lbl_entropy)

        layout.addWidget(grp_hash)

        # 2. Binary Value Decodings Table
        grp_val = QGroupBox("Binary Value Inspector (First 8 Bytes)")
        v_layout = QVBoxLayout(grp_val)

        val_table = QTableWidget()
        val_table.setColumnCount(3)
        val_table.setHorizontalHeaderLabels(["Data Type", "Little-Endian (x86)", "Big-Endian (Network)"])
        val_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        val_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        val_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        val_table.setFont(get_monospace_font(size=9))

        self._populate_val_table(val_table)
        v_layout.addWidget(val_table)
        layout.addWidget(grp_val)

        # 3. Bottom Buttons
        btn_layout = QHBoxLayout()
        btn_copy = QPushButton("Copy All Hashes")
        btn_copy.clicked.connect(lambda: (
            QApplication.clipboard().setText(f"MD5: {md5}\nSHA1: {sha1}\nSHA256: {sha256}\nEntropy: {entropy:.4f}"),
            QMessageBox.information(self, "Copied", "Hashes copied to clipboard!")
        ))

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)

        btn_layout.addWidget(btn_copy)
        btn_layout.addStretch()
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def _populate_val_table(self, table: QTableWidget):
        buf = self.data[:8]
        if len(buf) < 8:
            buf = buf.ljust(8, b'\x00')

        rows = []
        # uint8 / int8
        u8 = buf[0]
        i8 = struct.unpack("b", bytes([buf[0]]))[0]
        rows.append(("8-bit Integer (Unsigned / Signed)", f"{u8} / {i8}", f"{u8} / {i8}"))

        # uint16 / int16
        u16_le = struct.unpack("<H", buf[:2])[0]
        u16_be = struct.unpack(">H", buf[:2])[0]
        rows.append(("16-bit Unsigned Integer", f"{u16_le} (0x{u16_le:04X})", f"{u16_be} (0x{u16_be:04X})"))

        # uint32 / int32
        u32_le = struct.unpack("<I", buf[:4])[0]
        u32_be = struct.unpack(">I", buf[:4])[0]
        rows.append(("32-bit Unsigned Integer", f"{u32_le} (0x{u32_le:08X})", f"{u32_be} (0x{u32_be:08X})"))

        # uint64
        u64_le = struct.unpack("<Q", buf[:8])[0]
        u64_be = struct.unpack(">Q", buf[:8])[0]
        rows.append(("64-bit Unsigned Integer", f"{u64_le}", f"{u64_be}"))

        # IPv4
        ip_le = ".".join(str(b) for b in buf[:4])
        rows.append(("IPv4 Address", ip_le, ip_le))

        table.setRowCount(len(rows))
        for r_idx, (t_name, le_val, be_val) in enumerate(rows):
            table.setItem(r_idx, 0, QTableWidgetItem(t_name))
            table.setItem(r_idx, 1, QTableWidgetItem(le_val))
            table.setItem(r_idx, 2, QTableWidgetItem(be_val))
