"""
KShark Interactive Follow Stream Forensic Dialog.

Provides full conversational, execution, and payload reconstruction:
1. Follow Process I/O Stream (Process execution timeline, arguments, stdin/stdout, and file mutations)
2. Follow Network Socket Stream (TCP/UDP socket conversations with bidirectional coloring)
3. Follow File Access Lifecycle (Sequential file descriptor operations: open -> read/write -> close)

Equipped with:
- Directional Color Coding (Client/Send in #72B8FF, Server/Recv in #FF9E79)
- Multiple Decoders: ASCII, UTF-8, Hex Dump, C-Array, YAML
- Search with Next/Previous highlighting
- File Export and Clipboard Copying
"""

import os
import json
import base64
from typing import List, Dict, Any, Optional, Tuple
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QPlainTextEdit, QTextEdit, QLineEdit, QFileDialog, QMessageBox,
    QApplication, QFrame, QRadioButton, QButtonGroup, QStatusBar
)
from PyQt6.QtGui import (
    QTextCursor, QTextCharFormat, QTextDocument, QColor, QFont, QPalette
)
from PyQt6.QtCore import Qt, pyqtSignal

from kshark.core.theme import ThemeManager, get_monospace_font, get_ui_font
from kshark.core.syscall_table import resolve_syscall_name


class StreamSegment:
    """Represents a single segment/packet in a reconstructed stream."""
    def __init__(self, direction: str, text: str, raw_bytes: bytes, event: Dict[str, Any]):
        self.direction = direction  # "CLIENT" (Sender/Client) or "SERVER" (Receiver/Server) or "INFO"
        self.text = text
        self.raw_bytes = raw_bytes
        self.event = event


class FollowStreamDialog(QDialog):
    """
    KShark Follow Stream Forensic Dialog.
    """

    filterApplied = pyqtSignal(str)

    MODE_PROCESS = "Process I/O Stream"
    MODE_NETWORK = "Network Socket Stream"
    MODE_FILE = "File Access Lifecycle"

    FORMAT_ASCII = "ASCII"
    FORMAT_UTF8 = "UTF-8"
    FORMAT_HEX = "Hex Dump"
    FORMAT_CARRAY = "C-Array"
    FORMAT_YAML = "YAML Dissection"

    def __init__(self, target_event: Dict[str, Any], all_events: List[Dict[str, Any]], mode: str = MODE_PROCESS, parent=None):
        super().__init__(parent)
        self.target_event = target_event
        self.all_events = all_events
        self.current_mode = mode
        self.current_format = self.FORMAT_ASCII
        self.segments: List[StreamSegment] = []

        self.setWindowTitle(f"KShark · Follow {self.current_mode}")
        self.resize(860, 560)
        self._init_ui()
        self._reconstruct_stream()
        self._render_stream()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 4)
        layout.setSpacing(6)

        # ── 1. Top Configuration Bar ──
        top_bar = QHBoxLayout()
        top_bar.setSpacing(8)

        lbl_stream = QLabel("Stream Type:", self)
        lbl_stream.setFont(get_ui_font(size=8, bold=True))
        top_bar.addWidget(lbl_stream)

        self.combo_stream_type = QComboBox(self)
        self.combo_stream_type.setFont(get_ui_font(size=8.5))
        self.combo_stream_type.addItems([self.MODE_PROCESS, self.MODE_NETWORK, self.MODE_FILE])
        self.combo_stream_type.setCurrentText(self.current_mode)
        self.combo_stream_type.currentTextChanged.connect(self._on_mode_changed)
        top_bar.addWidget(self.combo_stream_type)

        top_bar.addSpacing(10)

        lbl_fmt = QLabel("Format:", self)
        lbl_fmt.setFont(get_ui_font(size=8, bold=True))
        top_bar.addWidget(lbl_fmt)

        self.combo_format = QComboBox(self)
        self.combo_format.setFont(get_ui_font(size=8.5))
        self.combo_format.addItems([self.FORMAT_ASCII, self.FORMAT_UTF8, self.FORMAT_HEX, self.FORMAT_CARRAY, self.FORMAT_YAML])
        self.combo_format.currentTextChanged.connect(self._on_format_changed)
        top_bar.addWidget(self.combo_format)

        top_bar.addStretch(1)

        c = ThemeManager.instance().get_palette_colors()
        is_dark = ThemeManager.is_dark()

        # Direction Legend
        lbl_legend_c = QLabel("■ Client / Send", self)
        lbl_legend_c.setFont(get_monospace_font(size=8, bold=True))
        lbl_legend_c.setStyleSheet(f"color: {'#72B8FF' if is_dark else '#0369A1'}; margin-right: 6px;")
        top_bar.addWidget(lbl_legend_c)

        lbl_legend_s = QLabel("■ Server / Recv", self)
        lbl_legend_s.setFont(get_monospace_font(size=8, bold=True))
        lbl_legend_s.setStyleSheet(f"color: {'#FF9E79' if is_dark else '#C2410C'};")
        top_bar.addWidget(lbl_legend_s)

        layout.addLayout(top_bar)

        # ── 2. Main Stream Display Area ──
        self.editor = QTextEdit(self)
        self.editor.setReadOnly(True)
        self.editor.setFont(get_monospace_font(size=9))
        self.editor.setStyleSheet(f"""
            QTextEdit {{
                background-color: {c['bg_base']};
                color: {c['fg_text']};
                border: 1px solid {c['border']};
                selection-background-color: {c['selection_bg']};
                selection-color: {c['selection_fg']};
            }}
        """)
        layout.addWidget(self.editor, stretch=1)

        # ── 3. Find / Search Bar ──
        search_bar = QHBoxLayout()
        search_bar.setSpacing(6)

        lbl_find = QLabel("Find:", self)
        lbl_find.setFont(get_ui_font(size=8))
        search_bar.addWidget(lbl_find)

        self.search_input = QLineEdit(self)
        self.search_input.setFont(get_ui_font(size=8))
        self.search_input.setPlaceholderText("Search inside stream...")
        self.search_input.returnPressed.connect(self._find_next)
        search_bar.addWidget(self.search_input, stretch=1)

        btn_find_prev = QPushButton("Previous", self)
        btn_find_prev.setFont(get_ui_font(size=8))
        btn_find_prev.clicked.connect(self._find_prev)
        search_bar.addWidget(btn_find_prev)

        btn_find_next = QPushButton("Next", self)
        btn_find_next.setFont(get_ui_font(size=8))
        btn_find_next.clicked.connect(self._find_next)
        search_bar.addWidget(btn_find_next)

        layout.addLayout(search_bar)

        # ── 4. Bottom Action Buttons Bar ──
        bot_bar = QHBoxLayout()
        bot_bar.setSpacing(8)

        btn_filter_out = QPushButton("Filter Out This Stream", self)
        btn_filter_out.setFont(get_ui_font(size=8))
        btn_filter_out.clicked.connect(self._filter_out_stream)
        bot_bar.addWidget(btn_filter_out)

        btn_save = QPushButton("Save As...", self)
        btn_save.setFont(get_ui_font(size=8))
        btn_save.clicked.connect(self._save_as)
        bot_bar.addWidget(btn_save)

        btn_copy = QPushButton("Copy to Clipboard", self)
        btn_copy.setFont(get_ui_font(size=8))
        btn_copy.clicked.connect(self._copy_all)
        bot_bar.addWidget(btn_copy)

        bot_bar.addStretch(1)

        btn_close = QPushButton("Close", self)
        btn_close.setFont(get_ui_font(size=8, bold=True))
        btn_close.clicked.connect(self.accept)
        bot_bar.addWidget(btn_close)

        layout.addLayout(bot_bar)

        # ── 5. Status Bar ──
        self.status_bar = QStatusBar(self)
        self.status_bar.setFont(get_ui_font(size=7.5))
        self.status_bar.setSizeGripEnabled(True)
        layout.addWidget(self.status_bar)

    def _on_mode_changed(self, mode: str):
        self.current_mode = mode
        self.setWindowTitle(f"KShark · Follow {self.current_mode}")
        self._reconstruct_stream()
        self._render_stream()

    def _on_format_changed(self, fmt: str):
        self.current_format = fmt
        self._render_stream()

    # ------------------------------------------------------------------
    # Stream Reconstruction Logic
    # ------------------------------------------------------------------
    def _reconstruct_stream(self):
        self.segments.clear()
        if not self.target_event or not self.all_events:
            return

        target_pid = self.target_event.get("pid", 0)
        target_dst_ip = str(self.target_event.get("dst_ip", ""))
        target_dst_port = int(self.target_event.get("dst_port", 0) or 0)
        target_file = str(self.target_event.get("file_path") or self.target_event.get("filename") or "")

        if self.current_mode == self.MODE_PROCESS:
            # Aggregate all events associated with target PID and its child forks
            matching_pids = {target_pid}
            for ev in self.all_events:
                if ev.get("ppid") in matching_pids:
                    matching_pids.add(ev.get("pid", 0))

            for ev in self.all_events:
                ev_pid = ev.get("pid", 0)
                if ev_pid in matching_pids:
                    sc = resolve_syscall_name(ev)
                    comm = ev.get("comm") or ev.get("proc_name") or "unknown"
                    ts = ev.get("timestamp_ns", 0)
                    cmdline = ev.get("cmdline") or ev.get("exe_path") or ""
                    fp = ev.get("file_path") or ev.get("filename") or ""
                    ret = ev.get("retval", 0)

                    # Extract payload or stdout/stderr if present
                    payload = ev.get("data") or ev.get("payload") or ev.get("buffer") or ""
                    raw_bytes = payload.encode("utf-8") if isinstance(payload, str) else (payload if isinstance(payload, bytes) else b"")

                    if sc == "execve":
                        text = f"[{comm}:{ev_pid}] EXECUTE: {cmdline} (ret={ret})\n"
                        self.segments.append(StreamSegment("CLIENT", text, text.encode("utf-8"), ev))
                    elif sc in ("write", "sendto") and raw_bytes:
                        self.segments.append(StreamSegment("CLIENT", raw_bytes.decode("utf-8", "replace"), raw_bytes, ev))
                    elif sc in ("read", "recvfrom") and raw_bytes:
                        self.segments.append(StreamSegment("SERVER", raw_bytes.decode("utf-8", "replace"), raw_bytes, ev))
                    elif sc in ("open", "openat", "unlink", "mkdir"):
                        text = f"[{comm}:{ev_pid}] FILE {sc.upper()}: {fp} (ret={ret})\n"
                        self.segments.append(StreamSegment("INFO", text, text.encode("utf-8"), ev))
                    elif sc == "exit" or sc == "exit_group":
                        text = f"[{comm}:{ev_pid}] PROCESS EXIT (code={ret})\n"
                        self.segments.append(StreamSegment("INFO", text, text.encode("utf-8"), ev))

        elif self.current_mode == self.MODE_NETWORK:
            # Aggregate all socket conversations matching this endpoint pair
            for ev in self.all_events:
                dst_ip = str(ev.get("dst_ip", ""))
                dst_port = int(ev.get("dst_port", 0) or 0)
                src_ip = str(ev.get("src_ip", ""))
                src_port = int(ev.get("src_port", 0) or 0)

                is_forward = (dst_ip == target_dst_ip and (dst_port == target_dst_port or target_dst_port == 0))
                is_reverse = (src_ip == target_dst_ip and (src_port == target_dst_port or target_dst_port == 0))

                if is_forward or is_reverse:
                    sc = resolve_syscall_name(ev)
                    payload = ev.get("data") or ev.get("payload") or ev.get("buffer") or ""
                    raw_bytes = payload.encode("utf-8") if isinstance(payload, str) else (payload if isinstance(payload, bytes) else b"")

                    if not raw_bytes:
                        raw_bytes = f"[{sc}] {ev.get('comm', '')} -> {dst_ip}:{dst_port}\n".encode("utf-8")

                    direction = "CLIENT" if (is_forward and sc in ("write", "sendto", "connect")) else "SERVER"
                    self.segments.append(StreamSegment(direction, raw_bytes.decode("utf-8", "replace"), raw_bytes, ev))

        elif self.current_mode == self.MODE_FILE:
            # Aggregate all filesystem access to this file path
            for ev in self.all_events:
                fp = str(ev.get("file_path") or ev.get("filename") or "")
                if target_file and (target_file in fp or fp in target_file):
                    sc = resolve_syscall_name(ev)
                    comm = ev.get("comm", "")
                    pid = ev.get("pid", 0)
                    ret = ev.get("retval", 0)
                    payload = ev.get("data") or ev.get("payload") or ""
                    raw_bytes = payload.encode("utf-8") if isinstance(payload, str) else (payload if isinstance(payload, bytes) else b"")

                    if sc in ("write", "pwrite64") and raw_bytes:
                        self.segments.append(StreamSegment("CLIENT", raw_bytes.decode("utf-8", "replace"), raw_bytes, ev))
                    elif sc in ("read", "pread64") and raw_bytes:
                        self.segments.append(StreamSegment("SERVER", raw_bytes.decode("utf-8", "replace"), raw_bytes, ev))
                    else:
                        text = f"[{comm}:{pid}] {sc.upper()} -> {fp} (ret={ret})\n"
                        self.segments.append(StreamSegment("INFO", text, text.encode("utf-8"), ev))

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------
    def _render_stream(self):
        self.editor.clear()
        if not self.segments:
            self.editor.setPlainText("No stream data captured for this context.")
            self.status_bar.showMessage("Stream empty")
            return

        cursor = self.editor.textCursor()
        client_bytes = 0
        server_bytes = 0
        is_dark = ThemeManager.is_dark()
        c = ThemeManager.instance().get_palette_colors()

        fmt_client = QTextCharFormat()
        fmt_client.setForeground(QColor("#72B8FF" if is_dark else "#0369A1"))
        fmt_client.setFont(get_monospace_font(size=9))

        fmt_server = QTextCharFormat()
        fmt_server.setForeground(QColor("#FF9E79" if is_dark else "#C2410C"))
        fmt_server.setFont(get_monospace_font(size=9))

        fmt_info = QTextCharFormat()
        fmt_info.setForeground(QColor("#95A5A6" if is_dark else "#64748B"))
        fmt_info.setFont(get_monospace_font(size=8.5))

        for seg in self.segments:
            if seg.direction == "CLIENT":
                client_bytes += len(seg.raw_bytes)
                fmt = fmt_client
            elif seg.direction == "SERVER":
                server_bytes += len(seg.raw_bytes)
                fmt = fmt_server
            else:
                fmt = fmt_info

            # Format text based on decoder format
            if self.current_format in (self.FORMAT_ASCII, self.FORMAT_UTF8):
                disp_text = seg.text
            elif self.current_format == self.FORMAT_HEX:
                disp_text = self._format_hex(seg.raw_bytes) + "\n"
            elif self.current_format == self.FORMAT_CARRAY:
                disp_text = self._format_carray(seg.raw_bytes) + "\n"
            elif self.current_format == self.FORMAT_YAML:
                disp_text = f"---\n# Event: {resolve_syscall_name(seg.event)}\n" + json.dumps(seg.event, indent=2) + "\n"
            else:
                disp_text = seg.text

            cursor.insertText(disp_text, fmt)

        self.status_bar.showMessage(
            f"Events: {len(self.segments):,}  |  Client Sent: {client_bytes:,} bytes  |  Server Recv: {server_bytes:,} bytes  |  Total: {client_bytes + server_bytes:,} bytes"
        )

    def _format_hex(self, data: bytes) -> str:
        lines = []
        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            hex_parts = [f"{b:02x}" for b in chunk]
            while len(hex_parts) < 16:
                hex_parts.append("  ")
            ascii_chars = "".join([chr(b) if 32 <= b <= 126 else "." for b in chunk])
            lines.append(f"{offset:04x}  {' '.join(hex_parts[:8])}  {' '.join(hex_parts[8:])}  |{ascii_chars}|")
        return "\n".join(lines)

    def _format_carray(self, data: bytes) -> str:
        hex_literals = [f"0x{b:02x}" for b in data]
        lines = []
        for i in range(0, len(hex_literals), 12):
            lines.append("    " + ", ".join(hex_literals[i:i + 12]) + ",")
        return "char payload[] = {\n" + "\n".join(lines) + "\n};"

    # ------------------------------------------------------------------
    # Search and Filter Operations
    # ------------------------------------------------------------------
    def _find_next(self):
        query = self.search_input.text().strip()
        if query:
            self.editor.find(query)

    def _find_prev(self):
        query = self.search_input.text().strip()
        if query:
            self.editor.find(query, QTextDocument.FindFlag.FindBackward)

    def _filter_out_stream(self):
        if self.current_mode == self.MODE_PROCESS:
            pid = self.target_event.get("pid", 0)
            expr = f"proc.pid != {pid}"
        elif self.current_mode == self.MODE_NETWORK:
            dst = self.target_event.get("dst_ip", "")
            expr = f'ip.dst != "{dst}"'
        else:
            fp = self.target_event.get("file_path", "")
            expr = f'!(fd.name contains "{fp}")'

        self.filterApplied.emit(expr)
        self.accept()

    def _save_as(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Reconstructed Stream", "kshark_stream.txt", "Text Files (*.txt);;Raw Bytes (*.bin);;All Files (*)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.editor.toPlainText())
                QMessageBox.information(self, "Saved", f"Stream saved successfully to:\n{path}")
            except Exception as e:
                QMessageBox.warning(self, "Save Failed", f"Could not write file: {e}")

    def _copy_all(self):
        QApplication.clipboard().setText(self.editor.toPlainText())
        self.status_bar.showMessage("Stream copied to clipboard!", 3000)
