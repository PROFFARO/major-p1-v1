"""
KShark Threat Timeline & Security Intelligence Dock.
Two-sided ergonomic forensic interface:
- Left Side: Interactive Chronological Scrubber & High-Density Alert Stream.
- Right Side: Live Incident Triage Card, MITRE ATT&CK Context & One-Click Process Containment.
"""

import time
import collections
from typing import List, Dict, Any, Optional

from PyQt6.QtWidgets import (
    QDockWidget, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QPushButton,
    QFrame, QMessageBox, QMenu, QSplitter, QLineEdit, QComboBox,
    QTextEdit, QApplication
)
from PyQt6.QtCore import Qt, QPointF, QRectF, pyqtSignal
from PyQt6.QtGui import (
    QPainter, QPen, QColor, QBrush, QFont, QLinearGradient, QAction
)

from kshark.core.theme import ThemeManager, get_monospace_font, get_ui_font


class TimelineThreatMarker:
    """Represents a discrete security alert pinned on the chronological timeline."""

    def __init__(self, timestamp_ns: int, threat_name: str, pid: int, comm: str, conf: float, mitre_id: str, forensic_info: str, event_index: int = -1, raw_event: dict = None):
        self.timestamp_ns = timestamp_ns
        self.threat_name = threat_name
        self.pid = pid
        self.comm = comm
        self.conf = conf
        self.mitre_id = mitre_id
        self.forensic_info = forensic_info
        self.event_index = event_index
        self.raw_event = raw_event or {}

    @property
    def severity(self) -> str:
        t = self.threat_name.upper()
        if any(x in t for x in ("RANSOMWARE", "ROOTKIT", "ESCAPE", "MEMFD", "INJECTION")):
            return "CRITICAL"
        elif any(x in t for x in ("SHELL", "CREDENTIAL", "SHADOW", "PRIVILEGE", "TAMPERING")):
            return "HIGH"
        return "MEDIUM"

    @property
    def color_hex(self) -> str:
        sev = self.severity
        if sev == "CRITICAL":
            return "#E74C3C"
        elif sev == "HIGH":
            return "#E67E22"
        return "#F1C40F"


class TimelineScrubberCanvas(QFrame):
    """
    Interactive horizontal Gantt/time scrubber plotting threat markers chronologically.
    Clicking any marker or time offset seeks the main table view directly to that event.
    """

    markerClicked = pyqtSignal(int)  # Emits event_index

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setFixedHeight(48)
        self.setMouseTracking(True)

        self.markers: List[TimelineThreatMarker] = []
        self.start_ns: int = 0
        self.latest_ns: int = 0
        self.mouse_pos: Optional[QPointF] = None
        self.selected_idx: int = -1

    def add_marker(self, marker: TimelineThreatMarker):
        if not self.markers:
            self.start_ns = marker.timestamp_ns
        self.latest_ns = max(self.latest_ns, marker.timestamp_ns)
        self.markers.append(marker)
        self.update()

    def set_time_bounds(self, start_ns: int, latest_ns: int):
        self.start_ns = start_ns
        self.latest_ns = latest_ns
        self.update()

    def clear(self):
        self.markers.clear()
        self.start_ns = 0
        self.latest_ns = 0
        self.selected_idx = -1
        self.update()

    def mouseMoveEvent(self, event):
        self.mouse_pos = event.position()
        self.update()

    def leaveEvent(self, event):
        self.mouse_pos = None
        self.update()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.markers:
            w = self.width() - 40
            mx = event.position().x() - 20
            if mx < 0 or w <= 0:
                return

            span_ns = max(1, self.latest_ns - self.start_ns)
            click_ns = self.start_ns + int((mx / w) * span_ns)

            closest_marker = min(self.markers, key=lambda m: abs(m.timestamp_ns - click_ns))
            if closest_marker.event_index >= 0:
                self.selected_idx = closest_marker.event_index
                self.markerClicked.emit(closest_marker.event_index)
                self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        c = ThemeManager.instance().get_palette_colors()

        painter.fillRect(0, 0, w, h, QColor(c["bg_alt"]))

        margin_x = 24
        track_w = max(10, w - margin_x * 2)
        track_y = 24
        track_h = 4

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(c["border"])))
        painter.drawRoundedRect(margin_x, track_y, track_w, track_h, 2, 2)

        if not self.markers or self.latest_ns <= self.start_ns:
            painter.setPen(QColor(c["fg_muted"]))
            painter.setFont(get_monospace_font(size=8))
            painter.drawText(margin_x, 18, "No active security anomalies detected in current session")
            painter.end()
            return

        span_ns = max(1, self.latest_ns - self.start_ns)
        duration_s = span_ns / 1e9

        painter.setPen(QColor(c["fg_muted"]))
        painter.setFont(get_monospace_font(size=8))
        painter.drawText(margin_x, 15, "T+0.0s")
        painter.drawText(w - margin_x - 60, 15, 60, 14, Qt.AlignmentFlag.AlignRight, f"+{duration_s:.1f}s")

        hovered_marker: Optional[TimelineThreatMarker] = None

        for m in self.markers:
            ratio = (m.timestamp_ns - self.start_ns) / span_ns
            ratio = min(1.0, max(0.0, ratio))
            px = margin_x + ratio * track_w

            col = QColor(m.color_hex)
            painter.setPen(QPen(col.darker(120), 1))
            painter.setBrush(QBrush(col))
            painter.drawEllipse(QPointF(px, track_y + 2), 4.5, 4.5)

            if self.mouse_pos and abs(self.mouse_pos.x() - px) <= 6:
                hovered_marker = m

        if hovered_marker:
            offset_s = (hovered_marker.timestamp_ns - self.start_ns) / 1e9
            tip_txt = f"[{hovered_marker.severity}] {hovered_marker.threat_name} | PID {hovered_marker.pid} ({hovered_marker.comm}) @ +{offset_s:.2f}s"
            painter.setFont(get_monospace_font(size=8))
            tip_w = min(w - 20, max(180, len(tip_txt) * 7 + 16))
            tip_x = min(w - tip_w - 10, max(10, int(self.mouse_pos.x() - tip_w / 2)))

            painter.fillRect(tip_x, 30, tip_w, 16, QColor(14, 23, 27, 245))
            painter.setPen(QPen(QColor(hovered_marker.color_hex), 1))
            painter.drawRect(tip_x, 30, tip_w, 16)
            painter.setPen(QColor("#FFFFFF"))
            painter.drawText(tip_x + 6, 42, tip_txt)

        painter.end()


class ThreatTimelineDock(QDockWidget):
    """
    Two-Sided Professional SOC Forensic Dock:
    - Left: Chronological Scrubber & Filterable Alert Feed Table.
    - Right: Real-time Incident Triage Card & Process Containment Operations.
    """

    threatMarkerSelected = pyqtSignal(int)
    filterMainViewRequested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__("Threat Timeline & Security Intelligence", parent)
        self.setObjectName("threatTimelineDock")
        self.setAllowedAreas(Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea)

        self._markers: List[TimelineThreatMarker] = []
        self._current_selected_marker: Optional[TimelineThreatMarker] = None
        self._init_ui()
        ThemeManager.instance().themeChanged.connect(self._apply_theme)
        self._apply_theme()

    def _init_ui(self):
        container = QWidget(self)
        root_layout = QVBoxLayout(container)
        root_layout.setContentsMargins(6, 6, 6, 6)
        root_layout.setSpacing(6)

        # ── 1. Top Horizontal Timeline Scrubber ──
        self.scrubber = TimelineScrubberCanvas(self)
        self.scrubber.markerClicked.connect(self._on_marker_clicked)
        root_layout.addWidget(self.scrubber)

        # ── 2. Master Horizontal Two-Sided Splitter ──
        self.splitter = QSplitter(Qt.Orientation.Horizontal, self)
        self.splitter.setChildrenCollapsible(False)

        # ── Left Side: Feed & Search Sub-Panel ──
        left_widget = QWidget(self)
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)

        # Filter Sub-Bar
        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(6)

        self.edit_search = QLineEdit(self)
        self.edit_search.setFont(get_ui_font(size=8))
        self.edit_search.setPlaceholderText("Filter threats by process, PID, or classification...")
        self.edit_search.textChanged.connect(self._apply_feed_filter)
        filter_bar.addWidget(self.edit_search, stretch=1)

        self.combo_sev = QComboBox(self)
        self.combo_sev.setFont(get_ui_font(size=8))
        self.combo_sev.addItems(["All Severities", "CRITICAL Only", "HIGH & CRITICAL", "MEDIUM & Above"])
        self.combo_sev.currentTextChanged.connect(self._apply_feed_filter)
        filter_bar.addWidget(self.combo_sev)

        left_layout.addLayout(filter_bar)

        # Threat Alert Table
        self.table = QTableWidget(0, 7, self)
        self.table.setHorizontalHeaderLabels([
            "Time", "Sev", "Threat Classification", "PID", "Process Comm", "Conf", "MITRE ID"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setFont(get_monospace_font(size=8))
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.cellClicked.connect(self._on_table_cell_clicked)
        self.table.cellDoubleClicked.connect(self._on_table_cell_double_clicked)
        left_layout.addWidget(self.table, stretch=1)

        # Left Bottom Status Strip
        left_status = QHBoxLayout()
        self.lbl_count = QLabel("Threats Logged: 0", self)
        self.lbl_count.setFont(get_monospace_font(size=8))
        left_status.addWidget(self.lbl_count)
        left_status.addStretch(1)

        btn_clear = QPushButton("Clear Feed", self)
        btn_clear.setFont(get_ui_font(size=8))
        btn_clear.clicked.connect(self.clear_feed)
        left_status.addWidget(btn_clear)
        left_layout.addLayout(left_status)

        self.splitter.addWidget(left_widget)

        # ── Right Side: Live Incident Triage Card & Action Center ──
        self.triage_panel = QFrame(self)
        self.triage_panel.setFrameShape(QFrame.Shape.StyledPanel)
        triage_layout = QVBoxLayout(self.triage_panel)
        triage_layout.setContentsMargins(8, 8, 8, 8)
        triage_layout.setSpacing(6)

        # Triage Header
        self.lbl_triage_title = QLabel("INCIDENT TRIAGE & FORENSIC CONTEXT", self)
        self.lbl_triage_title.setFont(get_ui_font(size=8, bold=True))
        triage_layout.addWidget(self.lbl_triage_title)

        # Rich Details Text View
        self.triage_text = QTextEdit(self)
        self.triage_text.setReadOnly(True)
        self.triage_text.setFont(get_monospace_font(size=8))
        triage_layout.addWidget(self.triage_text, stretch=1)

        # Containment Action Buttons
        btn_grid = QHBoxLayout()
        btn_grid.setSpacing(6)

        self.btn_suspend = QPushButton("Suspend (kill -STOP)", self)
        self.btn_suspend.setFont(get_ui_font(size=8, bold=True))
        self.btn_suspend.setStyleSheet("background-color: #D35400; color: #FFF; border-radius: 2px; padding: 4px 8px;")
        self.btn_suspend.clicked.connect(self._isolate_selected_process)
        btn_grid.addWidget(self.btn_suspend)

        self.btn_terminate = QPushButton("Terminate (kill -9)", self)
        self.btn_terminate.setFont(get_ui_font(size=8, bold=True))
        self.btn_terminate.setStyleSheet("background-color: #C0392B; color: #FFF; border-radius: 2px; padding: 4px 8px;")
        self.btn_terminate.clicked.connect(self._kill_selected_process)
        btn_grid.addWidget(self.btn_terminate)

        self.btn_filter_pid = QPushButton("Filter to PID", self)
        self.btn_filter_pid.setFont(get_ui_font(size=8))
        self.btn_filter_pid.clicked.connect(self._filter_main_view_to_pid)
        btn_grid.addWidget(self.btn_filter_pid)

        triage_layout.addLayout(btn_grid)
        self.splitter.addWidget(self.triage_panel)

        # Set Splitter Proportions: 60% Left, 40% Right
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 2)

        root_layout.addWidget(self.splitter, stretch=1)
        self.setWidget(container)

    def _apply_theme(self):
        c = ThemeManager.instance().get_palette_colors()
        is_dark = ThemeManager.is_dark()

        self.scrubber.update()
        self.lbl_count.setStyleSheet(f"color: {c['fg_muted']};")

        input_bg = "#111618" if is_dark else "#FFFFFF"
        self.edit_search.setStyleSheet(f"background-color: {input_bg}; color: {c['fg_text']}; border: 1px solid {c['border']}; border-radius: 2px;")
        self.combo_sev.setStyleSheet(f"background-color: {input_bg}; color: {c['fg_text']}; border: 1px solid {c['border']}; border-radius: 2px;")

        self.triage_panel.setStyleSheet(f"""
            QFrame {{
                background-color: {c["bg_base"]};
                border: 1px solid {c["border"]};
                border-radius: 3px;
            }}
        """)
        self.lbl_triage_title.setStyleSheet(f"color: {c['brand_primary']}; border: none; background: transparent;")
        self.triage_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {c['bg_base']};
                color: {c['fg_text']};
                border: 1px solid {c['border']};
            }}
        """)

    def record_threat_marker(self, alert: dict, event_index: int = -1):
        """Records an incoming threat detection into the timeline and feed table."""
        threat = alert.get("threat_name") or alert.get("threat_type") or "ANOMALY"
        if threat == "BENIGN":
            return

        ts = alert.get("timestamp_ns", int(time.time() * 1e9))
        pid = alert.get("pid", 0)
        comm = alert.get("comm", "") or alert.get("exe_path", "").split("/")[-1]
        conf = float(alert.get("confidence", 0.95))
        forensic = alert.get("forensic_info", "")

        mitre_id = ""
        if "MITRE" in forensic:
            parts = forensic.split("MITRE")
            if len(parts) > 1:
                mitre_id = parts[1].strip().split(" ")[0].split("-")[0]

        marker = TimelineThreatMarker(ts, threat, pid, comm, conf, mitre_id, forensic, event_index, raw_event=alert)
        self._markers.append(marker)
        self.scrubber.add_marker(marker)

        # Append to Table
        row = self.table.rowCount()
        self.table.insertRow(row)

        start_ts = self._markers[0].timestamp_ns if self._markers else ts
        offset_s = (ts - start_ts) / 1e9

        item_time = QTableWidgetItem(f"+{offset_s:.2f}s")
        item_sev = QTableWidgetItem(f"[{marker.severity[:4]}]")
        item_sev.setForeground(QBrush(QColor(marker.color_hex)))

        item_threat = QTableWidgetItem(threat)
        item_threat.setFont(get_monospace_font(size=8, bold=True))

        item_pid = QTableWidgetItem(str(pid))
        item_proc = QTableWidgetItem(comm)
        item_conf = QTableWidgetItem(f"{conf:.0%}")
        item_mitre = QTableWidgetItem(mitre_id or "—")

        self.table.setItem(row, 0, item_time)
        self.table.setItem(row, 1, item_sev)
        self.table.setItem(row, 2, item_threat)
        self.table.setItem(row, 3, item_pid)
        self.table.setItem(row, 4, item_proc)
        self.table.setItem(row, 5, item_conf)
        self.table.setItem(row, 6, item_mitre)
        self.table.setRowHeight(row, 22)

        self.table.scrollToBottom()
        self.lbl_count.setText(f"Threats Logged: {len(self._markers)}")

        # Auto-display latest if nothing selected
        if not self._current_selected_marker:
            self._update_triage_card(marker)

    def _on_marker_clicked(self, event_index: int):
        if event_index >= 0:
            self.threatMarkerSelected.emit(event_index)
            # Find marker
            for m in self._markers:
                if m.event_index == event_index:
                    self._update_triage_card(m)
                    break

    def _on_table_cell_clicked(self, row: int, col: int):
        if 0 <= row < len(self._markers):
            m = self._markers[row]
            self._update_triage_card(m)
            if m.event_index >= 0:
                self.threatMarkerSelected.emit(m.event_index)

    def _on_table_cell_double_clicked(self, row: int, col: int):
        if 0 <= row < len(self._markers):
            m = self._markers[row]
            self._update_triage_card(m)
            if m.event_index >= 0:
                self.threatMarkerSelected.emit(m.event_index)

    def _update_triage_card(self, marker: TimelineThreatMarker):
        self._current_selected_marker = marker
        c = ThemeManager.instance().get_palette_colors()

        ev = marker.raw_event
        exe = ev.get("exe_path") or "-"
        target = ev.get("file_path") or ev.get("filename") or ev.get("dst_ip") or "-"
        src = ev.get("detection_source", "dual_ensemble_ml")

        html = f"""
        <div style='font-family: monospace;'>
            <div style='font-size: 10pt; font-weight: bold; color: {marker.color_hex};'>
                ● [{marker.severity}] {marker.threat_name}
            </div>
            <div style='color: #D8E8EC; margin-top: 4px;'>
                <b>Target Process:</b> {marker.comm} (PID: <b>{marker.pid}</b>)
            </div>
            <div style='color: #8A9EA4; font-size: 7.5pt;'>
                <b>Executable:</b> {exe}
            </div>
            <div style='color: #8A9EA4; font-size: 7.5pt;'>
                <b>Target Object / IP:</b> {target}
            </div>
            <div style='color: #8A9EA4; font-size: 7.5pt;'>
                <b>Detection Source:</b> {src} (Confidence: <b>{marker.conf:.0%}</b>)
            </div>
            <hr style='border: 0; border-top: 1px solid #283C42; margin: 6px 0;'/>
            <div style='color: #2BC1CF; font-size: 8pt;'>
                <b>Forensic Signature:</b> {marker.forensic_info or 'Multi-Model ML Anomaly Consensus'}
            </div>
        </div>
        """
        self.triage_text.setHtml(html)

    def _apply_feed_filter(self):
        query = self.edit_search.text().strip().lower()
        sev_mode = self.combo_sev.currentText()

        for r in range(self.table.rowCount()):
            m = self._markers[r] if r < len(self._markers) else None
            if not m:
                continue

            match_text = True
            if query:
                match_text = (
                    query in m.comm.lower() or
                    query in str(m.pid) or
                    query in m.threat_name.lower() or
                    query in m.mitre_id.lower()
                )

            match_sev = True
            if sev_mode == "CRITICAL Only":
                match_sev = (m.severity == "CRITICAL")
            elif sev_mode == "HIGH & CRITICAL":
                match_sev = (m.severity in ("CRITICAL", "HIGH"))
            elif sev_mode == "MEDIUM & Above":
                match_sev = True

            self.table.setRowHidden(r, not (match_text and match_sev))

    def _isolate_selected_process(self):
        if not self._current_selected_marker or self._current_selected_marker.pid <= 0:
            QMessageBox.information(self, "Process Containment", "Please select a threat incident from the table.")
            return

        m = self._current_selected_marker
        reply = QMessageBox.question(
            self,
            "Confirm Process Suspension",
            f"Emergency Incident Response Directive:\n\nSend SIGSTOP to suspend PID {m.pid} ({m.comm})?\nThis halts process execution instantly without losing RAM forensics.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            import os, signal
            try:
                os.kill(m.pid, signal.SIGSTOP)
                QMessageBox.information(self, "Process Suspended", f"PID {m.pid} ({m.comm}) suspended successfully with SIGSTOP.")
            except ProcessLookupError:
                QMessageBox.warning(self, "Process Inactive", f"PID {m.pid} has already terminated.")
            except PermissionError:
                QMessageBox.critical(self, "Permission Denied", f"Root privileges required to isolate PID {m.pid}.\nExecute manually: sudo kill -STOP {m.pid}")

    def _kill_selected_process(self):
        if not self._current_selected_marker or self._current_selected_marker.pid <= 0:
            QMessageBox.information(self, "Process Termination", "Please select a threat incident from the table.")
            return

        m = self._current_selected_marker
        reply = QMessageBox.question(
            self,
            "Confirm Process Termination",
            f"Emergency Incident Response Directive:\n\nSend SIGKILL (-9) to terminate PID {m.pid} ({m.comm}) immediately?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            import os, signal
            try:
                os.kill(m.pid, signal.SIGKILL)
                QMessageBox.information(self, "Process Terminated", f"PID {m.pid} ({m.comm}) terminated with SIGKILL.")
            except ProcessLookupError:
                QMessageBox.warning(self, "Process Inactive", f"PID {m.pid} has already terminated.")
            except PermissionError:
                QMessageBox.critical(self, "Permission Denied", f"Root privileges required to kill PID {m.pid}.\nExecute manually: sudo kill -9 {m.pid}")

    def _filter_main_view_to_pid(self):
        if self._current_selected_marker and self._current_selected_marker.pid > 0:
            pid = self._current_selected_marker.pid
            self.filterMainViewRequested.emit(f"proc.pid == {pid}")

    def clear_feed(self):
        self._markers.clear()
        self.scrubber.clear()
        self.table.setRowCount(0)
        self.lbl_count.setText("Threats Logged: 0")
        self._current_selected_marker = None
        self.triage_text.clear()

