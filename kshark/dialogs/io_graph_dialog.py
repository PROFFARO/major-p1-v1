"""
KShark IO Graph Dialog — Enterprise System Call, Network & Threat Analytics Visualizer.
Direct implementation of Wireshark/Stratoshark IO Graph subsystem with multi-series real-time plotting,
customizable display filters, interval bucketing, statistical KPI cards, and CSV/image export.
"""

import os
import time
import math
import collections
from typing import List, Dict, Any, Optional

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QCheckBox, QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QMessageBox, QTabWidget, QWidget, QSplitter, QColorDialog
)
from PyQt6.QtGui import (
    QPainter, QPen, QColor, QBrush, QPolygonF, QFont, QLinearGradient,
    QPainterPath, QPixmap
)
from PyQt6.QtCore import Qt, QPointF, QTimer, QRectF, pyqtSignal

from kshark.core.theme import ThemeManager, get_monospace_font, get_ui_font
from kshark.core.filter_engine import compile_filter
from kshark.core.syscall_table import resolve_syscall_name


class GraphSeriesConfig:
    """Configuration and telemetry buffer for a single IO Graph curve."""

    def __init__(self, name: str, color_hex: str, dfilter: str = "", calc_mode: str = "Events/s", enabled: bool = True):
        self.name = name
        self.color_hex = color_hex
        self.dfilter = dfilter
        self.calc_mode = calc_mode  # "Events/s", "COUNT", "Threats", "Bytes/s"
        self.enabled = enabled
        self.points: collections.deque = collections.deque(maxlen=300)
        self._compiled_ast = None
        self._last_dfilter = None
        self.update_ast()

        # Seed with initial baseline points
        for _ in range(60):
            self.points.append(0.0)

    def update_ast(self):
        if self.dfilter != self._last_dfilter:
            self._last_dfilter = self.dfilter
            self._compiled_ast = compile_filter(self.dfilter) if self.dfilter.strip() else None

    def matches(self, event: Dict[str, Any]) -> bool:
        if not self.dfilter.strip():
            return True
        if self._compiled_ast is None:
            self.update_ast()
        if self._compiled_ast:
            return self._compiled_ast.matches(event)
        return True


class IOGraphCanvas(QFrame):
    """
    High-density interactive multi-series time-series plotting canvas.
    Renders multiple curves, gradient underfills, axis ticks, and hover tooltips.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setMinimumHeight(240)
        self.setMouseTracking(True)

        self.series_list: List[GraphSeriesConfig] = []
        self.interval_sec: float = 1.0
        self.mouse_pos: Optional[QPointF] = None

        self.init_default_series()

    def init_default_series(self):
        self.series_list = [
            GraphSeriesConfig("All Telemetry", "#0E9AA7", "", "Events/s", True),
            GraphSeriesConfig("Threat Spikes", "#E74C3C", "threat.name != 'BENIGN'", "Threats", True),
            GraphSeriesConfig("Process Executions", "#F39C12", "evt.type == 'execve'", "COUNT", False),
            GraphSeriesConfig("Socket Activity", "#2ECC71", "evt.type in ('connect', 'sendto')", "COUNT", False),
            GraphSeriesConfig("Custom Filter", "#9B59B6", "", "Events/s", False),
        ]
        self.update()

    def add_series(self, name: str, color_hex: str, dfilter: str = ""):
        self.series_list.append(GraphSeriesConfig(name, color_hex, dfilter, "Events/s", True))
        self.update()

    def remove_series(self, index: int):
        if 0 <= index < len(self.series_list):
            self.series_list.pop(index)
            self.update()

    def append_series_values(self, values: List[float]):
        for idx, val in enumerate(values):
            if idx < len(self.series_list):
                self.series_list[idx].points.append(val)
        self.update()

    def append_stats_tick(self, total_eps: float, threats_count: float, exec_count: float = 0.0, net_count: float = 0.0, custom_val: float = 0.0):
        if len(self.series_list) >= 5:
            self.series_list[0].points.append(total_eps)
            self.series_list[1].points.append(threats_count)
            self.series_list[2].points.append(exec_count)
            self.series_list[3].points.append(net_count)
            self.series_list[4].points.append(custom_val)
            for s in self.series_list[5:]:
                s.points.append(0.0)
            self.update()
        elif self.series_list:
            self.series_list[0].points.append(total_eps)
            if len(self.series_list) > 1:
                self.series_list[1].points.append(threats_count)
            self.update()

    def mouseMoveEvent(self, event):
        self.mouse_pos = event.position()
        self.update()

    def leaveEvent(self, event):
        self.mouse_pos = None
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        c = ThemeManager.instance().get_palette_colors()

        margin_left = 55
        margin_right = 20
        margin_top = 20
        margin_bottom = 28

        plot_w = max(10, w - margin_left - margin_right)
        plot_h = max(10, h - margin_top - margin_bottom)

        # 1. Backgrounds
        painter.fillRect(0, 0, w, h, QColor(c["bg_base"]))
        painter.fillRect(margin_left, margin_top, plot_w, plot_h, QColor(c["bg_alt"]))

        # Calculate max Y value across all enabled series
        max_y = 10.0
        for s in self.series_list:
            if s.enabled and s.points:
                max_y = max(max_y, max(s.points))
        max_y = math.ceil(max_y * 1.15)
        if max_y < 1.0:
            max_y = 1.0

        # 2. Grid Lines & Axis Labels
        painter.setPen(QPen(QColor(c["border"]), 1, Qt.PenStyle.DotLine))
        painter.setFont(get_monospace_font(size=8))

        # Y-Grid (4 horizontal divisions)
        for i in range(5):
            y_val = (max_y / 4.0) * i
            y_pos = margin_top + plot_h - (i / 4.0) * plot_h
            painter.drawLine(margin_left, int(y_pos), margin_left + plot_w, int(y_pos))

            # Y-Label (avoid overlapping 0 at very bottom)
            painter.setPen(QColor(c["fg_muted"]))
            y_text = f"{y_val:.1f}" if max_y < 100 else f"{int(y_val)}"
            painter.drawText(5, int(y_pos - 6), margin_left - 10, 14, Qt.AlignmentFlag.AlignRight, y_text)
            painter.setPen(QPen(QColor(c["border"]), 1, Qt.PenStyle.DotLine))

        # X-Grid (Vertical time divisions)
        time_steps = 6
        for i in range(time_steps + 1):
            x_pos = margin_left + (i / time_steps) * plot_w
            painter.drawLine(int(x_pos), margin_top, int(x_pos), margin_top + plot_h)

            # X-Label (offset relative to now)
            sec_offset = int((time_steps - i) * 10 * self.interval_sec)
            painter.setPen(QColor(c["fg_muted"]))
            x_label = f"-{sec_offset}s" if sec_offset > 0 else "Now"
            painter.drawText(int(x_pos - 20), margin_top + plot_h + 6, 40, 16, Qt.AlignmentFlag.AlignCenter, x_label)
            painter.setPen(QPen(QColor(c["border"]), 1, Qt.PenStyle.DotLine))

        # 3. Plot Enabled Series Curves
        for s in self.series_list:
            if not s.enabled or len(s.points) < 2:
                continue

            color = QColor(s.color_hex)
            step_x = plot_w / (len(s.points) - 1)

            poly = QPolygonF()
            for idx, val in enumerate(s.points):
                px = margin_left + idx * step_x
                py = margin_top + plot_h - (val / max_y) * plot_h
                poly.append(QPointF(px, py))

            # Gradient Underfill
            grad = QLinearGradient(0, margin_top, 0, margin_top + plot_h)
            grad.setColorAt(0.0, QColor(color.red(), color.green(), color.blue(), 50))
            grad.setColorAt(1.0, QColor(color.red(), color.green(), color.blue(), 4))

            path = QPainterPath()
            path.moveTo(margin_left, margin_top + plot_h)
            for pt in poly:
                path.lineTo(pt)
            path.lineTo(margin_left + plot_w, margin_top + plot_h)
            path.closeSubpath()

            painter.fillPath(path, QBrush(grad))

            # Polyline Stroke
            pen = QPen(color, 2)
            painter.setPen(pen)
            painter.drawPolyline(poly)

        # 4. Hover Inspector Crosshair & Tooltip
        if self.mouse_pos and margin_left <= self.mouse_pos.x() <= margin_left + plot_w and margin_top <= self.mouse_pos.y() <= margin_top + plot_h:
            hx = self.mouse_pos.x()
            painter.setPen(QPen(QColor("#FFFFFF"), 1, Qt.PenStyle.DashLine))
            painter.drawLine(int(hx), margin_top, int(hx), margin_top + plot_h)

            num_pts = len(self.series_list[0].points) if self.series_list else 1
            if num_pts > 1:
                ratio = (hx - margin_left) / plot_w
                pt_idx = min(num_pts - 1, max(0, int(ratio * (num_pts - 1))))

                tooltip_lines = []
                for s in self.series_list:
                    if s.enabled and pt_idx < len(s.points):
                        tooltip_lines.append((s.name, s.color_hex, f"{s.points[pt_idx]:.1f}"))

                if tooltip_lines:
                    painter.setFont(get_monospace_font(size=8))
                    box_w = 190
                    box_h = 14 + len(tooltip_lines) * 18
                    bx = min(w - box_w - 10, max(margin_left + 10, int(hx + 10)))
                    by = margin_top + 10

                    painter.fillRect(bx, by, box_w, box_h, QColor(14, 23, 27, 235))
                    painter.setPen(QPen(QColor(c["border"]), 1))
                    painter.drawRect(bx, by, box_w, box_h)

                    for l_idx, (s_name, s_col, s_val) in enumerate(tooltip_lines):
                        painter.setPen(QColor(s_col))
                        painter.drawText(bx + 8, by + 16 + l_idx * 18, f"● {s_name}:")
                        painter.setPen(QColor("#FFFFFF"))
                        painter.drawText(bx + box_w - 50, by + 16 + l_idx * 18, s_val)

        painter.end()


class KSharkIOGraphDialog(QDialog):
    """
    Enterprise KShark IO Graph & Statistical Analytics Dialog.
    Features:
    - Multi-series real-time time-series graphing canvas with customizable series.
    - Dynamic Add/Remove graph series with interactive color picker.
    - SOC KPI Summary Cards.
    - Syscall & Process distribution analytics breakdown tab.
    - Export to PNG image and CSV statistical report.
    """

    def __init__(self, parent=None, bridge=None, table_model=None):
        super().__init__(parent)
        self.setWindowTitle("KShark · IO Graphs & Statistical Analytics")
        self.resize(920, 640)
        self.bridge = bridge
        self.table_model = table_model
        self._last_event_index = 0

        self._init_ui()
        self._init_timer()

    def _init_ui(self):
        c = ThemeManager.instance().get_palette_colors()
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 10, 12, 10)
        main_layout.setSpacing(8)

        # ── 1. Top Unified Summary Header Bar ──
        self.summary_bar = self._build_summary_bar()
        main_layout.addWidget(self.summary_bar)

        # ── 2. Tabbed Analytical Workspace ──
        self.tabs = QTabWidget(self)
        self.tabs.setFont(get_ui_font(size=8, bold=True))

        # Tab 1: Time-Series IO Curve Plotter
        tab_graph = QWidget()
        graph_layout = QVBoxLayout(tab_graph)
        graph_layout.setContentsMargins(6, 6, 6, 6)
        graph_layout.setSpacing(6)

        self.canvas = IOGraphCanvas(self)
        graph_layout.addWidget(self.canvas, stretch=1)

        # Series Action Bar
        series_bar = QHBoxLayout()
        series_bar.setSpacing(6)

        btn_add = QPushButton("Add Graph", self)
        btn_add.setFont(get_ui_font(size=8))
        btn_add.clicked.connect(self._add_custom_series)
        series_bar.addWidget(btn_add)

        btn_remove = QPushButton("Remove Selected", self)
        btn_remove.setFont(get_ui_font(size=8))
        btn_remove.clicked.connect(self._remove_selected_series)
        series_bar.addWidget(btn_remove)

        btn_reset = QPushButton("Reset Defaults", self)
        btn_reset.setFont(get_ui_font(size=8))
        btn_reset.clicked.connect(self._reset_default_series)
        series_bar.addWidget(btn_reset)

        series_bar.addStretch(1)
        graph_layout.addLayout(series_bar)

        # Series Configuration Table
        self.table = QTableWidget(0, 5, self)
        self.table.setHorizontalHeaderLabels(["Enabled", "Graph Name", "Color", "Display Filter", "Calculation"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setFont(get_ui_font(size=8))
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setMinimumHeight(120)
        self.table.cellChanged.connect(self._on_table_cell_changed)

        self._refresh_series_table()
        graph_layout.addWidget(self.table)

        self.tabs.addTab(tab_graph, "IO Curves & Time-Series")

        # Tab 2: Syscall & Telemetry Distribution
        tab_dist = self._build_distribution_tab()
        self.tabs.addTab(tab_dist, "Syscall & Process Analytics")

        main_layout.addWidget(self.tabs, stretch=1)

        # ── 3. Bottom Control & Export Bar ──
        ctrl_bar = QHBoxLayout()
        ctrl_bar.setSpacing(8)

        lbl_interval = QLabel("Interval:", self)
        lbl_interval.setFont(get_ui_font(size=8))
        self.combo_interval = QComboBox(self)
        self.combo_interval.setFont(get_ui_font(size=8))
        self.combo_interval.addItems(["0.1 sec", "0.5 sec", "1 sec", "5 sec", "10 sec"])
        self.combo_interval.setCurrentText("1 sec")
        self.combo_interval.currentTextChanged.connect(self._on_interval_changed)
        ctrl_bar.addWidget(lbl_interval)
        ctrl_bar.addWidget(self.combo_interval)

        ctrl_bar.addSpacing(16)

        btn_export_png = QPushButton("Export Image (PNG)...", self)
        btn_export_png.setFont(get_ui_font(size=8))
        btn_export_png.clicked.connect(self._export_png)
        ctrl_bar.addWidget(btn_export_png)

        btn_export_csv = QPushButton("Export Data (CSV)...", self)
        btn_export_csv.setFont(get_ui_font(size=8))
        btn_export_csv.clicked.connect(self._export_csv)
        ctrl_bar.addWidget(btn_export_csv)

        ctrl_bar.addStretch(1)

        btn_close = QPushButton("Close", self)
        btn_close.setFont(get_ui_font(size=8, bold=True))
        btn_close.setStyleSheet(f"""
            QPushButton {{
                background-color: {c["brand_primary"]};
                color: #FFFFFF;
                border: 1px solid {c["brand_primary"]};
                border-radius: 4px;
                padding: 4px 16px;
            }}
            QPushButton:hover {{
                background-color: #38D3E0;
            }}
        """)
        btn_close.clicked.connect(self.accept)
        ctrl_bar.addWidget(btn_close)

        main_layout.addLayout(ctrl_bar)

    def _build_summary_bar(self) -> QFrame:
        c = ThemeManager.instance().get_palette_colors()
        bar = QFrame(self)
        bar.setFrameShape(QFrame.Shape.StyledPanel)
        bar.setStyleSheet(f"""
            QFrame {{
                background-color: {c["bg_alt"]};
                border: 1px solid {c["border"]};
                border-radius: 3px;
            }}
        """)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(14)

        self.lbl_kpi_peak = QLabel("Peak Rate: 0.0 evt/s", bar)
        self.lbl_kpi_peak.setFont(get_monospace_font(size=8))
        self.lbl_kpi_peak.setStyleSheet(f"color: {c['fg_text']}; border: none; background: transparent;")

        self.lbl_kpi_avg = QLabel("Avg Rate: 0.0 evt/s", bar)
        self.lbl_kpi_avg.setFont(get_monospace_font(size=8))
        self.lbl_kpi_avg.setStyleSheet(f"color: {c['fg_text']}; border: none; background: transparent;")

        self.lbl_kpi_threats = QLabel("Threats: 0", bar)
        self.lbl_kpi_threats.setFont(get_monospace_font(size=8))
        self.lbl_kpi_threats.setStyleSheet(f"color: {c['fg_text']}; border: none; background: transparent;")

        self.lbl_kpi_events = QLabel("Total Events: 0", bar)
        self.lbl_kpi_events.setFont(get_monospace_font(size=8))
        self.lbl_kpi_events.setStyleSheet(f"color: {c['fg_text']}; border: none; background: transparent;")

        sep1 = QLabel("|", bar)
        sep1.setStyleSheet(f"color: {c['border']}; border: none; background: transparent;")
        sep2 = QLabel("|", bar)
        sep2.setStyleSheet(f"color: {c['border']}; border: none; background: transparent;")
        sep3 = QLabel("|", bar)
        sep3.setStyleSheet(f"color: {c['border']}; border: none; background: transparent;")

        layout.addWidget(self.lbl_kpi_peak)
        layout.addWidget(sep1)
        layout.addWidget(self.lbl_kpi_avg)
        layout.addWidget(sep2)
        layout.addWidget(self.lbl_kpi_threats)
        layout.addWidget(sep3)
        layout.addWidget(self.lbl_kpi_events)
        layout.addStretch(1)
        return bar


    def _build_distribution_tab(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        # Left: Top System Calls Breakdown Table
        left_box = QFrame(widget)
        left_box.setFrameShape(QFrame.Shape.StyledPanel)
        left_layout = QVBoxLayout(left_box)
        left_layout.setContentsMargins(6, 6, 6, 6)

        lbl_sc_title = QLabel("<b>Top System Calls Distribution</b>", left_box)
        lbl_sc_title.setFont(get_ui_font(size=8))
        left_layout.addWidget(lbl_sc_title)

        self.table_syscalls = QTableWidget(0, 3, left_box)
        self.table_syscalls.setHorizontalHeaderLabels(["Syscall", "Count", "% Share"])
        self.table_syscalls.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table_syscalls.verticalHeader().setVisible(False)
        self.table_syscalls.setFont(get_monospace_font(size=8))
        left_layout.addWidget(self.table_syscalls)

        layout.addWidget(left_box, stretch=1)

        # Right: Top Active Processes Breakdown Table
        right_box = QFrame(widget)
        right_box.setFrameShape(QFrame.Shape.StyledPanel)
        right_layout = QVBoxLayout(right_box)
        right_layout.setContentsMargins(6, 6, 6, 6)

        lbl_proc_title = QLabel("<b>Top Active Processes & Threats</b>", right_box)
        lbl_proc_title.setFont(get_ui_font(size=8))
        right_layout.addWidget(lbl_proc_title)

        self.table_procs = QTableWidget(0, 3, right_box)
        self.table_procs.setHorizontalHeaderLabels(["Process (Comm)", "PID", "Events"])
        self.table_procs.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table_procs.verticalHeader().setVisible(False)
        self.table_procs.setFont(get_monospace_font(size=8))
        right_layout.addWidget(self.table_procs)

        layout.addWidget(right_box, stretch=1)
        return widget

    def _refresh_series_table(self):
        self.table.blockSignals(True)
        self.table.setRowCount(len(self.canvas.series_list))

        for row, s in enumerate(self.canvas.series_list):
            # Column 0: Checkbox
            chk = QCheckBox(self)
            chk.setChecked(s.enabled)
            chk.setStyleSheet("margin-left: 12px;")
            chk.toggled.connect(lambda checked, r=row: self._on_series_toggled(r, checked))
            self.table.setCellWidget(row, 0, chk)

            # Column 1: Name
            item_name = QTableWidgetItem(s.name)
            item_name.setFont(get_ui_font(size=8))

            # Column 2: Clickable Color Picker Button
            btn_col = QPushButton(f"  ● {s.color_hex}  ", self)
            btn_col.setFont(get_monospace_font(size=8, bold=True))
            btn_col.setStyleSheet(f"""
                QPushButton {{
                    background-color: {s.color_hex};
                    color: #FFFFFF;
                    border: 1px solid #1A2B32;
                    border-radius: 3px;
                    padding: 2px 6px;
                }}
            """)
            btn_col.clicked.connect(lambda _, r=row: self._pick_series_color(r))
            self.table.setCellWidget(row, 2, btn_col)

            # Column 3: Display Filter
            item_filter = QTableWidgetItem(s.dfilter)
            item_filter.setFont(get_monospace_font(size=8))

            # Column 4: Calculation Mode
            combo_calc = QComboBox(self)
            combo_calc.setFont(get_ui_font(size=8))
            combo_calc.addItems(["Events/s", "COUNT", "Threats", "Bytes/s"])
            combo_calc.setCurrentText(s.calc_mode)
            combo_calc.currentTextChanged.connect(lambda text, r=row: self._on_calc_mode_changed(r, text))
            self.table.setCellWidget(row, 4, combo_calc)

            self.table.setItem(row, 1, item_name)
            self.table.setItem(row, 3, item_filter)
            self.table.setRowHeight(row, 28)

        self.table.blockSignals(False)

    def _on_table_cell_changed(self, row: int, col: int):
        if 0 <= row < len(self.canvas.series_list):
            s = self.canvas.series_list[row]
            item = self.table.item(row, col)
            if item:
                if col == 1:
                    s.name = item.text().strip()
                elif col == 3:
                    s.dfilter = item.text().strip()
                    s.update_ast()
            self.canvas.update()

    def _on_series_toggled(self, row: int, checked: bool):
        if 0 <= row < len(self.canvas.series_list):
            self.canvas.series_list[row].enabled = checked
            self.canvas.update()

    def _pick_series_color(self, row: int):
        if 0 <= row < len(self.canvas.series_list):
            s = self.canvas.series_list[row]
            init_col = QColor(s.color_hex)
            col = QColorDialog.getColor(init_col, self, f"Pick Color for {s.name}")
            if col.isValid():
                s.color_hex = col.name().upper()
                self._refresh_series_table()
                self.canvas.update()

    def _on_calc_mode_changed(self, row: int, text: str):
        if 0 <= row < len(self.canvas.series_list):
            self.canvas.series_list[row].calc_mode = text

    def _add_custom_series(self):
        palette_picks = ["#3498DB", "#E67E22", "#1ABC9C", "#E91E63", "#00BCD4"]
        idx = len(self.canvas.series_list)
        col = palette_picks[idx % len(palette_picks)]
        self.canvas.add_series(f"Custom Series {idx + 1}", col, "")
        self._refresh_series_table()

    def _remove_selected_series(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if selected_rows:
            row_idx = selected_rows[0].row()
            if len(self.canvas.series_list) > 1:
                self.canvas.remove_series(row_idx)
                self._refresh_series_table()

    def _reset_default_series(self):
        self.canvas.init_default_series()
        self._refresh_series_table()

    def _on_interval_changed(self, text: str):
        sec_map = {"0.1 sec": 0.1, "0.5 sec": 0.5, "1 sec": 1.0, "5 sec": 5.0, "10 sec": 10.0}
        ms_map = {"0.1 sec": 100, "0.5 sec": 500, "1 sec": 1000, "5 sec": 5000, "10 sec": 10000}
        self.canvas.interval_sec = sec_map.get(text, 1.0)
        ms = ms_map.get(text, 1000)
        if hasattr(self, "update_timer") and self.update_timer.isActive():
            self.update_timer.setInterval(ms)
        self.canvas.update()

    def _init_timer(self):
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._on_timer_tick)
        self.update_timer.start(1000)

    def _on_timer_tick(self):
        events = []
        if self.table_model and hasattr(self.table_model, "_events"):
            events = self.table_model._events
        elif self.bridge and hasattr(self.bridge, "_events"):
            events = self.bridge._events

        total_evts = len(events)
        if self._last_event_index > total_evts:
            self._last_event_index = 0

        new_events = events[self._last_event_index:]
        self._last_event_index = total_evts

        interval = max(0.001, self.canvas.interval_sec)

        # Calculate values for each series based on its filter and calc_mode
        series_vals = []
        for s in self.canvas.series_list:
            s.update_ast()
            matching = [ev for ev in new_events if s.matches(ev)]
            if s.calc_mode == "Events/s":
                val = len(matching) / interval
            elif s.calc_mode == "COUNT":
                val = float(len(matching))
            elif s.calc_mode == "Threats":
                val = float(sum(1 for ev in matching if str(ev.get("threat_name") or ev.get("agreed_threat") or "BENIGN") not in ("BENIGN", "", "NONE")))
            elif s.calc_mode == "Bytes/s":
                val = float(sum(int(ev.get("bytes", 0) or ev.get("len", 0) or ev.get("ret", 0) or 0) for ev in matching)) / interval
            else:
                val = len(matching) / interval
            series_vals.append(val)

        self.canvas.append_series_values(series_vals)

        # KPI Metrics
        primary_points = list(self.canvas.series_list[0].points) if self.canvas.series_list else [0.0]
        max_rate = max(primary_points) if primary_points else 0.0
        non_zero_pts = [p for p in primary_points if p > 0.0]
        avg_rate = (sum(non_zero_pts) / len(non_zero_pts)) if non_zero_pts else (primary_points[-1] if primary_points else 0.0)

        threats_count = 0
        if self.table_model and hasattr(self.table_model, "threat_count"):
            threats_count = self.table_model.threat_count
        elif self.bridge and hasattr(self.bridge, "_threat_count"):
            threats_count = self.bridge._threat_count

        self.lbl_kpi_peak.setText(f"Peak Rate: {max_rate:.1f} evt/s")
        self.lbl_kpi_avg.setText(f"Avg Rate: {avg_rate:.1f} evt/s")
        if int(threats_count) > 0:
            self.lbl_kpi_threats.setText(f"Threats: {int(threats_count)} [ACTIVE]")
            self.lbl_kpi_threats.setStyleSheet("color: #F05252; font-weight: bold; border: none; background: transparent;")
        else:
            self.lbl_kpi_threats.setText("Threats: 0")
            c = ThemeManager.instance().get_palette_colors()
            self.lbl_kpi_threats.setStyleSheet(f"color: {c['fg_text']}; border: none; background: transparent;")
        self.lbl_kpi_events.setText(f"Total Events: {total_evts:,}")

        # Update Distribution Tables
        self._update_distribution_tables()

    def _update_distribution_tables(self):
        if not self.table_model or not hasattr(self.table_model, "_events"):
            return

        events = self.table_model._events
        if not events:
            return

        # 1. Syscall Frequencies (evaluated across telemetry with proper resolution)
        sc_counts = collections.Counter()
        proc_counts = collections.Counter()

        for ev in events:
            sc = resolve_syscall_name(ev)
            comm = ev.get("comm") or ev.get("proc_name") or "unknown"
            pid = ev.get("pid", 0)
            sc_counts[sc] += 1
            proc_counts[(comm, pid)] += 1

        total_sc = sum(sc_counts.values()) or 1
        top_sc = sc_counts.most_common(12)

        self.table_syscalls.setRowCount(len(top_sc))
        for r, (sc_name, count) in enumerate(top_sc):
            self.table_syscalls.setItem(r, 0, QTableWidgetItem(str(sc_name)))
            self.table_syscalls.setItem(r, 1, QTableWidgetItem(f"{count:,}"))
            self.table_syscalls.setItem(r, 2, QTableWidgetItem(f"{count / total_sc:.1%}"))
            self.table_syscalls.setRowHeight(r, 24)

        # 2. Process Frequencies
        top_procs = proc_counts.most_common(12)
        self.table_procs.setRowCount(len(top_procs))
        for r, ((comm, pid), count) in enumerate(top_procs):
            self.table_procs.setItem(r, 0, QTableWidgetItem(str(comm)))
            self.table_procs.setItem(r, 1, QTableWidgetItem(str(pid)))
            self.table_procs.setItem(r, 2, QTableWidgetItem(f"{count:,}"))
            self.table_procs.setRowHeight(r, 24)

    def _export_png(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export IO Graph as Image", "kshark_io_graph.png", "PNG Images (*.png)")
        if path:
            pixmap = self.canvas.grab()
            pixmap.save(path, "PNG")
            QMessageBox.information(self, "Export Successful", f"Graph exported successfully to:\n{path}")

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export IO Graph Data", "kshark_io_graph.csv", "CSV Files (*.csv)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    headers = [s.name for s in self.canvas.series_list]
                    f.write("TimeIndex," + ",".join(headers) + "\n")
                    num_pts = len(self.canvas.series_list[0].points) if self.canvas.series_list else 0
                    for i in range(num_pts):
                        vals = [str(round(s.points[i], 2)) for s in self.canvas.series_list]
                        f.write(f"{i}," + ",".join(vals) + "\n")
                QMessageBox.information(self, "Export Successful", f"IO Graph data exported to:\n{path}")
            except Exception as e:
                QMessageBox.warning(self, "Export Failed", f"Could not save CSV file: {e}")
