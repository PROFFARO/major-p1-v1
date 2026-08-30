"""
KShark Main Window — Direct Port & Implementation of KShark Desktop Architecture.
Integrated with real Linux OS telemetry, kernel eBPF probes, Dual ML Threat Engine, and DuckDB storage.
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QStackedWidget,
    QTableView, QTreeView, QHeaderView, QFileDialog, QMessageBox, QMenu, QToolBar
)
from PyQt6.QtGui import QAction, QKeySequence, QIcon, QBrush, QColor
from PyQt6.QtCore import Qt, QModelIndex, QByteArray, QTimer

from typing import Optional, Dict, Any
import os
import threading
import time

from kshark.core.theme import ThemeManager, get_monospace_font
from kshark.core.settings import KSharkSettings
from kshark.core.backend_bridge import BackendBridge
from kshark.models.event_table_model import EventTableModel
from kshark.models.event_proxy_model import EventFilterProxyModel
from kshark.models.detail_tree_model import DetailTreeModel
from kshark.widgets.main_toolbar import MainToolBar
from kshark.widgets.display_filter_entry import DisplayFilterEntry
from kshark.widgets.main_status_bar import MainStatusBar
from kshark.widgets.event_byte_view import EventByteView
from kshark.widgets.welcome_page import WelcomePage
from kshark.widgets.search_frame import KSharkSearchFrame
from kshark.widgets.accordion_frame import GoToFrame
from kshark.docks.copilot_dock import CopilotDock
from kshark.docks.threat_timeline_dock import ThreatTimelineDock, SubsystemStatusDock
from kshark.dialogs.preferences_dialog import PreferencesDialog
from kshark.dialogs.coloring_rules_dialog import ColoringRulesDialog
from kshark.dialogs.sql_console_dialog import SQLConsoleDialog
from kshark.dialogs.about_dialog import AboutDialog
from kshark.dialogs.io_graph_dialog import KSharkIOGraphDialog
from kshark.dialogs.plot_dialog import KSharkPlotDialog
from kshark.dialogs.capture_options_dialog import CaptureOptionsDialog
from kshark.dialogs.threat_forensics_dialog import ThreatForensicsDialog
from kshark.dialogs.byte_hasher_dialog import ByteHasherDialog
from kshark.resources.icons import KSharkIcons





class KSharkMainWindow(QMainWindow):
    """
    Main Window for KShark eBPF & Kernel Threat Analyzer.
    """

    def __init__(self):
        super().__init__()
        is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        mode_str = " [Root / Privileged Mode]" if is_root else " [Unprivileged User Mode]"
        self.setWindowTitle(f"KShark · System Call & Kernel Observability Analyzer{mode_str}")
        self.setWindowIcon(KSharkIcons.get_app_icon())
        self.resize(1340, 860)


        self.settings = KSharkSettings()
        self.bridge = BackendBridge(self)

        self.auto_scroll = True
        self.is_capturing = False
        self._zoom_level = 9
        self._current_file_path = ""

        self._init_models()

        self._init_ui()
        self._init_menus()
        self._init_docks()
        self._wire_signals()
        self._restore_state()

    def _init_models(self):
        self.table_model = EventTableModel(self)
        self.proxy_model = EventFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.table_model)
        self.detail_tree_model = DetailTreeModel(self)

    def _init_ui(self):
        # 1. Main Action Toolbar (Top Row)
        self.toolbar = MainToolBar(self)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, self.toolbar)

        # Dedicated Row 2 for Display Filter
        self.addToolBarBreak(Qt.ToolBarArea.TopToolBarArea)
        self.filter_toolbar = QToolBar("Display Filter", self)
        self.filter_toolbar.setObjectName("displayFilterToolBar")
        self.filter_toolbar.setMovable(False)
        self.filter_bar = DisplayFilterEntry(self)
        self.filter_toolbar.addWidget(self.filter_bar)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, self.filter_toolbar)

        # Central Widget & Master Stack
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        self.central_layout = QVBoxLayout(self.central_widget)
        self.central_layout.setContentsMargins(0, 0, 0, 0)
        self.central_layout.setSpacing(0)

        # Accordion Frames (Go to & Search)
        self.goto_frame = GoToFrame(self)
        self.goto_frame.hide()
        self.central_layout.addWidget(self.goto_frame)

        self.search_frame = KSharkSearchFrame(self)
        self.search_frame.hide()
        self.central_layout.addWidget(self.search_frame)

        # Master Stack (View 0: Welcome Page | View 1: 3-Pane Capture)
        self.master_stack = QStackedWidget(self)
        self.central_layout.addWidget(self.master_stack, stretch=1)

        # View 0: Welcome Page
        self.welcome_page = WelcomePage(self)
        self.master_stack.addWidget(self.welcome_page)

        # View 1: 3-Pane Capture Container
        self.capture_container = QWidget(self)
        cap_layout = QVBoxLayout(self.capture_container)
        cap_layout.setContentsMargins(0, 0, 0, 0)
        cap_layout.setSpacing(0)

        # Master Vertical Splitter (Top: Event List | Bottom: Horizontal Splitter)
        self.master_splitter = QSplitter(Qt.Orientation.Vertical, self)
        self.master_splitter.setObjectName("masterSplitter")
        self.master_splitter.setChildrenCollapsible(False)

        # Pane 1: Event List View (QTableView)
        self.event_list_view = QTableView(self)
        self.event_list_view.setObjectName("eventListView")
        self.event_list_view.setModel(self.proxy_model)
        self.event_list_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.event_list_view.setSelectionMode(QTableView.SelectionMode.ExtendedSelection)
        self.event_list_view.setAlternatingRowColors(True)
        self.event_list_view.setSortingEnabled(True)
        self.event_list_view.setShowGrid(False)
        self.event_list_view.verticalHeader().setVisible(False)
        self.event_list_view.verticalHeader().setDefaultSectionSize(20)
        self.event_list_view.setWordWrap(False)
        self.event_list_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.event_list_view.customContextMenuRequested.connect(self._show_event_context_menu)

        for col_idx, (col_name, default_w) in enumerate(EventTableModel.COLUMNS):
            self.event_list_view.setColumnWidth(col_idx, default_w)

        self.master_splitter.addWidget(self.event_list_view)

        # Bottom Horizontal Splitter (Pane 2: Details Tree | Pane 3: Hex/ASCII View)
        self.bottom_splitter = QSplitter(Qt.Orientation.Horizontal, self)
        self.bottom_splitter.setObjectName("bottomSplitter")
        self.bottom_splitter.setChildrenCollapsible(False)

        # Pane 2: Event Details Tree (QTreeView)
        self.detail_tree_view = QTreeView(self)
        self.detail_tree_view.setObjectName("detailTreeView")
        self.detail_tree_view.setModel(self.detail_tree_model)
        self.detail_tree_view.setHeaderHidden(False)
        self.detail_tree_view.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.detail_tree_view.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.detail_tree_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.detail_tree_view.customContextMenuRequested.connect(self._show_tree_context_menu)
        self.bottom_splitter.addWidget(self.detail_tree_view)

        # Pane 3: Event Bytes View (Hex Dump + ASCII + JSON + C-Array + Base64)
        self.byte_view = EventByteView(self)
        self.bottom_splitter.addWidget(self.byte_view)



        self.master_splitter.addWidget(self.bottom_splitter)
        cap_layout.addWidget(self.master_splitter, stretch=1)

        self.master_stack.addWidget(self.capture_container)
        self.master_stack.setCurrentIndex(0)

        # Status Bar
        self.status_bar = MainStatusBar(self)
        self.setStatusBar(self.status_bar)

    def _init_menus(self):
        menubar = self.menuBar()

        def add_act(menu, text, slot=None, shortcut_str=None):
            act = menu.addAction(text)
            if shortcut_str:
                act.setShortcut(QKeySequence(shortcut_str))
            if slot:
                act.triggered.connect(slot)
            return act

        # File Menu
        m_file = menubar.addMenu("&File")
        add_act(m_file, "&Open...", self._action_open_file, "Ctrl+O")
        add_act(m_file, "&Save As...", self._action_save_file, "Ctrl+S")
        add_act(m_file, "&Close", self._action_close_capture, "Ctrl+W")
        m_file.addSeparator()
        add_act(m_file, "E&xit", self.close, "Ctrl+Q")

        # Edit Menu
        m_edit = menubar.addMenu("&Edit")
        add_act(m_edit, "&Find Event...", self._action_find, "Ctrl+F")
        add_act(m_edit, "&Mark/Unmark Event", self._action_toggle_mark, "Ctrl+M")
        add_act(m_edit, "Set &Time Reference", self._action_toggle_time_ref, "Ctrl+T")
        m_edit.addSeparator()
        add_act(m_edit, "&Preferences...", self._action_open_preferences, "Ctrl+Shift+P")

        # View Menu
        m_view = menubar.addMenu("&View")
        add_act(m_view, "Colorize &Event List", self._action_toggle_colorize)
        add_act(m_view, "&Coloring Rules...", self._action_open_coloring_rules)
        
        m_view_color = m_view.addMenu("Colorize &Conversation")
        colors = [
            ("Color 1 (Amber)", "#FFC107"),
            ("Color 2 (Cyan)", "#00BCD4"),
            ("Color 3 (Purple)", "#9C27B0"),
            ("Color 4 (Green)", "#4CAF50"),
            ("Color 5 (Orange)", "#FF5722"),
            ("Color 6 (Pink)", "#E91E63"),
            ("Color 7 (Teal)", "#009688"),
            ("Color 8 (Lime)", "#CDDC39"),
            ("Color 9 (Magenta)", "#FF007F"),
            ("Color 10 (Blue)", "#2196F3"),
        ]
        for c_idx, (c_name, c_hex) in enumerate(colors, 1):
            m_view_color.addAction(f"Color {c_idx} ({c_hex})", lambda idx=c_idx: self._colorize_selected_row(idx))
        m_view_color.addSeparator()
        m_view_color.addAction("Reset Colorization", self._reset_selected_row_color)

        m_view.addSeparator()
        add_act(m_view, "Zoom &In", self._action_zoom_in, "Ctrl++")
        add_act(m_view, "Zoom &Out", self._action_zoom_out, "Ctrl+-")
        add_act(m_view, "Normal &Size", self._action_zoom_100, "Ctrl+0")
        add_act(m_view, "Resize All &Columns", self._action_resize_columns, "Shift+Ctrl+R")


        # Go Menu
        m_go = menubar.addMenu("&Go")
        add_act(m_go, "&Go to Event...", self._action_goto_event, "Ctrl+G")
        add_act(m_go, "&Next Event", self._go_next_row, "Ctrl+Down")
        add_act(m_go, "&Previous Event", self._go_prev_row, "Ctrl+Up")
        add_act(m_go, "&First Event", self._go_first_row, "Ctrl+Home")
        add_act(m_go, "&Last Event", self._go_last_row, "Ctrl+End")

        # Capture Menu
        m_cap = menubar.addMenu("&Capture")
        add_act(m_cap, "&Start", self.start_capture, "Ctrl+E")
        add_act(m_cap, "S&top", self.stop_capture, "Ctrl+E")
        add_act(m_cap, "&Restart", self.restart_capture, "Ctrl+R")



        # Statistics Menu
        m_stat = menubar.addMenu("&Statistics")
        add_act(m_stat, "&IO Graphs", self._action_open_io_graphs)
        add_act(m_stat, "&Plot Distribution", self._action_open_plot_dialog)
        add_act(m_stat, "&DuckDB SQL Analytics...", self._action_open_sql_console)

        # Help Menu
        m_help = menubar.addMenu("&Help")
        add_act(m_help, "&About KShark", self._action_open_about)

    def _init_docks(self):
        self.dock_copilot = CopilotDock(self)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.dock_copilot)
        self.dock_copilot.hide()

        self.dock_timeline = ThreatTimelineDock(self)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.dock_timeline)
        self.dock_timeline.hide()

        self.dock_subsystems = SubsystemStatusDock(self)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self.dock_subsystems)
        self.dock_subsystems.hide()

    def _wire_signals(self):
        # Bridge -> UI
        self.bridge.eventReceived.connect(self._handle_live_event)
        self.bridge.threatDetected.connect(self._handle_threat_detected)
        self.bridge.statsUpdated.connect(self._handle_stats_updated)
        self.bridge.copilotResponseReceived.connect(self.dock_copilot.append_copilot_response)

        # Live batch flush timer (50ms batching)
        self._live_event_buffer = []
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(50)
        self._flush_timer.timeout.connect(self._flush_live_events)
        self._flush_timer.start()

        # Toolbar Actions
        self.toolbar.startCaptureTriggered.connect(self.start_capture)
        self.toolbar.stopCaptureTriggered.connect(self.stop_capture)
        self.toolbar.restartCaptureTriggered.connect(self.restart_capture)
        self.toolbar.captureOptionsTriggered.connect(self._action_open_capture_options)

        self.toolbar.openFileTriggered.connect(self._action_open_file)
        self.toolbar.saveFileTriggered.connect(self._action_save_file)
        self.toolbar.closeFileTriggered.connect(self._action_close_capture)
        self.toolbar.reloadFileTriggered.connect(self._action_reload_file)

        self.toolbar.findTriggered.connect(self._action_find)
        self.toolbar.goPrevTriggered.connect(self._go_prev_row)
        self.toolbar.goNextTriggered.connect(self._go_next_row)
        self.toolbar.goFirstTriggered.connect(self._go_first_row)
        self.toolbar.goLastTriggered.connect(self._go_last_row)

        self.toolbar.autoScrollToggled.connect(self._set_autoscroll)
        self.toolbar.colorizeToggled.connect(self.table_model.set_colorize)

        self.toolbar.zoomInTriggered.connect(self._action_zoom_in)
        self.toolbar.zoomOutTriggered.connect(self._action_zoom_out)
        self.toolbar.zoom100Triggered.connect(self._action_zoom_100)
        self.toolbar.resizeColumnsTriggered.connect(self._action_resize_columns)


        # Display Filter Bar -> Proxy Model
        self.filter_bar.filterApplied.connect(self._on_filter_applied)
        self.proxy_model.filterStatsChanged.connect(self._on_filter_stats_changed)


        # Event List Selection -> Detail Tree & Byte View
        self.event_list_view.selectionModel().selectionChanged.connect(self._on_event_row_selected)
        self.event_list_view.verticalScrollBar().sliderMoved.connect(self._on_user_scrollbar_moved)

        # Search & GoTo Frames
        self.goto_frame.goToEventTriggered.connect(self._select_event_number)
        self.search_frame.findTriggered.connect(self._execute_search)

        # Welcome Page Signals
        self.welcome_page.startCaptureOnProbe.connect(self.start_capture)
        self.dock_copilot.copilotQuerySubmitted.connect(self.bridge.query_copilot)

    def _on_user_scrollbar_moved(self, value: int):
        sb = self.event_list_view.verticalScrollBar()
        if value < sb.maximum() - 4:
            if self.auto_scroll:
                self.auto_scroll = False
                self.toolbar.act_autoscroll.setChecked(False)
        elif value >= sb.maximum() - 2:
            if not self.auto_scroll:
                self.auto_scroll = True
                self.toolbar.act_autoscroll.setChecked(True)

    def _restore_state(self):
        geom = self.settings.get_window_geometry()
        if geom:
            self.restoreGeometry(geom)

        ms_state = self.settings.get_master_splitter_state()
        if ms_state:
            self.master_splitter.restoreState(ms_state)
        else:
            self.master_splitter.setSizes([400, 300])

        bs_state = self.settings.get_bottom_splitter_state()
        if bs_state:
            self.bottom_splitter.restoreState(bs_state)
        else:
            self.bottom_splitter.setSizes([350, 450])

    def start_capture(self, probe_name: str = "all"):
        if not isinstance(probe_name, str) or not probe_name:
            probe_name = "all"

        self.master_stack.setCurrentIndex(1)
        self.is_capturing = True
        self.toolbar.set_capturing_state(True)
        self.status_bar.set_status_message(f"Capturing live Linux OS & eBPF telemetry [{probe_name}]...")

        self.master_splitter.setSizes([400, 300])
        self.bottom_splitter.setSizes([350, 450])

        self.bridge.start_capture(self.settings.get_agent_ws_url())

    def stop_capture(self):
        self.is_capturing = False
        self.toolbar.set_capturing_state(False)
        self.status_bar.set_status_message("Capture stopped.")
        self._live_event_buffer.clear()
        self.status_bar.update_stats(self.table_model.rowCount(), self.proxy_model.rowCount(), self.status_bar.threat_count, 0.0)
        self.bridge.stop_capture()



    def restart_capture(self):
        self.table_model.clear()
        self.detail_tree_model.set_event(None)
        self.byte_view.clear()
        self.stop_capture()
        QTimer.singleShot(100, self.start_capture)

    def _action_close_capture(self):
        self.stop_capture()
        self.table_model.clear()
        self.master_stack.setCurrentIndex(0)

    def _handle_live_event(self, event: dict):
        if not self.is_capturing:
            self.table_model.add_events_batch([event])
            total = self.table_model.rowCount()
            displayed = self.proxy_model.rowCount()
            self.status_bar.update_stats(total, displayed, self.status_bar.threat_count, self.status_bar.eps)
            return
        self._live_event_buffer.append(event)


    def _flush_live_events(self):
        if not self._live_event_buffer:
            return

        if not self.is_capturing:
            self._live_event_buffer.clear()
            return

        # Smooth bounded batch insertion (max 25 events per tick to prevent GUI locking)
        batch = self._live_event_buffer[:25]
        self._live_event_buffer = self._live_event_buffer[25:]
        self.table_model.add_events_batch(batch)


        if self.auto_scroll and self.master_stack.currentIndex() == 1:
            self.event_list_view.scrollToBottom()

        total = self.table_model.rowCount()
        displayed = self.proxy_model.rowCount()
        threats = self.table_model.threat_count
        self.status_bar.update_stats(total, displayed, threats, self.status_bar.eps)

    def _handle_threat_detected(self, alert: dict):
        self.dock_timeline.record_threat_marker(alert)
        threat_name = alert.get("threat_name") or alert.get("threat_type") or "UNKNOWN"
        pid = alert.get("pid", 0)
        comm = alert.get("comm", "")
        self.status_bar.set_status_message(f"🚨 THREAT DETECTED: {threat_name} on PID {pid} ({comm})", is_error=True)

        if pid > 0:
            self.table_model.mark_pid_threat(pid, threat_name, float(alert.get("confidence", 0.95)))
            if self.proxy_model._filter_ast is not None:
                self.proxy_model.invalidateFilter()
                self.proxy_model.layoutChanged.emit()

    def _handle_stats_updated(self, stats: dict):
        total = self.table_model.rowCount()
        displayed = self.proxy_model.rowCount()
        threats = self.table_model.threat_count
        eps = float(stats.get("events_per_second", self.status_bar.eps))
        self.status_bar.update_stats(total, displayed, threats, eps)

    def _on_filter_applied(self, filter_text: str):
        self.proxy_model.set_display_filter(filter_text)
        self.event_list_view.viewport().update()

    def _on_filter_stats_changed(self, matched: int, total: int, elapsed_ms: float):
        threats = self.table_model.threat_count
        self.status_bar.update_stats(total, matched, threats, self.status_bar.eps)
        if elapsed_ms > 0:
            active_filter = self.filter_bar.entry.text().strip()
            if matched == 0 and total > 0 and active_filter:
                self.status_bar.set_status_message(f"Filter '{active_filter}' matched 0 of {total:,} events. Press ✖ to reset.")
            else:
                self.status_bar.set_status_message(f"Filter matched {matched:,} of {total:,} events ({elapsed_ms:.1f} ms)")



    def _on_event_row_selected(self, selected, deselected):
        indexes = self.event_list_view.selectionModel().selectedRows()
        if not indexes:
            return

        proxy_index = indexes[0]
        event = self.proxy_model.get_event_at_proxy_row(proxy_index.row())

        self.detail_tree_model.set_event(event)
        self.byte_view.set_event_data(event)
        self.detail_tree_view.expandToDepth(1)

    def _select_event_number(self, event_num: int):
        target_row = event_num - 1
        if 0 <= target_row < self.proxy_model.rowCount():
            idx = self.proxy_model.index(target_row, 0)
            self.event_list_view.selectRow(target_row)
            self.event_list_view.scrollTo(idx)

    def _execute_search(self, query: str, stype: str, direction: str, case_sensitive: bool):
        total = self.proxy_model.rowCount()
        if total == 0:
            return

        cur_idx = self.event_list_view.selectionModel().selectedRows()
        start = cur_idx[0].row() if cur_idx else 0
        step = 1 if direction == "down" else -1

        for offset in range(1, total):
            r = (start + offset * step) % total
            ev = self.proxy_model.get_event_at_proxy_row(r)
            if not ev:
                continue

            found = False
            for v in ev.values():
                val_str = str(v) if case_sensitive else str(v).lower()
                q_str = query if case_sensitive else query.lower()
                if q_str in val_str:
                    found = True
                    break

            if found:
                self.event_list_view.selectRow(r)
                self.event_list_view.scrollTo(self.proxy_model.index(r, 0))
                self.status_bar.set_status_message(f"Found match at Event #{r+1}")
                return

        self.status_bar.set_status_message(f"No match found for: '{query}'", is_error=True)

    def _set_autoscroll(self, enabled: bool):
        self.auto_scroll = enabled

    def _go_prev_row(self):
        cur = self.event_list_view.currentIndex().row()
        if cur > 0:
            self.event_list_view.selectRow(cur - 1)

    def _go_next_row(self):
        cur = self.event_list_view.currentIndex().row()
        if cur < self.proxy_model.rowCount() - 1:
            self.event_list_view.selectRow(cur + 1)

    def _go_first_row(self):
        if self.proxy_model.rowCount() > 0:
            self.event_list_view.selectRow(0)
            self.event_list_view.scrollToTop()

    def _go_last_row(self):
        cnt = self.proxy_model.rowCount()
        if cnt > 0:
            self.event_list_view.selectRow(cnt - 1)
            self.event_list_view.scrollToBottom()

    def _action_find(self):
        self.search_frame.setVisible(not self.search_frame.isVisible())
        if self.search_frame.isVisible():
            self.search_frame.search_input.setFocus()

    def _action_goto_event(self):
        self.goto_frame.setVisible(not self.goto_frame.isVisible())
        if self.goto_frame.isVisible():
            self.goto_frame.input_field.setFocus()

    def _action_toggle_mark(self):
        cur = self.event_list_view.currentIndex().row()
        if cur >= 0:
            src = self.proxy_model.mapToSource(self.proxy_model.index(cur, 0)).row()
            self.table_model.toggle_mark_row(src)

    def _action_toggle_time_ref(self):
        cur = self.event_list_view.currentIndex().row()
        if cur >= 0:
            src = self.proxy_model.mapToSource(self.proxy_model.index(cur, 0)).row()
            self.table_model.set_time_reference_row(src)

    def _action_toggle_colorize(self):
        self.table_model.set_colorize(not self.table_model.colorize_enabled)

    def _action_open_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open KShark Capture File",
            "",
            "KShark Telemetry (*.jsonl *.json *.duckdb *.db *.csv);;All Files (*)"
        )
        if not path:
            return

        self._current_file_path = path


        self.stop_capture()
        self.table_model.clear()
        self.detail_tree_model.set_event(None)
        self.byte_view.clear()

        loaded_events = []
        try:
            if path.endswith(".jsonl"):
                import json
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            loaded_events.append(json.loads(line))
            elif path.endswith(".json"):
                import json
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        loaded_events = data
                    elif isinstance(data, dict):
                        loaded_events = [data]
            elif path.endswith(".duckdb") or path.endswith(".db"):
                import duckdb
                conn = duckdb.connect(path)
                df = conn.execute("SELECT * FROM telemetry_events").df()
                loaded_events = df.to_dict(orient="records")
                conn.close()
            elif path.endswith(".csv"):
                import csv
                with open(path, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        loaded_events.append(row)

            if loaded_events:
                self.table_model.add_events_batch(loaded_events)
                self.master_stack.setCurrentIndex(1)
                self.status_bar.set_status_message(f"Loaded {len(loaded_events):,} events from {os.path.basename(path)}")
                QMessageBox.information(self, "Capture Loaded", f"Successfully loaded {len(loaded_events):,} events from:\n{path}")
            else:
                self.status_bar.set_status_message(f"No events found in {path}", is_error=True)
        except Exception as e:
            self.status_bar.set_status_message(f"Open failed: {e}", is_error=True)
            QMessageBox.critical(self, "Open Error", f"Failed to load capture file:\n{e}")

    def _action_save_file(self):
        path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save KShark Capture",
            f"kshark_capture_{int(time.time())}.jsonl",
            "JSON Lines (*.jsonl);;Formatted JSON (*.json);;Comma Separated Values (*.csv);;DuckDB (*.duckdb)"
        )
        if not path:
            return

        events = self.table_model._events
        if not events:
            QMessageBox.information(self, "Save Capture", "No telemetry events to save.")
            return

        try:
            if path.endswith(".jsonl"):
                import json
                with open(path, "w", encoding="utf-8") as f:
                    for ev in events:
                        f.write(json.dumps(ev) + "\n")
            elif path.endswith(".json"):
                import json
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(events, f, indent=2)
            elif path.endswith(".csv"):
                import csv
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([c[0] for c in EventTableModel.COLUMNS])
                    for row_idx in range(len(events)):
                        row_vals = [self.table_model.data(self.table_model.index(row_idx, col), Qt.ItemDataRole.DisplayRole) for col in range(len(EventTableModel.COLUMNS))]
                        writer.writerow(row_vals)
            elif path.endswith(".duckdb") or path.endswith(".db"):
                import duckdb
                import pandas as pd
                df = pd.DataFrame(events)
                conn = duckdb.connect(path)
                conn.execute("CREATE OR REPLACE TABLE telemetry_events AS SELECT * FROM df")
                conn.close()

            self.status_bar.set_status_message(f"Successfully saved {len(events):,} events to {path}")
            QMessageBox.information(self, "Save Successful", f"Saved {len(events):,} events to:\n{path}")
        except Exception as e:
            self.status_bar.set_status_message(f"Save failed: {e}", is_error=True)
            QMessageBox.critical(self, "Save Error", f"Failed to save capture:\n{e}")


    def _action_open_preferences(self):
        dlg = PreferencesDialog(self)
        dlg.exec()

    def _action_open_coloring_rules(self):
        dlg = ColoringRulesDialog(self)
        dlg.exec()

    def _action_open_io_graphs(self):
        dlg = KSharkIOGraphDialog(self)
        dlg.exec()

    def _action_open_plot_dialog(self):
        dlg = KSharkPlotDialog(self)
        dlg.exec()

    def _action_open_sql_console(self):
        dlg = SQLConsoleDialog(self)
        dlg.exec()

    def _action_open_about(self):
        dlg = AboutDialog(self)
        dlg.exec()

    def _action_open_capture_options(self):
        """Opens capture options and interfaces configuration dialog."""
        dlg = CaptureOptionsDialog(self, current_ws_url=self.bridge.ws_url)
        dlg.startCaptureRequested.connect(self._on_capture_options_start)
        dlg.exec()

    def _on_capture_options_start(self, opts: dict):
        """Applies configured capture options and initiates live capture."""
        if opts.get("ws_url"):
            self.bridge.ws_url = opts["ws_url"]
        self.start_capture()

    def _action_reload_file(self):
        """Reloads active capture file or restarts telemetry capture."""
        if hasattr(self, "_current_file_path") and self._current_file_path and os.path.exists(self._current_file_path):
            self._load_capture_from_path(self._current_file_path)
            self.status_bar.set_status_message(f"Reloaded capture file: {os.path.basename(self._current_file_path)}")
        elif self.is_capturing:
            self.restart_capture()
        else:
            self.start_capture()

    def _apply_zoom(self):
        """Applies uniform font scaling across table, tree, and byte view panes."""
        font = get_monospace_font(size=self._zoom_level)
        self.table_model.mono_font = font
        self.table_model.layoutChanged.emit()
        self.event_list_view.setFont(font)
        self.event_list_view.verticalHeader().setDefaultSectionSize(int(self._zoom_level * 2.2))
        self.detail_tree_view.setFont(font)
        self.byte_view.setFont(font)
        pct = int((self._zoom_level / 9.0) * 100)
        self.status_bar.set_status_message(f"Zoom Level: {pct}% ({self._zoom_level} pt)")


    def _action_zoom_in(self):
        if self._zoom_level < 22:
            self._zoom_level += 1
            self._apply_zoom()

    def _action_zoom_out(self):
        if self._zoom_level > 6:
            self._zoom_level -= 1
            self._apply_zoom()

    def _action_zoom_100(self):
        self._zoom_level = 9
        self._apply_zoom()

    def _action_resize_columns(self):
        """Resize all table columns dynamically to fit content."""
        for col in range(self.table_model.columnCount()):
            self.event_list_view.resizeColumnToContents(col)
            if self.event_list_view.columnWidth(col) < 65:
                self.event_list_view.setColumnWidth(col, 65)
        self.status_bar.set_status_message("Resized all columns to fit content.")


    # ─────────────────────────────────────────────────────────
    # Context Menus & Filter Helpers
    # ─────────────────────────────────────────────────────────

    def _apply_filter_expr(self, expr: str, mode: str = "replace"):
        cur = self.filter_bar.entry.text().strip()
        if mode == "replace" or not cur:
            new_expr = expr
        elif mode == "and":
            new_expr = f"({cur}) and ({expr})"
        elif mode == "or":
            new_expr = f"({cur}) or ({expr})"
        elif mode == "and not":
            new_expr = f"({cur}) and not ({expr})"
        elif mode == "or not":
            new_expr = f"({cur}) or not ({expr})"
        else:
            new_expr = expr

        self.filter_bar.set_filter_text(new_expr)

    def _prepare_filter_expr(self, expr: str, mode: str = "replace"):
        cur = self.filter_bar.entry.text().strip()
        if mode == "replace" or not cur:
            new_expr = expr
        elif mode == "and":
            new_expr = f"({cur}) and ({expr})"
        elif mode == "or":
            new_expr = f"({cur}) or ({expr})"
        elif mode == "and not":
            new_expr = f"({cur}) and not ({expr})"
        elif mode == "or not":
            new_expr = f"({cur}) or not ({expr})"
        else:
            new_expr = expr

        self.filter_bar.entry.setText(new_expr)

    def _colorize_selected_row(self, color_idx: int):
        indexes = self.event_list_view.selectionModel().selectedRows()
        if not indexes:
            return
        colors = [
            "#FFC107", "#00BCD4", "#9C27B0", "#4CAF50", "#FF5722",
            "#E91E63", "#009688", "#CDDC39", "#FF007F", "#2196F3"
        ]
        chosen = colors[(color_idx - 1) % len(colors)]
        for proxy_idx in indexes:
            src_row = self.proxy_model.mapToSource(proxy_idx).row()
            if src_row < len(self.table_model._row_bg_brushes):
                self.table_model._row_bg_brushes[src_row] = QBrush(QColor(chosen))
                self.table_model._row_fg_brushes[src_row] = QBrush(QColor("#000000"))
                self.table_model.dataChanged.emit(
                    self.table_model.index(src_row, 0),
                    self.table_model.index(src_row, len(EventTableModel.COLUMNS) - 1),
                    [Qt.ItemDataRole.BackgroundRole, Qt.ItemDataRole.ForegroundRole]
                )
        self.event_list_view.viewport().update()

    def _reset_selected_row_color(self):
        indexes = self.event_list_view.selectionModel().selectedRows()
        if not indexes:
            return
        for proxy_idx in indexes:
            src_row = self.proxy_model.mapToSource(proxy_idx).row()
            if src_row < len(self.table_model._events):
                event = self.table_model._events[src_row]
                bg, fg = self.table_model.coloring_engine.get_row_colors(event)
                self.table_model._row_bg_brushes[src_row] = QBrush(bg)
                self.table_model._row_fg_brushes[src_row] = QBrush(fg)
                self.table_model.dataChanged.emit(
                    self.table_model.index(src_row, 0),
                    self.table_model.index(src_row, len(EventTableModel.COLUMNS) - 1),
                    [Qt.ItemDataRole.BackgroundRole, Qt.ItemDataRole.ForegroundRole]
                )
        self.event_list_view.viewport().update()


    def _show_event_context_menu(self, pos):
        indexes = self.event_list_view.selectionModel().selectedRows()
        if not indexes:
            return

        proxy_idx = indexes[0]
        event = self.proxy_model.get_event_at_proxy_row(proxy_idx.row())
        if not event:
            return

        menu = QMenu(self)
        comm = event.get("comm", "")
        pid = event.get("pid", 0)
        ppid = event.get("ppid", 1)
        sc = event.get("syscall", "")
        dst_ip = event.get("dst_ip", "")
        dst_port = event.get("dst_port", 0)
        file_path = event.get("file_path", "")

        # 1. Forensic Inspection (Dedicated Dialog)
        act_forensic = menu.addAction("🛡️ Inspect Threat Forensics...")
        act_forensic.triggered.connect(lambda: ThreatForensicsDialog(event, self).exec())

        menu.addSeparator()

        # 2. Apply as Filter Submenu
        m_apply = menu.addMenu("Apply as Filter")
        m_apply.addAction("Selected (Process & Syscall)", lambda: self._apply_filter_expr(f'proc.name == "{comm}" and evt.type == "{sc}"', "replace"))
        m_apply.addAction("Not Selected (Exclude Process)", lambda: self._apply_filter_expr(f'proc.name != "{comm}"', "replace"))
        m_apply.addAction("... and Selected", lambda: self._apply_filter_expr(f'proc.name == "{comm}"', "and"))
        m_apply.addAction("... or Selected", lambda: self._apply_filter_expr(f'proc.name == "{comm}"', "or"))
        m_apply.addAction("... and not Selected", lambda: self._apply_filter_expr(f'proc.name == "{comm}"', "and not"))
        m_apply.addAction("... or not Selected", lambda: self._apply_filter_expr(f'proc.name == "{comm}"', "or not"))

        # 3. Prepare as Filter Submenu
        m_prep = menu.addMenu("Prepare as Filter")
        m_prep.addAction("Selected", lambda: self._prepare_filter_expr(f'proc.name == "{comm}" and evt.type == "{sc}"', "replace"))
        m_prep.addAction("Not Selected", lambda: self._prepare_filter_expr(f'proc.name != "{comm}"', "replace"))
        m_prep.addAction("... and Selected", lambda: self._prepare_filter_expr(f'proc.name == "{comm}"', "and"))
        m_prep.addAction("... or Selected", lambda: self._prepare_filter_expr(f'proc.name == "{comm}"', "or"))

        menu.addSeparator()

        # 4. Follow Submenu
        m_follow = menu.addMenu("Follow")
        m_follow.addAction(f"Follow Process Flow (PID {pid})", lambda: self._apply_filter_expr(f'proc.pid == {pid}', "replace"))
        m_follow.addAction(f"Follow Parent & Child Lineage (PID {pid} / PPID {ppid})", lambda: self._apply_filter_expr(f'proc.pid == {pid} or proc.pid == {ppid} or proc.ppid == {pid}', "replace"))
        if dst_ip and dst_ip != "0.0.0.0":
            m_follow.addAction(f"Follow TCP Stream ({dst_ip}:{dst_port})", lambda: self._apply_filter_expr(f'net.dst == "{dst_ip}" and net.port == {dst_port}', "replace"))
        if file_path and file_path != "-":
            m_follow.addAction(f"Follow File Access ({os.path.basename(file_path)})", lambda: self._apply_filter_expr(f'file.path contains "{file_path}"', "replace"))

        # 5. Colorize Conversation
        m_color = menu.addMenu("Colorize Conversation")
        colors = [
            ("Color 1 (Amber)", "#FFC107"),
            ("Color 2 (Cyan)", "#00BCD4"),
            ("Color 3 (Purple)", "#9C27B0"),
            ("Color 4 (Green)", "#4CAF50"),
            ("Color 5 (Orange)", "#FF5722"),
            ("Color 6 (Pink)", "#E91E63"),
            ("Color 7 (Teal)", "#009688"),
            ("Color 8 (Lime)", "#CDDC39"),
            ("Color 9 (Magenta)", "#FF007F"),
            ("Color 10 (Blue)", "#2196F3"),
        ]
        for c_idx, (c_name, c_hex) in enumerate(colors, 1):
            m_color.addAction(c_name, lambda idx=c_idx: self._colorize_selected_row(idx))
        m_color.addSeparator()
        m_color.addAction("Reset Colorization", self._reset_selected_row_color)

        menu.addSeparator()

        # 6. Mark / Time Ref
        src_row = self.proxy_model.mapToSource(proxy_idx).row()
        menu.addAction("Mark/Unmark Event (Ctrl+M)", lambda: self.table_model.toggle_mark_row(src_row))
        menu.addAction("Set Time Reference (Ctrl+T)", lambda: self.table_model.set_time_reference_row(src_row))

        menu.addSeparator()

        # 7. Copy Submenu
        m_copy = menu.addMenu("Copy")
        import json
        from PyQt6.QtWidgets import QApplication
        m_copy.addAction("Summary (CSV)", lambda: QApplication.clipboard().setText(",".join([str(v) for v in event.values()])))
        m_copy.addAction("As JSON", lambda: QApplication.clipboard().setText(json.dumps(event, indent=2)))
        m_copy.addAction("Process Name", lambda: QApplication.clipboard().setText(str(comm)))
        m_copy.addAction("PID", lambda: QApplication.clipboard().setText(str(pid)))
        m_copy.addAction("Executable Path", lambda: QApplication.clipboard().setText(str(event.get("exe_path", ""))))

        menu.exec(self.event_list_view.viewport().mapToGlobal(pos))

    def _show_tree_context_menu(self, pos):
        index = self.detail_tree_view.indexAt(pos)
        if not index.isValid():
            return

        node = index.internalPointer()
        if not node:
            return

        menu = QMenu(self)
        from PyQt6.QtWidgets import QApplication
        import json

        field_name = node.field_name or "evt.type"
        field_val = node.value or node.name

        filter_expr = f'{field_name} == "{field_val}"' if field_val else field_name

        # 1. Apply as Filter
        m_apply = menu.addMenu("Apply as Filter")
        m_apply.addAction("Selected", lambda: self._apply_filter_expr(filter_expr, "replace"))
        m_apply.addAction("Not Selected", lambda: self._apply_filter_expr(f'{field_name} != "{field_val}"', "replace"))
        m_apply.addAction("... and Selected", lambda: self._apply_filter_expr(filter_expr, "and"))
        m_apply.addAction("... or Selected", lambda: self._apply_filter_expr(filter_expr, "or"))
        m_apply.addAction("... and not Selected", lambda: self._apply_filter_expr(filter_expr, "and not"))
        m_apply.addAction("... or not Selected", lambda: self._apply_filter_expr(filter_expr, "or not"))

        # 2. Prepare as Filter
        m_prep = menu.addMenu("Prepare as Filter")
        m_prep.addAction("Selected", lambda: self._prepare_filter_expr(filter_expr, "replace"))
        m_prep.addAction("Not Selected", lambda: self._prepare_filter_expr(f'{field_name} != "{field_val}"', "replace"))
        m_prep.addAction("... and Selected", lambda: self._prepare_filter_expr(filter_expr, "and"))
        m_prep.addAction("... or Selected", lambda: self._prepare_filter_expr(filter_expr, "or"))

        menu.addSeparator()

        # 3. Expand / Collapse Subtree
        menu.addAction("Expand All", self.detail_tree_view.expandAll)
        menu.addAction("Collapse All", self.detail_tree_view.collapseAll)
        menu.addAction("Expand Subtree", lambda: self.detail_tree_view.expandRecursively(index))
        menu.addAction("Collapse Subtree", lambda: self.detail_tree_view.collapse(index))

        menu.addSeparator()

        # 4. Copy Submenu
        m_copy = menu.addMenu("Copy")
        m_copy.addAction("Field Name", lambda: QApplication.clipboard().setText(str(field_name)))
        m_copy.addAction("Field Value", lambda: QApplication.clipboard().setText(str(field_val)))
        m_copy.addAction("Field as Display Filter", lambda: QApplication.clipboard().setText(filter_expr))
        m_copy.addAction("Description", lambda: QApplication.clipboard().setText(str(node.name)))

        menu.exec(self.detail_tree_view.viewport().mapToGlobal(pos))


    def closeEvent(self, event):
        self.stop_capture()
        self.settings.set_window_geometry(self.saveGeometry())
        self.settings.set_master_splitter_state(self.master_splitter.saveState())

        self.settings.set_bottom_splitter_state(self.bottom_splitter.saveState())
        super().closeEvent(event)
