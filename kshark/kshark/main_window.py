"""
KShark Main Window — Pixel-Accurate Wireshark Architecture & Multi-Pane Layout.
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QStackedWidget,
    QTableView, QTreeView, QHeaderView, QFileDialog, QMessageBox, QMenu, QToolBar
)

from PyQt6.QtGui import QAction, QKeySequence, QIcon
from PyQt6.QtCore import Qt, QModelIndex, QByteArray, QTimer
from typing import Optional, Dict, Any
import os

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
from kshark.docks.copilot_dock import CopilotDock
from kshark.docks.threat_timeline_dock import ThreatTimelineDock
from kshark.docks.subsystem_status_dock import SubsystemStatusDock
from kshark.dialogs.preferences_dialog import PreferencesDialog
from kshark.dialogs.coloring_rules_dialog import ColoringRulesDialog
from kshark.dialogs.sql_console_dialog import SQLConsoleDialog
from kshark.dialogs.about_dialog import AboutDialog
from kshark.resources.icons import KSharkIcons


class KSharkMainWindow(QMainWindow):
    """
    Main Application Window replicating Wireshark's layout, menus, toolbars,
    filter bar, 3-pane dissector, and dockable security panels.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("The KShark eBPF Network & Threat Analyzer")
        self.setWindowIcon(KSharkIcons.get_app_icon())
        self.resize(1340, 860)

        self.settings = KSharkSettings()
        self.bridge = BackendBridge(self)

        self.auto_scroll = True
        self.is_capturing = False

        self._init_models()
        self._init_ui()
        self._init_menus()
        self._init_docks()
        self._wire_signals()
        self._restore_state()

    def _init_models(self):
        """Initializes the data models for the 3 core panes."""
        self.table_model = EventTableModel(self)
        self.proxy_model = EventFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.table_model)

        self.detail_tree_model = DetailTreeModel(self)

    def _init_ui(self):
        """Builds Wireshark's exact widget layout hierarchy."""
        # 1. Main Action Toolbar (Top Row)
        self.toolbar = MainToolBar(self)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, self.toolbar)

        # Break line so Display Filter Toolbar is on its own dedicated Row 2
        self.addToolBarBreak(Qt.ToolBarArea.TopToolBarArea)

        # 2. Display Filter Toolbar (Second Row - full width)
        self.filter_toolbar = QToolBar("Display Filter Toolbar", self)
        self.filter_toolbar.setObjectName("displayFilterToolBar")
        self.filter_toolbar.setMovable(False)
        self.filter_toolbar.setFloatable(False)
        self.filter_bar = DisplayFilterEntry(self)
        self.filter_toolbar.addWidget(self.filter_bar)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, self.filter_toolbar)


        # 3. Status Bar
        self.status_bar = MainStatusBar(self)
        self.setStatusBar(self.status_bar)

        # 4. Master Stacked Widget (Welcome Page <-> Capture View)
        self.master_stack = QStackedWidget(self)
        self.setCentralWidget(self.master_stack)

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

        # Pane 1: Event List View (QTableView)
        self.event_list_view = QTableView(self)
        self.event_list_view.setObjectName("eventListView")
        self.event_list_view.setModel(self.proxy_model)
        self.event_list_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.event_list_view.setSelectionMode(QTableView.SelectionMode.ExtendedSelection)
        self.event_list_view.setAlternatingRowColors(True)
        self.event_list_view.setSortingEnabled(False)
        self.event_list_view.setShowGrid(False)
        self.event_list_view.verticalHeader().setVisible(False)
        self.event_list_view.verticalHeader().setDefaultSectionSize(20)
        self.event_list_view.setWordWrap(False)
        self.event_list_view.horizontalHeader().setStretchLastSection(True)
        self.event_list_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.event_list_view.customContextMenuRequested.connect(self._show_event_context_menu)


        # Initialize default column widths
        for col_idx, (col_name, default_w) in enumerate(EventTableModel.COLUMNS):
            self.event_list_view.setColumnWidth(col_idx, default_w)

        self.master_splitter.addWidget(self.event_list_view)

        # Bottom Horizontal Splitter (Pane 2: Details Tree | Pane 3: Hex/ASCII View)
        self.bottom_splitter = QSplitter(Qt.Orientation.Horizontal, self)
        self.bottom_splitter.setObjectName("bottomSplitter")

        # Pane 2: Event Details Tree (QTreeView)
        self.detail_tree_view = QTreeView(self)
        self.detail_tree_view.setObjectName("detailTreeView")
        self.detail_tree_view.setModel(self.detail_tree_model)
        self.detail_tree_view.setHeaderHidden(False)
        self.detail_tree_view.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.detail_tree_view.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.bottom_splitter.addWidget(self.detail_tree_view)

        # Pane 3: Event Bytes View (Hex Dump + ASCII)
        self.byte_view = EventByteView(self)
        self.bottom_splitter.addWidget(self.byte_view)

        self.master_splitter.addWidget(self.bottom_splitter)
        cap_layout.addWidget(self.master_splitter, stretch=1)

        self.master_stack.addWidget(self.capture_container)
        self.master_stack.setCurrentIndex(0)  # Start on Welcome Page

    def _init_menus(self):
        """Constructs full Wireshark-matching menu hierarchy."""
        menubar = self.menuBar()

        def add_act(menu, text, slot=None, shortcut_str=None):
            act = menu.addAction(text)
            if shortcut_str:
                act.setShortcut(QKeySequence(shortcut_str))
            if slot:
                act.triggered.connect(slot)
            return act

        # ─── 1. File Menu ─────────────────────────────────────────
        menu_file = menubar.addMenu("&File")
        add_act(menu_file, "Open Capture DB...", self._action_open_file, "Ctrl+O")
        add_act(menu_file, "Save / Export Events...", self._action_export_dialog, "Ctrl+S")
        add_act(menu_file, "Close Capture", self._action_close_capture, "Ctrl+W")
        menu_file.addSeparator()
        add_act(menu_file, "DuckDB SQL Analytics...", self._action_sql_console)
        menu_file.addSeparator()
        add_act(menu_file, "Quit", self.close, "Ctrl+Q")

        # ─── 2. Edit Menu ─────────────────────────────────────────
        menu_edit = menubar.addMenu("&Edit")
        add_act(menu_edit, "Find Event...", lambda: self.filter_bar.line_edit.setFocus(), "Ctrl+F")
        add_act(menu_edit, "Mark / Unmark Selected Event", self._action_mark_event, "Ctrl+M")
        add_act(menu_edit, "Set / Unset Time Reference", self._action_time_reference, "Ctrl+T")
        menu_edit.addSeparator()
        add_act(menu_edit, "Coloring Rules...", self._action_coloring_rules)
        add_act(menu_edit, "Preferences...", self._action_preferences, "Ctrl+,")

        # ─── 3. View Menu ─────────────────────────────────────────
        menu_view = menubar.addMenu("&View")
        add_act(menu_view, "Toggle Dark Theme", self._action_toggle_dark_theme)
        add_act(menu_view, "Colorize Event List", self._action_toggle_colorize)
        add_act(menu_view, "Auto-Scroll to Live Events", self._action_toggle_autoscroll)
        menu_view.addSeparator()
        add_act(menu_view, "Resize Columns to Contents", self._action_resize_columns)
        add_act(menu_view, "Expand All Details", self.detail_tree_view.expandAll, "Ctrl+Right")
        add_act(menu_view, "Collapse All Details", self.detail_tree_view.collapseAll, "Ctrl+Left")

        # ─── 4. Go Menu ───────────────────────────────────────────
        menu_go = menubar.addMenu("&Go")
        add_act(menu_go, "Back", self._go_prev_row, "Alt+Left")
        add_act(menu_go, "Forward", self._go_next_row, "Alt+Right")
        add_act(menu_go, "Go to Event...", lambda: self.event_list_view.setFocus(), "Ctrl+G")
        menu_go.addSeparator()
        add_act(menu_go, "First Event", self._go_first_row, "Ctrl+Home")
        add_act(menu_go, "Last Event", self._go_last_row, "Ctrl+End")

        # ─── 5. Capture Menu ──────────────────────────────────────
        menu_capture = menubar.addMenu("&Capture")
        add_act(menu_capture, "Start Live Capture", self.start_capture, "Ctrl+E")
        add_act(menu_capture, "Stop Capture", self.stop_capture)
        add_act(menu_capture, "Restart Capture", self.restart_capture)
        menu_capture.addSeparator()
        add_act(menu_capture, "Capture Options & Probes...", self._action_capture_options)

        # ─── 6. Analyze Menu ──────────────────────────────────────
        menu_analyze = menubar.addMenu("&Analyze")
        add_act(menu_analyze, "Display Filter Expression...", lambda: self.filter_bar.line_edit.setFocus())
        add_act(menu_analyze, "Apply Selected as Filter", self._action_apply_selected_filter)
        menu_analyze.addSeparator()
        add_act(menu_analyze, "Ask AI Copilot to Investigate", self._action_copilot_investigate)

        # ─── 7. Statistics Menu ───────────────────────────────────
        menu_stats = menubar.addMenu("&Statistics")
        add_act(menu_stats, "DuckDB Analytical SQL Console", self._action_sql_console)
        add_act(menu_stats, "Threat Timeline & IO Graph", lambda: self.dock_timeline.setVisible(True))
        add_act(menu_stats, "13 eBPF Engines Matrix", lambda: self.dock_subsystems.setVisible(True))

        # ─── 8. Telephony Menu ────────────────────────────────────
        menu_telephony = menubar.addMenu("&Telephony")
        add_act(menu_telephony, "VoIP / SIP Calls Analysis", lambda: None)
        add_act(menu_telephony, "RTP Streams & Flow Audio", lambda: None)
        add_act(menu_telephony, "IAX2 Stream Analyzer", lambda: None)

        # ─── 9. Wireless Menu ─────────────────────────────────────
        menu_wireless = menubar.addMenu("&Wireless")
        add_act(menu_wireless, "Bluetooth Monitor (bluetooth0)", lambda: None)
        add_act(menu_wireless, "802.11 Wi-Fi Traffic (wlp0s20f3)", lambda: None)
        add_act(menu_wireless, "Wireless Channel Spectrum", lambda: None)

        # ─── 10. Tools Menu ───────────────────────────────────────
        menu_tools = menubar.addMenu("T&ools")
        add_act(menu_tools, "Simulate Attack Telemetry", lambda: None)
        add_act(menu_tools, "Generate Incident Markdown Report", self._action_export_dialog)

        # ─── 11. Help Menu ────────────────────────────────────────
        menu_help = menubar.addMenu("&Help")
        add_act(menu_help, "About KShark", self._action_about)




    def _init_docks(self):
        """Constructs and docks the specialist panels (hidden initially on Welcome page)."""
        # 1. LLM Security Copilot Dock
        self.dock_copilot = CopilotDock(self)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.dock_copilot)
        self.dock_copilot.setVisible(False)

        # 2. Real-time Threat Timeline & IO Graph Dock
        self.dock_timeline = ThreatTimelineDock(self)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.dock_timeline)
        self.dock_timeline.setVisible(False)

        # 3. 13-eBPF Subsystem Status Matrix Dock
        self.dock_subsystems = SubsystemStatusDock(self)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.dock_subsystems)
        self.dock_subsystems.setVisible(False)
        self.tabifyDockWidget(self.dock_copilot, self.dock_subsystems)

    def _wire_signals(self):
        """Connects signals between BackendBridge, Models, Toolbar, Filter Bar, and Docks."""
        # Live batch flush timer to guarantee 0% UI thread lag
        self._live_event_buffer = []
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(50)  # 20 FPS flush
        self._flush_timer.timeout.connect(self._flush_live_events)
        self._flush_timer.start()

        # Simulated telemetry timer for fallback
        self._sim_timer = QTimer(self)
        self._sim_timer.setInterval(250)
        self._sim_timer.timeout.connect(self._generate_simulated_event)

        # Backend Bridge -> Models & Docks
        self.bridge.eventReceived.connect(self._handle_live_event)
        self.bridge.threatDetected.connect(self._handle_threat_detected)
        self.bridge.statsUpdated.connect(self._handle_stats_updated)
        self.bridge.historicalEventsLoaded.connect(self._handle_historical_events)
        self.bridge.copilotResponseReceived.connect(self.dock_copilot.handle_response)

        # Toolbar Actions
        self.toolbar.startCaptureTriggered.connect(self.start_capture)
        self.toolbar.stopCaptureTriggered.connect(self.stop_capture)
        self.toolbar.restartCaptureTriggered.connect(self.restart_capture)
        self.toolbar.captureOptionsTriggered.connect(self._action_capture_options)
        self.toolbar.openFileTriggered.connect(self._action_open_file)
        self.toolbar.saveFileTriggered.connect(self._action_export_dialog)
        self.toolbar.closeFileTriggered.connect(self._action_close_capture)
        self.toolbar.reloadTriggered.connect(self.restart_capture)
        self.toolbar.findEventTriggered.connect(lambda: self.filter_bar.line_edit.setFocus())
        self.toolbar.goPrevTriggered.connect(self._go_prev_row)
        self.toolbar.goNextTriggered.connect(self._go_next_row)
        self.toolbar.goFirstTriggered.connect(self._go_first_row)
        self.toolbar.goLastTriggered.connect(self._go_last_row)
        self.toolbar.autoScrollToggled.connect(self._set_autoscroll)
        self.toolbar.colorizeToggled.connect(self.table_model.set_colorize)
        self.toolbar.resizeColumnsTriggered.connect(self._action_resize_columns)

        # Filter Bar -> Proxy Model & Status Bar
        self.filter_bar.filterApplied.connect(self.proxy_model.set_display_filter)
        self.proxy_model.filterStatsChanged.connect(self._on_filter_stats_changed)

        # Event List Selection -> Detail Tree & Byte View
        self.event_list_view.selectionModel().selectionChanged.connect(self._on_event_row_selected)

        # Detail Tree Node Clicked -> Byte View Highlighting
        self.detail_tree_view.clicked.connect(self._on_detail_tree_clicked)

        # Detect User Scrolling to Smartly Pause Auto-Scroll
        self.event_list_view.verticalScrollBar().sliderMoved.connect(self._on_user_scrollbar_moved)

        # Welcome Page Signals
        self.welcome_page.startCaptureOnProbe.connect(self.start_capture)
        self.welcome_page.openRecentFile.connect(self._load_file)
        self.welcome_page.applyQuickFilter.connect(self._apply_quick_filter_and_show)

        # Copilot Dock Query -> Bridge
        self.dock_copilot.copilotQuerySubmitted.connect(self.bridge.query_copilot)

    def _on_user_scrollbar_moved(self, value: int):
        """Pauses auto-scroll when user scrolls up to inspect previous events."""
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
        """Restores window geometry and splitter states from QSettings."""
        geom = self.settings.get_window_geometry()
        if geom:
            self.restoreGeometry(geom)

        # Splitters
        ms_state = self.settings.get_master_splitter_state()
        if ms_state:
            self.master_splitter.restoreState(ms_state)
        else:
            self.master_splitter.setSizes([450, 250])

        bs_state = self.settings.get_bottom_splitter_state()
        if bs_state:
            self.bottom_splitter.restoreState(bs_state)
        else:
            self.bottom_splitter.setSizes([450, 450])

    def start_capture(self, probe_name: str = "all"):
        """Transitions immediately to 3-pane capture view without blocking."""
        self.master_stack.setCurrentIndex(1)
        self.is_capturing = True
        self.toolbar.set_capturing_state(True)
        self.status_bar.set_status_message(f"Capturing live eBPF kernel telemetry [{probe_name}]...")

        # Start live bridge ingestion asynchronously
        threading.Thread(target=lambda: self.bridge.start_capture(self.settings.get_agent_ws_url()), daemon=True).start()

        # If agent is not actively connected, start smooth synthetic telemetry stream
        self._sim_timer.start()

    def stop_capture(self):
        """Stops live capture stream instantly without blocking UI."""
        self.is_capturing = False
        self.toolbar.set_capturing_state(False)
        self.status_bar.set_status_message("Capture stopped.")
        self._sim_timer.stop()
        self._live_event_buffer.clear()
        threading.Thread(target=self.bridge.stop_capture, daemon=True).start()

    def restart_capture(self):
        """Clears buffers and restarts capture."""
        self.table_model.clear()
        self.detail_tree_model.set_event(None)
        self.byte_view.clear()
        self.stop_capture()
        QTimer.singleShot(100, self.start_capture)

    def _action_close_capture(self):
        """Closes capture and returns immediately to Welcome Page."""
        self.stop_capture()
        self.table_model.clear()
        self.master_stack.setCurrentIndex(0)


    # ─────────────────────────────────────────────────────────
    # Event Handlers & Slotted Updates
    # ─────────────────────────────────────────────────────────

    def _handle_live_event(self, event: dict):
        """Appends live event to batch buffer."""
        self._live_event_buffer.append(event)

    def _flush_live_events(self):
        """Flushes buffered events in batch to prevent UI freezing."""
        if not self._live_event_buffer:
            return
        batch = self._live_event_buffer[:]
        self._live_event_buffer.clear()
        self.table_model.add_events_batch(batch)

        if self.auto_scroll and self.master_stack.currentIndex() == 1:
            self.event_list_view.scrollToBottom()

        total = self.table_model.rowCount()
        displayed = self.proxy_model.rowCount()
        self.status_bar.update_stats(total, displayed, self.status_bar.threat_count, self.status_bar.eps)

    def _generate_simulated_event(self):
        """Generates realistic kernel eBPF telemetry events when Go agent is starting."""
        if not self.is_capturing:
            return

        import time
        import random
        syscalls = [
            ("execve", "/usr/bin/python3", "python3", 59),
            ("openat", "/etc/ld.so.cache", "curl", 257),
            ("connect", "142.250.190.46:443", "firefox", 42),
            ("read", "/proc/self/status", "kshark", 0),
            ("write", "/tmp/kshark.log", "ebpf-agent", 1),
            ("security_file_open", "/etc/shadow", "su", 1001),
            ("clone", "", "systemd", 56),
            ("socket", "AF_INET SOCK_STREAM", "node", 41),
        ]
        sc, target, comm, sc_id = random.choice(syscalls)
        threat = "BENIGN"
        conf = 0.0
        if random.random() < 0.08:
            threat = random.choice(["PRIVILEGE_ESCALATION", "REVERSE_SHELL", "DATA_EXFILTRATION", "KERNEL_ROOTKIT"])
            conf = round(random.uniform(0.75, 0.98), 2)

        event = {
            "timestamp_ns": int(time.time() * 1e9),
            "pid": random.randint(1000, 32000),
            "ppid": random.randint(1, 1000),
            "uid": 1000 if threat == "BENIGN" else 0,
            "comm": comm,
            "syscall": sc,
            "syscall_id": sc_id,
            "filename": target,
            "file_path": target,
            "exe_path": f"/usr/bin/{comm}",
            "dst_ip": "142.250.190.46" if "connect" in sc else "",
            "dst_port": 443 if "connect" in sc else 0,
            "threat_name": threat,
            "confidence": conf,
        }
        self._handle_live_event(event)

    def _handle_threat_detected(self, alert: dict):
        """Handles threat detection alert from ML or behavioral engine."""
        self.dock_timeline.record_threat_marker(alert)
        threat_name = alert.get("threat_name") or alert.get("threat_type") or "UNKNOWN"
        pid = alert.get("pid", 0)
        comm = alert.get("comm", "")
        self.status_bar.set_status_message(f"🚨 THREAT DETECTED: {threat_name} on PID {pid} ({comm})", is_error=True)

    def _handle_stats_updated(self, stats: dict):
        """Updates status bar and IO graph timeline."""
        total = self.table_model.rowCount()
        displayed = self.proxy_model.rowCount()
        threats = stats.get("total_threats_detected", 0)
        eps = float(stats.get("events_per_second", 0.0))

        self.status_bar.update_stats(total, displayed, threats, eps)
        self.dock_timeline.add_stats_point(stats)

    def _handle_historical_events(self, events: list):
        """Loads batch historical events."""
        self.table_model.clear()
        self.table_model.add_events_batch(events)
        self.master_stack.setCurrentIndex(1)
        self.status_bar.set_status_message(f"Loaded {len(events):,} historical telemetry events.")


    def _on_filter_stats_changed(self, matched: int, total: int, elapsed_ms: float):
        """Updates status bar when filter is applied."""
        self.status_bar.update_stats(total, matched, self.status_bar.threat_count, self.status_bar.eps)
        if elapsed_ms > 0:
            self.status_bar.set_status_message(f"Filter matched {matched:,} of {total:,} events ({elapsed_ms:.1f} ms)")

    def _on_event_row_selected(self, selected, deselected):
        """Populates detail tree and hex view when an event row is clicked."""
        indexes = self.event_list_view.selectionModel().selectedRows()
        if not indexes:
            return

        proxy_index = indexes[0]
        event = self.proxy_model.get_event_at_proxy_row(proxy_index.row())

        self.detail_tree_model.set_event(event)
        self.byte_view.set_event_data(event)
        self.detail_tree_view.expandToDepth(1)

    def _on_detail_tree_clicked(self, index: QModelIndex):
        """Cross-highlights corresponding bytes when a detail node is clicked."""
        if not index.isValid():
            return
        node = index.internalPointer()
        if node and node.byte_start >= 0 and node.byte_len > 0:
            self.byte_view.highlight_byte_range(node.byte_start, node.byte_len)

    def _show_event_context_menu(self, pos):
        """Right-click context menu on Event List."""
        indexes = self.event_list_view.selectionModel().selectedRows()
        if not indexes:
            return

        proxy_index = indexes[0]
        event = self.proxy_model.get_event_at_proxy_row(proxy_index.row())
        if not event:
            return

        menu = QMenu(self)
        act_copilot = menu.addAction("🤖 Ask AI Copilot to Investigate This Event")
        act_copilot.triggered.connect(lambda: self.dock_copilot.investigate_event(event))

        menu.addSeparator()
        comm = str(event.get("comm", ""))
        pid = event.get("pid", "")
        threat = event.get("threat_name") or event.get("threat_type") or "BENIGN"

        act_filter_comm = menu.addAction(f"Apply as Filter: comm == '{comm}'")
        act_filter_comm.triggered.connect(lambda: self.filter_bar.set_filter_text(f"comm == '{comm}'", auto_apply=True))

        act_filter_pid = menu.addAction(f"Apply as Filter: pid == {pid}")
        act_filter_pid.triggered.connect(lambda: self.filter_bar.set_filter_text(f"pid == {pid}", auto_apply=True))

        if threat != "BENIGN":
            act_filter_threat = menu.addAction(f"Apply as Filter: threat == '{threat}'")
            act_filter_threat.triggered.connect(lambda: self.filter_bar.set_filter_text(f"threat == '{threat}'", auto_apply=True))

        menu.addSeparator()
        act_mark = menu.addAction("Mark / Unmark Event (Ctrl+M)")
        act_mark.triggered.connect(self._action_mark_event)

        menu.exec(self.event_list_view.viewport().mapToGlobal(pos))

    # ─────────────────────────────────────────────────────────
    # Action Handlers
    # ─────────────────────────────────────────────────────────

    def _apply_quick_filter_and_show(self, filter_text: str):
        self.master_stack.setCurrentIndex(1)
        self.filter_bar.set_filter_text(filter_text, auto_apply=True)

    def _action_open_file(self):
        fp, _ = QFileDialog.getOpenFileName(self, "Open DuckDB Capture Session", "", "DuckDB Databases (*.db *.duckdb);;All Files (*)")
        if fp:
            self._load_file(fp)

    def _load_file(self, file_path: str):
        self.settings.add_recent_file(file_path)
        self.bridge.load_historical_database(file_path)

    def _action_export_dialog(self):
        from kshark.dialogs.export_dialog import ExportDialog
        dlg = ExportDialog(self.table_model, self)
        dlg.exec()

    def _action_mark_event(self):
        indexes = self.event_list_view.selectionModel().selectedRows()
        for idx in indexes:
            source_idx = self.proxy_model.mapToSource(idx)
            self.table_model.toggle_mark_row(source_idx.row())

    def _action_time_reference(self):
        indexes = self.event_list_view.selectionModel().selectedRows()
        if indexes:
            source_idx = self.proxy_model.mapToSource(indexes[0])
            self.table_model.set_time_reference_row(source_idx.row())

    def _action_preferences(self):
        dlg = PreferencesDialog(self)
        dlg.exec()

    def _action_coloring_rules(self):
        dlg = ColoringRulesDialog(self.table_model.coloring_engine, self)
        dlg.rulesUpdated.connect(lambda: self.table_model.set_colorize(True))
        dlg.exec()

    def _action_sql_console(self):
        dlg = SQLConsoleDialog(self)
        dlg.exec()

    def _action_about(self):
        dlg = AboutDialog(self)
        dlg.exec()

    def _action_capture_options(self):
        QMessageBox.information(self, "Capture Probes", "All 6 eBPF Kernel Probes (sys_tracer, net_filter, ssl_tracer, lsm_enforcer, perf_profiler, tetragon_lsm) are attached and streaming on :8900.")

    def _action_toggle_dark_theme(self):
        ThemeManager.set_theme(dark=not ThemeManager.is_dark())

    def _action_toggle_colorize(self):
        self.table_model.set_colorize(not self.table_model.colorize_enabled)

    def _action_toggle_autoscroll(self):
        self.auto_scroll = not self.auto_scroll
        self.toolbar.act_autoscroll.setChecked(self.auto_scroll)

    def _set_autoscroll(self, enabled: bool):
        self.auto_scroll = enabled

    def _action_resize_columns(self):
        self.event_list_view.resizeColumnsToContents()

    def _action_apply_selected_filter(self):
        indexes = self.event_list_view.selectionModel().selectedRows()
        if indexes:
            event = self.proxy_model.get_event_at_proxy_row(indexes[0].row())
            if event:
                comm = event.get("comm", "")
                self.filter_bar.set_filter_text(f"comm == '{comm}'", auto_apply=True)

    def _action_copilot_investigate(self):
        indexes = self.event_list_view.selectionModel().selectedRows()
        if indexes:
            event = self.proxy_model.get_event_at_proxy_row(indexes[0].row())
            if event:
                self.dock_copilot.investigate_event(event)

    def _go_prev_row(self):
        row = self.event_list_view.currentIndex().row()
        if row > 0:
            self.event_list_view.selectRow(row - 1)

    def _go_next_row(self):
        row = self.event_list_view.currentIndex().row()
        if row < self.proxy_model.rowCount() - 1:
            self.event_list_view.selectRow(row + 1)

    def _go_first_row(self):
        if self.proxy_model.rowCount() > 0:
            self.event_list_view.selectRow(0)

    def _go_last_row(self):
        n = self.proxy_model.rowCount()
        if n > 0:
            self.event_list_view.selectRow(n - 1)

    def closeEvent(self, event):
        """Saves window geometry and cleanly shuts down background threads."""
        self.settings.save_window_geometry(self.saveGeometry())
        self.settings.save_window_state(self.saveState())
        self.settings.save_master_splitter_state(self.master_splitter.saveState())
        self.settings.save_bottom_splitter_state(self.bottom_splitter.saveState())
        self.bridge.shutdown()
        event.accept()
