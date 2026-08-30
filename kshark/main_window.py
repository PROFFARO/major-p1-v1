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
from kshark.widgets.dissection_intelligence_pane import DissectionIntelligencePane
from kshark.widgets.byte_payload_inspector import BytePayloadInspectorPane
from kshark.widgets.welcome_page import WelcomePage
from kshark.widgets.scroll_views import KSharkTableView, KSharkTreeView, KSharkTableWidget


from kshark.widgets.search_frame import KSharkSearchFrame
from kshark.widgets.accordion_frame import GoToFrame
from kshark.widgets.edge_dock_bar import BottomEdgeRestoreBar, RightEdgeRestoreBar
from kshark.widgets.custom_dock_title_bar import KSharkDockTitleBar
from kshark.docks.copilot_dock import CopilotDock
from kshark.docks.threat_timeline_dock import ThreatTimelineDock
from kshark.dialogs.preferences_dialog import PreferencesDialog

from kshark.dialogs.coloring_rules_dialog import ColoringRulesDialog
from kshark.dialogs.sql_console_dialog import SQLConsoleDialog
from kshark.dialogs.about_dialog import AboutDialog
from kshark.dialogs.io_graph_dialog import KSharkIOGraphDialog
from kshark.dialogs.plot_dialog import KSharkPlotDialog
from kshark.dialogs.capture_options_dialog import CaptureOptionsDialog
from kshark.dialogs.threat_forensics_dialog import ThreatForensicsDialog
from kshark.dialogs.byte_hasher_dialog import ByteHasherDialog
from kshark.dialogs.keyboard_shortcuts_dialog import KeyboardShortcutsDialog
from kshark.dialogs.follow_stream_dialog import FollowStreamDialog
from kshark.dialogs.expert_info_dialog import ExpertInfoDialog
from kshark.dialogs.edit_comment_dialog import EditCommentDialog
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
        self._zoom_level = self.settings.get_font_size()
        self._current_file_path = ""

        self._init_models()
        self._init_ui()
        self._init_docks()
        self._init_menus()
        self._wire_signals()
        self._restore_state()
        self.apply_font_size(self._zoom_level)


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

        # Pane 1: Event List View (High-Precision Trackpad & Mouse Scrollable Table)
        self.event_list_view = KSharkTableView(self)
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

        # Header sorting and context menu
        header = self.event_list_view.horizontalHeader()
        header.setSectionsClickable(True)
        header.setSortIndicatorShown(True)
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self._show_header_context_menu)
        self.event_list_view.setSortingEnabled(True)
        self.event_list_view.sortByColumn(0, Qt.SortOrder.AscendingOrder)

        for col_idx, (col_name, default_w) in enumerate(EventTableModel.COLUMNS):
            self.event_list_view.setColumnWidth(col_idx, default_w)


        self.master_splitter.addWidget(self.event_list_view)

        # Bottom Horizontal Splitter (Pane 2: Dissection & Intelligence | Pane 3: Byte & Binary Payload Inspector)
        self.bottom_splitter = QSplitter(Qt.Orientation.Horizontal, self)
        self.bottom_splitter.setObjectName("bottomSplitter")
        self.bottom_splitter.setChildrenCollapsible(False)

        # Pane 2: Dissection & Intelligence Pane (4 Tabs: Tree, MITRE Triage, Process Lineage, 12-Dim ML Metrics)
        self.detail_pane = DissectionIntelligencePane(self.detail_tree_model, self)
        self.detail_tree_view = self.detail_pane.tree_view
        self.detail_tree_view.customContextMenuRequested.connect(self._show_tree_context_menu)
        if self.detail_tree_view.selectionModel():
            self.detail_tree_view.selectionModel().currentChanged.connect(self._on_tree_field_selected)
        self.bottom_splitter.addWidget(self.detail_pane)

        # Pane 3: Byte & Binary Payload Inspector (5 Tabs: Hex+ASCII, Binary Decoder, Strings, C-Array, JSON)
        self.byte_view = BytePayloadInspectorPane(self)
        self.bottom_splitter.addWidget(self.byte_view)





        self.master_splitter.addWidget(self.bottom_splitter)
        cap_layout.addWidget(self.master_splitter, stretch=1)

        # Bottom Edge Restore Bar for quick one-click panel restoration
        self.bottom_restore_bar = BottomEdgeRestoreBar(self)
        cap_layout.addWidget(self.bottom_restore_bar)

        self.master_stack.addWidget(self.capture_container)
        self.master_stack.setCurrentIndex(0)

        # Workspace Shell Widget with Right Edge Restore Bar
        shell_widget = QWidget(self)
        shell_layout = QHBoxLayout(shell_widget)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)

        shell_layout.addWidget(self.master_stack, stretch=1)

        self.right_restore_bar = RightEdgeRestoreBar(self)
        shell_layout.addWidget(self.right_restore_bar)

        self.setCentralWidget(shell_widget)

        # Status Bar
        self.status_bar = MainStatusBar(self)
        self.setStatusBar(self.status_bar)

    def _init_menus(self):
        menubar = self.menuBar()
        menubar.clear()

        def add_act(menu, text, slot=None, shortcut_str=None, checkable=False, checked=False):
            act = menu.addAction(text)
            if checkable:
                act.setCheckable(True)
                act.setChecked(checked)
            if shortcut_str:
                act.setShortcut(QKeySequence(shortcut_str))
            if slot:
                act.triggered.connect(slot)
            return act

        # ── 1. File Menu ──
        m_file = menubar.addMenu("&File")
        add_act(m_file, "&Open Capture File...", self._action_open_file, "Ctrl+O")
        add_act(m_file, "&Save Telemetry As...", self._action_save_file, "Ctrl+S")
        add_act(m_file, "&Reload Capture File", self._action_reload_file, "Ctrl+R")
        add_act(m_file, "&Close Session", self._action_close_capture, "Ctrl+W")
        m_file.addSeparator()

        m_export = m_file.addMenu("Export Dissected Events")
        add_act(m_export, "As CSV Spreadsheet (.csv)...", self._action_export_csv, "Ctrl+Shift+C")
        add_act(m_export, "As Structured JSON Lines (.jsonl)...", self._action_export_jsonl, "Ctrl+Shift+J")
        add_act(m_export, "As DuckDB Columnar Database (.duckdb)...", self._action_save_file, "Ctrl+Shift+D")

        m_file.addSeparator()
        add_act(m_file, "E&xit KShark", self.close, "Ctrl+Q")

        # ── 2. Edit Menu ──
        m_edit = menubar.addMenu("&Edit")
        m_copy = m_edit.addMenu("&Copy")
        add_act(m_copy, "Summary (CSV)", self._copy_selected_csv, "Ctrl+C")
        add_act(m_copy, "As JSON Object", self._copy_selected_json, "Ctrl+Shift+C")
        add_act(m_copy, "Process Name", self._copy_selected_proc)
        add_act(m_copy, "Process PID", self._copy_selected_pid)
        add_act(m_copy, "Target / FD Path", self._copy_selected_target)
        m_copy.addSeparator()
        add_act(m_copy, "Dissected Telemetry Tree", self._copy_selected_tree, "Ctrl+Alt+T")

        m_edit.addSeparator()
        add_act(m_edit, "&Find Event...", self._action_find, "Ctrl+F")
        add_act(m_edit, "&Mark / Unmark Event", self._action_toggle_mark, "Ctrl+M")
        add_act(m_edit, "&Add / Edit Event Comment...", self._action_edit_comment, "Ctrl+Shift+N")
        add_act(m_edit, "Set / Unset &Time Reference", self._action_toggle_time_ref, "Ctrl+T")
        m_edit.addSeparator()
        add_act(m_edit, "Clear All Captured Events", self._action_clear_all_events, "Ctrl+Shift+X")
        m_edit.addSeparator()
        add_act(m_edit, "Keyboard &Shortcuts...", self._action_open_shortcuts_dialog, "Ctrl+Alt+K")
        add_act(m_edit, "&Preferences...", self._action_open_preferences, "Ctrl+,")

        # ── 3. View Menu ──
        m_view = menubar.addMenu("&View")

        # Toolbars & Status Bar Toggles
        act_tb = add_act(m_view, "Main Action Toolbar", lambda chk: self.toolbar.setVisible(chk), checkable=True, checked=True)
        act_fb = add_act(m_view, "Display Filter Toolbar", lambda chk: self.filter_toolbar.setVisible(chk), checkable=True, checked=True)
        act_sb = add_act(m_view, "SOC Status Bar", lambda chk: self.status_bar.setVisible(chk), checkable=True, checked=True)
        m_view.addSeparator()

        # Docks & Panes Submenu with Accelerators
        m_docks = m_view.addMenu("Panels & Forensic Docks")
        act_timeline = add_act(m_docks, "Threat Timeline & Incident Triage", self.toggle_threat_timeline, "Alt+1")
        act_copilot = add_act(m_docks, "AI Security Copilot Dock", self.toggle_copilot, "Alt+2")
        m_docks.addSeparator()
        add_act(m_docks, "Dissection & Intelligence Pane", self.toggle_dissection_pane, "Alt+3")
        add_act(m_docks, "Hex & Byte Inspector Pane", self.toggle_byte_view_pane, "Alt+4")

        m_view.addSeparator()

        # Time Display Format Submenu
        m_time = m_view.addMenu("Time Display Format")
        self._time_actions = []
        time_fmts = [
            ("Seconds Since Beginning of Capture (Relative)", EventTableModel.TIME_FMT_RELATIVE),
            ("Time of Day (UTC)", EventTableModel.TIME_FMT_TIME_OF_DAY),
            ("Date and Time of Day", EventTableModel.TIME_FMT_DATE_TIME),
            ("Seconds Since Epoch (1970-01-01)", EventTableModel.TIME_FMT_EPOCH),
        ]
        for name, code in time_fmts:
            act = m_time.addAction(name)
            act.setCheckable(True)
            act.setChecked(code == self.table_model.time_format)
            act.triggered.connect(lambda _, c=code: self._set_time_format(c))
            self._time_actions.append(act)

        # Displayed Columns Submenu
        m_cols = m_view.addMenu("Displayed Columns")
        for col_idx, (col_name, _) in enumerate(EventTableModel.COLUMNS):
            act = m_cols.addAction(col_name)
            act.setCheckable(True)
            act.setChecked(not self.event_list_view.isColumnHidden(col_idx))
            act.triggered.connect(lambda checked, idx=col_idx: self.event_list_view.setColumnHidden(idx, not checked))

        m_view.addSeparator()

        add_act(m_view, "Colorize &Event List", self._action_toggle_colorize, checkable=True, checked=True)
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

        # Theme Selector Submenu
        m_theme = m_view.addMenu("&Theme")
        self._theme_actions = []
        act_dark = m_theme.addAction("Wireshark Dark (Default)")
        act_dark.setCheckable(True)
        act_dark.setChecked(ThemeManager.current_theme() == ThemeManager.THEME_WIRESHARK_DARK)
        act_dark.triggered.connect(lambda: self._set_theme_direct(ThemeManager.THEME_WIRESHARK_DARK))

        act_light = m_theme.addAction("Wireshark Light")
        act_light.setCheckable(True)
        act_light.setChecked(ThemeManager.current_theme() == ThemeManager.THEME_WIRESHARK_LIGHT)
        act_light.triggered.connect(lambda: self._set_theme_direct(ThemeManager.THEME_WIRESHARK_LIGHT))

        self._theme_actions = [act_dark, act_light]

        m_view.addSeparator()
        add_act(m_view, "Zoom &In", self._action_zoom_in, "Ctrl++")
        add_act(m_view, "Zoom &Out", self._action_zoom_out, "Ctrl+-")
        add_act(m_view, "Normal &Size (100%)", self._action_zoom_100, "Ctrl+0")
        add_act(m_view, "Resize All &Columns to Contents", self._action_resize_columns, "Ctrl+Shift+R")
        add_act(m_view, "Reset &Default Workspace Layout", self._reset_default_layout, "Ctrl+Alt+R")

        # ── 4. Go Menu ──
        m_go = menubar.addMenu("&Go")
        add_act(m_go, "&Go to Event (Row / PID)...", self._action_goto_event, "Ctrl+G")
        add_act(m_go, "&Next Event", self._go_next_row, "Ctrl+Down")
        add_act(m_go, "&Previous Event", self._go_prev_row, "Ctrl+Up")
        add_act(m_go, "&First Event (Top)", self._go_first_row, "Ctrl+Home")
        add_act(m_go, "&Last Event (Bottom)", self._go_last_row, "Ctrl+End")
        m_go.addSeparator()
        add_act(m_go, "Next Threat / Anomaly Marker", self._go_next_threat, "Ctrl+Shift+Down")
        add_act(m_go, "Previous Threat / Anomaly Marker", self._go_prev_threat, "Ctrl+Shift+Up")

        # ── 5. Capture Menu ──
        m_cap = menubar.addMenu("&Capture")
        add_act(m_cap, "&Start Live Capture", self.start_capture, "Ctrl+E")
        add_act(m_cap, "S&top Capture", self.stop_capture, "Ctrl+E")
        add_act(m_cap, "&Restart Capture Session", self.restart_capture, "Ctrl+Shift+R")
        add_act(m_cap, "Capture &Options & BPF Filters...", self._action_open_capture_options, "Ctrl+K")
        m_cap.addSeparator()
        add_act(m_cap, "Refresh Network & Socket Interfaces", self._action_refresh_probes, "F5")

        # ── 6. Analyze Menu ──
        m_ana = menubar.addMenu("&Analyze")
        add_act(m_ana, "Display Filter &Expression Library...", self._action_open_filter_presets, "Ctrl+Shift+F")

        m_ana_apply = m_ana.addMenu("Apply as Filter")
        add_act(m_ana_apply, "Selected (Process & Syscall)", self._apply_filter_selected, "Ctrl+Alt+A")
        add_act(m_ana_apply, "Not Selected", self._apply_filter_not_selected)
        add_act(m_ana_apply, "... and Selected", self._apply_filter_and_selected)
        add_act(m_ana_apply, "... or Selected", self._apply_filter_or_selected)

        m_ana_prep = m_ana.addMenu("Prepare as Filter")
        add_act(m_ana_prep, "Selected", self._prep_filter_selected)
        add_act(m_ana_prep, "Not Selected", self._prep_filter_not_selected)
        add_act(m_ana_prep, "... and Selected", self._prep_filter_and_selected)
        add_act(m_ana_prep, "... or Selected", self._prep_filter_or_selected)

        m_ana.addSeparator()
        m_follow = m_ana.addMenu("Follow")
        add_act(m_follow, "Follow Process Flow (PID)", self._follow_process_flow, "Ctrl+Alt+P")
        add_act(m_follow, "Follow Parent & Child Lineage", self._follow_parent_child_lineage, "Ctrl+Alt+L")
        add_act(m_follow, "Follow Network Socket Stream", self._follow_tcp_stream, "Ctrl+Alt+S")
        add_act(m_follow, "Follow File Access History", self._follow_file_history, "Ctrl+Alt+H")

        m_ana.addSeparator()
        add_act(m_ana, "E&xpert Information & Diagnostics...", self._action_open_expert_info, "Ctrl+Alt+E")
        add_act(m_ana, "Inspect Threat Forensics & Mitigations...", self._action_open_threat_forensics, "Ctrl+Shift+T")

        # ── 7. Statistics Menu ──
        m_stat = menubar.addMenu("&Statistics")
        add_act(m_stat, "&IO Graphs & Statistical Analytics...", self._action_open_io_graphs, "Ctrl+Shift+G")
        add_act(m_stat, "&System Call Distribution Breakdown...", self._action_open_plot_dialog, "Ctrl+Shift+B")
        add_act(m_stat, "&DuckDB SQL Forensic Analytics...", self._action_open_sql_console, "Ctrl+Shift+Q")
        m_stat.addSeparator()
        add_act(m_stat, "Security Incident Summary Report...", self._action_open_threat_summary, "Ctrl+Shift+I")

        # ── 8. Tools Menu ──
        m_tools = menubar.addMenu("&Tools")
        add_act(m_tools, "Multi-Attack Benchmark Simulator...", self._action_open_attack_simulator, "Ctrl+Alt+M")
        add_act(m_tools, "AI Copilot Provider Settings...", self._action_open_copilot_settings, "Ctrl+Alt+O")

        # ── 9. Help Menu ──
        m_help = menubar.addMenu("&Help")
        add_act(m_help, "Keyboard &Shortcuts Reference Table...", self._action_open_shortcuts_dialog, "F1")
        add_act(m_help, "KShark Architecture & User Manual...", self._action_open_manual, "F2")
        add_act(m_help, "MITRE ATT&CK Telemetry Reference...", self._action_open_mitre_ref, "F3")
        add_act(m_help, "Check Linux Kernel BTF Compatibility", self._action_check_btf, "F4")
        m_help.addSeparator()
        add_act(m_help, "&About KShark", self._action_open_about, "Shift+F1")

    def _init_docks(self):
        self.dock_copilot = CopilotDock(self)
        self.dock_copilot_title = KSharkDockTitleBar(self.dock_copilot, "AI Security Copilot", self)
        self.dock_copilot.setTitleBarWidget(self.dock_copilot_title)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.dock_copilot)
        self.dock_copilot.hide()

        self.dock_timeline = ThreatTimelineDock(self)
        self.dock_timeline_title = KSharkDockTitleBar(self.dock_timeline, "Threat Timeline & Incident Triage", self)
        self.dock_timeline.setTitleBarWidget(self.dock_timeline_title)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.dock_timeline)
        self.dock_timeline.hide()



    def _wire_signals(self):
        # Bridge -> UI
        self.bridge.eventReceived.connect(self._handle_live_event)
        self.bridge.threatDetected.connect(self._handle_threat_detected)
        self.bridge.statsUpdated.connect(self._handle_stats_updated)
        self.bridge.copilotResponseReceived.connect(self.dock_copilot.append_copilot_response)
        self.dock_timeline.threatMarkerSelected.connect(self._on_timeline_marker_selected)
        self.dock_timeline.filterMainViewRequested.connect(self._on_filter_applied)


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
        self.toolbar.goToPacketTriggered.connect(self._action_goto_event)
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
        self.filter_bar.filterCleared.connect(self._on_filter_cleared)
        self.proxy_model.filterStatsChanged.connect(self._on_filter_stats_changed)



        # Event List Selection -> Detail Tree & Byte View
        self.event_list_view.selectionModel().selectionChanged.connect(self._on_event_row_selected)
        self.event_list_view.verticalScrollBar().sliderMoved.connect(self._on_user_scrollbar_moved)

        # Search & GoTo Frames
        self.goto_frame.goToEventTriggered.connect(self._select_event_number)
        self.search_frame.findTriggered.connect(self._execute_search)

        # Welcome Page Signals
        self.welcome_page.startCaptureRequested.connect(self.start_capture)
        self.welcome_page.startCaptureOnProbe.connect(self.start_capture)
        self.welcome_page.openFileRequested.connect(self._action_open_file)
        self.welcome_page.openRecentFile.connect(self._load_capture_from_path)
        self.welcome_page.configureCaptureRequested.connect(self._action_open_capture_options)
        self.welcome_page.launchScenarioRequested.connect(self._on_launch_scenario)

        # Status Bar Signals
        self.status_bar.timeFormatChanged.connect(self._set_time_format)
        # Edge Restore Bar connections
        self.bottom_restore_bar.toggleTimelineRequested.connect(self.toggle_threat_timeline)
        self.bottom_restore_bar.toggleDissectionRequested.connect(self.toggle_dissection_pane)
        self.bottom_restore_bar.toggleByteViewRequested.connect(self.toggle_byte_view_pane)
        self.right_restore_bar.toggleCopilotRequested.connect(self.toggle_copilot)

        # Dock visibility sync to edge buttons
        self.dock_timeline.visibilityChanged.connect(self.bottom_restore_bar.btn_timeline.set_component_active)
        self.dock_copilot.visibilityChanged.connect(self.right_restore_bar.set_copilot_active)

        # Pane corner minimize buttons
        self.detail_pane.minimizeRequested.connect(self.toggle_dissection_pane)
        self.byte_view.minimizeRequested.connect(self.toggle_byte_view_pane)

        self.dock_copilot.copilotQuerySubmitted.connect(self.bridge.query_copilot)

    def toggle_threat_timeline(self):
        """Toggles Threat Timeline Dock and updates bottom edge restore button."""
        vis = not self.dock_timeline.isVisible()
        self.dock_timeline.setVisible(vis)
        self.bottom_restore_bar.btn_timeline.set_component_active(vis)

    def toggle_copilot(self):
        """Toggles AI Copilot Dock and updates right edge restore button."""
        vis = not self.dock_copilot.isVisible()
        self.dock_copilot.setVisible(vis)
        self.right_restore_bar.set_copilot_active(vis)

    def toggle_dissection_pane(self):
        """Toggles Dissection & Intelligence Pane and updates bottom restore button."""
        vis = not self.detail_pane.isVisible()
        self.detail_pane.setVisible(vis)
        self.bottom_restore_bar.btn_dissection.set_component_active(vis)
        if vis and not self.bottom_splitter.isVisible():
            self.bottom_splitter.show()

    def toggle_byte_view_pane(self):
        """Toggles Hex & Byte Inspector Pane and updates bottom restore button."""
        vis = not self.byte_view.isVisible()
        self.byte_view.setVisible(vis)
        self.bottom_restore_bar.btn_byte.set_component_active(vis)
        if vis and not self.bottom_splitter.isVisible():
            self.bottom_splitter.show()

    def _reset_default_layout(self):
        """Restores the default clean workspace layout with all core panels visible."""
        self.detail_pane.show()
        self.byte_view.show()
        self.bottom_splitter.show()
        self.bottom_restore_bar.btn_dissection.set_component_active(True)
        self.bottom_restore_bar.btn_byte.set_component_active(True)
        self.master_splitter.setSizes([450, 350])
        self.bottom_splitter.setSizes([500, 500])
        self.status_bar.set_status_message("Restored default forensic workspace layout.")

    def _action_open_shortcuts_dialog(self):
        """Opens the enterprise Keyboard Shortcuts Reference dialog."""
        dlg = KeyboardShortcutsDialog(self)
        dlg.exec()

    def _set_theme_direct(self, theme_name: str):
        """Switches theme and persists setting."""
        ThemeManager.instance().set_theme(theme_name)
        self.settings.set_theme(theme_name)
        if hasattr(self, "_theme_actions"):
            for act in self._theme_actions:
                act.setChecked(
                    (theme_name == ThemeManager.THEME_WIRESHARK_DARK and "Dark" in act.text()) or
                    (theme_name == ThemeManager.THEME_WIRESHARK_LIGHT and "Light" in act.text())
                )
        self.status_bar.set_status_message(f"Theme changed to: {theme_name}")


    def _on_status_bar_threats_clicked(self):
        """Jumps to the first threat or applies a threat filter."""
        if self.table_model.threat_count > 0 or self.status_bar.threat_count > 0:
            self.filter_bar.set_filter_text('threat.name != "BENIGN"')
            self.status_bar.set_status_message("Filtered by detected security threats.")
        else:
            self.status_bar.set_status_message("No active security threats detected.")


    def _on_profile_changed(self, profile: str):
        """Switches active capture & filtering profile."""
        self.status_bar.set_status_message(f"Switched to Profile: {profile}")

    def _on_launch_scenario(self, name: str, filter_expr: str):
        """Launches a specialized threat hunting or triage scenario."""
        self.filter_bar.set_filter_text(filter_expr)
        self.start_capture()
        self.status_bar.set_status_message(f"Launched Scenario: {name}")



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
        self.status_bar.set_capture_state("CAPTURING")
        self.status_bar.set_status_message(f"Capturing live Linux OS & eBPF telemetry [{probe_name}]...")

        self.master_splitter.setSizes([400, 300])
        self.bottom_splitter.setSizes([350, 450])

        self.bridge.start_capture(self.settings.get_agent_ws_url())

    def stop_capture(self):
        self.is_capturing = False
        self.toolbar.set_capturing_state(False)
        self.status_bar.set_capture_state("IDLE")
        self.status_bar.set_status_message("Capture stopped.")
        self._live_event_buffer.clear()
        self.status_bar.update_stats(self.table_model.rowCount(), self.proxy_model.rowCount(), self.status_bar.threat_count, 0.0)
        self.bridge.stop_capture()




    def restart_capture(self):
        self.table_model.clear()
        self.detail_pane.clear()
        self.byte_view.clear()
        self.stop_capture()
        QTimer.singleShot(100, self.start_capture)

    def _action_close_capture(self):
        self.stop_capture()
        self.table_model.clear()
        self.detail_pane.clear()
        self.byte_view.clear()
        self.master_stack.setCurrentIndex(0)

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

        # Check max events limit
        if getattr(self, "_max_capture_events", 0) > 0 and total >= self._max_capture_events:
            self.stop_capture()
            self.status_bar.set_status_message(f"Capture stopped: Reached event limit of {self._max_capture_events:,} events.")

        # Check duration limit
        if getattr(self, "_max_capture_duration_s", 0) > 0 and getattr(self, "_capture_start_time", 0) > 0:
            if (time.time() - self._capture_start_time) >= self._max_capture_duration_s:
                self.stop_capture()
                self.status_bar.set_status_message(f"Capture stopped: Reached time duration limit of {self._max_capture_duration_s}s.")

    def _handle_threat_detected(self, alert: dict):
        event_idx = self.table_model.rowCount() - 1
        self.dock_timeline.record_threat_marker(alert, event_index=max(0, event_idx))
        threat_name = alert.get("threat_name") or alert.get("threat_type") or "UNKNOWN"
        pid = alert.get("pid", 0)
        comm = alert.get("comm", "")
        self.status_bar.set_status_message(f"[THREAT DETECTED] {threat_name} on PID {pid} ({comm})", is_error=True)

        if getattr(self, "_stop_on_threat", False):
            self.stop_capture()
            self.status_bar.set_capture_state("FROZEN")
            self.status_bar.set_status_message(f"Capture frozen on detected threat: {threat_name} (PID {pid})", is_error=True)

        if pid > 0:
            self.table_model.mark_pid_threat(pid, threat_name, float(alert.get("confidence", 0.95)))
            if self.proxy_model._filter_ast is not None:
                self.proxy_model.invalidateFilter()

    def _on_timeline_marker_selected(self, event_index: int):
        """Seeks and selects the corresponding row in the main packet table."""
        if event_index < 0 or event_index >= self.table_model.rowCount():
            return

        source_idx = self.table_model.index(event_index, 0)
        proxy_idx = self.proxy_model.mapFromSource(source_idx)

        if proxy_idx.isValid():
            target_row = proxy_idx.row()
            self.event_list_view.selectRow(target_row)
            self.event_list_view.scrollTo(proxy_idx, self.event_list_view.ScrollHint.PositionAtCenter)
            event = self.proxy_model.get_event_at_proxy_row(target_row)
            if event:
                self.detail_pane.set_event(event)
                self.byte_view.set_event_data(event)
        else:
            self.status_bar.set_status_message(f"Selected threat event #{event_index} is hidden by current display filter.", is_error=False)




    def _handle_stats_updated(self, stats: dict):
        total = self.table_model.rowCount()
        displayed = self.proxy_model.rowCount()
        threats = self.table_model.threat_count
        eps = float(stats.get("events_per_second", self.status_bar.eps))
        self.status_bar.update_stats(total, displayed, threats, eps)

    def _on_filter_applied(self, filter_text: str):
        self.proxy_model.set_display_filter(filter_text)
        self.event_list_view.viewport().update()

    def _on_filter_cleared(self):
        self.proxy_model.set_display_filter("")
        self.event_list_view.viewport().update()
        total = self.table_model.rowCount()
        self.status_bar.update_stats(total, total, self.table_model.threat_count, self.status_bar.eps)
        self.status_bar.set_status_message("Display filter cleared — showing all events.")


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

        self.detail_pane.set_event(event)
        self.byte_view.set_event_data(event)
        if event and hasattr(self, "dock_copilot"):
            self.dock_copilot.update_selected_event_context(event)

    def _on_tree_field_selected(self, current: QModelIndex, previous: QModelIndex):
        if not current.isValid():
            return
        range_data = self.detail_tree_model.data(current, Qt.ItemDataRole.UserRole + 1)
        if isinstance(range_data, tuple) and len(range_data) == 2:
            offset, length = range_data
            if offset >= 0 and length > 0:
                self.byte_view.highlight_byte_range(offset, length)
                field_name = str(self.detail_tree_model.data(current, Qt.ItemDataRole.DisplayRole) or "")
                if hasattr(self, "status_bar") and self.status_bar:
                    self.status_bar.set_status_message(f"Selected Field: {field_name} | Offset: 0x{offset:04X} ({offset}), Length: {length} bytes")



    def _select_event_number(self, event_num: int):
        target_row = event_num - 1
        if 0 <= target_row < self.proxy_model.rowCount():
            idx = self.proxy_model.index(target_row, 0)
            self.event_list_view.selectRow(target_row)
            self.event_list_view.scrollTo(idx, QTableView.ScrollHint.PositionAtCenter)
            self.event_list_view.setCurrentIndex(idx)
            self.status_bar.set_status_message(f"Go to Packet #{event_num}")
        else:
            self.status_bar.set_status_message(f"Packet #{event_num} is out of range (1 - {self.proxy_model.rowCount()})", is_error=True)

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
        if not self.search_frame.isHidden():
            self.search_frame.hide()
        else:
            self.goto_frame.hide()
            self.search_frame.show()
            self.search_frame.search_input.setFocus()

    def _action_goto_event(self):
        if not self.goto_frame.isHidden():
            self.goto_frame.hide()
        else:
            self.search_frame.hide()
            self.goto_frame.show_with_focus()

    def _action_toggle_mark(self):
        cur = self.event_list_view.currentIndex().row()
        if cur >= 0:
            src = self.proxy_model.mapToSource(self.proxy_model.index(cur, 0)).row()
            is_marked = self.table_model.toggle_mark(src)
            self.status_bar.set_status_message(f"Event #{src + 1} {'marked ★' if is_marked else 'unmarked'}")

    def _action_edit_comment(self):
        cur = self.event_list_view.currentIndex().row()
        if cur < 0:
            QMessageBox.information(self, "Edit Comment", "Please select an event to add or edit a comment.")
            return

        src_row = self.proxy_model.mapToSource(self.proxy_model.index(cur, 0)).row()
        cur_comment = self.table_model.get_comment(src_row)
        ev = self.proxy_model.get_event_at_proxy_row(cur)
        comm = ev.get("comm", "unknown") if ev else "unknown"
        sc = resolve_syscall_name(ev) if ev else "syscall"
        summary = f"{comm} ({sc})"

        dlg = EditCommentDialog(src_row + 1, cur_comment, summary, self)
        if dlg.exec():
            new_comment = dlg.get_comment()
            self.table_model.set_comment(src_row, new_comment)
            self.status_bar.set_status_message(f"Comment updated for Event #{src_row + 1}")

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
        if path:
            self._load_capture_from_path(path)

    def _load_capture_from_path(self, path: str):
        if not path or not os.path.exists(path):
            return

        self._current_file_path = path
        self.stop_capture()
        self.table_model.clear()
        self.detail_pane.clear()
        self.byte_view.clear()

        # Save to recent files in QSettings
        settings = QSettings("KShark", "WelcomePage")
        recent = settings.value("recent_files", [])
        if not isinstance(recent, list):
            recent = []
        if path in recent:
            recent.remove(path)
        recent.insert(0, path)
        settings.setValue("recent_files", recent[:10])

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
        dlg = KSharkIOGraphDialog(self, bridge=self.bridge, table_model=self.table_model)
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
        self._max_capture_events = opts.get("max_events", 0)
        self._max_capture_duration_s = opts.get("max_duration_s", 0)
        self._stop_on_threat = opts.get("stop_on_threat", False)
        self.auto_scroll = opts.get("autoscroll", True)
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

    def apply_font_size(self, size: int):
        """Applies uniform font scaling across table, tree, and byte view panes and persists setting."""
        self._zoom_level = max(6, min(24, int(size)))
        self.settings.set_font_size(self._zoom_level)
        font = get_monospace_font(size=self._zoom_level)

        # 1. Update Event Table
        if hasattr(self, "table_model"):
            self.table_model.set_font_size(self._zoom_level)
        if hasattr(self, "event_list_view"):
            self.event_list_view.setFont(font)
            row_height = max(18, int(self._zoom_level * 2.2))
            self.event_list_view.verticalHeader().setDefaultSectionSize(row_height)

        # 2. Update Dissection Pane & Tree
        if hasattr(self, "detail_pane") and hasattr(self.detail_pane, "set_font_size"):
            self.detail_pane.set_font_size(self._zoom_level)
        elif hasattr(self, "detail_tree_model"):
            self.detail_tree_model.set_font_size(self._zoom_level)
        if hasattr(self, "detail_tree_view"):
            self.detail_tree_view.setFont(font)

        # 3. Update Byte Payload Inspector Pane
        if hasattr(self, "byte_view") and hasattr(self.byte_view, "set_font_size"):
            self.byte_view.set_font_size(self._zoom_level)
        elif hasattr(self, "byte_view"):
            self.byte_view.setFont(font)

        # 4. Status message
        pct = int((self._zoom_level / 9.0) * 100)
        self.status_bar.set_status_message(f"Dissection & Telemetry Font Size: {self._zoom_level} pt ({pct}%)")

    def _apply_zoom(self):
        self.apply_font_size(self._zoom_level)

    def _action_zoom_in(self):
        if self._zoom_level < 24:
            self.apply_font_size(self._zoom_level + 1)

    def _action_zoom_out(self):
        if self._zoom_level > 6:
            self.apply_font_size(self._zoom_level - 1)

    def _action_zoom_100(self):
        self.apply_font_size(9)

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
    def _set_time_format(self, fmt: int):
        self.table_model.set_time_format(fmt)
        self.event_list_view.viewport().update()

    def _show_header_context_menu(self, pos):
        header = self.event_list_view.horizontalHeader()
        col_idx = header.logicalIndexAt(pos)
        if col_idx < 0:
            return

        menu = QMenu(self)
        col_name = EventTableModel.COLUMNS[col_idx][0]

        # 1. Sort options
        act_asc = menu.addAction(f"Sort by '{col_name}' Ascending (Lower to Higher)")
        act_asc.triggered.connect(lambda: self.event_list_view.sortByColumn(col_idx, Qt.SortOrder.AscendingOrder))

        act_desc = menu.addAction(f"Sort by '{col_name}' Descending (Higher to Lower)")
        act_desc.triggered.connect(lambda: self.event_list_view.sortByColumn(col_idx, Qt.SortOrder.DescendingOrder))

        menu.addSeparator()

        # 2. Resize actions
        act_fit = menu.addAction(f"Resize Column '{col_name}' to Fit")
        act_fit.triggered.connect(lambda: self.event_list_view.resizeColumnToContents(col_idx))

        act_fit_all = menu.addAction("Resize All Columns to Fit")
        act_fit_all.triggered.connect(self.event_list_view.resizeColumnsToContents)

        menu.addSeparator()

        # 3. Time format submenu
        m_time = menu.addMenu("Time Display Format")
        tf_opts = [
            ("Seconds Since Capture Start (00:00.123456)", EventTableModel.TIME_FMT_RELATIVE),
            ("Time of Day (HH:MM:SS.ffffff)", EventTableModel.TIME_FMT_TIME_OF_DAY),
            ("Date and Time (YYYY-MM-DD HH:MM:SS)", EventTableModel.TIME_FMT_DATE_TIME),
            ("Unix Epoch Timestamp", EventTableModel.TIME_FMT_EPOCH),
        ]
        for tf_label, tf_val in tf_opts:
            a = m_time.addAction(tf_label)
            a.setCheckable(True)
            a.setChecked(self.table_model.time_format == tf_val)
            a.triggered.connect(lambda checked, v=tf_val: self._set_time_format(v))

        # 4. Column Visibility Submenu
        m_cols = menu.addMenu("Displayed Columns")
        for idx, (c_name, _) in enumerate(EventTableModel.COLUMNS):
            a_col = m_cols.addAction(c_name)
            a_col.setCheckable(True)
            a_col.setChecked(not header.isSectionHidden(idx))
            a_col.triggered.connect(lambda checked, c=idx: header.setSectionHidden(c, not checked))

        menu.exec(header.mapToGlobal(pos))

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
        act_forensic = menu.addAction("Inspect Threat Forensics...")
        act_forensic.setIcon(KSharkIcons.tab_threat())
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
        m_follow.addAction(f"Follow Process I/O Stream (PID {pid})...", lambda: self._open_follow_stream_dialog(FollowStreamDialog.MODE_PROCESS))
        m_follow.addAction(f"Follow Parent & Child Lineage...", lambda: self._apply_filter_expr(f'proc.pid == {pid} or proc.pid == {ppid} or proc.ppid == {pid}', "replace"))
        if dst_ip and dst_ip != "0.0.0.0":
            m_follow.addAction(f"Follow Network Socket Stream ({dst_ip}:{dst_port})...", lambda: self._open_follow_stream_dialog(FollowStreamDialog.MODE_NETWORK))
        if file_path and file_path != "-":
            m_follow.addAction(f"Follow File Access Lifecycle ({os.path.basename(file_path)})...", lambda: self._open_follow_stream_dialog(FollowStreamDialog.MODE_FILE))

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

        # 6. Mark / Comment / Time Ref
        src_row = self.proxy_model.mapToSource(proxy_idx).row()
        menu.addAction("Mark / Unmark Event (Ctrl+M)", self._action_toggle_mark)
        menu.addAction("Add / Edit Event Comment... (Ctrl+Shift+N)", self._action_edit_comment)
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

    def _action_export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Dissected Events as CSV", "kshark_telemetry.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                headers = [col[0] for col in EventTableModel.COLUMNS] + ["Forensic Comment", "Marked"]
                f.write(",".join(headers) + "\n")
                for r in range(self.proxy_model.rowCount()):
                    src_r = self.proxy_model.mapToSource(self.proxy_model.index(r, 0)).row()
                    row_texts = [str(self.proxy_model.data(self.proxy_model.index(r, c), Qt.ItemDataRole.DisplayRole) or "").replace(",", ";") for c in range(len(EventTableModel.COLUMNS))]
                    row_texts.append(self.table_model.get_comment(src_r).replace(",", ";"))
                    row_texts.append("YES" if src_r in self.table_model._marked_rows else "NO")
                    f.write(",".join(row_texts) + "\n")
            QMessageBox.information(self, "Export Successful", f"Exported {self.proxy_model.rowCount():,} events with forensic annotations to:\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "Export Failed", f"Could not export CSV: {e}")

    def _action_export_jsonl(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Dissected Events as JSON Lines", "kshark_telemetry.jsonl", "JSON Lines (*.jsonl)")
        if not path:
            return
        try:
            import json
            with open(path, "w", encoding="utf-8") as f:
                for r in range(self.proxy_model.rowCount()):
                    ev = self.proxy_model.get_event_at_proxy_row(r)
                    if ev:
                        ev_copy = dict(ev)
                        src_r = self.proxy_model.mapToSource(self.proxy_model.index(r, 0)).row()
                        if src_r in self.table_model._comments:
                            ev_copy["forensic_comment"] = self.table_model.get_comment(src_r)
                        if src_r in self.table_model._marked_rows:
                            ev_copy["is_marked"] = True
                        f.write(json.dumps(ev_copy) + "\n")
            QMessageBox.information(self, "Export Successful", f"Exported {self.proxy_model.rowCount():,} events with forensic annotations to:\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "Export Failed", f"Could not export JSONL: {e}")

    def _get_current_selected_event(self) -> Optional[dict]:
        indexes = self.event_list_view.selectionModel().selectedRows()
        if indexes:
            return self.proxy_model.get_event_at_proxy_row(indexes[0].row())
        return None

    def _copy_selected_csv(self):
        indexes = self.event_list_view.selectionModel().selectedRows()
        if not indexes:
            return
        row = indexes[0].row()
        texts = [str(self.proxy_model.data(self.proxy_model.index(row, c), Qt.ItemDataRole.DisplayRole) or "") for c in range(len(EventTableModel.COLUMNS))]
        QApplication.clipboard().setText(",".join(texts))

    def _copy_selected_json(self):
        ev = self._get_current_selected_event()
        if ev:
            import json
            QApplication.clipboard().setText(json.dumps(ev, indent=2))

    def _copy_selected_proc(self):
        ev = self._get_current_selected_event()
        if ev:
            QApplication.clipboard().setText(str(ev.get("comm", "")))

    def _copy_selected_pid(self):
        ev = self._get_current_selected_event()
        if ev:
            QApplication.clipboard().setText(str(ev.get("pid", "")))

    def _copy_selected_target(self):
        ev = self._get_current_selected_event()
        if ev:
            tgt = ev.get("file_path") or ev.get("filename") or ev.get("exe_path") or ev.get("dst_ip") or ""
            QApplication.clipboard().setText(str(tgt))

    def _copy_selected_tree(self):
        ev = self._get_current_selected_event()
        if ev:
            lines = [f"{k}: {v}" for k, v in ev.items()]
            QApplication.clipboard().setText("\n".join(lines))

    def _action_clear_all_events(self):
        reply = QMessageBox.question(self, "Clear All Events", "Are you sure you want to clear all captured telemetry events?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.table_model.beginResetModel()
            self.table_model._events.clear()
            self.table_model._row_texts.clear()
            self.table_model._row_bg_brushes.clear()
            self.table_model._row_fg_brushes.clear()
            self.table_model._threat_count = 0
            self.table_model.endResetModel()
            self.dock_timeline.clear_feed()
            self.status_bar.update_stats(0, 0, 0, 0.0)

    def _action_find_next(self):
        if hasattr(self, "search_frame") and self.search_frame.isVisible():
            self.search_frame._on_find_next()
        else:
            self._action_find()

    def _action_find_prev(self):
        if hasattr(self, "search_frame") and self.search_frame.isVisible():
            self.search_frame._on_find_prev()
        else:
            self._action_find()

    def _go_next_threat(self):
        cur_row = self.event_list_view.currentIndex().row() if self.event_list_view.currentIndex().isValid() else 0
        for r in range(cur_row + 1, self.proxy_model.rowCount()):
            ev = self.proxy_model.get_event_at_proxy_row(r)
            if ev and str(ev.get("threat_name", "BENIGN")).upper() not in ("BENIGN", "", "NONE"):
                idx = self.proxy_model.index(r, 0)
                self.event_list_view.selectRow(r)
                self.event_list_view.scrollTo(idx)
                return
        self.status_bar.set_status_message("No further security anomalies found downwards.", is_error=False)

    def _go_prev_threat(self):
        cur_row = self.event_list_view.currentIndex().row() if self.event_list_view.currentIndex().isValid() else self.proxy_model.rowCount()
        for r in range(cur_row - 1, -1, -1):
            ev = self.proxy_model.get_event_at_proxy_row(r)
            if ev and str(ev.get("threat_name", "BENIGN")).upper() not in ("BENIGN", "", "NONE"):
                idx = self.proxy_model.index(r, 0)
                self.event_list_view.selectRow(r)
                self.event_list_view.scrollTo(idx)
                return
        self.status_bar.set_status_message("No further security anomalies found upwards.", is_error=False)

    def _action_refresh_probes(self):
        self.status_bar.set_status_message("Rescanned host eBPF tracepoints and socket interfaces. Probes active.", is_error=False)

    def _action_open_filter_presets(self):
        QMessageBox.information(self, "Display Filter Expressions", "Quick Filters Available on Toolbar:\n\n• Threats: threat_name != 'BENIGN'\n• Root Operations: user.uid == 0\n• Sockets: evt.type in ('connect', 'bind')\n• Exec Spawns: evt.type == 'execve'\n• File Modifications: file.op == 'WRITE'")

    def _apply_filter_selected(self):
        ev = self._get_current_selected_event()
        if ev:
            comm = ev.get("comm", "")
            sc = ev.get("syscall", "")
            self._apply_filter_expr(f'proc.name == "{comm}" and evt.type == "{sc}"', "replace")

    def _apply_filter_not_selected(self):
        ev = self._get_current_selected_event()
        if ev:
            comm = ev.get("comm", "")
            self._apply_filter_expr(f'proc.name != "{comm}"', "replace")

    def _apply_filter_and_selected(self):
        ev = self._get_current_selected_event()
        if ev:
            comm = ev.get("comm", "")
            self._apply_filter_expr(f'proc.name == "{comm}"', "and")

    def _apply_filter_or_selected(self):
        ev = self._get_current_selected_event()
        if ev:
            comm = ev.get("comm", "")
            self._apply_filter_expr(f'proc.name == "{comm}"', "or")

    def _prep_filter_selected(self):
        ev = self._get_current_selected_event()
        if ev:
            comm = ev.get("comm", "")
            sc = ev.get("syscall", "")
            self._prepare_filter_expr(f'proc.name == "{comm}" and evt.type == "{sc}"', "replace")

    def _prep_filter_not_selected(self):
        ev = self._get_current_selected_event()
        if ev:
            comm = ev.get("comm", "")
            self._prepare_filter_expr(f'proc.name != "{comm}"', "replace")

    def _prep_filter_and_selected(self):
        ev = self._get_current_selected_event()
        if ev:
            comm = ev.get("comm", "")
            self._prepare_filter_expr(f'proc.name == "{comm}"', "and")

    def _prep_filter_or_selected(self):
        ev = self._get_current_selected_event()
        if ev:
            comm = ev.get("comm", "")
            self._prepare_filter_expr(f'proc.name == "{comm}"', "or")

    def _open_follow_stream_dialog(self, mode: str = FollowStreamDialog.MODE_PROCESS):
        ev = self._get_current_selected_event()
        if not ev and self.proxy_model.rowCount() > 0:
            ev = self.proxy_model.get_event_at_proxy_row(0)

        if not ev:
            QMessageBox.information(self, "Follow Stream", "No event selected to follow.")
            return

        events = self.table_model._events if hasattr(self.table_model, "_events") else []
        dlg = FollowStreamDialog(ev, events, mode=mode, parent=self)
        dlg.filterApplied.connect(lambda expr: self._apply_filter_expr(expr, "replace"))
        dlg.exec()

    def _follow_process_flow(self):
        self._open_follow_stream_dialog(FollowStreamDialog.MODE_PROCESS)

    def _follow_parent_child_lineage(self):
        ev = self._get_current_selected_event()
        if ev:
            pid = ev.get("pid", 0)
            ppid = ev.get("ppid", 1)
            self._apply_filter_expr(f'proc.pid == {pid} or proc.ppid == {pid} or proc.pid == {ppid}', "replace")

    def _follow_tcp_stream(self):
        self._open_follow_stream_dialog(FollowStreamDialog.MODE_NETWORK)

    def _follow_file_history(self):
        self._open_follow_stream_dialog(FollowStreamDialog.MODE_FILE)

    def _action_open_threat_forensics(self):
        ev = self._get_current_selected_event()
        if not ev and self.proxy_model.rowCount() > 0:
            ev = self.proxy_model.get_event_at_proxy_row(0)
        if ev:
            dlg = ThreatForensicsDialog(ev, self)
            dlg.exec()
        else:
            QMessageBox.information(self, "Threat Forensics", "No telemetry event available to inspect.")

    def _action_open_expert_info(self):
        events = self.table_model._events if hasattr(self.table_model, "_events") else []
        dlg = ExpertInfoDialog(events, self)
        dlg.eventSelected.connect(self._select_event_number)
        dlg.filterApplied.connect(lambda expr: self._apply_filter_expr(expr, "replace"))
        dlg.exec()

    def _action_open_threat_summary(self):
        cnt = self.table_model.threat_count
        QMessageBox.information(self, "Security Incident Summary", f"Active Capture Session Security Summary:\n\n• Total Events: {self.table_model.rowCount():,}\n• Anomalies Detected: {cnt:,}\n• Active Consensus Mode: Dual-Ensemble ML + Behavioral Rules\n• eBPF LSM Hooks: Active")

    def _action_open_attack_simulator(self):
        QMessageBox.information(self, "Attack Simulator", "Multi-Attack Benchmark Simulator is available in scripts/:\n\nExecute safely in terminal:\npython3 scripts/multi_attack_simulator.py\n\nSimulates Ransomware, Reverse Shell C2, Shadow Credential Dump, and Port Scan Probes.")

    def _action_open_copilot_settings(self):

        self.dock_copilot.show()
        self.dock_copilot.raise_()
        self.dock_copilot.input_field.setFocus()

    def _action_open_manual(self):
        QMessageBox.information(self, "KShark Documentation", "KShark Architecture & Operations Manual:\n\n• 3-Pane Dissection Model (Event Table, 5-Layer Tree, 5-Tab Hex Inspector)\n• Real-Time Display Filter Syntax: proc.name, evt.type, user.uid, threat.name\n• Dual-Model ML Consensus Engine (Random Forest + XGBoost + Isolation Forest)")

    def _action_open_mitre_ref(self):
        QMessageBox.information(self, "MITRE ATT&CK Matrix", "Supported MITRE Telemetry Techniques:\n\n• T1486: Data Encrypted for Impact (Ransomware)\n• T1071: Application Layer Protocol (C2 Reverse Shell)\n• T1003.008: OS Credential Dumping (/etc/shadow)\n• T1046: Network Service Scanning (Port Probes)\n• T1547.006: Kernel Rootkit Modules\n• T1611: Container Escape")

    def _action_check_btf(self):
        btf_path = "/sys/kernel/btf/vmlinux"
        if os.path.exists(btf_path):
            size_kb = os.path.getsize(btf_path) // 1024
            QMessageBox.information(self, "Linux Kernel BTF Support", f"✅ BTF (BPF Type Format) is AVAILABLE on this host!\n\nPath: {btf_path}\nSize: {size_kb:,} KB\nKernel CO-RE (Compile Once - Run Everywhere) is fully functional.")
        else:
            QMessageBox.warning(self, "Linux Kernel BTF Support", "⚠️ /sys/kernel/btf/vmlinux not found. Operating with fallback tracepoint hooks.")


    def closeEvent(self, event):
        self.stop_capture()
        self.settings.set_window_geometry(self.saveGeometry())
        self.settings.set_master_splitter_state(self.master_splitter.saveState())
        self.settings.set_bottom_splitter_state(self.bottom_splitter.saveState())
        super().closeEvent(event)


# Standard alias
MainWindow = KSharkMainWindow

