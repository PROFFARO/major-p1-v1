"""
KShark Capture Options & Interfaces Dialog — Multi-source kernel telemetry configuration.
Engineered for Cybersecurity Engineers, SOC Analysts, and Network Administrators.
Features:
- Discovers and configures eBPF probes from bpf/probes/ and local OS collectors
- Live Interface selector (all, eth0, wlan0, lo, docker0, tun0)
- Configurable RingBuffer Map sizes (16MB to 128MB)
- Automatic stop triggers (max events, max duration, freeze on first threat)
- ML Threat Ensemble & Behavioral Falco Rule toggles with sensitivity slider
"""

import os
from pathlib import Path
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget,
    QLabel, QCheckBox, QLineEdit, QSpinBox, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QGroupBox, QFormLayout, QComboBox,
    QSlider, QFrame, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon, QFont

from kshark.core.theme import ThemeManager, get_monospace_font, get_ui_font
from kshark.resources.icons import KSharkIcons


class CaptureOptionsDialog(QDialog):
    """
    Dialog for configuring telemetry capture sources, interfaces, limits, and ML inference engines.
    """

    startCaptureRequested = pyqtSignal(dict)

    def __init__(self, parent=None, current_ws_url: str = "ws://localhost:8900/ws"):
        super().__init__(parent)
        self.setWindowTitle("KShark · Capture Interfaces & Kernel Probes")
        self.resize(800, 540)
        self.ws_url = current_ws_url
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        self.tabs = QTabWidget(self)
        self.tabs.setFont(get_ui_font(size=8, bold=True))

        # Tab 1: Telemetry Interfaces & Kernel Probes from bpf/probes/
        self.tab_interfaces = self._build_interfaces_tab()
        self.tabs.addTab(self.tab_interfaces, KSharkIcons.capture_options(), "Input Probes && Interfaces")

        # Tab 2: Capture Limits & Stop Triggers
        self.tab_limits = self._build_limits_tab()
        self.tabs.addTab(self.tab_limits, KSharkIcons.capture_stop(), "Capture Limits && Stop Triggers")

        # Tab 3: Security & ML Consensus
        self.tab_security = self._build_security_tab()
        self.tabs.addTab(self.tab_security, KSharkIcons.tab_threat(), "ML Engine && Behavioral Rules")

        main_layout.addWidget(self.tabs, stretch=1)

        # Bottom Button Bar
        btn_layout = QHBoxLayout()
        btn_layout.setContentsMargins(0, 4, 0, 0)
        btn_layout.setSpacing(8)
        btn_layout.addStretch()

        self.btn_close = QPushButton("Cancel", self)
        self.btn_close.setFont(get_ui_font(size=9))
        self.btn_close.setFixedHeight(28)
        self.btn_close.clicked.connect(self.reject)
        btn_layout.addWidget(self.btn_close)

        self.btn_start = QPushButton("Start Capture", self)
        self.btn_start.setFont(get_ui_font(size=9, bold=True))
        self.btn_start.setFixedHeight(28)
        c = ThemeManager.instance().get_palette_colors()
        self.btn_start.setStyleSheet(f"""
            QPushButton {{
                background-color: {c['green_btn']};
                border: 1px solid {c['green_btn_border']};
                border-radius: 4px;
                color: white;
                padding: 4px 20px;
            }}
            QPushButton:hover {{
                background-color: {c['green_btn_hover']};
            }}
            QPushButton:pressed {{
                background-color: #0D6640;
            }}
        """)
        self.btn_start.clicked.connect(self._on_start)
        btn_layout.addWidget(self.btn_start)

        main_layout.addLayout(btn_layout)

    def _build_interfaces_tab(self) -> QWidget:
        widget = QWidget(self)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        lbl = QLabel("Active Linux kernel telemetry sources and eBPF probes from <code>bpf/probes/</code>:")
        lbl.setFont(get_ui_font(size=8))
        layout.addWidget(lbl)

        # Discovered probe metadata
        probes_meta = [
            {
                "name": "sys_tracer",
                "obj": "sys_tracer.bpf.o",
                "type": "Tracepoints",
                "desc": "System Call Hooks (execve, openat, connect, clone, exit)",
                "status": "Ready (eBPF)",
            },
            {
                "name": "net_filter",
                "obj": "net_filter.bpf.o",
                "type": "Socket / TC",
                "desc": "Kernel Socket Connect & Packet Layer Flow Inspection",
                "status": "Ready (eBPF)",
            },
            {
                "name": "lsm_enforcer",
                "obj": "lsm_enforcer.bpf.o",
                "type": "BPF LSM",
                "desc": "Linux Security Module MAC Hooks & Privilege Gatekeeper",
                "status": "Ready (eBPF)",
            },
            {
                "name": "ssl_tracer",
                "obj": "ssl_tracer.bpf.o",
                "type": "uprobe",
                "desc": "OpenSSL / GnuTLS Plaintext Payload & Handshake Monitor",
                "status": "Ready (eBPF)",
            },
            {
                "name": "perf_profiler",
                "obj": "perf_profiler.bpf.o",
                "type": "perf_event",
                "desc": "Continuous CPU Cycle & Kernel Stack Trace Sampling",
                "status": "Ready (eBPF)",
            },
            {
                "name": "tetragon_lsm",
                "obj": "tetragon_lsm.bpf.o",
                "type": "Tetragon LSM",
                "desc": "Extended Container & Namespace Security Isolation",
                "status": "Ready (eBPF)",
            },
            {
                "name": "proc_collector",
                "obj": "/proc",
                "type": "Host OS /proc",
                "desc": "Linux Native Process Life-Cycles & FD State Tracker",
                "status": "Active (Local)",
            },
            {
                "name": "socket_collector",
                "obj": "/proc/net",
                "type": "Host OS Sockets",
                "desc": "Linux /proc/net/tcp & /proc/net/udp Socket Flow Tracker",
                "status": "Active (Local)",
            },
        ]

        bpf_dir = Path(__file__).resolve().parent.parent.parent / "bpf" / "probes"

        self.table_probes = QTableWidget(len(probes_meta), 5, self)
        self.table_probes.setHorizontalHeaderLabels(["Active", "Probe Name", "Hook Type", "Size / Source", "Description"])
        self.table_probes.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_probes.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_probes.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_probes.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_probes.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table_probes.verticalHeader().setVisible(False)
        self.table_probes.setAlternatingRowColors(True)
        self.table_probes.setFont(get_ui_font(size=8))

        for row, p in enumerate(probes_meta):
            chk = QCheckBox(self)
            chk.setChecked(True)
            self.table_probes.setCellWidget(row, 0, chk)

            # Probe name
            item_name = QTableWidgetItem(p["name"])
            item_name.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            self.table_probes.setItem(row, 1, item_name)

            # Hook type
            item_type = QTableWidgetItem(p["type"])
            item_type.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            self.table_probes.setItem(row, 2, item_type)

            # Size / Source
            obj_path = bpf_dir / p["obj"]
            if obj_path.exists():
                size_kb = obj_path.stat().st_size / 1024
                size_str = f"{size_kb:.0f} KB ({p['obj']})"
            else:
                size_str = p["obj"]

            item_size = QTableWidgetItem(size_str)
            item_size.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            self.table_probes.setItem(row, 3, item_size)

            # Description
            item_desc = QTableWidgetItem(p["desc"])
            item_desc.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            self.table_probes.setItem(row, 4, item_desc)

        layout.addWidget(self.table_probes, stretch=1)

        # Probe selection buttons bar
        bar_probes = QHBoxLayout()
        btn_sel_all = QPushButton("Select All")
        btn_sel_all.setFont(get_ui_font(size=8))
        btn_sel_all.setFixedHeight(22)
        btn_sel_all.clicked.connect(lambda: self._set_all_probes(True))

        btn_desel_all = QPushButton("Deselect All")
        btn_desel_all.setFont(get_ui_font(size=8))
        btn_desel_all.setFixedHeight(22)
        btn_desel_all.clicked.connect(lambda: self._set_all_probes(False))

        bar_probes.addWidget(btn_sel_all)
        bar_probes.addWidget(btn_desel_all)
        bar_probes.addStretch()

        layout.addLayout(bar_probes)

        # Lower Config Controls
        grp_hw = QGroupBox("Hardware & Socket Interface Settings")
        grp_hw.setFont(get_ui_font(size=8, bold=True))
        f_hw = QFormLayout(grp_hw)
        f_hw.setContentsMargins(8, 8, 8, 8)
        f_hw.setSpacing(6)

        # Network interface dropdown
        self.combo_net_iface = QComboBox(self)
        self.combo_net_iface.setFont(get_ui_font(size=8))
        # Dynamically discover host network interfaces
        ifaces = ["all (Any Active Network Interface)"]
        net_dir = Path("/sys/class/net")
        if net_dir.exists():
            for iface in sorted(net_dir.iterdir()):
                name = iface.name
                operstate = "unknown"
                try:
                    operstate = (iface / "operstate").read_text().strip()
                except (OSError, PermissionError):
                    pass
                ifaces.append(f"{name} ({operstate})")
        self.combo_net_iface.addItems(ifaces)
        f_hw.addRow("Target Network Interface:", self.combo_net_iface)

        # Ring buffer map size
        self.combo_ringbuf = QComboBox(self)
        self.combo_ringbuf.setFont(get_ui_font(size=8))
        self.combo_ringbuf.addItems(["64 MB (Recommended / Default)", "16 MB (Low Memory Footprint)", "32 MB (Standard)", "128 MB (High-Throughput Burst)"])
        f_hw.addRow("eBPF RingBuffer Map Capacity:", self.combo_ringbuf)

        # Connection URL
        self.edit_ws_url = QLineEdit(self.ws_url, self)
        self.edit_ws_url.setFont(get_monospace_font(size=9))
        f_hw.addRow("Telemetry Agent WebSocket:", self.edit_ws_url)

        layout.addWidget(grp_hw)

        return widget

    def _set_all_probes(self, checked: bool):
        for row in range(self.table_probes.rowCount()):
            chk = self.table_probes.cellWidget(row, 0)
            if isinstance(chk, QCheckBox):
                chk.setChecked(checked)

    def _build_limits_tab(self) -> QWidget:
        widget = QWidget(self)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Card 1: Stop Conditions
        group_stop = QGroupBox("Automatic Capture Stop Conditions (0 = Unlimited)", self)
        group_stop.setFont(get_ui_font(size=8, bold=True))
        form = QFormLayout(group_stop)
        form.setContentsMargins(8, 8, 8, 8)
        form.setSpacing(6)

        self.chk_limit_events = QCheckBox("Stop capture after event threshold:", self)
        self.chk_limit_events.setFont(get_ui_font(size=8))
        self.spin_max_events = QSpinBox(self)
        self.spin_max_events.setFont(get_monospace_font(size=8))
        self.spin_max_events.setRange(100, 10000000)
        self.spin_max_events.setValue(50000)
        self.spin_max_events.setSuffix(" events")
        form.addRow(self.chk_limit_events, self.spin_max_events)

        self.chk_limit_duration = QCheckBox("Stop capture after time duration:", self)
        self.chk_limit_duration.setFont(get_ui_font(size=8))
        self.spin_max_duration = QSpinBox(self)
        self.spin_max_duration.setFont(get_monospace_font(size=8))
        self.spin_max_duration.setRange(5, 86400)
        self.spin_max_duration.setValue(300)
        self.spin_max_duration.setSuffix(" seconds")
        form.addRow(self.chk_limit_duration, self.spin_max_duration)

        self.chk_stop_on_threat = QCheckBox("Immediately freeze & stop capture on first CRITICAL threat detection", self)
        self.chk_stop_on_threat.setFont(get_ui_font(size=8))
        self.chk_stop_on_threat.setStyleSheet("color: #E67E22; font-weight: bold;")
        form.addRow(self.chk_stop_on_threat)

        layout.addWidget(group_stop)

        # Card 2: Display & Viewport Buffer Management
        group_disp = QGroupBox("Live Display & In-Memory Buffer Management", self)
        group_disp.setFont(get_ui_font(size=8, bold=True))
        form_disp = QFormLayout(group_disp)
        form_disp.setContentsMargins(8, 8, 8, 8)
        form_disp.setSpacing(6)

        self.chk_autoscroll = QCheckBox("Automatically scroll event list to latest packet during capture", self)
        self.chk_autoscroll.setFont(get_ui_font(size=8))
        self.chk_autoscroll.setChecked(True)
        form_disp.addRow(self.chk_autoscroll)

        self.chk_resolve_syscalls = QCheckBox("Translate x86_64 kernel syscall IDs to human-readable names", self)
        self.chk_resolve_syscalls.setFont(get_ui_font(size=8))
        self.chk_resolve_syscalls.setChecked(True)
        form_disp.addRow(self.chk_resolve_syscalls)

        self.chk_stream_analytics = QCheckBox("Enable real-time sliding window statistical analytics & IO Graphs", self)
        self.chk_stream_analytics.setFont(get_ui_font(size=8))
        self.chk_stream_analytics.setChecked(True)
        form_disp.addRow(self.chk_stream_analytics)

        layout.addWidget(group_disp)
        layout.addStretch()

        return widget

    def _build_security_tab(self) -> QWidget:
        widget = QWidget(self)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Card 1: Machine Learning Ensemble
        group_ml = QGroupBox("Real-Time Machine Learning Threat Ensemble", self)
        group_ml.setFont(get_ui_font(size=8, bold=True))
        v_ml = QVBoxLayout(group_ml)
        v_ml.setContentsMargins(8, 8, 8, 8)
        v_ml.setSpacing(6)

        self.chk_ml_active = QCheckBox("Enable 12-dimensional sliding window ML threat detection", self)
        self.chk_ml_active.setFont(get_ui_font(size=8, bold=True))
        self.chk_ml_active.setChecked(True)
        v_ml.addWidget(self.chk_ml_active)

        self.chk_rf = QCheckBox("Random Forest Multi-Class Threat Classifier (150 trees)", self)
        self.chk_rf.setFont(get_ui_font(size=8))
        self.chk_rf.setChecked(True)
        v_ml.addWidget(self.chk_rf)

        self.chk_xgb = QCheckBox("XGBoost Dual-Model Consensus Validator (150 estimators)", self)
        self.chk_xgb.setFont(get_ui_font(size=8))
        self.chk_xgb.setChecked(True)
        v_ml.addWidget(self.chk_xgb)

        self.chk_iso = QCheckBox("Isolation Forest Zero-Day Anomaly Detection (5% contamination)", self)
        self.chk_iso.setFont(get_ui_font(size=8))
        self.chk_iso.setChecked(True)
        v_ml.addWidget(self.chk_iso)

        # Sensitivity Slider
        h_slider = QHBoxLayout()
        lbl_sens = QLabel("Detection Confidence Threshold:")
        lbl_sens.setFont(get_ui_font(size=8))
        
        self.slider_sens = QSlider(Qt.Orientation.Horizontal)
        self.slider_sens.setRange(50, 99)
        self.slider_sens.setValue(80)
        
        self.lbl_sens_val = QLabel("80%")
        self.lbl_sens_val.setFont(get_monospace_font(size=8, bold=True))
        self.lbl_sens_val.setStyleSheet("color: #0E9AA7;")
        self.slider_sens.valueChanged.connect(lambda v: self.lbl_sens_val.setText(f"{v}%"))

        h_slider.addWidget(lbl_sens)
        h_slider.addWidget(self.slider_sens, stretch=1)
        h_slider.addWidget(self.lbl_sens_val)
        v_ml.addLayout(h_slider)

        layout.addWidget(group_ml)

        # Card 2: Behavioral Rules Engine
        group_rules = QGroupBox("Behavioral Threat Signature Rules", self)
        group_rules.setFont(get_ui_font(size=8, bold=True))
        v_rules = QVBoxLayout(group_rules)
        v_rules.setContentsMargins(8, 8, 8, 8)
        v_rules.setSpacing(4)

        rules = [
            ("Rule 1: /etc/shadow & Sensitive Credential Harvesting (T1003.008)", True),
            ("Rule 2: Interactive Reverse Shell C2 Outbound Socket (T1059.004)", True),
            ("Rule 3: Mass High-Frequency File Encryption Burst (T1486)", True),
            ("Rule 4: SUID & Root Privilege Escalation (T1068)", True),
            ("Rule 5: Cryptominer Resource Hijacking Loop (T1496)", True),
            ("Rule 6: In-Memory Anonymous memfd_create Execution (T1620)", True),
            ("Rule 7: Container Escape via Host Namespace Switch (T1611)", True),
        ]
        self.rule_checkboxes = []
        for r_title, default_state in rules:
            chk_r = QCheckBox(r_title, self)
            chk_r.setFont(get_ui_font(size=8))
            chk_r.setChecked(default_state)
            self.rule_checkboxes.append(chk_r)
            v_rules.addWidget(chk_r)

        layout.addWidget(group_rules)
        layout.addStretch()

        return widget

    def _on_start(self):
        # Collect enabled probes
        enabled_probes = []
        for row in range(self.table_probes.rowCount()):
            chk = self.table_probes.cellWidget(row, 0)
            if chk and chk.isChecked():
                item = self.table_probes.item(row, 1)
                if item:
                    enabled_probes.append(item.text())

        # Collect enabled behavioral rules
        enabled_rules = []
        for chk_r in self.rule_checkboxes:
            if chk_r.isChecked():
                enabled_rules.append(chk_r.text())

        opts = {
            "ws_url": self.edit_ws_url.text().strip(),
            "enabled_probes": enabled_probes,
            "net_interface": self.combo_net_iface.currentText(),
            "ringbuf_capacity": self.combo_ringbuf.currentText(),
            "max_events": self.spin_max_events.value() if self.chk_limit_events.isChecked() else 0,
            "max_duration_s": self.spin_max_duration.value() if self.chk_limit_duration.isChecked() else 0,
            "stop_on_threat": self.chk_stop_on_threat.isChecked(),
            "autoscroll": self.chk_autoscroll.isChecked(),
            "resolve_syscalls": self.chk_resolve_syscalls.isChecked(),
            "stream_analytics": self.chk_stream_analytics.isChecked(),
            "ml_enabled": self.chk_ml_active.isChecked(),
            "confidence_threshold": self.slider_sens.value() / 100.0,
            "rf_enabled": self.chk_rf.isChecked(),
            "xgb_enabled": self.chk_xgb.isChecked(),
            "iso_enabled": self.chk_iso.isChecked(),
            "enabled_rules": enabled_rules,
        }
        self.startCaptureRequested.emit(opts)
        self.accept()
