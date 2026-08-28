"""
About KShark Dialog (Wireshark About Dialog Equivalent).
"""

from PyQt6.QtWidgets import (
    QDialog, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextBrowser, 
    QDialogButtonBox
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt
import platform
import sys

from kshark.resources.icons import KSharkIcons
from kshark.core.theme import get_ui_font


class AboutDialog(QDialog):
    """
    Wireshark-styled About Dialog.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About KShark")
        self.resize(580, 420)

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # Header Banner
        header_layout = QHBoxLayout()
        icon_lbl = QLabel(self)
        icon_lbl.setPixmap(KSharkIcons.get_app_icon().pixmap(64, 64))
        header_layout.addWidget(icon_lbl)

        title_vbox = QVBoxLayout()
        title_lbl = QLabel("KShark 1.0.0", self)
        title_lbl.setFont(get_ui_font(size=14, bold=True))
        title_lbl.setStyleSheet("color: #007ACC;")

        sub_lbl = QLabel("Linux Kernel eBPF Threat Detection & Security Observability Analyzer", self)
        sub_lbl.setFont(get_ui_font(size=9))
        sub_lbl.setStyleSheet("color: #666666;")

        title_vbox.addWidget(title_lbl)
        title_vbox.addWidget(sub_lbl)
        header_layout.addLayout(title_vbox)
        header_layout.addStretch(1)

        layout.addLayout(header_layout)

        # Tabs
        tabs = QTabWidget(self)

        # Tab 1: KShark Architecture
        tab_about = QWidget()
        t1_layout = QVBoxLayout(tab_about)
        browser1 = QTextBrowser()
        browser1.setHtml(f"""
        <h3>KShark Security Platform</h3>
        <p><b>KShark</b> is an enterprise-grade native Linux security observability and threat detection application modeled after the gold-standard forensic UX of <b>Wireshark</b>.</p>
        <p>It unifies eBPF kernel tracing, streaming feature windowing, Random Forest / XGBoost ensemble anomaly detection, Falco-compatible deterministic behavioral rules, and an interactive LLM Security Copilot into a high-performance native desktop platform.</p>
        <hr>
        <p><b>Runtime Environment:</b></p>
        <ul>
            <li>Python: {sys.version.split()[0]}</li>
            <li>OS: Linux {platform.release()} ({platform.machine()})</li>
            <li>GUI Toolkit: Qt6 / PyQt6 (Wayland & X11 Native)</li>
            <li>Analytics Engine: DuckDB Columnar Store</li>
            <li>Audit Store: SQLite WAL Mode</li>
        </ul>
        """)
        t1_layout.addWidget(browser1)
        tabs.addTab(tab_about, "KShark")

        # Tab 2: eBPF Subsystems
        tab_bpf = QWidget()
        t2_layout = QVBoxLayout(tab_bpf)
        browser2 = QTextBrowser()
        browser2.setHtml("""
        <h3>Active Kernel Probes & Architecture</h3>
        <p>KShark interfaces directly with Linux kernel eBPF ring buffers via its Go agent:</p>
        <ul>
            <li><b>sys_tracer:</b> Syscall tracepoints for execve, openat, socket, connect, and privilege transitions.</li>
            <li><b>net_filter:</b> Traffic Control (TC) and socket packet inspection.</li>
            <li><b>ssl_tracer:</b> Dynamic uprobes attached to libssl for plaintext inspection.</li>
            <li><b>lsm_enforcer:</b> Linux Security Module (LSM) security hooks for real-time PID containment.</li>
            <li><b>perf_profiler:</b> High-frequency CPU instruction stack sampling.</li>
            <li><b>tetragon_lsm:</b> Security credential validation and namespace isolation.</li>
        </ul>
        """)
        t2_layout.addWidget(browser2)
        tabs.addTab(tab_bpf, "eBPF Subsystem")

        # Tab 3: Authors & License
        tab_lic = QWidget()
        t3_layout = QVBoxLayout(tab_lic)
        browser3 = QTextBrowser()
        browser3.setHtml("""
        <h3>Authors & Open Source Credits</h3>
        <p>Developed by the Advanced Security Observability & eBPF Research Team.</p>
        <p>Special acknowledgments to the <b>Wireshark Foundation</b> for inspiring the forensic multi-pane analysis workflow and user interface ergonomics.</p>
        <p>Licensed under the Apache License, Version 2.0.</p>
        """)
        t3_layout.addWidget(browser3)
        tabs.addTab(tab_lic, "Authors & License")

        layout.addWidget(tabs)

        # OK button
        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        btn_box.accepted.connect(self.accept)
        layout.addWidget(btn_box)
