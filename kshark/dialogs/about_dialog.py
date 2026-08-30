"""
KShark About Dialog — Version, Kernel eBPF Support, and Credits.
Direct port of ui/kshark/kshark_about_dialog.cpp.
"""

from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextBrowser, QTabWidget, QWidget
from PyQt6.QtGui import QFont, QPixmap
from PyQt6.QtCore import Qt

from kshark.resources.icons import KSharkIcons
from kshark.core.theme import ThemeManager, get_ui_font


class AboutDialog(QDialog):
    """
    KShark Official About Dialog.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About KShark")
        self.resize(600, 420)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header with Shark Fin
        hdr_layout = QHBoxLayout()
        icon_lbl = QLabel(self)
        icon_lbl.setPixmap(KSharkIcons.get_app_icon().pixmap(48, 48))
        hdr_layout.addWidget(icon_lbl)

        title_layout = QVBoxLayout()
        title_lbl = QLabel("KShark", self)
        title_lbl.setFont(get_ui_font(size=14, bold=True))
        ver_lbl = QLabel("Version 4.7.3 (eBPF Kernel & Cloud Observability Edition)", self)
        ver_lbl.setStyleSheet("color: #0E9AA7; font-weight: 500;")
        title_layout.addWidget(title_lbl)
        title_layout.addWidget(ver_lbl)
        hdr_layout.addLayout(title_layout)
        hdr_layout.addStretch(1)
        layout.addLayout(hdr_layout)

        # Tabs
        tabs = QTabWidget(self)

        # Tab 1: KShark
        t1 = QWidget()
        l1 = QVBoxLayout(t1)
        browser1 = QTextBrowser(t1)
        browser1.setHtml("""
            <p><b>KShark</b> is a specialized system call and kernel observability analyzer derived from Wireshark.</p>
            <p>It captures and dissects Linux kernel system calls, process lifecycles, and network socket activity using native eBPF tracepoints and security probes.</p>
            <p><b>Subsystems Integrated:</b></p>
            <ul>
                <li><b>eBPF Probes:</b> sys_tracer, net_filter, ssl_tracer, lsm_enforcer, tetragon_lsm</li>
                <li><b>ML Threat Detector:</b> Dual Random Forest / XGBoost + PyTorch Anomaly Models</li>
                <li><b>Columnar Analytics:</b> DuckDB and SQLite WAL database ingestion</li>
                <li><b>AI Copilot:</b> LLM Security Analyst Platform</li>
            </ul>
        """)
        l1.addWidget(browser1)
        tabs.addTab(t1, "KShark")

        # Tab 2: Authors & Credits
        t2 = QWidget()
        l2 = QVBoxLayout(t2)
        browser2 = QTextBrowser(t2)
        browser2.setHtml("""
            <p><b>Wireshark & KShark Creator:</b> Gerald Combs &lt;gerald@wireshark.org&gt;</p>
            <p><b>eBPF Observability & ML Integration:</b> KShark / KShark Platform Team</p>
            <p><b>License:</b> GNU General Public License v2 or later (GPL-2.0-or-later)</p>
        """)
        l2.addWidget(browser2)
        tabs.addTab(t2, "Authors")

        layout.addWidget(tabs, stretch=1)

        # Close Button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch(1)
        btn_close = QPushButton("OK", self)
        btn_close.setDefault(True)
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)
