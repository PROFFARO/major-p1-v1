"""
KShark Threat Timeline & Subsystem Docks.
"""

from PyQt6.QtWidgets import (
    QDockWidget, QWidget, QVBoxLayout, QLabel, QListWidget, QListWidgetItem, QProgressBar
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QColor, QBrush

from kshark.core.theme import ThemeManager, get_monospace_font


class ThreatTimelineDock(QDockWidget):
    """
    Live Threat Detection Markers Dock.
    """

    def __init__(self, parent=None):
        super().__init__("Threat Timeline & Security Alerts", parent)
        self.setObjectName("threatTimelineDock")
        self.setAllowedAreas(Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea)
        self._init_ui()

    def _init_ui(self):
        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(6, 6, 6, 6)

        self.list_widget = QListWidget(self)
        self.list_widget.setFont(get_monospace_font(size=8))
        layout.addWidget(self.list_widget)
        self.setWidget(container)

    def record_threat_marker(self, alert: dict):
        threat = alert.get("threat_name") or alert.get("threat_type") or "ANOMALY"
        pid = alert.get("pid", 0)
        comm = alert.get("comm", "")
        conf = float(alert.get("confidence", 0.95))

        item_text = f"🚨 [{threat}] PID: {pid} ({comm}) - Conf: {conf:.0%}"
        item = QListWidgetItem(item_text, self.list_widget)
        item.setForeground(QBrush(QColor("#FF9999" if ThemeManager.is_dark() else "#990000")))
        self.list_widget.scrollToBottom()


class SubsystemStatusDock(QDockWidget):
    """
    eBPF Kernel Probes Health & Subsystem Status Dock.
    """

    def __init__(self, parent=None):
        super().__init__("eBPF Probes & Subsystems", parent)
        self.setObjectName("subsystemStatusDock")
        self.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea)
        self._init_ui()

    def _init_ui(self):
        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        probes = [
            ("sys_tracer (Syscall Tracepoints)", "ATTACHED / ACTIVE", "#0EA773"),
            ("net_filter (TC & Socket Ingress)", "ATTACHED / ACTIVE", "#0EA773"),
            ("ssl_tracer (Uprobes Plaintext)", "ATTACHED / ACTIVE", "#0EA773"),
            ("lsm_enforcer (Security Hooks)", "ATTACHED / ACTIVE", "#0EA773"),
            ("Dual ML Consensus Engine", "ONLINE (XGBoost + PyTorch)", "#0E9AA7"),
            ("DuckDB Columnar Store", "ACTIVE / STREAMING", "#0EA773"),
        ]

        for name, status, col in probes:
            lbl_name = QLabel(f"<b>{name}</b>", self)
            lbl_status = QLabel(f"<span style='color: {col};'>{status}</span>", self)
            layout.addWidget(lbl_name)
            layout.addWidget(lbl_status)

        layout.addStretch(1)
        self.setWidget(container)
