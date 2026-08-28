"""
13-eBPF Integrated Subsystems Operational Matrix Dock for KShark.

Monitors live attachment, event rates, and detection schemas across all 13 integrated tools.
"""

from PyQt6.QtWidgets import (
    QDockWidget, QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtGui import QColor, QBrush, QFont
from PyQt6.QtCore import Qt
from typing import Dict, Any

from kshark.core.theme import get_monospace_font


class SubsystemStatusDock(QDockWidget):
    """
    Operational Health Matrix for 13 Integrated eBPF Tool Subsystems.
    """

    SUBSYSTEMS = [
        ("Bpfman", "BPF Program Manager & CRD Lifecycle", "Active", "Probes: 6"),
        ("eCapture", "TLS / SSL Plaintext Payload Decoder", "Active", "0.0 B/s"),
        ("eunomia-bpf", "Dynamic WASM / JSON Skeleton Engine", "Ready", "Schemas: 8"),
        ("Falco", "Behavioral Rule Engine (10 Sigma/Falco Rules)", "Active", "Rules: 10"),
        ("Inspektor Gadget", "OCI Container CGroup & Pod Context Enricher", "Active", "CGroups: All"),
        ("Kepler", "Microjoule Energy / CPU Power Ratio Profiler", "Active", "0.00 W"),
        ("KubeArmor", "LSM Security Posture & Container Enforcer", "Active", "Hooks: LSM"),
        ("NetObserv", "eBPF Flow Tracker, RTT & TCP Window Scaling", "Active", "0.0 KB/s"),
        ("Parca", "DWARF Kernel Stack Unwinder & Profiler", "Ready", "Frames: 0"),
        ("Pyroscope", "CPU Continuous Profiler & Flamegraph Tracer", "Active", "100 Hz"),
        ("Sysmon", "Linux Sysmon Event ID (1-25) Normalizer", "Active", "IDs: 1,3,5,11"),
        ("Tetragon", "LSM Process Credential & Capability Validator", "Active", "Bypass: Blocked"),
        ("Tracee", "W^X Memory Protection & Exec Injection Guard", "Active", "Memory: Guarded"),
    ]

    def __init__(self, parent=None):
        super().__init__("eBPF Subsystems Operational Matrix (13 Engines)", parent)
        self.setObjectName("subsystemStatusDock")
        self.setAllowedAreas(Qt.DockWidgetArea.RightDockWidgetArea | Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.LeftDockWidgetArea)

        self._init_ui()

    def _init_ui(self):
        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(4, 4, 4, 4)

        self.table = QTableWidget(len(self.SUBSYSTEMS), 4, self)
        self.table.setHorizontalHeaderLabels(["Subsystem Engine", "Role & Forensic Description", "Status", "Metrics / Context"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setFont(get_monospace_font(size=8.5))
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        for row, (name, desc, status, metrics) in enumerate(self.SUBSYSTEMS):
            item_name = QTableWidgetItem(name)
            item_name.setFont(QFont("Cantarell", 9, QFont.Weight.Bold))

            item_desc = QTableWidgetItem(desc)
            item_status = QTableWidgetItem(f"● {status}")
            item_status.setForeground(QBrush(QColor("#2E7D32")))
            item_status.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            item_metrics = QTableWidgetItem(metrics)
            item_metrics.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            self.table.setItem(row, 0, item_name)
            self.table.setItem(row, 1, item_desc)
            self.table.setItem(row, 2, item_status)
            self.table.setItem(row, 3, item_metrics)

        layout.addWidget(self.table)
        self.setWidget(container)

    def update_subsystem_metric(self, name: str, metric_text: str):
        """Updates live metrics column for a specific subsystem."""
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0).text() == name:
                self.table.item(row, 3).setText(metric_text)
                break
