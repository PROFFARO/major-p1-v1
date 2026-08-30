"""
KShark Plot Dialog — Syscall Frequency, Latency, and Scatter Distribution.
Direct port of ui/kshark/kshark_plot_dialog.cpp.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtGui import QPainter, QColor, QBrush, QPen
from PyQt6.QtCore import Qt


class KSharkPlotDialog(QDialog):
    """
    KShark Plot Dialog for Syscall & Event Distribution.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("KShark · Event Plot Distribution")
        self.resize(700, 420)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Category Selector
        ctrl_layout = QHBoxLayout()
        ctrl_layout.addWidget(QLabel("Plot Type:"))
        self.combo_type = QComboBox(self)
        self.combo_type.addItems(["Syscall Frequency Bar Chart", "Process Event Timeline", "Threat Severity Scatter"])
        ctrl_layout.addWidget(self.combo_type)
        ctrl_layout.addStretch(1)
        layout.addLayout(ctrl_layout)

        # Syscall Frequency Summary Table
        self.table = QTableWidget(7, 3, self)
        self.table.setHorizontalHeaderLabels(["Syscall / Event", "Count", "% of Total"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        sample_data = [
            ("execve", "1,420", "35.5%"),
            ("openat", "1,180", "29.5%"),
            ("connect", "640", "16.0%"),
            ("read", "320", "8.0%"),
            ("write", "210", "5.2%"),
            ("security_file_open", "150", "3.8%"),
            ("socket", "80", "2.0%"),
        ]
        for row, (sc, cnt, pct) in enumerate(sample_data):
            self.table.setItem(row, 0, QTableWidgetItem(sc))
            self.table.setItem(row, 1, QTableWidgetItem(cnt))
            self.table.setItem(row, 2, QTableWidgetItem(pct))

        layout.addWidget(self.table, stretch=1)

        # Bottom Bar
        btn_bar = QHBoxLayout()
        btn_bar.addStretch(1)
        btn_close = QPushButton("Close", self)
        btn_close.clicked.connect(self.accept)
        btn_bar.addWidget(btn_close)
        layout.addLayout(btn_bar)
