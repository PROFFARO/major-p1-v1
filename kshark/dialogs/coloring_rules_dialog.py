"""
KShark Coloring Rules Dialog.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView
)
from PyQt6.QtGui import QColor, QBrush
from PyQt6.QtCore import Qt

from kshark.core.coloring_engine import ColoringEngine


class ColoringRulesDialog(QDialog):
    """
    KShark Coloring Rules Dialog.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("KShark · Coloring Rules")
        self.resize(650, 380)
        self.coloring_engine = ColoringEngine()
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self.table = QTableWidget(len(self.coloring_engine.rules), 3, self)
        self.table.setHorizontalHeaderLabels(["Rule Name", "Filter Expression", "Preview"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(2, 100)

        for row, rule in enumerate(self.coloring_engine.rules):
            item_name = QTableWidgetItem(rule.name)
            item_filter = QTableWidgetItem(rule.filter_expr)
            item_prev = QTableWidgetItem(" Sample Event ")
            item_prev.setBackground(QBrush(QColor(rule.bg_dark)))
            item_prev.setForeground(QBrush(QColor(rule.fg_dark)))
            item_prev.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            self.table.setItem(row, 0, item_name)
            self.table.setItem(row, 1, item_filter)
            self.table.setItem(row, 2, item_prev)

        layout.addWidget(self.table, stretch=1)

        btn_bar = QHBoxLayout()
        btn_bar.addStretch(1)
        btn_close = QPushButton("OK", self)
        btn_close.clicked.connect(self.accept)
        btn_bar.addWidget(btn_close)
        layout.addLayout(btn_bar)
