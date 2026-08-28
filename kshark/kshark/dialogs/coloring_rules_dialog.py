"""
Coloring Rules Configuration Dialog for KShark (Wireshark Coloring Rules Equivalent).
"""

from PyQt6.QtWidgets import (
    QDialog, QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QToolButton, QColorDialog, QDialogButtonBox, QLabel
)
from PyQt6.QtGui import QColor, QBrush
from PyQt6.QtCore import Qt, pyqtSignal
from typing import List

from kshark.core.coloring_engine import ColoringEngine, ColoringRule


class ColoringRulesDialog(QDialog):
    """
    Wireshark-styled Coloring Rules Management Dialog.
    """

    rulesUpdated = pyqtSignal()

    def __init__(self, coloring_engine: ColoringEngine, parent=None):
        super().__init__(parent)
        self.setWindowTitle("KShark · Coloring Rules")
        self.resize(720, 480)
        self.engine = coloring_engine

        self._init_ui()
        self._populate_table()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        hint_lbl = QLabel("Coloring rules are evaluated from top to bottom. The first matching rule colorizes the event row.", self)
        hint_lbl.setStyleSheet("color: #666666; font-size: 8.5pt;")
        layout.addWidget(hint_lbl)

        # 1. Rules Table
        self.table = QTableWidget(0, 5, self)
        self.table.setHorizontalHeaderLabels(["Active", "Rule Name", "Filter Expression", "Foreground", "Background"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.table)

        # 2. Action Buttons Toolbar (+, -, Up, Down, Duplicate)
        btn_bar = QHBoxLayout()
        self.add_btn = QPushButton("➕ Add Rule")
        self.add_btn.clicked.connect(self._add_rule)
        btn_bar.addWidget(self.add_btn)

        self.del_btn = QPushButton("➖ Delete")
        self.del_btn.clicked.connect(self._delete_rule)
        btn_bar.addWidget(self.del_btn)

        self.dup_btn = QPushButton("📋 Duplicate")
        self.dup_btn.clicked.connect(self._duplicate_rule)
        btn_bar.addWidget(self.dup_btn)

        self.up_btn = QPushButton("▲ Move Up")
        self.up_btn.clicked.connect(self._move_up)
        btn_bar.addWidget(self.up_btn)

        self.down_btn = QPushButton("▼ Move Down")
        self.down_btn.clicked.connect(self._move_down)
        btn_bar.addWidget(self.down_btn)

        btn_bar.addStretch(1)
        layout.addLayout(btn_bar)

        # 3. Dialog Button Box (OK, Cancel)
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self._save_and_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _populate_table(self):
        self.table.setRowCount(0)
        for row, rule in enumerate(self.engine.rules):
            self._insert_rule_row(row, rule)

    def _insert_rule_row(self, row: int, rule: ColoringRule):
        self.table.insertRow(row)

        # Col 0: Active Checkbox
        chk_item = QTableWidgetItem()
        chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
        chk_item.setCheckState(Qt.CheckState.Checked if rule.enabled else Qt.CheckState.Unchecked)
        self.table.setItem(row, 0, chk_item)

        # Col 1: Rule Name
        name_item = QTableWidgetItem(rule.name)
        self.table.setItem(row, 1, name_item)

        # Col 2: Filter Expression
        filter_item = QTableWidgetItem(rule.filter_expr)
        self.table.setItem(row, 2, filter_item)

        # Col 3: Foreground Color Picker Button
        fg_btn = QPushButton("Sample Text")
        fg_btn.setStyleSheet(f"background-color: #FFFFFF; color: {rule.fg_color.name()}; font-weight: bold;")
        fg_btn.clicked.connect(lambda checked, r=row: self._pick_fg_color(r))
        self.table.setCellWidget(row, 3, fg_btn)

        # Col 4: Background Color Picker Button
        bg_btn = QPushButton("       ")
        bg_btn.setStyleSheet(f"background-color: {rule.bg_color.name()}; border: 1px solid #777777;")
        bg_btn.clicked.connect(lambda checked, r=row: self._pick_bg_color(r))
        self.table.setCellWidget(row, 4, bg_btn)

    def _pick_fg_color(self, row: int):
        cur_col = self.engine.rules[row].fg_color if row < len(self.engine.rules) else QColor("#000000")
        col = QColorDialog.getColor(cur_col, self, "Select Foreground Text Color")
        if col.isValid():
            widget = self.table.cellWidget(row, 3)
            if widget:
                widget.setStyleSheet(f"background-color: #FFFFFF; color: {col.name()}; font-weight: bold;")
            if row < len(self.engine.rules):
                self.engine.rules[row].fg_color = col

    def _pick_bg_color(self, row: int):
        cur_col = self.engine.rules[row].bg_color if row < len(self.engine.rules) else QColor("#FFFFFF")
        col = QColorDialog.getColor(cur_col, self, "Select Background Row Color")
        if col.isValid():
            widget = self.table.cellWidget(row, 4)
            if widget:
                widget.setStyleSheet(f"background-color: {col.name()}; border: 1px solid #777777;")
            if row < len(self.engine.rules):
                self.engine.rules[row].bg_color = col

    def _add_rule(self):
        new_rule = ColoringRule("New Security Rule", 'threat != "BENIGN"', QColor("#FFF3CD"), QColor("#000000"))
        self.engine.rules.insert(0, new_rule)
        self._populate_table()
        self.table.selectRow(0)

    def _delete_rule(self):
        row = self.table.currentRow()
        if 0 <= row < len(self.engine.rules):
            del self.engine.rules[row]
            self._populate_table()

    def _duplicate_rule(self):
        row = self.table.currentRow()
        if 0 <= row < len(self.engine.rules):
            orig = self.engine.rules[row]
            dup = ColoringRule(f"{orig.name} (Copy)", orig.filter_expr, orig.bg_color, orig.fg_color, orig.enabled)
            self.engine.rules.insert(row + 1, dup)
            self._populate_table()
            self.table.selectRow(row + 1)

    def _move_up(self):
        row = self.table.currentRow()
        if row > 0 and row < len(self.engine.rules):
            self.engine.rules[row - 1], self.engine.rules[row] = self.engine.rules[row], self.engine.rules[row - 1]
            self._populate_table()
            self.table.selectRow(row - 1)

    def _move_down(self):
        row = self.table.currentRow()
        if 0 <= row < len(self.engine.rules) - 1:
            self.engine.rules[row], self.engine.rules[row + 1] = self.engine.rules[row + 1], self.engine.rules[row]
            self._populate_table()
            self.table.selectRow(row + 1)

    def _save_and_accept(self):
        # Update names and expressions from table edits
        for row in range(min(self.table.rowCount(), len(self.engine.rules))):
            chk = self.table.item(row, 0)
            name_item = self.table.item(row, 1)
            filter_item = self.table.item(row, 2)

            if chk:
                self.engine.rules[row].enabled = (chk.checkState() == Qt.CheckState.Checked)
            if name_item:
                self.engine.rules[row].name = name_item.text().strip()
            if filter_item:
                self.engine.rules[row].filter_expr = filter_item.text().strip()

        self.rulesUpdated.emit()
        self.accept()
