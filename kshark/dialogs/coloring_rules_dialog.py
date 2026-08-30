"""
KShark Coloring Rules Dialog.

Wireshark-compliant rule editor with full CRUD capabilities:
- Add, Delete, Move Up, Move Down
- In-place Name and Filter editing with validation
- Background & Foreground Color Pickers
- Import & Export Coloring Rules (JSON)
- Real-time Preview and instant Apply to active table model
"""

import json
from typing import List, Optional
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QColorDialog, QFileDialog,
    QMessageBox, QCheckBox, QWidget, QAbstractItemView, QApplication
)
from PyQt6.QtGui import QColor, QBrush, QFont
from PyQt6.QtCore import Qt

from kshark.core.coloring_engine import ColoringEngine, ColoringRule
from kshark.core.filter_engine import compile_filter
from kshark.core.theme import ThemeManager, get_monospace_font, get_ui_font


class ColoringRulesDialog(QDialog):
    """
    Dialog for viewing, adding, modifying, and reordering packet coloring rules.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("KShark · Coloring Rules")
        self.resize(780, 460)

        self._parent = parent
        # Reference active engine or create one
        if parent and hasattr(parent, "table_model") and hasattr(parent.table_model, "coloring_engine"):
            self.coloring_engine = parent.table_model.coloring_engine
        else:
            self.coloring_engine = ColoringEngine()

        # Work on a local working copy of rules
        self.rules: List[ColoringRule] = [
            ColoringRule(
                r.name, r.filter_expr, r.bg_light, r.fg_light,
                r.bg_dark, r.fg_dark, r.enabled
            )
            for r in self.coloring_engine.rules
        ]

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # ── Rules Table ──
        self.table = QTableWidget(0, 6, self)
        self.table.setHorizontalHeaderLabels([
            "Enabled", "Rule Name", "Filter Expression", "Background", "Foreground", "Preview"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(1, 160)
        self.table.setColumnWidth(5, 120)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setFont(get_monospace_font(size=8.5))

        self.table.cellChanged.connect(self._on_cell_changed)
        layout.addWidget(self.table, stretch=1)

        # ── Middle Action Bar (Add, Delete, Move Up, Move Down) ──
        mid_bar = QHBoxLayout()
        mid_bar.setSpacing(6)

        btn_add = QPushButton("＋ Add Rule", self)
        btn_add.setFont(get_ui_font(size=8))
        btn_add.clicked.connect(self._add_rule)
        mid_bar.addWidget(btn_add)

        btn_del = QPushButton("－ Delete", self)
        btn_del.setFont(get_ui_font(size=8))
        btn_del.clicked.connect(self._delete_rule)
        mid_bar.addWidget(btn_del)

        btn_up = QPushButton("▲ Move Up", self)
        btn_up.setFont(get_ui_font(size=8))
        btn_up.clicked.connect(self._move_up)
        mid_bar.addWidget(btn_up)

        btn_down = QPushButton("▼ Move Down", self)
        btn_down.setFont(get_ui_font(size=8))
        btn_down.clicked.connect(self._move_down)
        mid_bar.addWidget(btn_down)

        mid_bar.addSpacing(12)

        btn_import = QPushButton("Import...", self)
        btn_import.setFont(get_ui_font(size=8))
        btn_import.clicked.connect(self._import_rules)
        mid_bar.addWidget(btn_import)

        btn_export = QPushButton("Export...", self)
        btn_export.setFont(get_ui_font(size=8))
        btn_export.clicked.connect(self._export_rules)
        mid_bar.addWidget(btn_export)

        btn_reset = QPushButton("Reset Defaults", self)
        btn_reset.setFont(get_ui_font(size=8))
        btn_reset.clicked.connect(self._reset_defaults)
        mid_bar.addWidget(btn_reset)

        mid_bar.addStretch(1)
        layout.addLayout(mid_bar)

        # ── Bottom Bar (OK, Apply, Cancel) ──
        bot_bar = QHBoxLayout()
        bot_bar.setSpacing(8)
        bot_bar.addStretch(1)

        btn_apply = QPushButton("Apply", self)
        btn_apply.setFont(get_ui_font(size=8))
        btn_apply.clicked.connect(self._apply_rules)
        bot_bar.addWidget(btn_apply)

        btn_ok = QPushButton("OK", self)
        btn_ok.setFont(get_ui_font(size=8, bold=True))
        btn_ok.setDefault(True)
        btn_ok.clicked.connect(self._on_ok)
        bot_bar.addWidget(btn_ok)

        btn_cancel = QPushButton("Cancel", self)
        btn_cancel.setFont(get_ui_font(size=8))
        btn_cancel.clicked.connect(self.reject)
        bot_bar.addWidget(btn_cancel)

        layout.addLayout(bot_bar)

        self._refresh_table()

    def _refresh_table(self):
        self.table.blockSignals(True)
        self.table.setRowCount(len(self.rules))
        is_dark = ThemeManager.is_dark()

        for row, rule in enumerate(self.rules):
            # 0: Enabled checkbox
            chk = QCheckBox(self)
            chk.setChecked(rule.enabled)
            chk.setStyleSheet("margin-left: 8px;")
            chk.toggled.connect(lambda checked, r=row: self._toggle_rule(r, checked))
            self.table.setCellWidget(row, 0, chk)

            # 1: Rule Name
            item_name = QTableWidgetItem(rule.name)
            item_name.setFont(get_ui_font(size=8.5))
            self.table.setItem(row, 1, item_name)

            # 2: Filter Expression
            item_filter = QTableWidgetItem(rule.filter_expr)
            item_filter.setFont(get_monospace_font(size=8.5))
            self.table.setItem(row, 2, item_filter)

            # 3: Background Color Picker Button
            bg_col = rule.bg_dark if is_dark else rule.bg_light
            btn_bg = QPushButton(f"  ● {bg_col}  ", self)
            btn_bg.setFont(get_monospace_font(size=8))
            btn_bg.setStyleSheet(f"background-color: {bg_col}; color: #FFFFFF; border: 1px solid #1A2830; border-radius: 2px; padding: 2px 4px;")
            btn_bg.clicked.connect(lambda _, r=row: self._pick_color(r, is_bg=True))
            self.table.setCellWidget(row, 3, btn_bg)

            # 4: Foreground Color Picker Button
            fg_col = rule.fg_dark if is_dark else rule.fg_light
            btn_fg = QPushButton(f"  ● {fg_col}  ", self)
            btn_fg.setFont(get_monospace_font(size=8))
            btn_fg.setStyleSheet(f"background-color: {fg_col}; color: #FFFFFF; border: 1px solid #1A2830; border-radius: 2px; padding: 2px 4px;")
            btn_fg.clicked.connect(lambda _, r=row: self._pick_color(r, is_bg=False))
            self.table.setCellWidget(row, 4, btn_fg)

            # 5: Preview
            item_prev = QTableWidgetItem(" Sample Event ")
            item_prev.setBackground(QBrush(QColor(bg_col)))
            item_prev.setForeground(QBrush(QColor(fg_col)))
            item_prev.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item_prev.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(row, 5, item_prev)

            self.table.setRowHeight(row, 28)

        self.table.blockSignals(False)

    def _on_cell_changed(self, row: int, col: int):
        if 0 <= row < len(self.rules):
            item = self.table.item(row, col)
            if item:
                if col == 1:
                    self.rules[row].name = item.text().strip()
                elif col == 2:
                    self.rules[row].filter_expr = item.text().strip()

    def _toggle_rule(self, row: int, checked: bool):
        if 0 <= row < len(self.rules):
            self.rules[row].enabled = checked

    def _pick_color(self, row: int, is_bg: bool):
        if 0 <= row < len(self.rules):
            rule = self.rules[row]
            is_dark = ThemeManager.is_dark()
            current_hex = (rule.bg_dark if is_dark else rule.bg_light) if is_bg else (rule.fg_dark if is_dark else rule.fg_light)
            col = QColorDialog.getColor(QColor(current_hex), self, f"Pick {'Background' if is_bg else 'Foreground'} Color")
            if col.isValid():
                chosen_hex = col.name().upper()
                if is_bg:
                    if is_dark:
                        rule.bg_dark = chosen_hex
                    else:
                        rule.bg_light = chosen_hex
                else:
                    if is_dark:
                        rule.fg_dark = chosen_hex
                    else:
                        rule.fg_light = chosen_hex
                self._refresh_table()

    def _add_rule(self):
        new_rule = ColoringRule(
            f"New Rule {len(self.rules) + 1}",
            "",
            "#FFFFFF", "#000000",
            "#1A3540", "#2BC1CF",
            True
        )
        self.rules.append(new_rule)
        self._refresh_table()
        self.table.selectRow(len(self.rules) - 1)

    def _delete_rule(self):
        row = self.table.currentRow()
        if 0 <= row < len(self.rules):
            self.rules.pop(row)
            self._refresh_table()
            if self.rules:
                self.table.selectRow(min(row, len(self.rules) - 1))

    def _move_up(self):
        row = self.table.currentRow()
        if row > 0:
            self.rules[row - 1], self.rules[row] = self.rules[row], self.rules[row - 1]
            self._refresh_table()
            self.table.selectRow(row - 1)

    def _move_down(self):
        row = self.table.currentRow()
        if 0 <= row < len(self.rules) - 1:
            self.rules[row + 1], self.rules[row] = self.rules[row], self.rules[row + 1]
            self._refresh_table()
            self.table.selectRow(row + 1)

    def _reset_defaults(self):
        self.rules = self.coloring_engine._get_default_rules()
        self._refresh_table()

    def _apply_rules(self):
        self.coloring_engine.rules = [
            ColoringRule(
                r.name, r.filter_expr, r.bg_light, r.fg_light,
                r.bg_dark, r.fg_dark, r.enabled
            )
            for r in self.rules
        ]
        self.coloring_engine.clear_cache()

        # Update main window table model if connected
        if self._parent and hasattr(self._parent, "table_model"):
            tm = self._parent.table_model
            if hasattr(tm, "_row_bg_brushes"):
                tm._row_bg_brushes.clear()
                tm._row_fg_brushes.clear()
                # Re-compute row colors for all events
                for ev in tm._events:
                    bg, fg = self.coloring_engine.get_colors_for_event(ev)
                    tm._row_bg_brushes.append(QBrush(bg))
                    tm._row_fg_brushes.append(QBrush(fg))
                tm.layoutChanged.emit()

    def _on_ok(self):
        self._apply_rules()
        self.accept()

    def _export_rules(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Coloring Rules", "kshark_coloring_rules.json", "JSON Files (*.json)"
        )
        if path:
            try:
                data = [
                    {
                        "name": r.name,
                        "filter_expr": r.filter_expr,
                        "bg_light": r.bg_light,
                        "fg_light": r.fg_light,
                        "bg_dark": r.bg_dark,
                        "fg_dark": r.fg_dark,
                        "enabled": r.enabled,
                    }
                    for r in self.rules
                ]
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                QMessageBox.information(self, "Export Successful", f"Coloring rules exported to:\n{path}")
            except Exception as e:
                QMessageBox.warning(self, "Export Failed", f"Could not save rules: {e}")

    def _import_rules(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Coloring Rules", "", "JSON Files (*.json);;All Files (*)"
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                new_rules = []
                for d in data:
                    new_rules.append(ColoringRule(
                        d.get("name", "Rule"),
                        d.get("filter_expr", ""),
                        d.get("bg_light", "#FFFFFF"),
                        d.get("fg_light", "#000000"),
                        d.get("bg_dark", "#1A3540"),
                        d.get("fg_dark", "#2BC1CF"),
                        d.get("enabled", True),
                    ))
                self.rules = new_rules
                self._refresh_table()
                QMessageBox.information(self, "Import Successful", f"Loaded {len(new_rules)} coloring rules.")
            except Exception as e:
                QMessageBox.warning(self, "Import Failed", f"Could not load rules: {e}")
