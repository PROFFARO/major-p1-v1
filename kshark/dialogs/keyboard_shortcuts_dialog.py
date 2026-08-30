"""
KShark Keyboard Shortcuts Reference Dialog.
Enterprise searchable modal displaying all keyboard accelerators across all subsystems.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QPushButton,
    QFrame, QApplication, QMessageBox
)
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import Qt

from kshark.core.theme import ThemeManager, get_ui_font, get_monospace_font


SHORTCUTS_DATA = [
    # Category, Action, Shortcut, Scope
    ("Capture & Session", "Start / Stop Live Capture", "Ctrl+E  or  F5", "Global"),
    ("Capture & Session", "Restart Capture Session", "Ctrl+Shift+R", "Global"),
    ("Capture & Session", "Capture Options & BPF Filters", "Ctrl+K", "Global"),
    ("Capture & Session", "Open Telemetry Capture File", "Ctrl+O", "Global"),
    ("Capture & Session", "Save Telemetry Database As...", "Ctrl+S", "Global"),
    ("Capture & Session", "Export As CSV Spreadsheet", "Ctrl+Shift+C", "Global"),
    ("Capture & Session", "Export As JSON Lines (.jsonl)", "Ctrl+Shift+J", "Global"),
    ("Capture & Session", "Reload Capture File", "Ctrl+R", "Global"),
    ("Capture & Session", "Close Session", "Ctrl+W", "Global"),
    ("Capture & Session", "Exit KShark Application", "Ctrl+Q", "Global"),

    ("Navigation & Search", "Find Event / Text in Buffer", "Ctrl+F", "Main View"),
    ("Navigation & Search", "Go to Event Number (PID/Row)", "Ctrl+G", "Main View"),
    ("Navigation & Search", "Next Event", "Ctrl+Down  or  J", "Main View"),
    ("Navigation & Search", "Previous Event", "Ctrl+Up  or  K", "Main View"),
    ("Navigation & Search", "First Event (Top)", "Ctrl+Home", "Main View"),
    ("Navigation & Search", "Last Event (Bottom)", "Ctrl+End", "Main View"),
    ("Navigation & Search", "Next Threat / Anomaly Marker", "Ctrl+Shift+Down", "Main View"),
    ("Navigation & Search", "Previous Threat / Anomaly Marker", "Ctrl+Shift+Up", "Main View"),
    ("Navigation & Search", "Toggle Event Mark / Flag", "Ctrl+M", "Main View"),
    ("Navigation & Search", "Set / Clear Time Reference (t0)", "Ctrl+T", "Main View"),
    ("Navigation & Search", "Clear All Events Buffer", "Ctrl+Shift+X", "Main View"),

    ("Panels & Forensic Docks", "Toggle Threat Timeline Dock", "Alt+1", "Global"),
    ("Panels & Forensic Docks", "Toggle AI Security Copilot Dock", "Alt+2", "Global"),
    ("Panels & Forensic Docks", "Toggle Dissection Intelligence Pane", "Alt+3", "Global"),
    ("Panels & Forensic Docks", "Toggle Hex & Byte Inspector Pane", "Alt+4", "Global"),
    ("Panels & Forensic Docks", "Minimize / Restore Active Dock Panel", "Esc  or  Ctrl+M", "Dock"),
    ("Panels & Forensic Docks", "Reset Default Window Layout", "Ctrl+Alt+R", "Global"),
    ("Panels & Forensic Docks", "Toggle Fullscreen Mode", "F11", "Global"),
    ("Panels & Forensic Docks", "Zoom In Typography", "Ctrl++", "Global"),
    ("Panels & Forensic Docks", "Zoom Out Typography", "Ctrl+-", "Global"),
    ("Panels & Forensic Docks", "Reset Typography Zoom (100%)", "Ctrl+0", "Global"),
    ("Panels & Forensic Docks", "Auto-Fit All Table Columns", "Ctrl+Shift+R", "Main View"),

    ("Analysis & Filtering", "Apply Display Filter Expression", "Enter", "Filter Bar"),
    ("Analysis & Filtering", "Clear Active Display Filter", "Esc  or  Ctrl+Backspace", "Filter Bar"),
    ("Analysis & Filtering", "Open Display Filter Preset Library", "Ctrl+Shift+F", "Global"),
    ("Analysis & Filtering", "Apply Selected as Display Filter", "Ctrl+Alt+A", "Main View"),
    ("Analysis & Filtering", "Follow Process Execution Stream (PID)", "Ctrl+Alt+P", "Main View"),
    ("Analysis & Filtering", "Follow Parent-Child Process Lineage", "Ctrl+Alt+L", "Main View"),
    ("Analysis & Filtering", "Follow Network Socket Stream", "Ctrl+Alt+S", "Main View"),
    ("Analysis & Filtering", "Follow File I/O History", "Ctrl+Alt+H", "Main View"),
    ("Analysis & Filtering", "Open Threat Forensics & Mitigations", "Ctrl+Shift+T", "Global"),

    ("Statistical Analytics", "Syscall IO Graphs & Performance Analytics", "Ctrl+Shift+G", "Global"),
    ("Statistical Analytics", "System Call Distribution Breakdown", "Ctrl+Shift+B", "Global"),
    ("Statistical Analytics", "DuckDB Embedded SQL Query Console", "Ctrl+Shift+Q", "Global"),
    ("Statistical Analytics", "Security Incident Executive Summary", "Ctrl+Shift+I", "Global"),

    ("AI Copilot & Tools", "Trigger Deep Forensic Event Analysis", "Ctrl+Shift+A", "Copilot"),
    ("AI Copilot & Tools", "Reconstruct MITRE Execution Chain", "Ctrl+Shift+E", "Copilot"),
    ("AI Copilot & Tools", "Generate Containment Playbook", "Ctrl+Shift+P", "Copilot"),
    ("AI Copilot & Tools", "Multi-Attack Benchmark Simulator", "Ctrl+Alt+M", "Global"),
    ("AI Copilot & Tools", "AI Copilot Provider Configuration", "Ctrl+Alt+O", "Global"),

    ("Help & Reference", "Keyboard Shortcuts Reference Table", "F1", "Global"),
    ("Help & Reference", "KShark Architecture & User Manual", "F2", "Global"),
    ("Help & Reference", "MITRE ATT&CK Telemetry Reference", "F3", "Global"),
    ("Help & Reference", "Check Linux Kernel BTF Compatibility", "F4", "Global"),
    ("Help & Reference", "Application Preferences & Tuning", "Ctrl+,", "Global"),
    ("Help & Reference", "About KShark Platform", "Shift+F1", "Global"),
]


class KeyboardShortcutsDialog(QDialog):
    """Searchable modal displaying all keyboard accelerators and shortcuts."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("KShark Keyboard Shortcuts Reference")
        self.resize(720, 560)
        self._init_ui()

    def _init_ui(self):
        c = ThemeManager.instance().get_palette_colors()
        bg_base = c.get("bg_base", "#182428")
        bg_alt = c.get("bg_alt", "#1F2E34")
        brand = c.get("brand_primary", "#2BC1CF")
        border = c.get("border", "#283C42")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        # Header Search & Info Bar
        top_bar = QHBoxLayout()
        lbl_title = QLabel("Keyboard Accelerators & Shortcuts", self)
        lbl_title.setFont(get_ui_font(size=10, bold=True))
        lbl_title.setStyleSheet(f"color: {brand};")
        top_bar.addWidget(lbl_title)

        top_bar.addStretch(1)

        self.search_input = QLineEdit(self)
        self.search_input.setFont(get_ui_font(size=8))
        self.search_input.setPlaceholderText("Filter shortcuts by action, key, or category...")
        self.search_input.setFixedWidth(280)
        self.search_input.textChanged.connect(self._filter_shortcuts)
        top_bar.addWidget(self.search_input)

        layout.addLayout(top_bar)

        # Shortcuts Table
        self.table = QTableWidget(self)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Category", "Action Description", "Shortcut Key", "Scope"])
        self.table.setFont(get_ui_font(size=8))
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

        c = ThemeManager.instance().get_palette_colors()
        self.table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {c['bg_base']};
                alternate-background-color: {c['bg_alt']};
                gridline-color: {c['border']};
                border: 1px solid {c['border']};
                color: {c['fg_text']};
            }}
            QHeaderView::section {{
                background-color: {c['bg_window']};
                color: {c['brand_primary']};
                font-weight: bold;
                padding: 4px 6px;
                border: 1px solid {c['border']};
            }}
        """)

        self._populate_table(SHORTCUTS_DATA)
        layout.addWidget(self.table, stretch=1)

        # Footer close button
        btn_bar = QHBoxLayout()
        btn_copy = QPushButton("Copy All Shortcuts to Clipboard", self)
        btn_copy.setFont(get_ui_font(size=8))
        btn_copy.clicked.connect(self._copy_all)
        btn_bar.addWidget(btn_copy)

        btn_bar.addStretch(1)

        btn_close = QPushButton("Close", self)
        btn_close.setFont(get_ui_font(size=8, bold=True))
        btn_close.clicked.connect(self.accept)
        btn_bar.addWidget(btn_close)

        layout.addLayout(btn_bar)

    def _populate_table(self, data):
        c = ThemeManager.instance().get_palette_colors()
        brand = c.get("brand_primary", "#2BC1CF")
        fg_text = c.get("fg_text", "#D8E8EC")
        fg_muted = c.get("fg_muted", "#8A9EA4")

        self.table.setRowCount(len(data))
        for row_idx, (cat, action, shortcut, scope) in enumerate(data):
            # Category
            item_cat = QTableWidgetItem(cat)
            item_cat.setFont(get_ui_font(size=7.5, bold=True))
            item_cat.setForeground(QColor(brand))
            self.table.setItem(row_idx, 0, item_cat)

            # Action
            item_act = QTableWidgetItem(action)
            item_act.setFont(get_ui_font(size=8))
            item_act.setForeground(QColor(fg_text))
            self.table.setItem(row_idx, 1, item_act)

            # Shortcut
            item_sc = QTableWidgetItem(shortcut)
            item_sc.setFont(get_monospace_font(size=8, bold=True))
            item_sc.setForeground(QColor(brand))
            item_sc.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row_idx, 2, item_sc)

            # Scope
            item_scope = QTableWidgetItem(scope)
            item_scope.setFont(get_ui_font(size=7.5))
            item_scope.setForeground(QColor(fg_muted))
            item_scope.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row_idx, 3, item_scope)


    def _filter_shortcuts(self, text: str):
        query = text.strip().lower()
        if not query:
            self._populate_table(SHORTCUTS_DATA)
            return

        filtered = [
            row for row in SHORTCUTS_DATA
            if query in row[0].lower() or query in row[1].lower() or query in row[2].lower() or query in row[3].lower()
        ]
        self._populate_table(filtered)

    def _copy_all(self):
        lines = ["# KShark Keyboard Shortcuts Reference\n"]
        current_cat = None
        for cat, action, sc, scope in SHORTCUTS_DATA:
            if cat != current_cat:
                current_cat = cat
                lines.append(f"\n### {cat}")
            lines.append(f"- **{action}**: `{sc}` ({scope})")

        QApplication.clipboard().setText("\n".join(lines))
        QMessageBox.information(self, "Shortcuts Copied", "All keyboard shortcuts copied to clipboard.")
