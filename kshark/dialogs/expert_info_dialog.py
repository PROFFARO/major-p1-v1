"""
KShark Expert Information & Security Diagnostics Dialog.

Direct Wireshark-standard Analyze > Expert Information dialog.
Aggregates, deduplicates, and categorizes telemetry into 4 severity tiers:
1. Critical Threats (ML consensus detections, Falco rules, MITRE ATT&CK techniques)
2. Security Warnings (Root UID privilege transitions, memfd anonymous execution, SUID)
3. Kernel Errors (EACCES / Permission Denied, ENOENT, ECONNREFUSED, EPERM, negative errno)
4. Operational Notes (Process launches, socket binds, container namespace transitions)

Equipped with Jump-to-Packet navigation, live filtering, and CSV/Markdown export.
"""

from typing import List, Dict, Any, Optional
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTreeWidget, QTreeWidgetItem, QHeaderView, QAbstractItemView,
    QApplication, QStatusBar, QFileDialog, QMessageBox, QFrame
)
from PyQt6.QtGui import QColor, QFont, QBrush
from PyQt6.QtCore import Qt, pyqtSignal

from kshark.core.theme import ThemeManager, get_monospace_font, get_ui_font
from kshark.core.syscall_table import resolve_syscall_name


class ExpertInfoDialog(QDialog):
    """
    KShark Security Expert Information & Kernel Diagnostics Dialog.
    """

    eventSelected = pyqtSignal(int)      # Emits 1-indexed event number to select in main window
    filterApplied = pyqtSignal(str)      # Emits display filter string

    def __init__(self, events: List[Dict[str, Any]], parent=None):
        super().__init__(parent)
        self.events = events
        self.setWindowTitle("KShark · Expert Information")
        self.resize(920, 600)
        self._init_ui()
        self._populate_diagnostics()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 4)
        layout.setSpacing(6)

        c = ThemeManager.instance().get_palette_colors()
        is_dark = ThemeManager.is_dark()

        # ── 1. Top Severity Badges Ribbon ──
        ribbon = QHBoxLayout()
        ribbon.setSpacing(8)

        self.card_threats = QLabel("🔴 Threats: 0", self)
        self.card_threats.setFont(get_ui_font(size=8.5, bold=True))
        self.card_threats.setStyleSheet(f"background-color: {c['card_threats_bg']}; color: {c['card_threats_fg']}; border: 1px solid {c['card_threats_border']}; border-radius: 4px; padding: 4px 10px;")

        self.card_warnings = QLabel("🟠 Warnings: 0", self)
        self.card_warnings.setFont(get_ui_font(size=8.5, bold=True))
        self.card_warnings.setStyleSheet(f"background-color: {c['card_warnings_bg']}; color: {c['card_warnings_fg']}; border: 1px solid {c['card_warnings_border']}; border-radius: 4px; padding: 4px 10px;")

        self.card_errors = QLabel("🟡 Errors: 0", self)
        self.card_errors.setFont(get_ui_font(size=8.5, bold=True))
        self.card_errors.setStyleSheet(f"background-color: {c['card_errors_bg']}; color: {c['card_errors_fg']}; border: 1px solid {c['card_errors_border']}; border-radius: 4px; padding: 4px 10px;")

        self.card_notes = QLabel("🔵 Notes: 0", self)
        self.card_notes.setFont(get_ui_font(size=8.5, bold=True))
        self.card_notes.setStyleSheet(f"background-color: {c['card_notes_bg']}; color: {c['card_notes_fg']}; border: 1px solid {c['card_notes_border']}; border-radius: 4px; padding: 4px 10px;")

        ribbon.addWidget(self.card_threats)
        ribbon.addWidget(self.card_warnings)
        ribbon.addWidget(self.card_errors)
        ribbon.addWidget(self.card_notes)
        ribbon.addStretch(1)

        # Search Bar
        lbl_search = QLabel("Search:", self)
        lbl_search.setFont(get_ui_font(size=8))
        ribbon.addWidget(lbl_search)

        self.search_input = QLineEdit(self)
        self.search_input.setFont(get_ui_font(size=8))
        self.search_input.setPlaceholderText("Filter diagnostics...")
        self.search_input.textChanged.connect(self._filter_tree)
        ribbon.addWidget(self.search_input)

        layout.addLayout(ribbon)

        # ── 2. Diagnostics Tree Widget (Wireshark-Style) ──
        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(["Severity / Group", "Event #", "Diagnostic Summary", "Process (PID)", "Syscall", "Target / Destination"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tree.setUniformRowHeights(True)
        self.tree.setFont(get_monospace_font(size=8.5))
        self.tree.setStyleSheet(f"""
            QTreeWidget {{
                background-color: {c['bg_base']};
                alternate-background-color: {c['bg_alt']};
                border: 1px solid {c['border']};
                color: {c['fg_text']};
                outline: none;
            }}
            QTreeWidget::item:selected {{
                background-color: {c['selection_bg']};
                color: {c['selection_fg']};
            }}
            QHeaderView::section {{
                background-color: {c['bg_window']};
                color: {c['fg_muted']};
                border: none;
                border-right: 1px solid {c['border']};
                border-bottom: 1px solid {c['border']};
                padding: 4px 6px;
                font-weight: bold;
            }}
        """)
        self.tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self.tree, stretch=1)

        # ── 3. Bottom Action Buttons Bar ──
        bot_bar = QHBoxLayout()
        bot_bar.setSpacing(8)

        btn_apply_filter = QPushButton("Apply Selected as Filter", self)
        btn_apply_filter.setFont(get_ui_font(size=8))
        btn_apply_filter.clicked.connect(self._apply_filter)
        bot_bar.addWidget(btn_apply_filter)

        btn_export = QPushButton("Export Diagnostics (Markdown)...", self)
        btn_export.setFont(get_ui_font(size=8))
        btn_export.clicked.connect(self._export_markdown)
        bot_bar.addWidget(btn_export)

        btn_copy = QPushButton("Copy Summary", self)
        btn_copy.setFont(get_ui_font(size=8))
        btn_copy.clicked.connect(self._copy_summary)
        bot_bar.addWidget(btn_copy)

        bot_bar.addStretch(1)

        btn_close = QPushButton("Close", self)
        btn_close.setFont(get_ui_font(size=8, bold=True))
        btn_close.clicked.connect(self.accept)
        bot_bar.addWidget(btn_close)

        layout.addLayout(bot_bar)

        # ── 4. Status Bar ──
        self.status_bar = QStatusBar(self)
        self.status_bar.setFont(get_ui_font(size=7.5))
        self.status_bar.setSizeGripEnabled(True)
        layout.addWidget(self.status_bar)

    def _populate_diagnostics(self):
        self.tree.clear()
        if not self.events:
            self.status_bar.showMessage("No events available for diagnostic analysis.")
            return

        threat_items = []
        warning_items = []
        error_items = []
        note_items = []

        for idx, ev in enumerate(self.events, start=1):
            sc = resolve_syscall_name(ev)
            comm = str(ev.get("comm") or ev.get("proc_name") or "unknown")
            pid = ev.get("pid", 0)
            uid = ev.get("uid", 1000)
            ret = int(ev.get("retval", 0))
            fp = str(ev.get("file_path") or ev.get("filename") or "")
            dst_ip = str(ev.get("dst_ip", ""))
            dst_port = ev.get("dst_port", 0)
            threat_name = str(ev.get("threat_name") or ev.get("threat_type") or ev.get("agreed_threat") or "BENIGN")
            conf = float(ev.get("confidence", 0.0))

            target_str = f"{dst_ip}:{dst_port}" if dst_ip and dst_ip != "0.0.0.0" else (fp if fp and fp != "-" else "-")

            # 1. Critical Threats
            if threat_name not in ("BENIGN", "", "NONE", "NORMAL"):
                threat_items.append((idx, f"Threat Detected: {threat_name} (Confidence: {conf:.1%})", f"{comm} ({pid})", str(sc), target_str, threat_name))

            # 2. Security Warnings
            if uid == 0 and comm not in ("systemd", "init", "kthreadd"):
                warning_items.append((idx, f"Elevated UID 0 (Root) execution", f"{comm} ({pid})", str(sc), target_str, "ROOT_PRIV"))
            elif "memfd" in fp:
                warning_items.append((idx, f"Fileless in-memory execution via memfd_create", f"{comm} ({pid})", str(sc), fp, "FILELESS_MEMFD"))
            elif "/." in str(ev.get("exe_path", "")):
                warning_items.append((idx, f"Binary launched from hidden UNIX directory", f"{comm} ({pid})", str(sc), str(ev.get("exe_path")), "HIDDEN_PATH"))

            # 3. Kernel & Syscall Errors
            if ret < 0:
                errno_desc = "EPERM / Operation not permitted" if ret == -1 else ("ENOENT / No such file" if ret == -2 else ("EACCES / Permission denied" if ret == -13 else f"ERRNO {ret}"))
                error_items.append((idx, f"Syscall Failed: {errno_desc}", f"{comm} ({pid})", str(sc), target_str, f"ERR_{ret}"))

            # 4. Operational Notes
            if sc == "execve":
                note_items.append((idx, f"Process Spawn: {ev.get('cmdline') or comm}", f"{comm} ({pid})", "execve", target_str, "EXECVE"))
            elif sc in ("bind", "listen"):
                note_items.append((idx, f"Socket Server Listener Bound", f"{comm} ({pid})", str(sc), target_str, "SOCKET_BIND"))
            elif sc == "unshare" or sc == "setns":
                note_items.append((idx, f"Container Namespace Isolation Transition", f"{comm} ({pid})", str(sc), target_str, "NAMESPACE"))

        # Update Badge Cards
        self.card_threats.setText(f"🔴 Threats: {len(threat_items):,}")
        self.card_warnings.setText(f"🟠 Warnings: {len(warning_items):,}")
        self.card_errors.setText(f"🟡 Errors: {len(error_items):,}")
        self.card_notes.setText(f"🔵 Notes: {len(note_items):,}")

        # Add Tier Groups to Tree
        self._add_group_to_tree("🔴 Critical Security Threats", threat_items, "#E74C3C")
        self._add_group_to_tree("🟠 Security Warnings & Root Transitions", warning_items, "#E67E22")
        self._add_group_to_tree("🟡 Kernel & Syscall Errors", error_items, "#F1C40F")
        self._add_group_to_tree("🔵 Operational Telemetry Notes", note_items, "#3498DB")

        self.tree.expandAll()
        total_diag = len(threat_items) + len(warning_items) + len(error_items) + len(note_items)
        self.status_bar.showMessage(f"Total Diagnostic Indicators: {total_diag:,} across {len(self.events):,} events. Double-click any item to jump to packet.")

    def _add_group_to_tree(self, group_title: str, items: list, color_hex: str):
        if not items:
            return

        grp = QTreeWidgetItem(self.tree)
        grp.setText(0, f"{group_title} ({len(items)})")
        grp.setFont(0, get_ui_font(size=9, bold=True))
        grp.setForeground(0, QBrush(QColor(color_hex)))

        for (ev_num, summary, proc_str, sc_str, target_str, tag) in items:
            child = QTreeWidgetItem(grp)
            child.setText(0, "")
            child.setText(1, f"#{ev_num}")
            child.setText(2, summary)
            child.setText(3, proc_str)
            child.setText(4, sc_str)
            child.setText(5, target_str)
            child.setData(1, Qt.ItemDataRole.UserRole, ev_num)
            child.setData(2, Qt.ItemDataRole.UserRole, tag)

    def _filter_tree(self, text: str):
        q = text.strip().lower()
        for i in range(self.tree.topLevelItemCount()):
            grp = self.tree.topLevelItem(i)
            grp_match = False
            for j in range(grp.childCount()):
                child = grp.child(j)
                match = (q in child.text(1).lower() or q in child.text(2).lower() or q in child.text(3).lower() or q in child.text(4).lower() or q in child.text(5).lower()) if q else True
                child.setHidden(not match)
                if match:
                    grp_match = True
            grp.setHidden(not grp_match)

    def _on_item_double_clicked(self, item: QTreeWidgetItem, col: int):
        ev_num = item.data(1, Qt.ItemDataRole.UserRole)
        if ev_num is not None:
            self.eventSelected.emit(int(ev_num))
            self.status_bar.showMessage(f"Jumped to Event #{ev_num}", 2000)

    def _apply_filter(self):
        item = self.tree.currentItem()
        if not item:
            return

        tag = item.data(2, Qt.ItemDataRole.UserRole)
        if tag:
            if "ERR_" in tag:
                expr = "evt.res < 0"
            elif tag == "ROOT_PRIV":
                expr = "user.uid == 0"
            elif tag == "FILELESS_MEMFD":
                expr = "fd.name contains 'memfd'"
            elif tag == "EXECVE":
                expr = "evt.type == 'execve'"
            else:
                expr = f'threat.name == "{tag}"'
            self.filterApplied.emit(expr)
            self.accept()

    def _copy_summary(self):
        lines = []
        for i in range(self.tree.topLevelItemCount()):
            grp = self.tree.topLevelItem(i)
            lines.append(f"=== {grp.text(0)} ===")
            for j in range(grp.childCount()):
                child = grp.child(j)
                if not child.isHidden():
                    lines.append(f"  {child.text(1)} | {child.text(2)} | {child.text(3)} | {child.text(4)} | {child.text(5)}")
        QApplication.clipboard().setText("\n".join(lines))
        self.status_bar.showMessage("Diagnostics copied to clipboard!", 3000)

    def _export_markdown(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Diagnostics Report", "kshark_expert_diagnostics.md", "Markdown Files (*.md)")
        if path:
            try:
                md_lines = ["# KShark Expert Information & Diagnostics Report\n"]
                for i in range(self.tree.topLevelItemCount()):
                    grp = self.tree.topLevelItem(i)
                    md_lines.append(f"## {grp.text(0)}\n")
                    md_lines.append("| Event # | Diagnostic Summary | Process | Syscall | Target |")
                    md_lines.append("|---|---|---|---|---|")
                    for j in range(grp.childCount()):
                        child = grp.child(j)
                        md_lines.append(f"| {child.text(1)} | {child.text(2)} | {child.text(3)} | {child.text(4)} | {child.text(5)} |")
                    md_lines.append("")
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(md_lines))
                QMessageBox.information(self, "Export Successful", f"Diagnostics report saved to:\n{path}")
            except Exception as e:
                QMessageBox.warning(self, "Export Failed", f"Could not save report: {e}")
