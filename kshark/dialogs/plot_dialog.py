"""
KShark Event Distribution Statistics Dialog.

Modeled after Wireshark's Statistics > Protocol Hierarchy / Conversations
dialogs. Auto-refreshes every 2s during live capture. Uses native-style
widgets with minimal custom styling — functional, not decorative.
"""

from collections import Counter
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QTreeWidget, QTreeWidgetItem, QHeaderView,
    QAbstractItemView, QApplication, QCheckBox, QStatusBar,
    QWidget,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QColor, QPainter, QBrush

from kshark.core.theme import ThemeManager, get_ui_font, get_monospace_font

# Consistent with main application palette
_BG = "#0D1519"
_BG_ALT = "#0F1C21"
_BORDER = "#1A2830"
_FG = "#C8D6DA"
_FG_DIM = "#6E8088"
_FG_BRIGHT = "#E0ECEF"
_BAR_COLOR = "#1A5A60"


class PercentBarItem(QTreeWidgetItem):
    """Custom tree item that stores numeric data for proper sorting."""

    def __lt__(self, other):
        col = self.treeWidget().sortColumn() if self.treeWidget() else 0
        # Try numeric sort first
        try:
            self_val = self.data(col, Qt.ItemDataRole.UserRole)
            other_val = other.data(col, Qt.ItemDataRole.UserRole)
            if self_val is not None and other_val is not None:
                return float(self_val) < float(other_val)
        except (TypeError, ValueError):
            pass
        return super().__lt__(other)


class KSharkPlotDialog(QDialog):
    """
    Event distribution statistics dialog.
    Reads live data from the parent's EventTableModel.
    Auto-refreshes every 2 seconds when capture is active.
    """

    _AUTO_REFRESH_MS = 2000

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("KShark · Statistics")
        self.resize(820, 520)
        self._table_model = None
        self._last_event_count = -1

        if parent and hasattr(parent, "table_model"):
            self._table_model = parent.table_model

        self._init_ui()
        self._refresh()

        # Auto-refresh timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._auto_refresh)
        self._timer.start(self._AUTO_REFRESH_MS)

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 0)
        layout.setSpacing(6)

        # ── Toolbar strip ──
        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)

        lbl_topic = QLabel("Topic:", self)
        lbl_topic.setFont(get_ui_font(size=8.5))
        toolbar.addWidget(lbl_topic)

        self.combo_view = QComboBox(self)
        self.combo_view.setFont(get_ui_font(size=8.5))
        self.combo_view.addItems([
            "Syscall / Event Frequency",
            "Process Activity",
            "Threat Classification",
        ])
        self.combo_view.setMinimumWidth(200)
        self.combo_view.currentIndexChanged.connect(self._refresh)
        toolbar.addWidget(self.combo_view)

        toolbar.addSpacing(12)

        self.chk_auto = QCheckBox("Auto-refresh", self)
        self.chk_auto.setFont(get_ui_font(size=8))
        self.chk_auto.setChecked(True)
        self.chk_auto.toggled.connect(self._toggle_auto_refresh)
        toolbar.addWidget(self.chk_auto)

        toolbar.addStretch(1)

        btn_copy = QPushButton("Copy as CSV", self)
        btn_copy.setFont(get_ui_font(size=8))
        btn_copy.clicked.connect(self._copy_csv)
        toolbar.addWidget(btn_copy)

        btn_close = QPushButton("Close", self)
        btn_close.setFont(get_ui_font(size=8))
        btn_close.clicked.connect(self.accept)
        toolbar.addWidget(btn_close)

        layout.addLayout(toolbar)

        # ── Tree table (Wireshark uses QTreeWidget for statistics) ──
        c = ThemeManager.instance().get_palette_colors()
        self.tree = QTreeWidget(self)
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tree.setSortingEnabled(True)
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
            QTreeWidget::item {{
                padding: 2px 6px;
                border: none;
                color: {c['fg_text']};
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
        layout.addWidget(self.tree, stretch=1)

        # ── Status bar ──
        self.status_bar = QStatusBar(self)
        self.status_bar.setFont(get_ui_font(size=7.5))
        self.status_bar.setStyleSheet(f"""
            QStatusBar {{
                background: {c['bg_window']};
                color: {c['fg_muted']};
                border-top: 1px solid {c['border']};
            }}
        """)
        self.status_bar.setSizeGripEnabled(True)
        layout.addWidget(self.status_bar)

    # ------------------------------------------------------------------
    # Auto-refresh logic
    # ------------------------------------------------------------------
    def _toggle_auto_refresh(self, enabled: bool):
        if enabled:
            self._timer.start(self._AUTO_REFRESH_MS)
        else:
            self._timer.stop()

    def _auto_refresh(self):
        """Only re-aggregate if event count changed (cheap check)."""
        events = self._get_events()
        count = len(events)
        if count != self._last_event_count:
            self._refresh()

    # ------------------------------------------------------------------
    # Data source
    # ------------------------------------------------------------------
    def _get_events(self) -> list:
        if self._table_model is not None and hasattr(self._table_model, "_events"):
            return self._table_model._events
        return []

    # ------------------------------------------------------------------
    # Refresh dispatcher
    # ------------------------------------------------------------------
    def _refresh(self):
        idx = self.combo_view.currentIndex()
        events = self._get_events()
        total = len(events)
        self._last_event_count = total

        if total == 0:
            self._show_empty()
            self.status_bar.showMessage("No events captured")
            return

        if idx == 0:
            self._view_syscall_freq(events, total)
        elif idx == 1:
            self._view_process_activity(events, total)
        elif idx == 2:
            self._view_threat_classes(events, total)

        distinct = self.tree.topLevelItemCount()
        self.status_bar.showMessage(
            f"Events: {total:,}  |  Distinct entries: {distinct}"
        )

    # ------------------------------------------------------------------
    # View 0 — Syscall / Event Frequency
    # ------------------------------------------------------------------
    def _view_syscall_freq(self, events: list, total: int):
        from kshark.core.syscall_table import resolve_syscall_name

        counter = Counter()
        for ev in events:
            counter[str(resolve_syscall_name(ev))] += 1

        headers = ["Syscall / Event", "Count", "Percent", "Bar"]
        col_widths = [220, 90, 80, 0]
        self._prepare_tree(headers, col_widths)

        ranked = counter.most_common()
        max_count = ranked[0][1] if ranked else 1

        self.tree.setSortingEnabled(False)
        for name, count in ranked:
            pct = (count / total) * 100
            bar_val = count / max_count  # 0.0 – 1.0 for bar width

            item = PercentBarItem()
            item.setText(0, name)
            item.setText(1, f"{count:,}")
            item.setTextAlignment(1, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            item.setText(2, f"{pct:.1f}%")
            item.setTextAlignment(2, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

            # Store numeric data for proper sorting
            item.setData(0, Qt.ItemDataRole.UserRole, name)
            item.setData(1, Qt.ItemDataRole.UserRole, count)
            item.setData(2, Qt.ItemDataRole.UserRole, pct)

            # Visual bar in last column — use background color trick
            bar_text = "█" * max(1, int(bar_val * 30))
            item.setText(3, bar_text)
            item.setForeground(3, QColor(_BAR_COLOR))

            self.tree.addTopLevelItem(item)

        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(1, Qt.SortOrder.DescendingOrder)

    # ------------------------------------------------------------------
    # View 1 — Process Activity
    # ------------------------------------------------------------------
    def _view_process_activity(self, events: list, total: int):
        proc_map: dict[str, dict] = {}
        for ev in events:
            comm = str(ev.get("comm", ev.get("proc_name", "unknown")))
            pid = str(ev.get("pid", 0))
            key = f"{comm}|{pid}"

            if key not in proc_map:
                proc_map[key] = {
                    "comm": comm, "pid": pid,
                    "count": 0, "threats": 0, "syscalls": Counter()
                }
            proc_map[key]["count"] += 1

            threat = str(ev.get("threat_name") or ev.get("agreed_threat") or "BENIGN")
            if threat not in ("BENIGN", "", "NONE"):
                proc_map[key]["threats"] += 1

            from kshark.core.syscall_table import resolve_syscall_name
            proc_map[key]["syscalls"][str(resolve_syscall_name(ev))] += 1

        headers = ["Process", "PID", "Events", "Percent", "Threats", "Top Syscall"]
        col_widths = [180, 60, 80, 70, 70, 0]
        self._prepare_tree(headers, col_widths)

        ranked = sorted(proc_map.values(), key=lambda x: x["count"], reverse=True)

        self.tree.setSortingEnabled(False)
        for d in ranked:
            pct = (d["count"] / total) * 100
            top_sc = d["syscalls"].most_common(1)
            top_sc_str = top_sc[0][0] if top_sc else "-"

            item = PercentBarItem()
            item.setText(0, d["comm"])
            item.setText(1, d["pid"])
            item.setTextAlignment(1, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            item.setText(2, f"{d['count']:,}")
            item.setTextAlignment(2, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            item.setText(3, f"{pct:.1f}%")
            item.setTextAlignment(3, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            item.setText(4, str(d["threats"]) if d["threats"] > 0 else "-")
            item.setTextAlignment(4, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            item.setText(5, top_sc_str)

            item.setData(0, Qt.ItemDataRole.UserRole, d["comm"])
            item.setData(1, Qt.ItemDataRole.UserRole, int(d["pid"]) if d["pid"].isdigit() else 0)
            item.setData(2, Qt.ItemDataRole.UserRole, d["count"])
            item.setData(3, Qt.ItemDataRole.UserRole, pct)
            item.setData(4, Qt.ItemDataRole.UserRole, d["threats"])

            # Color threat count if non-zero
            if d["threats"] > 0:
                item.setForeground(4, QColor("#E0A020"))

            self.tree.addTopLevelItem(item)

        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(2, Qt.SortOrder.DescendingOrder)

    # ------------------------------------------------------------------
    # View 2 — Threat Classification
    # ------------------------------------------------------------------
    def _view_threat_classes(self, events: list, total: int):
        threat_map: dict[str, dict] = {}
        for ev in events:
            threat = str(
                ev.get("threat_name") or ev.get("agreed_threat")
                or ev.get("threat_class") or "BENIGN"
            )
            conf = float(ev.get("confidence", 0.0))
            if threat not in threat_map:
                threat_map[threat] = {"count": 0, "total_conf": 0.0, "pids": set()}
            threat_map[threat]["count"] += 1
            threat_map[threat]["total_conf"] += conf
            threat_map[threat]["pids"].add(ev.get("pid", 0))

        headers = ["Threat Class", "Events", "Percent", "Avg Confidence", "Distinct PIDs"]
        col_widths = [200, 80, 70, 110, 0]
        self._prepare_tree(headers, col_widths)

        ranked = sorted(threat_map.items(), key=lambda x: x[1]["count"], reverse=True)

        self.tree.setSortingEnabled(False)
        for name, d in ranked:
            pct = (d["count"] / total) * 100
            avg_c = d["total_conf"] / d["count"] if d["count"] > 0 else 0

            item = PercentBarItem()
            item.setText(0, name)
            item.setText(1, f"{d['count']:,}")
            item.setTextAlignment(1, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            item.setText(2, f"{pct:.1f}%")
            item.setTextAlignment(2, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            item.setText(3, f"{avg_c:.1%}" if avg_c > 0 else "-")
            item.setTextAlignment(3, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            item.setText(4, str(len(d["pids"])))
            item.setTextAlignment(4, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

            item.setData(0, Qt.ItemDataRole.UserRole, name)
            item.setData(1, Qt.ItemDataRole.UserRole, d["count"])
            item.setData(2, Qt.ItemDataRole.UserRole, pct)
            item.setData(3, Qt.ItemDataRole.UserRole, avg_c)
            item.setData(4, Qt.ItemDataRole.UserRole, len(d["pids"]))

            self.tree.addTopLevelItem(item)

        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(1, Qt.SortOrder.DescendingOrder)

    # ------------------------------------------------------------------
    # Tree helpers
    # ------------------------------------------------------------------
    def _prepare_tree(self, headers: list[str], col_widths: list[int]):
        """Reset tree and configure columns. Width 0 = Stretch to fill."""
        self.tree.clear()
        self.tree.setColumnCount(len(headers))
        self.tree.setHeaderLabels(headers)
        header = self.tree.header()
        for i, w in enumerate(col_widths):
            if w > 0:
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Fixed)
                header.resizeSection(i, w)
            else:
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)

    def _show_empty(self):
        self.tree.clear()
        self.tree.setColumnCount(1)
        self.tree.setHeaderLabels([""])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        item = QTreeWidgetItem()
        item.setText(0, "No events captured. Start a live capture or open a capture file.")
        item.setFlags(Qt.ItemFlag.ItemIsEnabled)
        item.setTextAlignment(0, Qt.AlignmentFlag.AlignCenter)
        self.tree.addTopLevelItem(item)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def _copy_csv(self):
        """Copy as CSV to clipboard."""
        lines = []
        # Header
        cols = self.tree.columnCount()
        hdr = []
        for c in range(cols):
            hdr.append(self.tree.headerItem().text(c) if self.tree.headerItem() else "")
        lines.append(",".join(hdr))

        # Rows
        for r in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(r)
            if item is None:
                continue
            cells = [item.text(c).replace(",", "") for c in range(cols)]
            lines.append(",".join(cells))

        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText("\n".join(lines))
            self.status_bar.showMessage("Copied to clipboard", 3000)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def closeEvent(self, event):
        self._timer.stop()
        super().closeEvent(event)
