"""
High-Performance Virtualized Table Model for KShark Event List (Packet List Equivalent).
Optimized for 60+ FPS zero-lag rendering with O(1) cell caching.
"""

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt, QVariant
from PyQt6.QtGui import QColor, QFont, QBrush
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
import time

from kshark.core.coloring_engine import ColoringEngine
from kshark.core.theme import get_monospace_font


class EventTableModel(QAbstractTableModel):
    """
    Virtualized data model for the top Event List pane.
    Renders raw telemetry events with Wireshark-matching columns at 60+ FPS.
    """

    COLUMNS = [
        ("No.", 60),
        ("Time", 120),
        ("PID", 65),
        ("PPID", 65),
        ("UID", 55),
        ("Process", 110),
        ("Event / Syscall", 140),
        ("File / Target", 220),
        ("Network Destination", 160),
        ("Threat Class", 150),
        ("Confidence", 90),
        ("Forensic Info", 280),
    ]

    TIME_FMT_RELATIVE = 0      # 00:00.123456
    TIME_FMT_TIME_OF_DAY = 1   # 22:05:16.123456
    TIME_FMT_DATE_TIME = 2     # 2026-08-28 22:05:16
    TIME_FMT_EPOCH = 3         # 1724876716.123456

    MAX_EVENTS = 50000         # Maximum ring buffer size

    def __init__(self, parent=None):
        super().__init__(parent)
        self._events: List[Dict[str, Any]] = []
        self._row_texts: List[List[str]] = []
        self._row_bg_brushes: List[QBrush] = []
        self._row_fg_brushes: List[QBrush] = []

        self.coloring_engine = ColoringEngine()
        self.time_format = self.TIME_FMT_RELATIVE
        self.mono_font = get_monospace_font(size=9)
        self.colorize_enabled = True

        # Special Row Flags
        self._marked_rows = set()
        self._time_ref_row: Optional[int] = None
        self._first_timestamp_ns: Optional[int] = None

    # ─────────────────────────────────────────────────────────
    # QAbstractTableModel Mandatory Overrides
    # ─────────────────────────────────────────────────────────

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._events)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLUMNS[section][0]
        return QVariant()

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return QVariant()

        row = index.row()
        if row >= len(self._events):
            return QVariant()

        col = index.column()

        # 1. Display Text Role (O(1) Instant Cache)
        if role == Qt.ItemDataRole.DisplayRole:
            if row < len(self._row_texts) and col < len(self._row_texts[row]):
                return self._row_texts[row][col]
            return ""

        # 2. Background Color Role (O(1) Instant Cache)
        elif role == Qt.ItemDataRole.BackgroundRole:
            if row in self._marked_rows:
                return QBrush(QColor("#FFFF99"))
            if self._time_ref_row == row:
                return QBrush(QColor("#D0E0FF"))
            if self.colorize_enabled and row < len(self._row_bg_brushes):
                return self._row_bg_brushes[row]
            return QVariant()

        # 3. Foreground Color Role (O(1) Instant Cache)
        elif role == Qt.ItemDataRole.ForegroundRole:
            if row in self._marked_rows:
                return QBrush(QColor("#000000"))
            if self.colorize_enabled and row < len(self._row_fg_brushes):
                return self._row_fg_brushes[row]
            return QVariant()

        # 4. Font Role
        elif role == Qt.ItemDataRole.FontRole:
            return self.mono_font

        # 5. Text Alignment Role
        elif role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 2, 3, 4, 10):
                return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        return QVariant()

    # ─────────────────────────────────────────────────────────
    # Precomputing Row Cache
    # ─────────────────────────────────────────────────────────

    def _precompute_row(self, event: Dict[str, Any], row_num: int) -> Tuple[List[str], QBrush, QBrush]:
        ts_ns = int(event.get("timestamp_ns", 0))
        if self._first_timestamp_ns is None and ts_ns > 0:
            self._first_timestamp_ns = ts_ns

        # 1. Columns
        col_0 = str(row_num + 1)
        col_1 = self._format_timestamp(ts_ns)
        col_2 = str(event.get("pid", 0))
        col_3 = str(event.get("ppid", 1))
        col_4 = str(event.get("uid", 1000))
        col_5 = str(event.get("comm", "unknown"))

        syscall = event.get("syscall") or event.get("syscall_name")
        if syscall:
            col_6 = str(syscall)
        elif event.get("syscall_id") is not None:
            col_6 = f"sys_{event['syscall_id']}"
        else:
            col_6 = str(event.get("event_type", event.get("event_type_str", "EVENT")))

        fp = str(event.get("file_path") or event.get("filename") or event.get("exe_path") or "")
        col_7 = fp if fp else "-"

        dst_ip = str(event.get("dst_ip", ""))
        dst_port = event.get("dst_port")
        if dst_ip and dst_ip != "0.0.0.0":
            col_8 = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
        else:
            col_8 = "-"

        threat = str(event.get("threat_name") or event.get("threat_type") or event.get("agreed_threat") or "BENIGN")
        col_9 = threat

        conf = float(event.get("confidence", 0.0))
        col_10 = f"{conf:.2f}" if conf > 0 else "-"

        col_11 = self._build_info_summary(event)

        texts = [col_0, col_1, col_2, col_3, col_4, col_5, col_6, col_7, col_8, col_9, col_10, col_11]

        # 2. Colors
        bg_col, fg_col = self.coloring_engine.get_colors_for_event(event)
        return texts, QBrush(bg_col), QBrush(fg_col)

    def _format_timestamp(self, ts_ns: int) -> str:
        if ts_ns <= 0:
            return "00:00.000000"

        ref_ns = self._first_timestamp_ns or ts_ns
        if self._time_ref_row is not None and 0 <= self._time_ref_row < len(self._events):
            ref_ns = int(self._events[self._time_ref_row].get("timestamp_ns", ref_ns))

        if self.time_format == self.TIME_FMT_RELATIVE:
            diff_sec = max(0.0, (ts_ns - ref_ns) / 1e9)
            mins = int(diff_sec // 60)
            secs = diff_sec % 60
            return f"{mins:02d}:{secs:09.6f}"
        elif self.time_format == self.TIME_FMT_EPOCH:
            return f"{ts_ns / 1e9:.6f}"
        else:
            dt = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc)
            if self.time_format == self.TIME_FMT_DATE_TIME:
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            return dt.strftime("%H:%M:%S.%f")

    def _build_info_summary(self, event: Dict[str, Any]) -> str:
        threat = str(event.get("threat_name") or event.get("threat_type") or event.get("agreed_threat") or "BENIGN")
        comm = str(event.get("comm", ""))
        exe = str(event.get("exe_path", ""))
        file_p = str(event.get("file_path") or event.get("filename") or "")

        parts = []
        if threat != "BENIGN":
            parts.append(f"[{threat}]")

        if exe:
            parts.append(f"exe={exe}")
        elif file_p:
            parts.append(f"target={file_p}")

        dst_ip = str(event.get("dst_ip", ""))
        if dst_ip and dst_ip != "0.0.0.0":
            parts.append(f"dst={dst_ip}:{event.get('dst_port', '')}")

        if not parts:
            parts.append(f"comm={comm}")

        return " ".join(parts)

    # ─────────────────────────────────────────────────────────
    # Public Model Manipulation API
    # ─────────────────────────────────────────────────────────

    def add_event(self, event: Dict[str, Any]):
        """Append a single event to the model."""
        self.add_events_batch([event])

    def add_events_batch(self, events: List[Dict[str, Any]]):
        """Batch append multiple events efficiently."""
        if not events:
            return

        # Cap memory to MAX_EVENTS
        if len(self._events) + len(events) > self.MAX_EVENTS:
            excess = (len(self._events) + len(events)) - self.MAX_EVENTS
            self.beginResetModel()
            self._events = self._events[excess:]
            self._row_texts = self._row_texts[excess:]
            self._row_bg_brushes = self._row_bg_brushes[excess:]
            self._row_fg_brushes = self._row_fg_brushes[excess:]
            self.endResetModel()

        start_row = len(self._events)
        end_row = start_row + len(events) - 1

        new_texts = []
        new_bgs = []
        new_fgs = []

        for idx, ev in enumerate(events):
            r_num = start_row + idx
            texts, bg, fg = self._precompute_row(ev, r_num)
            new_texts.append(texts)
            new_bgs.append(bg)
            new_fgs.append(fg)

        self.beginInsertRows(QModelIndex(), start_row, end_row)
        self._events.extend(events)
        self._row_texts.extend(new_texts)
        self._row_bg_brushes.extend(new_bgs)
        self._row_fg_brushes.extend(new_fgs)
        self.endInsertRows()

    def get_event(self, row: int) -> Optional[Dict[str, Any]]:
        """Retrieve raw event dictionary by row index."""
        if 0 <= row < len(self._events):
            return self._events[row]
        return None

    def clear(self):
        """Clear all events in the table."""
        self.beginResetModel()
        self._events.clear()
        self._row_texts.clear()
        self._row_bg_brushes.clear()
        self._row_fg_brushes.clear()
        self._marked_rows.clear()
        self._time_ref_row = None
        self._first_timestamp_ns = None
        self.endResetModel()

    def set_colorize(self, enabled: bool):
        """Toggles packet list colorization."""
        self.colorize_enabled = enabled
        self.layoutChanged.emit()

    def toggle_mark_row(self, row: int):
        """Toggles Wireshark Ctrl+M mark state for selected row."""
        if row in self._marked_rows:
            self._marked_rows.remove(row)
        else:
            self._marked_rows.add(row)
        top_left = self.index(row, 0)
        bot_right = self.index(row, len(self.COLUMNS) - 1)
        self.dataChanged.emit(top_left, bot_right)

    def set_time_reference_row(self, row: int):
        """Sets or toggles Wireshark Ctrl+T time reference row."""
        if self._time_ref_row == row:
            self._time_ref_row = None
        else:
            self._time_ref_row = row

        # Refresh all time column cells
        top_left = self.index(0, 1)
        bot_right = self.index(len(self._events) - 1, 1)
        self.dataChanged.emit(top_left, bot_right)
