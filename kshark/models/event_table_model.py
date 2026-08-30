"""
KShark Event Table Model — Canonical 11-Column System Call Dissection Table.
Retains 100% of captured telemetry events without arbitrary truncation, with O(1) cell caching for 60+ FPS rendering.
Accurate threat count tracking synchronized with table rows.
"""

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt, QVariant
from PyQt6.QtGui import QColor, QFont, QBrush
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
import time

from kshark.core.coloring_engine import ColoringEngine
from kshark.core.theme import get_monospace_font
from kshark.core.syscall_table import resolve_syscall_name


class EventTableModel(QAbstractTableModel):
    """
    Virtualized data model for the top KShark Event List pane.
    Canonical KShark columns matching app/kshark_flavor.c.
    """

    COLUMNS = [
        ("No.", 65),
        ("Time", 120),
        ("Event Name", 130),
        ("Proc Name", 110),
        ("PID", 65),
        ("TID", 65),
        ("FD / Target", 220),
        ("Network Destination", 160),
        ("Container Name", 130),
        ("Threat Class", 150),
        ("Forensic Info", 280),
    ]

    TIME_FMT_RELATIVE = 0
    TIME_FMT_TIME_OF_DAY = 1
    TIME_FMT_DATE_TIME = 2
    TIME_FMT_EPOCH = 3

    def __init__(self, parent=None):
        super().__init__(parent)
        self._events: List[Dict[str, Any]] = []
        self._row_texts: List[List[str]] = []
        self._row_bg_brushes: List[QBrush] = []
        self._row_fg_brushes: List[QBrush] = []

        self._threat_count: int = 0
        self.coloring_engine = ColoringEngine()
        self.time_format = self.TIME_FMT_RELATIVE
        self.mono_font = get_monospace_font(size=9)
        self.colorize_enabled = True

        self._marked_rows = set()
        self._comments: Dict[int, str] = {}
        self._time_ref_row: Optional[int] = None
        self._first_timestamp_ns: Optional[int] = None

    @property
    def threat_count(self) -> int:
        return self._threat_count

    def set_comment(self, row: int, comment: str):
        """Attaches or clears a forensic comment for a given row."""
        if 0 <= row < len(self._events):
            if comment.strip():
                self._comments[row] = comment.strip()
                if row < len(self._row_texts) and len(self._row_texts[row]) > 0:
                    self._row_texts[row][0] = f"💬 {row + 1}"
            else:
                self._comments.pop(row, None)
                if row < len(self._row_texts) and len(self._row_texts[row]) > 0:
                    self._row_texts[row][0] = f"★ {row + 1}" if row in self._marked_rows else str(row + 1)
            self.dataChanged.emit(self.index(row, 0), self.index(row, len(self.COLUMNS) - 1))

    def get_comment(self, row: int) -> str:
        """Returns the forensic comment for a given row."""
        return self._comments.get(row, "")

    def toggle_mark(self, row: int) -> bool:
        """Toggles the visual mark on a given row."""
        if 0 <= row < len(self._events):
            if row in self._marked_rows:
                self._marked_rows.remove(row)
                res = False
            else:
                self._marked_rows.add(row)
                res = True
            if row < len(self._row_texts) and len(self._row_texts[row]) > 0:
                if row in self._comments:
                    self._row_texts[row][0] = f"💬 {row + 1}"
                else:
                    self._row_texts[row][0] = f"★ {row + 1}" if res else str(row + 1)
            self.dataChanged.emit(self.index(row, 0), self.index(row, len(self.COLUMNS) - 1))
            return res
        return False

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
                return QBrush(QColor("#2C3E50" if ThemeManager.is_dark() else "#FFFF99"))
            if self._time_ref_row == row:
                return QBrush(QColor("#1A303A" if ThemeManager.is_dark() else "#D0E0FF"))
            if self.colorize_enabled and row < len(self._row_bg_brushes):
                return self._row_bg_brushes[row]
            return QVariant()

        # 3. Foreground Color Role (O(1) Instant Cache)
        elif role == Qt.ItemDataRole.ForegroundRole:
            if row in self._marked_rows:
                return QBrush(QColor("#F1C40F" if ThemeManager.is_dark() else "#000000"))
            if self.colorize_enabled and row < len(self._row_fg_brushes):
                return self._row_fg_brushes[row]
            return QVariant()

        # 4. ToolTip Role
        elif role == Qt.ItemDataRole.ToolTipRole:
            if row in self._comments:
                return f"Forensic Note: {self._comments[row]}"
            return QVariant()

        # 5. Font Role
        elif role == Qt.ItemDataRole.FontRole:
            return self.mono_font

        # 6. Text Alignment Role
        elif role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 4, 5):
                return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        return QVariant()

    def _precompute_row(self, event: Dict[str, Any], row_num: int) -> Tuple[List[str], QBrush, QBrush]:
        ts_ns = int(event.get("timestamp_ns", 0))
        if self._first_timestamp_ns is None and ts_ns > 0:
            self._first_timestamp_ns = ts_ns

        # Columns
        col_0 = str(row_num + 1)
        col_1 = self._format_timestamp(ts_ns)

        # Event Name (evt.type / syscall name)
        sc = resolve_syscall_name(event)
        col_2 = str(sc)

        # Proc Name (proc.name / comm)
        col_3 = str(event.get("comm", event.get("proc_name", "unknown")))

        # PID & TID
        col_4 = str(event.get("pid", 0))
        col_5 = str(event.get("tid", event.get("ppid", 1)))

        # FD / Target (fd.name / file_path)
        fp = str(event.get("file_path") or event.get("filename") or event.get("exe_path") or "")
        col_6 = fp if fp else "-"

        # Network Destination
        dst_ip = str(event.get("dst_ip", ""))
        dst_port = event.get("dst_port")
        if dst_ip and dst_ip != "0.0.0.0":
            col_7 = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
        else:
            col_7 = "-"

        # Container Name
        col_8 = str(event.get("container_name") or event.get("cgroup_id") or "host")

        # Threat Class
        threat = str(event.get("threat_name") or event.get("threat_type") or event.get("agreed_threat") or event.get("threat_class") or "BENIGN")
        conf = float(event.get("confidence", 0.0))
        if threat not in ("BENIGN", "", "NONE") and conf > 0:
            col_9 = f"{threat} ({conf:.0%})"
        else:
            col_9 = threat

        # Forensic Info / Arguments
        col_10 = self._build_info_summary(event)

        texts = [col_0, col_1, col_2, col_3, col_4, col_5, col_6, col_7, col_8, col_9, col_10]
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
        parts = []
        exe = str(event.get("exe_path", ""))
        file_p = str(event.get("file_path") or event.get("filename") or "")

        if exe:
            parts.append(f"exe={exe}")
        elif file_p:
            parts.append(f"target={file_p}")

        dst_ip = str(event.get("dst_ip", ""))
        if dst_ip and dst_ip != "0.0.0.0":
            parts.append(f"dst={dst_ip}:{event.get('dst_port', '')}")

        if not parts:
            parts.append(f"comm={event.get('comm', '')}")

        return " ".join(parts)

    def add_events_batch(self, events: List[Dict[str, Any]]):
        """Batch append multiple events efficiently without truncation."""
        if not events:
            return

        start_row = len(self._events)
        end_row = start_row + len(events) - 1

        new_texts = []
        new_bgs = []
        new_fgs = []

        for idx, ev in enumerate(events):
            r_num = start_row + idx
            th = ev.get("threat_name") or ev.get("threat_type") or "BENIGN"
            if str(th).upper() not in ("BENIGN", "", "NONE"):
                self._threat_count += 1
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

    def mark_pid_threat(self, pid: int, threat_name: str, confidence: float):
        """Updates threat classification for existing events matching PID."""
        modified_rows = []
        pid_str = str(pid)
        for idx, ev in enumerate(self._events):
            ev_pid = str(ev.get("pid", ""))
            ev_threat = ev.get("threat_name")
            if ev_pid == pid_str and (ev_threat is None or ev_threat in ("", "BENIGN")):
                ev["threat_name"] = threat_name
                ev["confidence"] = confidence
                self._threat_count += 1
                texts, bg, fg = self._precompute_row(ev, idx)
                self._row_texts[idx] = texts
                self._row_bg_brushes[idx] = bg
                self._row_fg_brushes[idx] = fg
                modified_rows.append(idx)

        if modified_rows:
            self.dataChanged.emit(
                self.index(modified_rows[0], 0),
                self.index(modified_rows[-1], len(self.COLUMNS) - 1)
            )

    def get_event(self, row: int) -> Optional[Dict[str, Any]]:
        if 0 <= row < len(self._events):
            return self._events[row]
        return None

    def clear(self):
        self.beginResetModel()
        self._events.clear()
        self._row_texts.clear()
        self._row_bg_brushes.clear()
        self._row_fg_brushes.clear()
        self._marked_rows.clear()
        self._threat_count = 0
        self._time_ref_row = None
        self._first_timestamp_ns = None
        self.endResetModel()

    def set_colorize(self, enabled: bool):
        self.colorize_enabled = enabled
        if self._events:
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(len(self._events) - 1, len(self.COLUMNS) - 1),
                [Qt.ItemDataRole.BackgroundRole, Qt.ItemDataRole.ForegroundRole]
            )


    def toggle_mark_row(self, row: int):
        if row in self._marked_rows:
            self._marked_rows.remove(row)
        else:
            self._marked_rows.add(row)
        self.dataChanged.emit(self.index(row, 0), self.index(row, len(self.COLUMNS) - 1))

    def set_time_reference_row(self, row: int):
        if self._time_ref_row == row:
            self._time_ref_row = None
        else:
            self._time_ref_row = row
        self.dataChanged.emit(self.index(0, 1), self.index(len(self._events) - 1, 1))

    def set_time_format(self, fmt: int):
        """Switches timestamp format (Relative, Time of Day, Date Time, Epoch)."""
        self.time_format = fmt
        for idx, ev in enumerate(self._events):
            ts_ns = int(ev.get("timestamp_ns", 0))
            if idx < len(self._row_texts) and len(self._row_texts[idx]) > 1:
                self._row_texts[idx][1] = self._format_timestamp(ts_ns)
        if self._events:
            self.dataChanged.emit(self.index(0, 1), self.index(len(self._events) - 1, 1), [Qt.ItemDataRole.DisplayRole])

    def set_font_size(self, size: float):
        """Updates monospace font size dynamically across the event table."""
        self.mono_font = get_monospace_font(size=size)
        self.layoutChanged.emit()

