"""
Sort & Filter Proxy Model for Stratoshark Event List.
Applies AST-based Display Filter expressions and natural numeric sorting across columns.
"""

from PyQt6.QtCore import QSortFilterProxyModel, QModelIndex, pyqtSignal, Qt
from typing import Optional, Dict, Any
import time

from stratoshark.core.filter_engine import compile_filter, ASTNode


class EventFilterProxyModel(QSortFilterProxyModel):
    """
    Proxy model filtering and sorting the underlying EventTableModel with correct numeric and text comparison.
    """

    filterStatsChanged = pyqtSignal(int, int, float)  # (matched_rows, total_rows, elapsed_ms)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._filter_ast: Optional[ASTNode] = None
        self._filter_text: str = ""
        self.setDynamicSortFilter(True)
        self.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def set_display_filter(self, filter_text: str) -> bool:
        """Sets and compiles a new display filter expression."""
        start_time = time.perf_counter()
        self._filter_text = filter_text.strip()

        if not self._filter_text:
            self._filter_ast = None
            self.invalidateFilter()
            self.layoutChanged.emit()
            total = self.sourceModel().rowCount() if self.sourceModel() else 0
            self.filterStatsChanged.emit(total, total, 0.0)
            return True

        try:
            self._filter_ast = compile_filter(self._filter_text)
            self.invalidateFilter()
            self.layoutChanged.emit()
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            matched = self.rowCount()
            total = self.sourceModel().rowCount() if self.sourceModel() else 0
            self.filterStatsChanged.emit(matched, total, elapsed_ms)
            return True
        except Exception:
            self._filter_ast = None
            self.invalidateFilter()
            self.layoutChanged.emit()
            return False

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        """Evaluates whether the row satisfies the active filter AST."""
        if self._filter_ast is None:
            return True

        source_model = self.sourceModel()
        if source_model is None or not hasattr(source_model, "get_event"):
            return True

        event = source_model.get_event(source_row)
        if event is None:
            return False

        try:
            return self._filter_ast.evaluate(event)
        except Exception:
            return True

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        """
        Custom comparator enabling natural numeric sorting for No., Time, PID, TID, and text sorting for others.
        """
        source_model = self.sourceModel()
        if not source_model or not hasattr(source_model, "get_event"):
            return super().lessThan(left, right)

        col = left.column()
        ev_left = source_model.get_event(left.row())
        ev_right = source_model.get_event(right.row())

        if not ev_left or not ev_right:
            return super().lessThan(left, right)

        # 1. Column 0: "No." (Numeric)
        if col == 0:
            return left.row() < right.row()

        # 2. Column 1: "Time" (Timestamp Nanoseconds)
        elif col == 1:
            ts_l = int(ev_left.get("timestamp_ns", 0))
            ts_r = int(ev_right.get("timestamp_ns", 0))
            return ts_l < ts_r

        # 3. Column 4: "PID" & Column 5: "TID" (Numeric)
        elif col == 4:
            return int(ev_left.get("pid", 0)) < int(ev_right.get("pid", 0))
        elif col == 5:
            return int(ev_left.get("ppid", ev_left.get("tid", 0))) < int(ev_right.get("ppid", ev_right.get("tid", 0)))

        # 4. Column 9: "Threat Class" (Threat severity priority)
        elif col == 9:
            th_l = ev_left.get("threat_name") or "BENIGN"
            th_r = ev_right.get("threat_name") or "BENIGN"
            is_threat_l = 1 if th_l != "BENIGN" else 0
            is_threat_r = 1 if th_r != "BENIGN" else 0
            if is_threat_l != is_threat_r:
                return is_threat_l < is_threat_r
            return th_l < th_r

        # 5. Default Text Sorting
        left_data = source_model.data(left, Qt.ItemDataRole.DisplayRole)
        right_data = source_model.data(right, Qt.ItemDataRole.DisplayRole)
        return str(left_data).lower() < str(right_data).lower()

    def get_event_at_proxy_row(self, proxy_row: int) -> Optional[Dict[str, Any]]:
        """Retrieve event dictionary from proxy index."""
        source_index = self.mapToSource(self.index(proxy_row, 0))
        if source_index.isValid() and hasattr(self.sourceModel(), "get_event"):
            return self.sourceModel().get_event(source_index.row())
        return None
