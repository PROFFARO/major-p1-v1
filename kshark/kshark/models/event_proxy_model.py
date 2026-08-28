"""
Sort & Filter Proxy Model for KShark Event List.
Applies AST-based Display Filter expressions with sub-millisecond evaluation.
"""

from PyQt6.QtCore import QSortFilterProxyModel, QModelIndex, pyqtSignal
from typing import Optional, Dict, Any
import time

from kshark.core.filter_engine import compile_filter, ASTNode


class EventFilterProxyModel(QSortFilterProxyModel):
    """
    Proxy model filtering and sorting the underlying EventTableModel.
    """

    filterStatsChanged = pyqtSignal(int, int, float)  # (matched_rows, total_rows, elapsed_ms)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._filter_ast: Optional[ASTNode] = None
        self._filter_text: str = ""
        self.setDynamicSortFilter(False)

    def set_display_filter(self, filter_text: str) -> bool:
        """
        Sets and compiles a new display filter expression.
        Returns True if filter is valid, False if syntax error.
        """
        start_time = time.perf_counter()
        self._filter_text = filter_text.strip()

        if not self._filter_text:
            self._filter_ast = None
            self.invalidateFilter()
            total = self.sourceModel().rowCount() if self.sourceModel() else 0
            self.filterStatsChanged.emit(total, total, 0.0)
            return True

        try:
            self._filter_ast = compile_filter(self._filter_text)
            self.invalidateFilter()
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            matched = self.rowCount()
            total = self.sourceModel().rowCount() if self.sourceModel() else 0
            self.filterStatsChanged.emit(matched, total, elapsed_ms)
            return True
        except Exception:
            self._filter_ast = None
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

    def get_event_at_proxy_row(self, proxy_row: int) -> Optional[Dict[str, Any]]:
        """Retrieve event dictionary from proxy index."""
        source_index = self.mapToSource(self.index(proxy_row, 0))
        if source_index.isValid() and hasattr(self.sourceModel(), "get_event"):
            return self.sourceModel().get_event(source_index.row())
        return None
