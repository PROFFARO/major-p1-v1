"""
Sort & Filter Proxy Model for KShark Event List.
Applies AST-based Display Filter expressions and natural numeric / semantic sorting across columns.
"""

from PyQt6.QtCore import QSortFilterProxyModel, QModelIndex, pyqtSignal, Qt
from typing import Optional, Dict, Any, List
import time

from kshark.core.filter_engine import compile_filter, ASTNode
from kshark.core.syscall_table import resolve_syscall_name


class EventFilterProxyModel(QSortFilterProxyModel):
    """
    Proxy model filtering and sorting the underlying EventTableModel with correct numeric, IP, and semantic comparison.
    """

    filterStatsChanged = pyqtSignal(int, int, float)  # (matched_rows, total_rows, elapsed_ms)

    THREAT_SEVERITY_RANK = {
        "BENIGN": 0,
        "SUSPICIOUS_EXECUTION": 1,
        "FILELESS_EXECUTION": 2,
        "CRYPTO_MINER": 2,
        "PRIVILEGE_ESCALATION": 3,
        "CREDENTIAL_DUMPING": 3,
        "REVERSE_SHELL": 4,
        "RANSOMWARE": 4,
        "KERNEL_ROOTKIT": 4,
        "CONTAINER_ESCAPE": 4,
    }

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
            self.invalidateFilter()
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
        Custom comparator enabling natural numeric sorting for No., Time, PID, TID, IP, Threat severity, and strings.
        """
        source_model = self.sourceModel()
        if not source_model or not hasattr(source_model, "get_event"):
            return super().lessThan(left, right)

        col = left.column()
        ev_left = source_model.get_event(left.row())
        ev_right = source_model.get_event(right.row())

        if not ev_left or not ev_right:
            return super().lessThan(left, right)

        # 1. Column 0: "No." (Natural event index numeric sort)
        if col == 0:
            return left.row() < right.row()

        # 2. Column 1: "Time" (Timestamp Nanoseconds numeric sort)
        elif col == 1:
            ts_l = int(ev_left.get("timestamp_ns", 0))
            ts_r = int(ev_right.get("timestamp_ns", 0))
            return ts_l < ts_r

        # 3. Column 2: "Event Name" (Syscall string sort)
        elif col == 2:
            sc_l = resolve_syscall_name(ev_left).lower()
            sc_r = resolve_syscall_name(ev_right).lower()
            return sc_l < sc_r

        # 4. Column 3: "Proc Name" (Process command string sort)
        elif col == 3:
            p_l = str(ev_left.get("comm") or ev_left.get("proc_name") or "").lower()
            p_r = str(ev_right.get("comm") or ev_right.get("proc_name") or "").lower()
            return p_l < p_r

        # 5. Column 4: "PID" (Numeric sort)
        elif col == 4:
            return int(ev_left.get("pid", 0)) < int(ev_right.get("pid", 0))

        # 6. Column 5: "TID" / PPID (Numeric sort)
        elif col == 5:
            tid_l = int(ev_left.get("tid", ev_left.get("ppid", 0)))
            tid_r = int(ev_right.get("tid", ev_right.get("ppid", 0)))
            return tid_l < tid_r

        # 7. Column 6: "FD / Target" (Path string sort)
        elif col == 6:
            fp_l = str(ev_left.get("file_path") or ev_left.get("filename") or ev_left.get("exe_path") or "").lower()
            fp_r = str(ev_right.get("file_path") or ev_right.get("filename") or ev_right.get("exe_path") or "").lower()
            return fp_l < fp_r

        # 8. Column 7: "Network Destination" (IP Address octet numeric sort)
        elif col == 7:
            ip_l = str(ev_left.get("dst_ip", ""))
            ip_r = str(ev_right.get("dst_ip", ""))
            return self._compare_ips(ip_l, ip_r)

        # 9. Column 8: "Container Name" (String sort)
        elif col == 8:
            c_l = str(ev_left.get("container_name") or "host").lower()
            c_r = str(ev_right.get("container_name") or "host").lower()
            return c_l < c_r

        # 10. Column 9: "Threat Class" (Severity rank sort)
        elif col == 9:
            th_l = str(ev_left.get("threat_name") or ev_left.get("threat_type") or "BENIGN").upper()
            th_r = str(ev_right.get("threat_name") or ev_right.get("threat_type") or "BENIGN").upper()
            rank_l = self.THREAT_SEVERITY_RANK.get(th_l, 1)
            rank_r = self.THREAT_SEVERITY_RANK.get(th_r, 1)
            if rank_l != rank_r:
                return rank_l < rank_r
            conf_l = float(ev_left.get("confidence", 0.0))
            conf_r = float(ev_right.get("confidence", 0.0))
            return conf_l < conf_r

        # 11. Column 10: "Forensic Info" (Default Text)
        left_data = source_model.data(left, Qt.ItemDataRole.DisplayRole)
        right_data = source_model.data(right, Qt.ItemDataRole.DisplayRole)
        return str(left_data).lower() < str(right_data).lower()

    def _compare_ips(self, ip_a: str, ip_b: str) -> bool:
        """Compares IPv4 strings numerically by octets."""
        try:
            parts_a = tuple(int(x) for x in ip_a.split(".") if x.isdigit())
            parts_b = tuple(int(x) for x in ip_b.split(".") if x.isdigit())
            if len(parts_a) == 4 and len(parts_b) == 4:
                return parts_a < parts_b
        except Exception:
            pass
        return ip_a.lower() < ip_b.lower()

    def get_event_at_proxy_row(self, proxy_row: int) -> Optional[Dict[str, Any]]:
        """Retrieve event dictionary from proxy index."""
        source_index = self.mapToSource(self.index(proxy_row, 0))
        if source_index.isValid() and hasattr(self.sourceModel(), "get_event"):
            return self.sourceModel().get_event(source_index.row())
        return None
