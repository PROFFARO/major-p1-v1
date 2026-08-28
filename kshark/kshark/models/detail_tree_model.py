"""
Hierarchical Detail Tree Model for KShark Event Details Pane (Wireshark ProtoTree Equivalent).
"""

from PyQt6.QtCore import QAbstractItemModel, QModelIndex, Qt, QVariant
from PyQt6.QtGui import QFont, QColor, QBrush, QIcon
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import json

from kshark.core.theme import get_monospace_font


class TreeNode:
    """Represents a node in the event dissection tree."""

    def __init__(
        self,
        name: str,
        value: str = "",
        field_name: str = "",
        byte_start: int = -1,
        byte_len: int = 0,
        severity: str = "INFO",
        icon: Optional[QIcon] = None,
        parent: Optional['TreeNode'] = None
    ):
        self.name = name
        self.value = value
        self.field_name = field_name
        self.byte_start = byte_start
        self.byte_len = byte_len
        self.severity = severity
        self.icon = icon
        self.parent = parent
        self.children: List['TreeNode'] = []

    def append_child(self, child: 'TreeNode'):
        child.parent = self
        self.children.append(child)

    def child(self, row: int) -> Optional['TreeNode']:
        if 0 <= row < len(self.children):
            return self.children[row]
        return None

    def child_count(self) -> int:
        return len(self.children)

    def row(self) -> int:
        if self.parent:
            return self.parent.children.index(self)
        return 0


class DetailTreeModel(QAbstractItemModel):
    """
    Hierarchical model representing dissected layers of a selected telemetry event.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.root_node = TreeNode("Root")
        self.mono_font = get_monospace_font(size=9)

    def set_event(self, event: Optional[Dict[str, Any]], raw_json_str: str = ""):
        """Populates the tree with hierarchical dissection nodes for the selected event."""
        self.beginResetModel()
        self.root_node = TreeNode("Root")

        if not event:
            self.endResetModel()
            return

        self._build_tree(event, raw_json_str)
        self.endResetModel()

    def _build_tree(self, event: Dict[str, Any], raw_json: str):
        """Constructs category and field nodes from event dictionary."""
        # ─────────────────────────────────────────────────────
        # 1. Event Summary Header Node
        # ─────────────────────────────────────────────────────
        threat_name = str(event.get("threat_name") or event.get("threat_type") or event.get("agreed_threat") or "BENIGN")
        event_type = str(event.get("event_type", event.get("event_type_str", "SYS_EXEC")))
        pid = event.get("pid", 0)
        comm = event.get("comm", "unknown")
        ts_ns = int(event.get("timestamp_ns", 0))

        dt_str = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f") if ts_ns > 0 else "N/A"

        header_node = TreeNode(
            name=f"Linux Kernel eBPF Telemetry Event, Subsystem: {event_type}, PID: {pid} ({comm})",
            value="",
            field_name="event_header"
        )
        self.root_node.append_child(header_node)

        header_node.append_child(TreeNode("Event Class", str(event_type), "event_type"))
        header_node.append_child(TreeNode("Timestamp (UTC)", dt_str, "timestamp_utc"))
        header_node.append_child(TreeNode("Timestamp (Nanoseconds Epoch)", str(ts_ns), "timestamp_ns"))

        # ─────────────────────────────────────────────────────
        # 2. Process Context & Execution Lineage
        # ─────────────────────────────────────────────────────
        proc_node = TreeNode(
            name=f"Process Context & Execution Lineage (PID: {pid}, Comm: {comm})",
            value="",
            field_name="process_context"
        )
        self.root_node.append_child(proc_node)

        proc_node.append_child(TreeNode("Process ID (PID)", str(pid), "pid"))
        proc_node.append_child(TreeNode("Parent Process ID (PPID)", str(event.get("ppid", 1)), "ppid"))
        proc_node.append_child(TreeNode("User ID (UID)", str(event.get("uid", 1000)), "uid"))
        proc_node.append_child(TreeNode("Group ID (GID)", str(event.get("gid", 1000)), "gid"))
        proc_node.append_child(TreeNode("Executable Command", str(comm), "comm"))
        proc_node.append_child(TreeNode("Executable Path", str(event.get("exe_path", "/usr/bin/unknown")), "exe_path"))
        proc_node.append_child(TreeNode("Parent Process Name", str(event.get("parent_comm", "systemd")), "parent_comm"))

        lineage = event.get("lineage_str")
        if lineage:
            proc_node.append_child(TreeNode("Process Lineage Tree (DAG)", str(lineage), "lineage_str"))

        # ─────────────────────────────────────────────────────
        # 3. System Call Dissection
        # ─────────────────────────────────────────────────────
        syscall_node = TreeNode(
            name=f"System Call Dissection",
            value="",
            field_name="syscall_context"
        )
        self.root_node.append_child(syscall_node)

        sc_id = event.get("syscall_id")
        sc_name = event.get("syscall") or event.get("syscall_name") or (f"sys_{sc_id}" if sc_id is not None else "N/A")
        syscall_node.append_child(TreeNode("Syscall Name", str(sc_name), "syscall"))
        if sc_id is not None:
            syscall_node.append_child(TreeNode("Syscall ID", str(sc_id), "syscall_id"))

        ret_val = event.get("ret_val")
        if ret_val is not None:
            syscall_node.append_child(TreeNode("Return Value", str(ret_val), "ret_val"))

        file_p = event.get("file_path") or event.get("filename")
        if file_p:
            syscall_node.append_child(TreeNode("Target File / Resource Path", str(file_p), "file_path"))

        bytes_w = event.get("bytes_written")
        if bytes_w is not None and int(bytes_w) > 0:
            syscall_node.append_child(TreeNode("Bytes Written", f"{bytes_w} bytes", "bytes_written"))

        bytes_r = event.get("bytes_read")
        if bytes_r is not None and int(bytes_r) > 0:
            syscall_node.append_child(TreeNode("Bytes Read", f"{bytes_r} bytes", "bytes_read"))

        # ─────────────────────────────────────────────────────
        # 4. Network Socket Telemetry (if present)
        # ─────────────────────────────────────────────────────
        dst_ip = str(event.get("dst_ip", ""))
        dst_port = event.get("dst_port")
        if dst_ip and dst_ip != "0.0.0.0":
            net_node = TreeNode(
                name=f"Network Socket Flow Context ({dst_ip}:{dst_port})",
                value="",
                field_name="network_context"
            )
            self.root_node.append_child(net_node)
            net_node.append_child(TreeNode("Destination IP Address", dst_ip, "dst_ip"))
            net_node.append_child(TreeNode("Destination Port", str(dst_port), "dst_port"))
            net_node.append_child(TreeNode("Protocol", str(event.get("protocol", "TCP")), "protocol"))

        # ─────────────────────────────────────────────────────
        # 5. Machine Learning Threat Analysis & Anomaly Scoring
        # ─────────────────────────────────────────────────────
        ml_scores = event.get("ml_scores", {})
        conf = float(event.get("confidence", 0.0))

        ml_node = TreeNode(
            name=f"Machine Learning Threat Analysis (Consensus: {threat_name}, Confidence: {conf*100:.1f}%)",
            value="",
            field_name="ml_analysis",
            severity="CRITICAL" if threat_name != "BENIGN" else "INFO"
        )
        self.root_node.append_child(ml_node)

        ml_node.append_child(TreeNode("Ensemble Consensus Classification", threat_name, "agreed_threat"))
        ml_node.append_child(TreeNode("Ensemble Confidence Score", f"{conf:.4f} ({conf*100:.1f}%)", "confidence"))

        if ml_scores:
            if "rf" in ml_scores:
                ml_node.append_child(TreeNode("Random Forest Classification", str(ml_scores["rf"]), "rf_score"))
            if "xgb" in ml_scores:
                ml_node.append_child(TreeNode("XGBoost Classification", str(ml_scores["xgb"]), "xgb_score"))
            if "iso_score" in ml_scores:
                ml_node.append_child(TreeNode("Isolation Forest Anomaly Score", f"{ml_scores['iso_score']:.4f}", "iso_score"))

        # ─────────────────────────────────────────────────────
        # 6. Falco Behavioral Rules & MITRE ATT&CK
        # ─────────────────────────────────────────────────────
        rule_info = event.get("rule_info")
        rule_name = event.get("rule_name")
        mitre_id = event.get("mitre_id")

        if rule_info or rule_name or mitre_id:
            r_name = rule_name or (rule_info.get("rule_name") if isinstance(rule_info, dict) else "Behavioral Anomaly")
            r_id = event.get("rule_id") or (rule_info.get("rule_id") if isinstance(rule_info, dict) else "RULE-000")
            r_mitre = mitre_id or (rule_info.get("mitre_id") if isinstance(rule_info, dict) else "T1059")
            r_desc = event.get("description") or (rule_info.get("description") if isinstance(rule_info, dict) else "")

            falco_node = TreeNode(
                name=f"Behavioral Engine Detection (Rule: {r_name}, MITRE: {r_mitre})",
                value="",
                field_name="behavioral_match",
                severity="HIGH"
            )
            self.root_node.append_child(falco_node)
            falco_node.append_child(TreeNode("Rule ID", str(r_id), "rule_id"))
            falco_node.append_child(TreeNode("Rule Name", str(r_name), "rule_name"))
            falco_node.append_child(TreeNode("MITRE ATT&CK Technique", str(r_mitre), "mitre_id"))
            if r_desc:
                falco_node.append_child(TreeNode("Rule Description", str(r_desc), "rule_description"))

    # ─────────────────────────────────────────────────────────
    # QAbstractItemModel Mandatory Methods
    # ─────────────────────────────────────────────────────────

    def index(self, row: int, column: int, parent=QModelIndex()) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        parent_node = parent.internalPointer() if parent.isValid() else self.root_node
        child_node = parent_node.child(row)
        if child_node:
            return self.createIndex(row, column, child_node)
        return QModelIndex()

    def parent(self, index: QModelIndex) -> QModelIndex:
        if not index.isValid():
            return QModelIndex()

        child_node = index.internalPointer()
        parent_node = child_node.parent

        if parent_node == self.root_node or parent_node is None:
            return QModelIndex()

        return self.createIndex(parent_node.row(), 0, parent_node)

    def rowCount(self, parent=QModelIndex()) -> int:
        if parent.column() > 0:
            return 0
        parent_node = parent.internalPointer() if parent.isValid() else self.root_node
        return parent_node.child_count()

    def columnCount(self, parent=QModelIndex()) -> int:
        return 2  # Column 0: Property Name / Layer, Column 1: Value

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return QVariant()

        node: TreeNode = index.internalPointer()

        if role == Qt.ItemDataRole.DisplayRole:
            if index.column() == 0:
                if node.value:
                    return f"{node.name}: {node.value}"
                return node.name
            elif index.column() == 1:
                return node.value

        elif role == Qt.ItemDataRole.FontRole:
            return self.mono_font

        elif role == Qt.ItemDataRole.ForegroundRole:
            if node.severity == "CRITICAL":
                return QBrush(QColor("#D32F2F"))
            elif node.severity == "HIGH":
                return QBrush(QColor("#E65100"))

        return QVariant()

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return "Event Layer / Property" if section == 0 else "Value"
        return QVariant()
