"""
Stratoshark Hierarchical Detail Tree Model (ProtoTree Equivalent for System Calls).
Renders structured dissection layers: Process Context, Syscall Arguments, Network Sockets, eBPF Hooks, and ML Threat Intel.
"""

from PyQt6.QtCore import QAbstractItemModel, QModelIndex, Qt, QVariant
from PyQt6.QtGui import QFont, QColor, QBrush, QIcon
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import json

from stratoshark.core.theme import get_monospace_font


class TreeNode:
    """Represents a node in the Stratoshark event dissection tree."""

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
    Hierarchical model representing Stratoshark dissected layers of an event.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.root_node = TreeNode("Root")
        self.mono_font = get_monospace_font(size=9)

    def set_event(self, event: Optional[Dict[str, Any]], raw_json_str: str = ""):
        self.beginResetModel()
        self.root_node = TreeNode("Root")

        if not event:
            self.endResetModel()
            return

        self._build_tree(event, raw_json_str)
        self.endResetModel()

    def _build_tree(self, event: Dict[str, Any], raw_json: str):
        threat_name = str(event.get("threat_name") or event.get("threat_type") or event.get("agreed_threat") or "BENIGN")
        sc = str(event.get("syscall") or event.get("syscall_name") or event.get("event_type") or "SYS_EXEC")
        pid = event.get("pid", 0)
        comm = event.get("comm", "unknown")
        ts_ns = int(event.get("timestamp_ns", 0))

        dt_str = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f") if ts_ns > 0 else "N/A"

        # 1. Event Summary Header
        header_node = TreeNode(
            name=f"Stratoshark Event: {sc} (PID: {pid} - {comm})",
            value="",
            field_name="event_header"
        )
        self.root_node.append_child(header_node)

        header_node.append_child(TreeNode("Event Name (evt.type)", str(sc), "evt.type"))
        header_node.append_child(TreeNode("Timestamp (UTC)", dt_str, "timestamp_utc"))
        header_node.append_child(TreeNode("Timestamp (ns)", str(ts_ns), "timestamp_ns"))

        # 2. Process & Execution Context
        proc_node = TreeNode(
            name=f"Process Context: {comm} [PID: {pid}, PPID: {event.get('ppid', 1)}]",
            value="",
            field_name="proc_context"
        )
        self.root_node.append_child(proc_node)
        proc_node.append_child(TreeNode("Process Name (proc.name)", str(comm), "proc.name"))
        proc_node.append_child(TreeNode("Process ID (proc.pid)", str(pid), "proc.pid"))
        proc_node.append_child(TreeNode("Parent PID (proc.ppid)", str(event.get("ppid", 1)), "proc.ppid"))
        proc_node.append_child(TreeNode("User ID (user.uid)", str(event.get("uid", 1000)), "user.uid"))
        proc_node.append_child(TreeNode("Group ID (user.gid)", str(event.get("gid", 1000)), "user.gid"))
        proc_node.append_child(TreeNode("Executable Path", str(event.get("exe_path", f"/usr/bin/{comm}")), "proc.exe"))
        proc_node.append_child(TreeNode("Container Name", str(event.get("container_name", "host")), "container.name"))

        # 3. Syscall Parameters & Target
        sys_node = TreeNode(
            name=f"System Call Parameters: sys_{event.get('syscall_id', sc)}",
            value="",
            field_name="syscall_params"
        )
        self.root_node.append_child(sys_node)
        sys_node.append_child(TreeNode("Syscall ID", str(event.get("syscall_id", 0)), "syscall.id"))
        sys_node.append_child(TreeNode("Syscall Name", str(sc), "syscall.name"))
        fp = str(event.get("file_path") or event.get("filename") or event.get("exe_path") or "")
        if fp:
            sys_node.append_child(TreeNode("FD / Target Path (fd.name)", fp, "fd.name"))

        # 4. Network & Socket Context
        dst_ip = str(event.get("dst_ip", ""))
        dst_port = event.get("dst_port")
        if dst_ip and dst_ip != "0.0.0.0":
            net_node = TreeNode(
                name=f"Network Socket: Destination {dst_ip}:{dst_port}",
                value="",
                field_name="net_context"
            )
            self.root_node.append_child(net_node)
            net_node.append_child(TreeNode("Destination IP (ip.dst)", dst_ip, "ip.dst"))
            net_node.append_child(TreeNode("Destination Port (net.port)", str(dst_port), "net.port"))
            net_node.append_child(TreeNode("Protocol", "TCP/IPv4" if dst_port == 443 else "UDP/IPv4", "net.proto"))

        # 5. eBPF Hook & Kernel Subsystem
        ebpf_node = TreeNode(
            name=f"eBPF Kernel Probes: sys_tracer & net_filter active",
            value="",
            field_name="ebpf_context"
        )
        self.root_node.append_child(ebpf_node)
        ebpf_node.append_child(TreeNode("Attach Type", "BPF_PROG_TYPE_TRACEPOINT", "ebpf.type"))
        ebpf_node.append_child(TreeNode("Kernel Hook", f"sys_enter_{sc}", "ebpf.hook"))

        # 6. ML Security Classification & MITRE ATT&CK
        threat_node = TreeNode(
            name=f"Threat Detection Consensus: {threat_name}",
            value="",
            field_name="threat_context"
        )
        self.root_node.append_child(threat_node)
        threat_node.append_child(TreeNode("Classification", threat_name, "threat.name"))
        conf = float(event.get("confidence", 0.0))
        threat_node.append_child(TreeNode("Confidence Score", f"{conf:.4f}", "threat.confidence"))

        if threat_name != "BENIGN":
            tactic_map = {
                "PRIVILEGE_ESCALATION": "TA0004 - Privilege Escalation (T1068)",
                "REVERSE_SHELL": "TA0011 - Command and Control (T1059)",
                "DATA_EXFILTRATION": "TA0010 - Exfiltration (T1048)",
                "KERNEL_ROOTKIT": "TA0003 - Persistence (T1014)",
            }
            threat_node.append_child(TreeNode("MITRE ATT&CK Tactic", tactic_map.get(threat_name, "TA0002 - Execution"), "threat.mitre"))

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
        parent_node = parent.internalPointer() if parent.isValid() else self.root_node
        return parent_node.child_count()

    def columnCount(self, parent=QModelIndex()) -> int:
        return 2

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return "Event Layer / Property" if section == 0 else "Value"
        return QVariant()

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return QVariant()

        node = index.internalPointer()
        if role == Qt.ItemDataRole.DisplayRole:
            return node.name if index.column() == 0 else node.value
        elif role == Qt.ItemDataRole.FontRole:
            return self.mono_font
        return QVariant()
