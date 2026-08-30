"""
KShark Hierarchical Dissection Detail Tree Model (ProtoTree Architecture for System Telemetry).
Engineered for Developers, Security Analysts, Cyber Engineers, and Network Administrators.
Provides 6-tier deep protocol & kernel dissection:
- Frame / Kernel Telemetry Header
- Process & Security Identity
- System Call & Argument Dissection
- Network Socket & Transport Layer
- Threat Intelligence & MITRE ATT&CK Consensus
- eBPF Kernel Probes & Hook Telemetry
"""

from PyQt6.QtCore import QAbstractItemModel, QModelIndex, Qt, QVariant
from PyQt6.QtGui import QFont, QColor, QBrush, QIcon
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import json
import os

from kshark.core.theme import get_monospace_font, get_ui_font
from kshark.core.syscall_table import resolve_syscall_name, get_syscall_id


class TreeNode:
    """Represents a node in the KShark event dissection tree."""

    def __init__(
        self,
        name: str,
        value: str = "",
        field_name: str = "",
        badge: str = "",
        badge_color: Optional[str] = None,
        severity: str = "INFO",
        icon: Optional[QIcon] = None,
        tooltip: str = "",
        byte_offset: int = -1,
        byte_length: int = 0,
        parent: Optional['TreeNode'] = None
    ):
        self.name = name
        self.value = value
        self.field_name = field_name
        self.badge = badge
        self.badge_color = badge_color
        self.severity = severity
        self.icon = icon
        self.tooltip = tooltip
        self.byte_offset = byte_offset
        self.byte_length = byte_length
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
    Hierarchical model representing KShark dissected layers of a telemetry event.
    """

    COLUMNS = ["Layer / Property", "Value", "Dissection Metadata"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.root_node = TreeNode("Root")
        self.mono_font = get_monospace_font(size=9)
        self.header_font = get_ui_font(size=9, bold=True)
    def set_font_size(self, size: float):
        """Updates fonts dynamically across the hierarchical dissection tree."""
        self.mono_font = get_monospace_font(size=size)
        self.header_font = get_ui_font(size=size, bold=True)
        self.layoutChanged.emit()

    def set_search_filter(self, filter_text: str):
        self._search_filter = filter_text.strip().lower()

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
        sc = resolve_syscall_name(event)
        sc_id = event.get("syscall_id", get_syscall_id(sc) if isinstance(sc, str) else 0)
        pid = event.get("pid", 0)
        ppid = event.get("ppid", 1)
        uid = event.get("uid", 1000)
        gid = event.get("gid", 1000)
        comm = str(event.get("comm") or event.get("proc_name") or "unknown")
        exe_path = str(event.get("exe_path") or f"/usr/bin/{comm}")
        cmdline = str(event.get("cmdline") or exe_path)
        cwd = str(event.get("cwd") or "/home/proffaro")
        file_path = str(event.get("file_path") or event.get("filename") or "")
        dst_ip = str(event.get("dst_ip", ""))
        dst_port = event.get("dst_port", 0)
        src_ip = str(event.get("src_ip", "127.0.0.1"))
        src_port = event.get("src_port", 0)
        ts_ns = int(event.get("timestamp_ns", 0))
        retval = event.get("retval", 0)
        conf = float(event.get("confidence", 0.0))

        # Format human-readable UTC timestamp
        dt_str = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f") if ts_ns > 0 else "N/A"

        # ── 1. Frame & Kernel Telemetry Header ──
        hdr_layer = TreeNode(
            name=f"Frame: System Call Telemetry ({sc})",
            value=f"PID {pid} · {dt_str}",
            field_name="frame.header",
            badge="KERNEL TRACE",
            badge_color="#0E9AA7",
            tooltip="Kernel tracepoint capture metadata and timing attributes",
            byte_offset=0,
            byte_length=16
        )
        self.root_node.append_child(hdr_layer)
        hdr_layer.append_child(TreeNode("Event Name (evt.type)", str(sc), "evt.type", tooltip="Linux System Call event identifier", byte_offset=0, byte_length=4))
        hdr_layer.append_child(TreeNode("Timestamp (UTC)", dt_str, "timestamp_utc", tooltip="Universal Coordinated Time", byte_offset=4, byte_length=8))
        hdr_layer.append_child(TreeNode("Timestamp (ns)", str(ts_ns), "timestamp_ns", tooltip="Kernel nanosecond monotonic clock", byte_offset=4, byte_length=8))
        hdr_layer.append_child(TreeNode("Architecture", "Linux x86_64 (64-bit ELF)", "arch", tooltip="Target CPU architecture", byte_offset=12, byte_length=2))
        hdr_layer.append_child(TreeNode("Kernel Subsystem", self._get_subsystem(str(sc)), "kernel.subsystem", tooltip="Target Linux kernel subsystem", byte_offset=14, byte_length=2))

        # ── 2. Process & Security Identity ──
        user_badge = "ROOT (UID 0)" if uid == 0 else f"USER (UID {uid})"
        user_badge_color = "#E74C3C" if uid == 0 else "#2ECC71"
        proc_layer = TreeNode(
            name=f"Process Context: {comm} (PID: {pid}, PPID: {ppid})",
            value=f"{exe_path}",
            field_name="proc.context",
            badge=user_badge,
            badge_color=user_badge_color,
            tooltip="Process execution environment, user credentials, and namespace attributes",
            byte_offset=16,
            byte_length=48
        )
        self.root_node.append_child(proc_layer)
        proc_layer.append_child(TreeNode("Process Name (proc.name)", comm, "proc.name", badge="COMM", tooltip="Process command name", byte_offset=16, byte_length=16))
        proc_layer.append_child(TreeNode("Process ID (proc.pid)", str(pid), "proc.pid", tooltip="Process Identifier", byte_offset=32, byte_length=4))
        proc_layer.append_child(TreeNode("Thread ID (proc.tid)", str(event.get("tid", pid)), "proc.tid", tooltip="Thread Identifier", byte_offset=36, byte_length=4))
        proc_layer.append_child(TreeNode("Parent Process ID (proc.ppid)", str(ppid), "proc.ppid", tooltip="Parent Process Identifier", byte_offset=40, byte_length=4))
        proc_layer.append_child(TreeNode("User ID (user.uid)", f"{uid} ({'root' if uid == 0 else 'user'})", "user.uid", badge="SECURITY", tooltip="Effective User ID", byte_offset=44, byte_length=2))
        proc_layer.append_child(TreeNode("Group ID (user.gid)", f"{gid}", "user.gid", tooltip="Effective Group ID", byte_offset=46, byte_length=2))
        proc_layer.append_child(TreeNode("Executable Binary (proc.exe)", exe_path, "proc.exe", tooltip="Absolute filesystem path to executable binary", byte_offset=48, byte_length=32))
        proc_layer.append_child(TreeNode("Command Line (proc.cmdline)", cmdline, "proc.cmdline", tooltip="Full process invocation arguments", byte_offset=48, byte_length=len(cmdline.encode('utf-8'))))
        proc_layer.append_child(TreeNode("Working Directory (proc.cwd)", cwd, "proc.cwd", tooltip="Process current working directory", byte_offset=48, byte_length=len(cwd.encode('utf-8'))))
        proc_layer.append_child(TreeNode("Container / CGroup", str(event.get("container_name", "host")), "container.name", badge="ISOLATION", tooltip="Container name or host namespace", byte_offset=16, byte_length=16))

        # ── 3. System Call & Argument Dissection ──
        res_badge = "SUCCESS" if retval >= 0 else f"ERRNO {retval}"
        res_color = "#2ECC71" if retval >= 0 else "#E74C3C"
        sys_layer = TreeNode(
            name=f"System Call Dissection: {sc} (ID: {sc_id})",
            value=f"Return: {retval}",
            field_name="syscall.dissection",
            badge=res_badge,
            badge_color=res_color,
            tooltip="Detailed system call parameters, file descriptors, and kernel return values",
            byte_offset=64,
            byte_length=48
        )
        self.root_node.append_child(sys_layer)
        sys_layer.append_child(TreeNode("Syscall ID (evt.id)", str(sc_id), "evt.id", tooltip="POSIX syscall vector number", byte_offset=64, byte_length=4))
        sys_layer.append_child(TreeNode("Syscall Name (evt.type)", str(sc), "evt.type", tooltip="Syscall name", byte_offset=68, byte_length=8))
        sys_layer.append_child(TreeNode("Return Value (evt.res)", str(retval), "evt.res", tooltip="Syscall return status or errno", byte_offset=76, byte_length=4))

        if file_path and file_path != "-":
            sys_layer.append_child(TreeNode("Target Path (fd.name)", file_path, "fd.name", badge="PATH", tooltip="Target file path / resource", byte_offset=80, byte_length=min(48, len(file_path.encode('utf-8')))))
            sys_layer.append_child(TreeNode("Filename Basename", os.path.basename(file_path), "file.name", tooltip="File basename", byte_offset=80, byte_length=len(os.path.basename(file_path).encode('utf-8'))))

        # ── 4. Network Socket & Transport Layer ──
        if (dst_ip and dst_ip != "0.0.0.0") or (src_ip and src_port > 0) or "sock" in str(sc) or "connect" in str(sc) or "accept" in str(sc):
            proto = "TCP" if dst_port in (80, 443, 4444, 22, 8080) or "tcp" in str(sc) else "UDP"
            net_layer = TreeNode(
                name=f"Network & Transport Layer: {proto} ({src_ip}:{src_port} -> {dst_ip}:{dst_port})",
                value=f"{proto} Socket",
                field_name="net.layer",
                badge=f"{proto} PORT {dst_port}" if dst_port > 0 else "SOCKET",
                badge_color="#3498DB",
                tooltip="Network socket layer, endpoints, and transport protocols",
                byte_offset=128,
                byte_length=32
            )
            self.root_node.append_child(net_layer)
            net_layer.append_child(TreeNode("Socket Protocol (net.proto)", proto, "net.proto", tooltip="Transport protocol", byte_offset=128, byte_length=2))
            net_layer.append_child(TreeNode("Destination IP (ip.dst)", dst_ip if dst_ip else "0.0.0.0", "ip.dst", tooltip="Remote IP address", byte_offset=130, byte_length=4))
            net_layer.append_child(TreeNode("Destination Port (net.port)", str(dst_port), "net.port", tooltip="Remote port number", byte_offset=134, byte_length=2))
            net_layer.append_child(TreeNode("Source IP (ip.src)", src_ip, "ip.src", tooltip="Local IP address", byte_offset=136, byte_length=4))
            net_layer.append_child(TreeNode("Source Port (net.srcport)", str(src_port), "net.srcport", tooltip="Local port number", byte_offset=140, byte_length=2))
            net_layer.append_child(TreeNode("Traffic Direction", "OUTBOUND / EGRESS" if dst_port > 0 else "INBOUND", "net.dir", tooltip="Traffic flow direction", byte_offset=142, byte_length=2))

        # ── 5. Threat Intelligence & MITRE ATT&CK ──
        is_threat = threat_name != "BENIGN"
        threat_badge = f"THREAT: {threat_name}" if is_threat else "BENIGN BASELINE"
        threat_badge_color = "#E74C3C" if is_threat else "#2ECC71"
        threat_layer = TreeNode(
            name=f"Threat Intelligence Consensus: {threat_name}",
            value=f"Confidence: {conf * 100:.1f}%",
            field_name="threat.intel",
            badge=threat_badge,
            badge_color=threat_badge_color,
            tooltip="Machine learning ensemble analysis, behavioral rules, and MITRE ATT&CK taxonomy",
            byte_offset=160,
            byte_length=32
        )
        self.root_node.append_child(threat_layer)
        threat_layer.append_child(TreeNode("Threat Classification (threat.name)", threat_name, "threat.name", badge="CONSENSUS", tooltip="Ensemble consensus classification", byte_offset=160, byte_length=16))
        threat_layer.append_child(TreeNode("Detection Confidence (threat.confidence)", f"{conf:.4f} ({conf * 100:.1f}%)", "threat.confidence", tooltip="Dual Random Forest + XGBoost weighted probability", byte_offset=176, byte_length=4))
        threat_layer.append_child(TreeNode("Detection Engine", str(event.get("detection_source", "dual_ensemble_ml")), "detection.engine", tooltip="ML Ensemble / Falco Behavioral Rules Engine", byte_offset=180, byte_length=12))

        mitre_id = self._get_mitre_id(threat_name)
        if mitre_id:
            threat_layer.append_child(TreeNode("MITRE ATT&CK Technique", mitre_id, "mitre.id", badge="MITRE ATT&CK", badge_color="#F39C12", tooltip="MITRE Enterprise ATT&CK matrix technique", byte_offset=160, byte_length=16))

        # ── 6. eBPF Kernel Probes & Hook Telemetry ──
        ebpf_layer = TreeNode(
            name=f"eBPF Kernel Probes: sys_tracer & net_filter active",
            value="RingBuffer Stream",
            field_name="ebpf.telemetry",
            badge="ACTIVE",
            badge_color="#9B59B6",
            tooltip="Underlying Linux kernel eBPF tracepoints and security probes",
            byte_offset=192,
            byte_length=32
        )
        self.root_node.append_child(ebpf_layer)
        ebpf_layer.append_child(TreeNode("eBPF Attach Type", "BPF_PROG_TYPE_TRACEPOINT", "ebpf.type", tooltip="eBPF program type", byte_offset=192, byte_length=8))
        ebpf_layer.append_child(TreeNode("Kernel Tracepoint Hook", f"sys_enter_{sc}", "ebpf.hook", tooltip="Kernel tracepoint hook location", byte_offset=200, byte_length=8))
        ebpf_layer.append_child(TreeNode("Telemetry RingBuffer", "BPF_MAP_TYPE_RINGBUF (64MB)", "ebpf.ringbuf", tooltip="Lockless ring buffer channel", byte_offset=208, byte_length=8))

    def _get_subsystem(self, sc: str) -> str:
        sc_l = sc.lower()
        if sc_l in ("open", "openat", "read", "write", "close", "unlink", "stat", "fstat", "rename", "chmod"):
            return "VFS / Filesystem"
        elif sc_l in ("socket", "connect", "accept", "sendto", "recvfrom", "bind", "listen"):
            return "Networking / Sockets"
        elif sc_l in ("execve", "fork", "vfork", "clone", "exit", "wait4", "kill"):
            return "Process Lifecycle"
        elif sc_l in ("mmap", "mprotect", "brk", "munmap", "memfd_create"):
            return "Memory Management"
        elif "security" in sc_l or sc_l in ("setuid", "capset", "ptrace"):
            return "Security / LSM"
        return "Kernel Core"

    def _get_mitre_id(self, threat: str) -> Optional[str]:
        t = threat.upper()
        if "RANSOMWARE" in t:
            return "T1486 — Data Encrypted for Impact"
        elif "REVERSE" in t or "SHELL" in t:
            return "T1059.004 — Unix Shell / Command Execution"
        elif "PRIVILEGE" in t:
            return "T1068 — Exploitation for Privilege Escalation"
        elif "MINER" in t or "CRYPTO" in t:
            return "T1496 — Resource Hijacking"
        elif "FILELESS" in t or "MEMFD" in t:
            return "T1620 — Reflective Code Loading"
        elif "SHADOW" in t or "CREDENTIAL" in t:
            return "T1003.008 — OS Credential Dumping"
        elif "TEMP" in t or "SUSPICIOUS" in t:
            return "T1059 — Execution in Temporary Directory"
        elif "SCAN" in t or "PORT" in t:
            return "T1046 — Network Service Discovery"
        return None

    def index(self, row: int, column: int, parent: QModelIndex = QModelIndex()) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        if not parent.isValid():
            parent_node = self.root_node
        else:
            parent_node = parent.internalPointer()

        child_node = parent_node.child(row)
        if child_node:
            return self.createIndex(row, column, child_node)
        return QModelIndex()

    def parent(self, index: QModelIndex) -> QModelIndex:
        if not index.isValid():
            return QModelIndex()

        child_node = index.internalPointer()
        parent_node = child_node.parent

        if parent_node == self.root_node or not parent_node:
            return QModelIndex()

        return self.createIndex(parent_node.row(), 0, parent_node)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.column() > 0:
            return 0
        if not parent.isValid():
            parent_node = self.root_node
        else:
            parent_node = parent.internalPointer()
        return parent_node.child_count()

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLUMNS[section]
        return QVariant()

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return QVariant()

        node = index.internalPointer()
        col = index.column()

        # Display text role
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return node.name
            elif col == 1:
                return node.value
            elif col == 2:
                return node.badge

        # Tooltip role
        elif role == Qt.ItemDataRole.ToolTipRole:
            if node.tooltip:
                return f"{node.tooltip} (Filter: {node.field_name})"
            return node.field_name

        # Font role
        elif role == Qt.ItemDataRole.FontRole:
            if not node.parent or node.parent == self.root_node:
                return self.header_font
            return self.mono_font

        # Foreground color role
        elif role == Qt.ItemDataRole.ForegroundRole:
            if not node.parent or node.parent == self.root_node:
                return QBrush(QColor("#0E9AA7"))
            if col == 2 and node.badge_color:
                return QBrush(QColor(node.badge_color))
            if col == 1:
                if node.severity == "CRITICAL" or "ERRNO" in node.value:
                    return QBrush(QColor("#E74C3C"))
                return QBrush(QColor("#E0E0E0"))

        # Byte offset range role (UserRole + 1)
        elif role == Qt.ItemDataRole.UserRole + 1:
            return (node.byte_offset, node.byte_length)

        return QVariant()
