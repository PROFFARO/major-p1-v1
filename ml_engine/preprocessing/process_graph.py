"""
Process Lineage Tree Graph (DAG) for Attack Chain & Ancestry Reconstruction.

Tracks parent-child process relationships (pid, ppid, comm, exe_path, cmdline)
to construct lateral movement and multi-stage attack trees.
"""

import logging
import threading
import time
from typing import Dict, Any, List, Optional

logger = logging.getLogger("ml_engine.preprocessing.process_graph")


class ProcessNode:
    """Represents a single process node in the execution graph."""

    def __init__(self, pid: int, ppid: int, comm: str, exe_path: str = "", cmdline: str = ""):
        self.pid = pid
        self.ppid = ppid
        self.comm = comm
        self.exe_path = exe_path
        self.cmdline = cmdline
        self.created_at = time.time()
        self.children: List[int] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "comm": self.comm,
            "exe_path": self.exe_path,
            "cmdline": self.cmdline,
            "created_at": self.created_at,
            "children_count": len(self.children),
        }


class ProcessTreeGraph:
    """
    Thread-safe Process Lineage DAG Manager.
    """

    def __init__(self, max_nodes: int = 50000):
        self.max_nodes = max_nodes
        self._lock = threading.Lock()
        self.nodes: Dict[int, ProcessNode] = {}

    def add_event(self, event: Dict[str, Any]) -> Optional[ProcessNode]:
        """Ingest a telemetry event to update process lineage tree."""
        pid = event.get("pid")
        if not pid or pid <= 0:
            return None

        ppid = event.get("ppid", 1)
        comm = str(event.get("comm", ""))
        exe_path = str(event.get("exe_path", ""))
        cmdline = str(event.get("cmdline", ""))

        with self._lock:
            # Evict oldest nodes if max capacity reached
            if len(self.nodes) >= self.max_nodes and pid not in self.nodes:
                oldest_pids = sorted(self.nodes.keys(), key=lambda k: self.nodes[k].created_at)[:1000]
                for opid in oldest_pids:
                    del self.nodes[opid]

            node = self.nodes.get(pid)
            if not node:
                node = ProcessNode(pid=pid, ppid=ppid, comm=comm, exe_path=exe_path, cmdline=cmdline)
                self.nodes[pid] = node
            else:
                if comm and not node.comm:
                    node.comm = comm
                if exe_path and not node.exe_path:
                    node.exe_path = exe_path
                if cmdline and not node.cmdline:
                    node.cmdline = cmdline

            # Update parent node children link
            if ppid > 0 and ppid in self.nodes and pid not in self.nodes[ppid].children:
                self.nodes[ppid].children.append(pid)

            return node

    def get_lineage(self, pid: int) -> List[Dict[str, Any]]:
        """
        Reconstruct parent chain from process PID up to root ancestor.
        Returns list of node dicts starting from root ancestor down to target PID.
        """
        chain = []
        visited = set()

        with self._lock:
            curr_pid = pid
            while curr_pid and curr_pid > 0 and curr_pid not in visited:
                visited.add(curr_pid)
                node = self.nodes.get(curr_pid)
                if not node:
                    # Synthetic node for missing parent
                    chain.append({"pid": curr_pid, "ppid": 0, "comm": f"pid_{curr_pid}", "exe_path": "", "cmdline": ""})
                    break
                chain.append(node.to_dict())
                curr_pid = node.ppid

        chain.reverse()
        return chain

    def get_lineage_string(self, pid: int) -> str:
        """Return formatted ASCII process lineage path string (e.g. systemd(1) -> bash(100) -> nc(500))."""
        chain = self.get_lineage(pid)
        if not chain:
            return f"PID_{pid}"
        return " -> ".join(f"{item['comm']}({item['pid']})" for item in chain)

    def size(self) -> int:
        with self._lock:
            return len(self.nodes)
