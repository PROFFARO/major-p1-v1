"""
Unit Tests for KShark EventTableModel & DetailTreeModel.
"""

from PyQt6.QtWidgets import QApplication
import sys

# Ensure QApplication exists for Qt models
app = QApplication.instance() or QApplication(sys.argv)

from kshark.models.event_table_model import EventTableModel
from kshark.models.detail_tree_model import DetailTreeModel
from kshark.models.event_proxy_model import EventFilterProxyModel


def test_event_table_model_basic():
    model = EventTableModel()
    assert model.rowCount() == 0
    assert model.columnCount() == len(EventTableModel.COLUMNS)

    event1 = {
        "timestamp_ns": 1724876716123456789,
        "pid": 1001,
        "ppid": 1,
        "uid": 1000,
        "comm": "sshd",
        "syscall": "execve",
        "syscall_id": 59,
        "file_path": "/usr/sbin/sshd",
        "dst_ip": "192.168.1.50",
        "dst_port": 22,
        "threat_name": "BENIGN",
        "confidence": 0.0
    }
    model.add_event(event1)
    assert model.rowCount() == 1
    assert model.get_event(0) == event1


def test_proxy_filter_integration():
    source_model = EventTableModel()
    proxy = EventFilterProxyModel()
    proxy.setSourceModel(source_model)

    source_model.add_events_batch([
        {"comm": "bash", "pid": 101, "threat_name": "BENIGN", "confidence": 0.0},
        {"comm": "nc", "pid": 102, "threat_name": "REVERSE_SHELL", "confidence": 0.92},
        {"comm": "python3", "pid": 103, "threat_name": "RANSOMWARE", "confidence": 0.98},
    ])
    assert proxy.rowCount() == 3

    # Apply filter for threats only
    ok = proxy.set_display_filter('threat != "BENIGN"')
    assert ok
    assert proxy.rowCount() == 2

    # Apply filter for reverse shell only
    ok = proxy.set_display_filter('comm == "nc"')
    assert ok
    assert proxy.rowCount() == 1
    assert proxy.get_event_at_proxy_row(0)["pid"] == 102


def test_detail_tree_model():
    detail_model = DetailTreeModel()
    event = {
        "event_type": "SYS_EXEC",
        "timestamp_ns": 1724876716123456789,
        "pid": 4567,
        "ppid": 1234,
        "uid": 0,
        "comm": "cryptor",
        "exe_path": "/tmp/cryptor",
        "syscall": "openat",
        "syscall_id": 257,
        "file_path": "/var/data/secret.db",
        "threat_name": "RANSOMWARE",
        "confidence": 0.96,
        "ml_scores": {"rf": "RANSOMWARE", "xgb": "RANSOMWARE", "iso_score": -0.45}
    }
    detail_model.set_event(event)
    assert detail_model.rowCount() > 0
