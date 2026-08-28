"""
Export Dissections & Incident Reports Dialog for KShark (Wireshark Export Equivalent).
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QRadioButton, QButtonGroup, 
    QCheckBox, QPushButton, QLabel, QFileDialog, QMessageBox, QComboBox
)
from PyQt6.QtCore import Qt
import csv
import json
from typing import List, Dict, Any
from pathlib import Path


class ExportDialog(QDialog):
    """
    Multi-format Telemetry Exporter Dialog.
    """

    def __init__(self, table_model, parent=None):
        super().__init__(parent)
        self.setWindowTitle("KShark · Export Event Dissections")
        self.resize(480, 320)
        self.table_model = table_model

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("<b>Select Export Format:</b>", self))

        # Format Selection Radio Buttons
        self.fmt_group = QButtonGroup(self)
        self.rb_csv = QRadioButton("CSV (Comma Separated Values)", self)
        self.rb_csv.setChecked(True)
        self.rb_json = QRadioButton("JSON Lines (.jsonl Raw Telemetry)", self)
        self.rb_md = QRadioButton("Markdown Forensic Incident Summary (.md)", self)

        self.fmt_group.addButton(self.rb_csv, 0)
        self.fmt_group.addButton(self.rb_json, 1)
        self.fmt_group.addButton(self.rb_md, 2)

        layout.addWidget(self.rb_csv)
        layout.addWidget(self.rb_json)
        layout.addWidget(self.rb_md)

        layout.addSpacing(10)
        layout.addWidget(QLabel("<b>Export Scope:</b>", self))

        self.chk_threats_only = QCheckBox("Export only events flagged as Security Threats (threat != BENIGN)", self)
        layout.addWidget(self.chk_threats_only)

        layout.addStretch(1)

        # Bottom Buttons
        btn_bar = QHBoxLayout()
        btn_bar.addStretch(1)

        cancel_btn = QPushButton("Cancel", self)
        cancel_btn.clicked.connect(self.reject)
        btn_bar.addWidget(cancel_btn)

        export_btn = QPushButton("Export...", self)
        export_btn.setStyleSheet("background-color: #007ACC; color: #FFFFFF; font-weight: bold; padding: 4px 14px;")
        export_btn.clicked.connect(self._do_export)
        btn_bar.addWidget(export_btn)

        layout.addLayout(btn_bar)

    def _do_export(self):
        events = self.table_model._events
        if not events:
            QMessageBox.warning(self, "Export", "No telemetry events currently captured to export.")
            return

        if self.chk_threats_only.isChecked():
            events = [e for e in events if (e.get("threat_name") or e.get("threat_type") or e.get("agreed_threat") or "BENIGN") != "BENIGN"]
            if not events:
                QMessageBox.information(self, "Export", "No threat events found in current capture.")
                return

        btn_id = self.fmt_group.checkedId()

        if btn_id == 0:  # CSV
            fp, _ = QFileDialog.getSaveFileName(self, "Export CSV", "kshark_export.csv", "CSV Files (*.csv)")
            if fp:
                self._export_csv(fp, events)

        elif btn_id == 1:  # JSON
            fp, _ = QFileDialog.getSaveFileName(self, "Export JSON", "kshark_export.jsonl", "JSON Lines (*.jsonl)")
            if fp:
                self._export_json(fp, events)

        elif btn_id == 2:  # Markdown
            fp, _ = QFileDialog.getSaveFileName(self, "Export Forensic Report", "kshark_incident_report.md", "Markdown Files (*.md)")
            if fp:
                self._export_markdown(fp, events)

    def _export_csv(self, fp: str, events: list):
        try:
            keys = ["timestamp_ns", "pid", "ppid", "uid", "comm", "exe_path", "syscall_id", "file_path", "dst_ip", "dst_port", "threat_name", "confidence"]
            with open(fp, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                writer.writeheader()
                for e in events:
                    writer.writerow(e)
            QMessageBox.information(self, "Export Success", f"Successfully exported {len(events):,} events to {fp}")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _export_json(self, fp: str, events: list):
        try:
            with open(fp, "w", encoding="utf-8") as f:
                for e in events:
                    f.write(json.dumps(e) + "\n")
            QMessageBox.information(self, "Export Success", f"Successfully exported {len(events):,} events to {fp}")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _export_markdown(self, fp: str, events: list):
        try:
            threats = [e for e in events if (e.get("threat_name") or e.get("threat_type") or "BENIGN") != "BENIGN"]
            with open(fp, "w", encoding="utf-8") as f:
                f.write("# KShark Security Forensic Incident Report\n\n")
                f.write(f"- **Total Events Analyzed:** {len(events):,}\n")
                f.write(f"- **Total Security Threats Detected:** {len(threats):,}\n\n")
                f.write("## Identified Threats Summary\n\n")
                f.write("| PID | Process (Comm) | Threat Classification | Confidence | Target / Syscall |\n")
                f.write("|---|---|---|---|---|\n")
                for t in threats:
                    pid = t.get("pid", 0)
                    comm = t.get("comm", "")
                    t_name = t.get("threat_name") or t.get("threat_type") or "ANOMALY"
                    conf = float(t.get("confidence", 0.0))
                    target = t.get("file_path") or t.get("exe_path") or t.get("dst_ip") or ""
                    f.write(f"| {pid} | `{comm}` | **{t_name}** | {conf*100:.1f}% | `{target}` |\n")
            QMessageBox.information(self, "Export Success", f"Successfully generated incident report at {fp}")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))
