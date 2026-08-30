"""
KShark Threat Forensics & Incident Response Inspector Dialog.
Provides security analysts, SOC engineers, and cyber responders with in-depth MITRE ATT&CK taxonomy,
12-dimensional ML feature vectors, automated incident response containment scripts, and Sigma / YARA rule generators.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget, QLabel,
    QPushButton, QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QFormLayout, QApplication, QMessageBox, QFrame, QProgressBar
)
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import Qt
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from kshark.core.theme import ThemeManager, get_monospace_font, get_ui_font
from kshark.resources.icons import KSharkIcons
from ml_engine.config import FEATURE_COLUMNS, THREAT_LABELS


class ThreatForensicsDialog(QDialog):
    """
    Comprehensive Security Threat & Forensics Inspector for KShark.
    """

    def __init__(self, event: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.event = event
        self.setWindowTitle(f"Forensic Threat Inspection — PID {event.get('pid', 0)} ({event.get('comm', 'unknown')})")
        self.resize(840, 620)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        c = ThemeManager.instance().get_palette_colors()
        is_dark = ThemeManager.is_dark()

        # ── 1. Top Threat Banner Card ──
        header = QFrame(self)
        header.setObjectName("threatHeaderCard")
        header.setStyleSheet(f"""
            QFrame#threatHeaderCard {{
                background-color: {c['bg_base']};
                border: 1px solid {c['border']};
                border-radius: 6px;
                padding: 6px;
            }}
        """)
        h_layout = QFormLayout(header)
        h_layout.setContentsMargins(10, 8, 10, 8)
        h_layout.setSpacing(6)

        threat_name = str(self.event.get("threat_name") or self.event.get("threat_type") or "BENIGN").upper()
        confidence = float(self.event.get("confidence", 0.0))
        source = self.event.get("detection_source", "ensemble_ml")
        pid = self.event.get("pid", 0)
        comm = self.event.get("comm", "unknown")
        exe_path = self.event.get("exe_path") or self.event.get("file_path", "-")
        uid = self.event.get("uid", 1000)

        # Threat Status Badge & Confidence Bar
        h_threat_row = QHBoxLayout()
        lbl_threat_badge = QLabel(f"  {threat_name}  ")
        lbl_threat_badge.setFont(get_ui_font(size=9, bold=True))

        if threat_name != "BENIGN":
            lbl_threat_badge.setStyleSheet(f"background-color: {c['card_threats_bg']}; color: {c['card_threats_fg']}; border-radius: 3px; border: 1px solid {c['card_threats_border']}; padding: 2px 6px;")
        else:
            lbl_threat_badge.setStyleSheet(f"background-color: {c['filter_valid_bg']}; color: {c['accent_success']}; border-radius: 3px; border: 1px solid {c['filter_valid_border']}; padding: 2px 6px;")

        prog_conf = QProgressBar()
        prog_conf.setRange(0, 100)
        prog_conf.setValue(int(confidence * 100) if confidence > 0 else 0)
        prog_conf.setTextVisible(True)
        if confidence > 0:
            prog_conf.setFormat(f"Confidence: {confidence * 100:.1f}%")
        elif threat_name != "BENIGN":
            prog_conf.setFormat("Confidence: Unrated / Signature Match")
        else:
            prog_conf.setFormat("Confidence: 0.0% (Clean)")
        prog_conf.setFixedHeight(18)
        prog_conf.setFont(get_ui_font(size=8, bold=True))
        prog_bg = "#121E24" if is_dark else "#F1F5F9"
        prog_text = "#FFFFFF" if is_dark else "#0F172A"
        prog_conf.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {c['border']};
                border-radius: 3px;
                background-color: {prog_bg};
                color: {prog_text};
                text-align: center;
            }}
            QProgressBar::chunk {{
                background-color: {c['brand_primary']};
                border-radius: 2px;
            }}
        """)

        h_threat_row.addWidget(lbl_threat_badge)
        h_threat_row.addWidget(prog_conf, stretch=1)

        h_layout.addRow("Classification:", h_threat_row)
        h_layout.addRow("Detection Source:", QLabel(f"<code>{source}</code> (Dual-Model Ensemble)"))
        
        uid_label = f"<b>{comm}</b> (PID: {pid}) — UID {uid}"
        if uid == 0:
            uid_label += " <span style='color: #E67E22; font-weight: bold;'>[ROOT PRIVILEGED]</span>"
        h_layout.addRow("Target Process:", QLabel(uid_label))
        h_layout.addRow("Executable Path:", QLabel(f"<code>{exe_path}</code>"))

        layout.addWidget(header)

        # ── 2. Tabbed Forensic Panes (Vector SVGs + Escaped Ampersands) ──
        self.tabs = QTabWidget()
        self.tabs.setFont(get_ui_font(size=8, bold=True))

        # Tab 1: MITRE ATT&CK & Tactical Containment
        tab_mitre = self._build_mitre_tab(threat_name)
        self.tabs.addTab(tab_mitre, KSharkIcons.tab_threat(), "MITRE ATT&&CK && Containment")

        # Tab 2: 12-Dimensional ML Feature Vector
        tab_features = self._build_features_tab()
        self.tabs.addTab(tab_features, KSharkIcons.tab_metrics(), "ML 12-Dim Feature Vector")

        # Tab 3: Raw Event Dissection (JSON)
        tab_raw = self._build_json_tab()
        self.tabs.addTab(tab_raw, KSharkIcons.tab_json(), "Raw Event Telemetry")

        # Tab 4: Sigma & YARA Detection Rules
        tab_rules = self._build_detection_rules_tab(threat_name)
        self.tabs.addTab(tab_rules, KSharkIcons.tab_code(), "Sigma && YARA Rules")

        layout.addWidget(self.tabs, stretch=1)


        # ── 3. Bottom Action Buttons ──
        btn_layout = QHBoxLayout()
        btn_layout.setContentsMargins(0, 4, 0, 0)
        btn_layout.setSpacing(8)

        btn_copy_json = QPushButton("Copy as JSON")
        btn_copy_json.setFont(get_ui_font(size=8))
        btn_copy_json.setFixedHeight(26)
        btn_copy_json.clicked.connect(lambda: (QApplication.clipboard().setText(json.dumps(self.event, indent=2)), QMessageBox.information(self, "Copied", "Event telemetry copied to clipboard as JSON!")))

        btn_copy_ioc = QPushButton("Export as STIX 2.1 IOC")
        btn_copy_ioc.setFont(get_ui_font(size=8))
        btn_copy_ioc.setFixedHeight(26)
        btn_copy_ioc.clicked.connect(self._export_stix)

        btn_report = QPushButton("Generate Incident Report (Markdown)")
        btn_report.setFont(get_ui_font(size=8))
        btn_report.setFixedHeight(26)
        btn_report.clicked.connect(self._export_incident_report)

        btn_close = QPushButton("Close")
        btn_close.setFont(get_ui_font(size=8))
        btn_close.setFixedHeight(26)
        btn_close.clicked.connect(self.accept)

        btn_layout.addWidget(btn_copy_json)
        btn_layout.addWidget(btn_copy_ioc)
        btn_layout.addWidget(btn_report)
        btn_layout.addStretch()
        btn_layout.addWidget(btn_close)

        layout.addLayout(btn_layout)

    def _build_mitre_tab(self, threat_name: str) -> QWidget:
        widget = QWidget(self)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Top Text Overview
        txt_overview = QTextEdit()
        txt_overview.setReadOnly(True)
        txt_overview.setFont(get_ui_font(size=8))
        txt_overview.setHtml(self._get_mitre_html(threat_name))
        txt_overview.setMaximumHeight(140)
        layout.addWidget(txt_overview)

        # Incident Response Containment Script Box
        grp_script = QGroupBox("Automated Host Containment & Incident Response Script (Bash)")
        grp_script.setFont(get_ui_font(size=8, bold=True))
        l_script = QVBoxLayout(grp_script)
        l_script.setContentsMargins(6, 6, 6, 6)
        l_script.setSpacing(6)

        script_code = self._generate_containment_script()
        txt_script = QTextEdit()
        txt_script.setReadOnly(True)
        txt_script.setFont(get_monospace_font(size=8))
        txt_script.setPlainText(script_code)
        l_script.addWidget(txt_script)

        btn_copy_script = QPushButton("Copy Bash Containment Script")
        btn_copy_script.setFont(get_ui_font(size=8, bold=True))
        btn_copy_script.setFixedHeight(24)
        c = ThemeManager.instance().get_palette_colors()
        btn_copy_script.setStyleSheet(f"background-color: {c['brand_primary']}; color: white; border-radius: 3px;")
        btn_copy_script.clicked.connect(lambda: (QApplication.clipboard().setText(script_code), QMessageBox.information(self, "Copied", "Containment shell script copied to clipboard!")))
        l_script.addWidget(btn_copy_script)

        layout.addWidget(grp_script, stretch=1)
        return widget

    def _generate_containment_script(self) -> str:
        pid = self.event.get("pid", 0)
        comm = self.event.get("comm", "unknown")
        dst_ip = self.event.get("dst_ip", "")
        exe = self.event.get("exe_path") or self.event.get("file_path", "")

        lines = [
            "#!/usr/bin/env bash",
            f"# KShark Automated Forensic Containment Script — Process: {comm} (PID: {pid})",
            "set -euo pipefail",
            "",
            "# 1. Freeze execution to prevent further forensic destruction",
            f"echo '[*] Freezing process tree for PID {pid}...' ",
            f"kill -STOP {pid} 2>/dev/null || true",
            "",
            "# 2. Dump volatile memory map and open file descriptors",
            f"echo '[*] Collecting volatile forensic artifacts...' ",
            f"mkdir -p /tmp/kshark_incident_p{pid}",
            f"ls -la /proc/{pid}/fd/ > /tmp/kshark_incident_p{pid}/open_fds.txt 2>/dev/null || true",
            f"cat /proc/{pid}/maps > /tmp/kshark_incident_p{pid}/memory_maps.txt 2>/dev/null || true",
        ]

        if dst_ip and dst_ip not in ("0.0.0.0", "127.0.0.1"):
            lines.extend([
                "",
                f"# 3. Sever remote C2 network socket and isolate egress IP {dst_ip}",
                f"echo '[*] Dropping network communication to {dst_ip}...' ",
                f"ss -K dst {dst_ip} 2>/dev/null || true",
                f"iptables -A OUTPUT -d {dst_ip} -j DROP 2>/dev/null || true",
            ])

        lines.extend([
            "",
            "# 4. Terminate malicious process tree",
            f"echo '[*] Terminating process {pid} ({comm})...' ",
            f"kill -9 {pid} 2>/dev/null || true",
            "echo '[+] Containment actions completed successfully.'",
        ])

        return "\n".join(lines)

    def _get_mitre_html(self, threat_name: str) -> str:
        t_upper = str(threat_name).upper()
        forensic_info = str(self.event.get("forensic_info", "") or "")

        if t_upper in ("BENIGN", "CLEAN", "NONE", "NORMAL", ""):
            return """
            <b>MITRE ATT&CK: Baseline System Telemetry (BENIGN)</b><br>
            <b>Tactic:</b> Normal Host Operation | <b>Severity:</b> <span style='color: #2ECC71;'>CLEAN / LOW</span><br>
            <b>Overview:</b> System call patterns, file access, and network socket activity align within expected operational thresholds and machine learning baseline profiles.
            """

        # Dynamic Threat Mapping
        if "FILELESS" in t_upper or "MEMFD" in t_upper or "T1620" in t_upper:
            tactic = "Defense Evasion"
            tech = "T1620 — Reflective Code Loading / Fileless Execution"
            sev = "<span style='color: #E74C3C;'>CRITICAL</span>"
            desc = "In-memory anonymous file descriptor allocated via <code>memfd_create</code> and executed without touching persistent disk storage."
        elif "RANSOMWARE" in t_upper or "ENCRYPT" in t_upper or "T1486" in t_upper:
            tactic = "Impact"
            tech = "T1486 — Data Encrypted for Impact"
            sev = "<span style='color: #E74C3C;'>CRITICAL</span>"
            desc = "Mass file encryption, entropy surge, and file extension renaming observed. Adversaries encrypt victim files to disrupt operations."
        elif "REVERSE" in t_upper or "SHELL" in t_upper or "C2" in t_upper or "T1071" in t_upper:
            tactic = "Execution, Command and Control"
            tech = "T1071 — Standard Non-Application Layer Protocol / C2"
            sev = "<span style='color: #E74C3C;'>CRITICAL</span>"
            desc = "Outbound interactive command shell connected to recognized hacker/C2 listener port (e.g. 4444, 1337, 31337)."
        elif "CREDENTIAL" in t_upper or "SHADOW" in t_upper or "T1003" in t_upper:
            tactic = "Credential Access"
            tech = "T1003.008 — OS Credential Dumping (/etc/shadow)"
            sev = "<span style='color: #E74C3C;'>HIGH</span>"
            desc = "Unauthorized access attempt targeting <code>/etc/shadow</code>, <code>/etc/gshadow</code>, or SSH private key stores."
        elif "ESCAPE" in t_upper or "CONTAINER" in t_upper or "T1611" in t_upper:
            tactic = "Privilege Escalation"
            tech = "T1611 — Container Escape via Namespace Switch"
            sev = "<span style='color: #E74C3C;'>CRITICAL</span>"
            desc = "Unauthorized process invoked setns/unshare system calls to break container namespace isolation."
        elif "ROOTKIT" in t_upper or "MODULE" in t_upper or "T1547" in t_upper:
            tactic = "Persistence, Privilege Escalation"
            tech = "T1547.006 — Kernel Module Loading & Rootkits"
            sev = "<span style='color: #E74C3C;'>CRITICAL</span>"
            desc = "Execution of init_module or finit_module syscalls indicating in-kernel rootkit insertion."
        elif "PTRACE" in t_upper or "INJECTION" in t_upper or "T1055" in t_upper:
            tactic = "Defense Evasion, Privilege Escalation"
            tech = "T1055.008 — Process Memory Injection via Ptrace"
            sev = "<span style='color: #E74C3C;'>CRITICAL</span>"
            desc = "Unauthorized process invoked ptrace syscall to inspect or modify code within another running process address space."
        else:
            tactic = "Suspicious Behavioral Anomaly"
            tech = f"Anomaly Indicator — {t_upper}"
            sev = "<span style='color: #E67E22;'>HIGH</span>"
            desc = forensic_info or f"Anomalous system call behavior flagged by ML consensus engine ({t_upper})."

        return f"""
        <b>MITRE ATT&CK: {tech}</b><br>
        <b>Tactic:</b> {tactic} | <b>Severity:</b> {sev}<br>
        <b>Overview:</b> {desc}
        """


    def _build_features_tab(self) -> QWidget:
        widget = QWidget(self)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Dimension #", "Feature Name", "Runtime Value", "Forensic Significance"])
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        table.verticalHeader().setVisible(False)
        table.setFont(get_monospace_font(size=8))
        self._populate_feature_table(table)
        layout.addWidget(table)

        return widget

    def _populate_feature_table(self, table: QTableWidget):
        eps_val = self.event.get('eps')
        eps_str = f"{float(eps_val):.1f} evt/s" if eps_val is not None else "-"

        entropy_val = self.event.get('entropy')
        entropy_str = f"{float(entropy_val):.2f} bits" if entropy_val is not None else "-"

        write_ratio = self.event.get('write_ratio')
        write_str = f"{float(write_ratio):.1%}" if write_ratio is not None else "-"

        sens_hits = self.event.get('sensitive_hits')
        sens_str = str(sens_hits) if sens_hits is not None else "0"

        net_pps = self.event.get('net_pps')
        net_pps_str = f"{float(net_pps):.1f} pkt/s" if net_pps is not None else "-"

        in_pps = self.event.get('in_pps')
        in_pps_str = f"{float(in_pps):.1f} pkt/s" if in_pps is not None else "-"

        exec_burst = self.event.get('exec_burst')
        exec_str = str(exec_burst) if exec_burst is not None else "-"

        err_ratio = self.event.get('err_ratio')
        err_str = f"{float(err_ratio):.1%}" if err_ratio is not None else "-"

        features = [
            ("01", "eps_rate", eps_str, "Real-time system call execution frequency burst rate"),
            ("02", "shannon_entropy", entropy_str, "File payload randomness (Values > 7.2 indicate encrypted/packed payloads)"),
            ("03", "file_write_ratio", write_str, "Proportion of file mutations vs read operations"),
            ("04", "sensitive_path_hits", sens_str, "Access count to /etc/shadow, /etc/sudoers, or private SSH keys"),
            ("05", "outbound_net_pps", net_pps_str, "Outbound network packet rate across TCP/UDP sockets"),
            ("06", "inbound_net_pps", in_pps_str, "Inbound network packet rate across listening sockets"),
            ("07", "execve_burst_count", exec_str, "Child process spawns within the last 500ms sliding window"),
            ("08", "failed_syscall_ratio", err_str, "Proportion of system calls returning EACCES/ENOENT errno errors"),
            ("09", "memfd_create_flag", "YES [1]" if "memfd" in str(self.event.get("file_path", "")) else "NO [0]", "Reflective anonymous memory descriptor allocation"),
            ("10", "root_uid_switch", "YES [1]" if self.event.get("uid", 1000) == 0 else "NO [0]", "Process executing under Effective UID 0 (Root) privileges"),
            ("11", "non_standard_port", "YES [1]" if int(self.event.get("dst_port", 0) or 0) in (4444, 1337, 8080, 9001) else "NO [0]", "Egress connection targeting recognized hacker/C2 listener ports"),
            ("12", "hidden_binary_path", "YES [1]" if "/." in str(self.event.get("exe_path", "")) else "NO [0]", "Binary executing from hidden UNIX directory (e.g. /tmp/.xyz)"),
        ]

        table.setRowCount(len(features))
        for row, (idx, name, val, desc) in enumerate(features):
            item_idx = QTableWidgetItem(idx)
            item_name = QTableWidgetItem(name)
            item_val = QTableWidgetItem(val)
            item_desc = QTableWidgetItem(desc)

            for it in (item_idx, item_name, item_val, item_desc):
                it.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)

            table.setItem(row, 0, item_idx)
            table.setItem(row, 1, item_name)
            table.setItem(row, 2, item_val)
            table.setItem(row, 3, item_desc)

    def _build_json_tab(self) -> QWidget:
        widget = QWidget(self)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setFont(get_monospace_font(size=8))
        txt.setPlainText(json.dumps(self.event, indent=2))
        layout.addWidget(txt)
        return widget

    def _build_detection_rules_tab(self, threat_name: str) -> QWidget:
        widget = QWidget(self)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        comm = self.event.get("comm", "malware")
        exe = self.event.get("exe_path") or "/tmp/unknown"
        rule_uuid = str(uuid.uuid4())
        date_slash = datetime.now(timezone.utc).strftime("%Y/%m/%d")
        date_dash = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # 1. Sigma Rule
        grp_sigma = QGroupBox("Generated Sigma Rule (SIEM / Elastic / Splunk)")
        grp_sigma.setFont(get_ui_font(size=8, bold=True))
        l_sigma = QVBoxLayout(grp_sigma)
        l_sigma.setContentsMargins(6, 6, 6, 6)

        sigma_yaml = f"""title: Detection of {threat_name} via KShark Forensics
id: {rule_uuid}
status: experimental
description: Auto-generated detection rule from KShark eBPF kernel telemetry.
author: KShark Forensic AI Engine
date: {date_slash}
references:
  - https://attack.mitre.org/
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: '{comm}'
    CommandLine|contains: '{comm}'
  condition: selection
falsepositives:
  - Legitimate administrative tooling
level: high
tags:
  - attack.execution
  - attack.t1059.004"""

        txt_sigma = QTextEdit()
        txt_sigma.setReadOnly(True)
        txt_sigma.setFont(get_monospace_font(size=8))
        txt_sigma.setPlainText(sigma_yaml)
        l_sigma.addWidget(txt_sigma)

        btn_copy_sigma = QPushButton("Copy Sigma YAML Rule")
        btn_copy_sigma.setFont(get_ui_font(size=8))
        btn_copy_sigma.setFixedHeight(22)
        btn_copy_sigma.clicked.connect(lambda: (QApplication.clipboard().setText(sigma_yaml), QMessageBox.information(self, "Copied", "Sigma rule copied to clipboard!")))
        l_sigma.addWidget(btn_copy_sigma)

        layout.addWidget(grp_sigma)

        # 2. YARA Rule
        grp_yara = QGroupBox("Generated YARA Rule (Memory / Binary Scanning)")
        grp_yara.setFont(get_ui_font(size=8, bold=True))
        l_yara = QVBoxLayout(grp_yara)
        l_yara.setContentsMargins(6, 6, 6, 6)

        clean_comm = comm.replace('-', '_').replace('.', '_')
        yara_code = f"""rule KShark_Detection_{clean_comm} {{
    meta:
        description = "Auto-generated YARA signature for {threat_name}"
        author = "KShark Threat Forensics Engine"
        date = "{date_dash}"
    strings:
        $s1 = "{comm}" ascii wide
        $s2 = "{exe}" ascii wide
    condition:
        uint32(0) == 0x464c457f and ( $s1 or $s2 )
}}"""

        txt_yara = QTextEdit()
        txt_yara.setReadOnly(True)
        txt_yara.setFont(get_monospace_font(size=8))
        txt_yara.setPlainText(yara_code)
        l_yara.addWidget(txt_yara)

        btn_copy_yara = QPushButton("Copy YARA Rule")
        btn_copy_yara.setFont(get_ui_font(size=8))
        btn_copy_yara.setFixedHeight(22)
        btn_copy_yara.clicked.connect(lambda: (QApplication.clipboard().setText(yara_code), QMessageBox.information(self, "Copied", "YARA rule copied to clipboard!")))
        l_yara.addWidget(btn_copy_yara)

        layout.addWidget(grp_yara)

        return widget

    def _export_stix(self):
        pid = self.event.get("pid", 0)
        comm = self.event.get("comm", "unknown")
        threat_name = self.event.get("threat_name", "BENIGN")
        dst_ip = self.event.get("dst_ip", "")
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [
                {
                    "type": "indicator",
                    "id": f"indicator--{uuid.uuid4()}",
                    "name": f"KShark Threat Indicator: {threat_name}",
                    "pattern": f"[process:name = '{comm}']",
                    "pattern_type": "stix",
                    "valid_from": now_iso
                }
            ]
        }
        if dst_ip and dst_ip not in ("0.0.0.0", "127.0.0.1"):
            stix_bundle["objects"].append({
                "type": "ipv4-addr",
                "id": f"ipv4-addr--{uuid.uuid4()}",
                "value": dst_ip
            })

        stix_json = json.dumps(stix_bundle, indent=2)
        QApplication.clipboard().setText(stix_json)
        if self.isVisible():
            QMessageBox.information(self, "STIX 2.1 Export", "STIX 2.1 IOC Bundle generated and copied to clipboard!")

    def _export_incident_report(self):
        pid = self.event.get("pid", 0)
        comm = self.event.get("comm", "unknown")
        threat = self.event.get("threat_name", "BENIGN")
        conf = float(self.event.get("confidence", 0.0))
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        md = f"""# KShark Security Incident Forensic Report
**Target Process:** {comm} (PID: {pid})
**Classification:** {threat}
**Confidence Score:** {conf:.1%}
**Detection Timestamp:** {now_ts}
**Detection Engine:** KShark eBPF & Dual ML Ensemble

## Executive Summary
KShark kernel telemetry probes intercepted threat behaviors associated with process `{comm}` (PID: {pid}).

## Forensic Artifacts
- **Executable Path:** `{self.event.get('exe_path') or self.event.get('file_path') or '-'}`
- **Destination Socket:** `{self.event.get('dst_ip', '-')}:{self.event.get('dst_port', '-')}`
- **Effective UID:** `{self.event.get('uid', '-')}`

## Immediate Containment Actions
```bash
kill -STOP {pid}
kill -9 {pid}
```
"""
        QApplication.clipboard().setText(md)
        if self.isVisible():
            QMessageBox.information(self, "Incident Report", "Markdown Incident Report copied to clipboard!")

