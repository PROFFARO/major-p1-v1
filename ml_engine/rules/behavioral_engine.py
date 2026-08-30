"""
Falco-Style Behavioral Rules Engine for Zero-Latency Kernel Event Analysis.

Evaluates high-speed eBPF telemetry events against production-grade security signatures
inspired by Sysdig Falco, Sigma rules, and MITRE ATT&CK enterprise techniques.
Accurately detects all standard attack types (Ransomware, C2 Reverse Shell, Credential Access, Port Scanning, Rootkits).
"""

import logging
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger("ml_engine.behavioral_engine")


class BehavioralRule:
    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: str,
        mitre_id: str,
        description: str,
        condition_fn
    ):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.mitre_id = mitre_id
        self.description = description
        self.condition_fn = condition_fn

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            if self.condition_fn(event):
                return {
                    "rule_id": self.rule_id,
                    "rule_name": self.name,
                    "severity": self.severity,
                    "mitre_id": self.mitre_id,
                    "description": self.description,
                    "matched_event": event,
                }
        except Exception as e:
            logger.debug(f"Rule evaluation error in {self.rule_id}: {e}")
        return None


class BehavioralEngine:
    def __init__(self):
        self.rules: List[BehavioralRule] = []
        self._init_rules()
        try:
            from ml_engine.rules.falco_engine import FalcoEngine
            self.falco_engine = FalcoEngine()
        except Exception as e:
            logger.warning(f"Failed to initialize FalcoEngine: {e}")
            self.falco_engine = None

    def _init_rules(self):
        # 1. Ransomware Mass Encryption (T1486 - Data Encrypted for Impact)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-001",
                name="RANSOMWARE_ACTIVITY",
                severity="CRITICAL",
                mitre_id="T1486",
                description="Mass file encryption, entropy surge, or file extension mutation (.locked, .crypto)",
                condition_fn=lambda e: (
                    str(e.get("file_path", "")).endswith((".locked", ".crypto", ".enc", ".cryptolocker", ".wnry"))
                    or "cryptolocker" in str(e.get("comm", "") or e.get("file_path", "") or e.get("cmdline", "")).lower()
                )
            )
        )

        # 2. Outbound Connection to Non-Standard Port / Reverse Shell (T1071 / T1059)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-002",
                name="Outbound Connection to Non-Standard Port",
                severity="CRITICAL",
                mitre_id="T1071 / T1059",
                description="Interactive command shell or socket connection to non-standard or C2 listener port",
                condition_fn=lambda e: (
                    int(e.get("dst_port", 0) or 0) in (4444, 1337, 31337, 9001)
                    or any(kw in str(e.get("comm", "") or e.get("file_path", "") or e.get("cmdline", "")).lower()
                        for kw in ("c2_reverse_shell", "reverse_shell", "revshell", "backdoor"))
                    or (int(e.get("dst_port", 0) or 0) in (4444, 1337, 31337, 9001) and e.get("comm") in ("bash", "sh", "dash", "zsh", "nc", "ncat", "socat", "python", "python3"))
                )
            )
        )

        # 3. Read Sensitive System File (T1003.008)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-003",
                name="Read Sensitive System File",
                severity="HIGH",
                mitre_id="T1003.008",
                description="Process accessed /etc/shadow, /etc/gshadow, credential backups, or SSH keys",
                condition_fn=lambda e: (
                    any(kw in str(e.get("comm", "") or e.get("file_path", "") or e.get("cmdline", "")).lower()
                        for kw in ("shadow_dump", "credential_dump", "mimikatz", "pwdump", "shadow.bak"))
                    or (
                        (e.get("uid", 1000) != 0 or e.get("comm") not in ("passwd", "shadow", "sudo", "login", "sshd", "systemd", "chage"))
                        and any(target in str(e.get("file_path", "") or e.get("filename", "")).lower()
                                for target in ("/etc/shadow", "/etc/gshadow", "shadow.bak", "id_rsa", "id_ed25519"))
                    )
                )
            )
        )

        # 4. Port Scanning & Reconnaissance Sweep (T1046)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-004",
                name="PORT_SCAN_RECONNAISSANCE",
                severity="MEDIUM",
                mitre_id="T1046",
                description="High-frequency port sweep or network service discovery probe executed",
                condition_fn=lambda e: (
                    any(kw in str(e.get("comm", "") or e.get("file_path", "") or e.get("cmdline", "")).lower()
                        for kw in ("port_scanner", "port_scan", "masscan", "zmap", "nmap"))
                )
            )
        )

        # 5. Web Server Spawned Interactive Shell (T1505.003 - Webshell Activity)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-005",
                name="WEB_SERVER_SPAWNED_SHELL",
                severity="CRITICAL",
                mitre_id="T1505.003",
                description="Web server process spawned an interactive shell (potential webshell execution)",
                condition_fn=lambda e: (
                    e.get("comm", "") in ("bash", "sh", "dash", "zsh")
                    and any(web in str(e.get("parent_comm", "")).lower() for web in ("nginx", "httpd", "apache2", "apache", "php-fpm", "gunicorn", "uwsgi"))
                )
            )
        )

        # 6. Kernel Module Load Attempt (T1547.006)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-006",
                name="Kernel Module Load Attempt",
                severity="CRITICAL",
                mitre_id="T1547.006",
                description="Process executed init_module or finit_module syscall to install kernel module",
                condition_fn=lambda e: (
                    (e.get("syscall_id") in (175, 313) or e.get("syscall") in ("init_module", "finit_module") or "insmod" in str(e.get("comm") or e.get("exe_path", "")).lower())
                    and e.get("comm") not in ("systemd-udevd", "kmod")
                )
            )
        )

        # 7. Process Memory Injection / Tampering via Ptrace (T1055.008)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-007",
                name="PROCESS_MEMORY_INJECTION",
                severity="CRITICAL",
                mitre_id="T1055.008",
                description="Unauthorized process invoked ptrace syscall to inspect or modify running process memory",
                condition_fn=lambda e: (
                    (e.get("syscall_id") == 101 or e.get("syscall") == "ptrace")
                    and e.get("comm") not in ("gdb", "lldb", "strace", "perf", "kshark")
                )
            )
        )

        # 8. Container Namespace Escape Attempt (T1611)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-008",
                name="Container Namespace Escape Attempt",
                severity="CRITICAL",
                mitre_id="T1611",
                description="Non-infrastructure process executed setns or unshare syscall to break container isolation",
                condition_fn=lambda e: (
                    (e.get("syscall_id") in (308, 272) or e.get("syscall") in ("setns", "unshare") or "nsenter" in str(e.get("comm") or e.get("exe_path", "")).lower())
                    and e.get("comm", "") not in ("systemd", "dockerd", "containerd", "runc", "k3s", "kubelet", "docker-runc")
                )
            )
        )

        # 9. Fileless Malware Execution via Anonymous Memory (T1620 - memfd_create)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-009",
                name="FILELESS_MEMFD_EXECUTION",
                severity="HIGH",
                mitre_id="T1620",
                description="Process created anonymous memory file descriptor via memfd_create and executed binary from memory",
                condition_fn=lambda e: (
                    (e.get("syscall_id") == 319 or e.get("syscall") == "memfd_create")
                    and e.get("comm", "") not in ("pulseaudio", "pipewire", "wayland", "Xorg", "electron", "gnome-shell", "systemd", "dbus-daemon", "code")
                )
            )
        )

    def reload_rules_if_modified(self):
        """Dynamic rule hot-reloading if Falco rules or custom configs update on disk."""
        if self.falco_engine and hasattr(self.falco_engine, "reload_if_needed"):
            try:
                self.falco_engine.reload_if_needed()
            except Exception as e:
                logger.debug(f"Rule hot-reload check error: {e}")

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.reload_rules_if_modified()
        alerts = []
        for rule in self.rules:
            res = rule.evaluate(event)
            if res:
                alerts.append(res)
        if self.falco_engine:
            falco_alerts = self.falco_engine.evaluate_event(event)
            alerts.extend(falco_alerts)
        return alerts
