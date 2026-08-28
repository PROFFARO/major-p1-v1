"""
Falco-Style Behavioral Rules Engine for Zero-Latency Kernel Event Analysis.

Evaluates high-speed eBPF telemetry events against a comprehensive rule-set
inspired by Sysdig Falco, Sigma rules, and MITRE ATT&CK enterprise techniques.
Complements ML anomaly models with deterministic signature and behavior matching.
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
        # Rule 1: Sensitive File Read (/etc/shadow, /etc/sudoers, ssh keys, shadow backups)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-001",
                name="Read Sensitive System File",
                severity="HIGH",
                mitre_id="T1003.008",
                description="Process accessed sensitive credential files or shadow backup stores",
                condition_fn=lambda e: (
                    any(sens in (e.get("file_path", "") or e.get("filename", "")) for sens in ("shadow", "sudoers", "id_rsa", "id_ed25519", "master.passwd"))
                )
            )
        )

        # Rule 2: Shell Spawned by Web Server (Webshell indicator)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-002",
                name="Web Server Spawned Shell",
                severity="CRITICAL",
                mitre_id="T1505.003",
                description="Web server process (nginx, apache, lighttpd) spawned a shell process",
                condition_fn=lambda e: (
                    e.get("event_type_str") == "EXEC"
                    and e.get("comm", "") in ("bash", "sh", "dash", "zsh")
                    and any(web in e.get("parent_comm", "") for web in ("nginx", "httpd", "apache", "node", "php-fpm"))
                )
            )
        )

        # Rule 3: Kernel Module Injection
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-003",
                name="Kernel Module Load Attempt",
                severity="CRITICAL",
                mitre_id="T1547.006",
                description="Execution of init_module or finit_module syscall indicating kernel rootkit installation",
                condition_fn=lambda e: e.get("syscall_id") in (175, 313)
            )
        )

        # Rule 4: Ptrace Process Injection / Tampering
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-004",
                name="Process Memory Injection via Ptrace",
                severity="CRITICAL",
                mitre_id="T1055.008",
                description="Process invoked ptrace syscall to inspect or modify another running process memory",
                condition_fn=lambda e: e.get("syscall_id") == 101 # ptrace
            )
        )

        # Rule 5: Container Escape Attempt via Namespace Switch
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-005",
                name="Container Namespace Escape Attempt",
                severity="CRITICAL",
                mitre_id="T1611",
                description="Non-infrastructure process executed setns or unshare syscall to break container isolation",
                condition_fn=lambda e: (
                    e.get("syscall_id") in (308, 272)
                    and e.get("comm", "") not in ("systemd", "dockerd", "containerd", "runc", "k3s", "kubelet")
                    and e.get("uid", 1000) != 0
                )
            )
        )

        # Rule 6: Execution of Memfd Anonymous Executable (Fileless Malware)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-006",
                name="Fileless Execution in In-Memory Anonymous File",
                severity="HIGH",
                mitre_id="T1620",
                description="Process created anonymous memory file descriptor via memfd_create and executed binary from memory",
                condition_fn=lambda e: (
                    e.get("syscall_id") == 319
                    and e.get("comm", "") not in ("pulseaudio", "pipewire", "wayland", "Xorg", "electron", "zsh", "bash", "sh", "python", "python3", "python3.13", "gnome-shell", "systemd", "dbus-daemon", "code")
                    and (str(e.get("file_path", "")).startswith("/memfd:") or e.get("event_type_str") == "EXEC" or e.get("event_type_str") == "SYS_EXEC")
                )
            )
        )


        # Rule 7: Outbound Connection to Suspicious Port (Reverse Shell / C2)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-007",
                name="REVERSE_SHELL_C2",
                severity="HIGH",
                mitre_id="T1071",
                description="Outbound TCP connection to common interactive shell or C2 ports (4444, 1337, 31337, 6667)",
                condition_fn=lambda e: (
                    int(e.get("dst_port", 0)) in (4444, 1337, 31337, 6667, 8888, 9999)
                    or "4444" in str(e.get("file_path", ""))
                    or "4444" in str(e.get("cmdline", ""))
                )
            )
        )

        # Rule 11: Ransomware File Encryption Pattern
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-011",
                name="RANSOMWARE_ACTIVITY",
                severity="CRITICAL",
                mitre_id="T1486",
                description="Mass file encryption and .locked extension renaming observed",
                condition_fn=lambda e: (
                    str(e.get("file_path", "")).endswith((".locked", ".enc", ".crypto"))
                    or "cryptolocker" in str(e.get("comm", ""))
                    or "cryptolocker" in str(e.get("cmdline", ""))
                )
            )
        )


        # Rule 8: Privilege Escalation via Capability Mutation
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-008",
                name="Capability Set Escalation",
                severity="HIGH",
                mitre_id="T1068",
                description="Untrusted process modified kernel security capabilities via capset syscall",
                condition_fn=lambda e: (
                    e.get("syscall_id") == 125
                    and e.get("comm", "") not in ("systemd", "dockerd", "containerd", "sudo", "su", "runc")
                    and e.get("uid", 1000) != 0
                )
            )
        )

        # Rule 9: Execution of Hidden Binary in /tmp or /dev/shm
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-009",
                name="SUSPICIOUS_EXECUTION",
                severity="HIGH",
                mitre_id="T1059",
                description="Executable launched from world-writable path (/tmp, /var/tmp, /dev/shm)",
                condition_fn=lambda e: (
                    (e.get("event_type_str") in ("EXEC", "SYS_EXEC", "SYSCALL") or e.get("syscall") in ("execve", "sys_enter_execve", "openat", "write"))
                    and (e.get("file_path", "") or e.get("exe_path", "") or e.get("filename", "")).startswith(("/tmp/", "/var/tmp/", "/dev/shm/"))
                    and not (e.get("file_path", "") or e.get("exe_path", "")).endswith((".so", ".tmp", ".lock"))
                )
            )
        )




        # Rule 10: Clear System Audit Logs / Tampering
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-010",
                name="System Log Tampering Attempt",
                severity="HIGH",
                mitre_id="T1070.002",
                description="Truncation or unlink operation on system audit logs (/var/log/audit, /var/log/wtmp)",
                condition_fn=lambda e: (
                    e.get("event_type_str") == "FILE"
                    and any(log_f in e.get("filename", "") for log_f in ("syslog", "audit.log", "wtmp", "utmp", "btmp"))
                    and e.get("file_op") in (5, 6) # DELETE or RENAME
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
