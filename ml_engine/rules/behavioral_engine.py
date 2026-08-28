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
        # Rule 1: Sensitive File Read (/etc/shadow, /etc/sudoers)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-001",
                name="Read Sensitive System File",
                severity="HIGH",
                mitre_id="T1003.008",
                description="Non-privileged or suspicious process accessed /etc/shadow or sensitive credentials",
                condition_fn=lambda e: (
                    e.get("filename", "").startswith(("/etc/shadow", "/etc/sudoers", "/root/.ssh"))
                    and e.get("uid", 1000) != 0
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
                description="Process executed setns or unshare syscall to break container isolation",
                condition_fn=lambda e: e.get("syscall_id") in (308, 272) # setns, unshare
            )
        )

        # Rule 6: Execution of Memfd Anonymous Executable (Fileless Malware)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-006",
                name="Fileless Execution in In-Memory Anonymous File",
                severity="HIGH",
                mitre_id="T1620",
                description="Process created anonymous memory file descriptor via memfd_create",
                condition_fn=lambda e: e.get("syscall_id") == 319 # memfd_create
            )
        )

        # Rule 7: Outbound Connection to Suspicious Port (Reverse Shell / C2)
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-007",
                name="Outbound Connection to Non-Standard Port",
                severity="MEDIUM",
                mitre_id="T1071",
                description="Outbound TCP connection to common interactive shell or IRC ports (4444, 1337, 6667)",
                condition_fn=lambda e: (
                    e.get("event_type_str") == "NET"
                    and e.get("dst_port") in (4444, 1337, 31337, 6667, 8888, 9999)
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
                description="Process modified kernel security capabilities via capset syscall",
                condition_fn=lambda e: e.get("syscall_id") == 125 # capset
            )
        )

        # Rule 9: Execution of Hidden Binary in /tmp or /dev/shm
        self.rules.append(
            BehavioralRule(
                rule_id="RULE-009",
                name="Execution of Binary in Temporary Directory",
                severity="HIGH",
                mitre_id="T1059",
                description="Executable launched from world-writable path (/tmp, /var/tmp, /dev/shm)",
                condition_fn=lambda e: (
                    e.get("event_type_str") == "EXEC"
                    and e.get("filename", "").startswith(("/tmp", "/var/tmp", "/dev/shm", "/run/user"))
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

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        for rule in self.rules:
            res = rule.evaluate(event)
            if res:
                alerts.append(res)
        if self.falco_engine:
            falco_alerts = self.falco_engine.evaluate_event(event)
            alerts.extend(falco_alerts)
        return alerts
