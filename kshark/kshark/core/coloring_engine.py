"""
Coloring Rules Engine for KShark.

Replicates Wireshark's rule-based colorization mechanism:
Processes a list of rules from top to bottom. The first rule whose expression
evaluates to True determines the row's background and foreground QColor.
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any
from PyQt6.QtGui import QColor
import re


@dataclass
class ColoringRule:
    """Represents a single row coloring rule."""
    name: str
    filter_expr: str
    bg_color: QColor
    fg_color: QColor
    enabled: bool = True

    def matches(self, event: Dict[str, Any]) -> bool:
        """Evaluates whether this event satisfies the rule expression."""
        if not self.enabled or not self.filter_expr:
            return False
        
        expr = self.filter_expr.strip()

        # Fast path 1: Threat match
        if "threat" in expr:
            threat_name = str(event.get("threat_name") or event.get("threat_type") or event.get("agreed_threat") or "BENIGN")
            if "threat != 'BENIGN'" in expr or 'threat != "BENIGN"' in expr or "threat != BENIGN" in expr:
                return threat_name != "BENIGN"
            for t_class in ("RANSOMWARE", "PRIVILEGE_ESCALATION", "REVERSE_SHELL", "DATA_EXFILTRATION", 
                            "KERNEL_ROOTKIT", "CRYPTO_MINER", "BRUTE_FORCE", "CONTAINER_ESCAPE", "LOG_TAMPERING"):
                if t_class in expr and threat_name == t_class:
                    return True

        # Fast path 2: Comm / Process name match
        comm = str(event.get("comm", ""))
        if "comm ==" in expr or "comm contains" in expr:
            match = re.search(r'comm\s*(?:==|contains)\s*["\']?([^"\'\s]+)["\']?', expr)
            if match:
                target_comm = match.group(1)
                if "contains" in expr and target_comm in comm:
                    return True
                if "==" in expr and target_comm == comm:
                    return True

        # Fast path 3: Event Type match (SYS_EXEC, NET, FILE, LSM)
        event_type = str(event.get("event_type", event.get("event_type_str", "")))
        if "event_type ==" in expr:
            match = re.search(r'event_type\s*==\s*["\']?([^"\'\s]+)["\']?', expr)
            if match and match.group(1) in event_type:
                return True

        # Fast path 4: Sensitive file access
        file_path = str(event.get("file_path", event.get("filename", "")))
        if "file_path contains" in expr:
            match = re.search(r'file_path\s*contains\s*["\']?([^"\'\s]+)["\']?', expr)
            if match and match.group(1) in file_path:
                return True

        # Fast path 5: Confidence threshold
        conf = float(event.get("confidence", 0.0))
        if "confidence >=" in expr:
            match = re.search(r'confidence\s*>=\s*([0-9.]+)', expr)
            if match and conf >= float(match.group(1)):
                return True

        return False


class ColoringEngine:
    """Manages the ordered collection of coloring rules."""

    def __init__(self):
        self.rules: List[ColoringRule] = []
        self._init_default_rules()

    def _init_default_rules(self):
        """Standard Wireshark + Security Telemetry Coloring Presets."""
        self.rules = [
            # 1. Critical Threats (Red / Dark Red)
            ColoringRule(
                name="Ransomware Activity",
                filter_expr='threat == "RANSOMWARE"',
                bg_color=QColor("#FF4444"),
                fg_color=QColor("#FFFFFF"),
            ),
            ColoringRule(
                name="Kernel Rootkit Injection",
                filter_expr='threat == "KERNEL_ROOTKIT"',
                bg_color=QColor("#B71C1C"),
                fg_color=QColor("#FFFFFF"),
            ),
            ColoringRule(
                name="Container Escape Attempt",
                filter_expr='threat == "CONTAINER_ESCAPE"',
                bg_color=QColor("#D32F2F"),
                fg_color=QColor("#FFFFFF"),
            ),
            # 2. High Severity Threats (Orange / Purple)
            ColoringRule(
                name="Interactive Reverse Shell",
                filter_expr='threat == "REVERSE_SHELL"',
                bg_color=QColor("#6A1B9A"),
                fg_color=QColor("#FFFFFF"),
            ),
            ColoringRule(
                name="Privilege Escalation",
                filter_expr='threat == "PRIVILEGE_ESCALATION"',
                bg_color=QColor("#FF8C00"),
                fg_color=QColor("#FFFFFF"),
            ),
            ColoringRule(
                name="Data Exfiltration",
                filter_expr='threat == "DATA_EXFILTRATION"',
                bg_color=QColor("#E65100"),
                fg_color=QColor("#FFFFFF"),
            ),
            # 3. Anomaly & Suspicious Activity (Yellow / Amber)
            ColoringRule(
                name="High Anomaly Confidence (>= 80%)",
                filter_expr='confidence >= 0.80',
                bg_color=QColor("#FFF3CD"),
                fg_color=QColor("#000000"),
            ),
            ColoringRule(
                name="Sensitive /etc Credentials Access",
                filter_expr='file_path contains "/etc/shadow"',
                bg_color=QColor("#FFE0B2"),
                fg_color=QColor("#000000"),
            ),
            ColoringRule(
                name="Hidden /tmp Binary Execution",
                filter_expr='file_path contains "/tmp"',
                bg_color=QColor("#FFF9C4"),
                fg_color=QColor("#000000"),
            ),
            # 4. Standard Benign Telemetry Subsystems (Wireshark Classic Colors)
            ColoringRule(
                name="Network Socket Traffic (TCP)",
                filter_expr='event_type == "NET"',
                bg_color=QColor("#E7E6FF"),
                fg_color=QColor("#000000"),
            ),
            ColoringRule(
                name="Process Executions (SYS_EXEC)",
                filter_expr='event_type == "SYS_EXEC"',
                bg_color=QColor("#E4FFC7"),
                fg_color=QColor("#000000"),
            ),
            ColoringRule(
                name="TLS / SSL Plaintext Tracer",
                filter_expr='event_type == "SSL_DATA"',
                bg_color=QColor("#FFE5D9"),
                fg_color=QColor("#000000"),
            ),
            ColoringRule(
                name="LSM Security Hook",
                filter_expr='event_type == "LSM_HOOK"',
                bg_color=QColor("#DAE8FC"),
                fg_color=QColor("#000000"),
            ),
        ]

    def get_colors_for_event(self, event: Dict[str, Any]) -> Tuple[QColor, QColor]:
        """
        Returns (bg_color, fg_color) for an event by checking rules in priority order.
        Falls back to default white/black if no rule matches.
        """
        for rule in self.rules:
            if rule.matches(event):
                return rule.bg_color, rule.fg_color

        # Default fallback
        return QColor("#FFFFFF"), QColor("#000000")
