"""
KShark & Wireshark Coloring Rules Engine.
Evaluates event attributes against prioritized rules to assign background/foreground colors.
"""

from PyQt6.QtGui import QColor
from typing import List, Tuple, Dict, Any

from kshark.core.theme import ThemeManager


class ColoringRule:
    def __init__(self, name: str, filter_expr: str, bg_light: str, fg_light: str, bg_dark: str, fg_dark: str, enabled: bool = True):
        self.name = name
        self.filter_expr = filter_expr
        self.bg_light = bg_light
        self.fg_light = fg_light
        self.bg_dark = bg_dark
        self.fg_dark = fg_dark
        self.enabled = enabled


class ColoringEngine:
    """Evaluates coloring rules for KShark event list rows."""

    def __init__(self):
        self.rules: List[ColoringRule] = self._get_default_rules()

    def _get_default_rules(self) -> List[ColoringRule]:
        return [
            ColoringRule("High Severity Threat", "threat_name != 'BENIGN'", "#FFD6D6", "#990000", "#5C1D1D", "#FF9999"),
            ColoringRule("Process Execve", "syscall == 'execve'", "#F5E6FF", "#4A1A70", "#361D48", "#E6C6FF"),
            ColoringRule("Network Connect", "syscall == 'connect'", "#E4F0FF", "#10356E", "#1A2F4D", "#B3D4FF"),
            ColoringRule("File Open / Modify", "syscall == 'openat' or syscall == 'write'", "#E6F9E6", "#145214", "#1E3D1E", "#B8F0B8"),
            ColoringRule("LSM Security Hook", "syscall contains 'security'", "#FFFDE6", "#61570A", "#474218", "#FFF7A3"),
        ]

    def get_colors_for_event(self, event: Dict[str, Any]) -> Tuple[QColor, QColor]:
        """Returns (bg_color, fg_color) for an event based on active rules and theme."""
        is_dark = ThemeManager.is_dark()
        threat = str(event.get("threat_name") or event.get("threat_type") or "BENIGN")
        sc = str(event.get("syscall") or event.get("syscall_name") or "")

        # Fast direct evaluation for highest throughput
        if threat != "BENIGN":
            return (QColor("#5C1D1D"), QColor("#FF9999")) if is_dark else (QColor("#FFD6D6"), QColor("#990000"))

        if sc == "execve":
            return (QColor("#361D48"), QColor("#E6C6FF")) if is_dark else (QColor("#F5E6FF"), QColor("#4A1A70"))

        if sc == "connect" or event.get("dst_ip"):
            return (QColor("#1A2F4D"), QColor("#B3D4FF")) if is_dark else (QColor("#E4F0FF"), QColor("#10356E"))

        if sc in ("openat", "write", "read"):
            return (QColor("#1E3D1E"), QColor("#B8F0B8")) if is_dark else (QColor("#E6F9E6"), QColor("#145214"))

        if "security" in sc:
            return (QColor("#474218"), QColor("#FFF7A3")) if is_dark else (QColor("#FFFDE6"), QColor("#61570A"))

        # Default fallback zebra colors
        if is_dark:
            return (QColor("#182428"), QColor("#D8E8EC"))
        return (QColor("#FFFFFF"), QColor("#102A30"))

    def get_row_colors(self, event: Dict[str, Any]) -> Tuple[QColor, QColor]:
        return self.get_colors_for_event(event)

