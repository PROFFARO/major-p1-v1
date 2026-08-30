from PyQt6.QtGui import QColor
from typing import List, Tuple, Dict, Any, Optional

from kshark.core.theme import ThemeManager
from kshark.core.filter_engine import compile_filter


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
        self._compiled_cache = {}

    def _get_default_rules(self) -> List[ColoringRule]:
        return [
            ColoringRule("High Severity Threat", "threat.name != 'BENIGN'", "#FEE2E2", "#991B1B", "#5C1D1D", "#FF9999", True),
            ColoringRule("Process Execve", "evt.type == 'execve'", "#F3E8FF", "#581C87", "#361D48", "#E6C6FF", True),
            ColoringRule("Network Connect", "evt.type in ('connect', 'socket', 'bind', 'listen', 'sendto', 'recvfrom') or dst_ip != ''", "#E0F2FE", "#075985", "#1A2F4D", "#B3D4FF", True),
            ColoringRule("File Open / Modify", "evt.type in ('openat', 'write', 'read', 'unlink', 'rename')", "#DCFCE7", "#166534", "#1E3D1E", "#B8F0B8", True),
            ColoringRule("LSM Security Hook", "evt.type contains 'security' or evt.type in ('setuid', 'capset')", "#FEF3C7", "#854D0E", "#474218", "#FFF7A3", True),
        ]

    def clear_cache(self):
        self._compiled_cache.clear()

    def get_colors_for_event(self, event: Dict[str, Any]) -> Tuple[QColor, QColor]:
        """Returns (bg_color, fg_color) for an event based on active rules and theme."""
        is_dark = ThemeManager.is_dark()

        for rule in self.rules:
            if not rule.enabled or not rule.filter_expr.strip():
                continue
            if rule.filter_expr not in self._compiled_cache:
                self._compiled_cache[rule.filter_expr] = compile_filter(rule.filter_expr)
            ast = self._compiled_cache.get(rule.filter_expr)
            if ast and ast.matches(event):
                bg = rule.bg_dark if is_dark else rule.bg_light
                fg = rule.fg_dark if is_dark else rule.fg_light
                return (QColor(bg), QColor(fg))

        # Default fallback zebra colors
        if is_dark:
            return (QColor("#182428"), QColor("#D8E8EC"))
        return (QColor("#FFFFFF"), QColor("#102A30"))

    def get_row_colors(self, event: Dict[str, Any]) -> Tuple[QColor, QColor]:
        return self.get_colors_for_event(event)


