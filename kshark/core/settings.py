"""
KShark Persistent Settings Manager via QSettings.
"""

from PyQt6.QtCore import QSettings, QByteArray
from typing import Optional, List, Dict, Any


class KSharkSettings:
    """Manages KShark configuration profiles, geometry, preferences, and recent files."""

    def __init__(self):
        self.settings = QSettings("KShark", "KSharkObservability")

    def get_window_geometry(self) -> Optional[QByteArray]:
        return self.settings.value("geometry")

    def set_window_geometry(self, geom: QByteArray):
        self.settings.setValue("geometry", geom)

    def get_master_splitter_state(self) -> Optional[QByteArray]:
        return self.settings.value("master_splitter")

    def set_master_splitter_state(self, state: QByteArray):
        self.settings.setValue("master_splitter", state)

    def get_bottom_splitter_state(self) -> Optional[QByteArray]:
        return self.settings.value("bottom_splitter")

    def set_bottom_splitter_state(self, state: QByteArray):
        self.settings.setValue("bottom_splitter", state)

    def get_theme(self) -> str:
        return str(self.settings.value("theme", "wireshark_dark"))

    def set_theme(self, theme_name: str):
        self.settings.setValue("theme", theme_name)

    def get_recent_files(self) -> List[str]:
        val = self.settings.value("recent_files", [])
        return list(val) if isinstance(val, (list, tuple)) else []

    def add_recent_file(self, file_path: str):
        recent = self.get_recent_files()
        if file_path in recent:
            recent.remove(file_path)
        recent.insert(0, file_path)
        self.settings.setValue("recent_files", recent[:10])

    def get_agent_ws_url(self) -> str:
        return str(self.settings.value("agent_ws_url", "ws://localhost:8900/ws"))

    def set_agent_ws_url(self, url: str):
        self.settings.setValue("agent_ws_url", url)

    # ── Profiles ──
    def get_profiles(self) -> List[str]:
        val = self.settings.value("profiles", [
            "Default (Linux Syscalls & eBPF)",
            "CloudTrail (AWS Cloud Logs)",
            "Kubernetes (Container Pods)",
            "Forensics & Threat Hunting"
        ])
        if isinstance(val, (list, tuple)) and val:
            return list(val)
        return ["Default (Linux Syscalls & eBPF)"]

    def set_profiles(self, profiles: List[str]):
        self.settings.setValue("profiles", profiles)

    def get_active_profile(self) -> str:
        return str(self.settings.value("active_profile", "Default (Linux Syscalls & eBPF)"))

    def set_active_profile(self, profile_name: str):
        self.settings.setValue("active_profile", profile_name)

    # ── General Preferences ──
    def get_font_size(self) -> int:
        return int(self.settings.value("font_size", 9))

    def set_font_size(self, size: int):
        self.settings.setValue("font_size", size)

    def get_auto_scroll(self) -> bool:
        val = self.settings.value("auto_scroll", True)
        return str(val).lower() in ("true", "1")

    def set_auto_scroll(self, enabled: bool):
        self.settings.setValue("auto_scroll", enabled)

    def get_max_buffer_events(self) -> int:
        return int(self.settings.value("max_buffer_events", 50000))

    def set_max_buffer_events(self, count: int):
        self.settings.setValue("max_buffer_events", count)

    def get_default_filter(self) -> str:
        return str(self.settings.value("default_filter", ""))

    def set_default_filter(self, filter_text: str):
        self.settings.setValue("default_filter", filter_text)
