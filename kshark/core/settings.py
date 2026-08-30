"""
KShark Persistent Settings Manager via QSettings.
"""

from PyQt6.QtCore import QSettings, QByteArray
from typing import Optional, List, Dict, Any


class KSharkSettings:
    """Manages KShark configuration profiles, geometry, and recent files."""

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
        return self.settings.value("theme", "kshark_dark")

    def set_theme(self, theme_name: str):
        self.settings.setValue("theme", theme_name)

    def get_recent_files(self) -> List[str]:
        return self.settings.value("recent_files", [])

    def add_recent_file(self, file_path: str):
        recent = self.get_recent_files()
        if file_path in recent:
            recent.remove(file_path)
        recent.insert(0, file_path)
        self.settings.setValue("recent_files", recent[:10])

    def get_agent_ws_url(self) -> str:
        return self.settings.value("agent_ws_url", "ws://localhost:8900/ws")

    def set_agent_ws_url(self, url: str):
        self.settings.setValue("agent_ws_url", url)
