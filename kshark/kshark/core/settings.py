"""
Persistent Configuration & Profile Settings Manager for KShark.
Backed by QSettings (INI / native Linux config path ~/.config/kshark/kshark.conf).
"""

from PyQt6.QtCore import QSettings, QByteArray, QPoint, QSize
from typing import List, Dict, Any, Optional
import os


class KSharkSettings:
    """Centralized QSettings wrapper for KShark."""

    ORGANIZATION = "KShark"
    APPLICATION = "KShark"

    def __init__(self):
        self.settings = QSettings(self.ORGANIZATION, self.APPLICATION)

    # ─────────────────────────────────────────────────────────
    # Window Geometry & Splitter Layout
    # ─────────────────────────────────────────────────────────

    def get_window_geometry(self) -> Optional[QByteArray]:
        val = self.settings.value("geometry/main_window", None)
        return val if isinstance(val, QByteArray) else None

    def save_window_geometry(self, geometry: QByteArray):
        self.settings.setValue("geometry/main_window", geometry)

    def get_window_state(self) -> Optional[QByteArray]:
        val = self.settings.value("geometry/main_window_state", None)
        return val if isinstance(val, QByteArray) else None

    def save_window_state(self, state: QByteArray):
        self.settings.setValue("geometry/main_window_state", state)

    def get_master_splitter_state(self) -> Optional[QByteArray]:
        val = self.settings.value("geometry/master_splitter", None)
        return val if isinstance(val, QByteArray) else None

    def save_master_splitter_state(self, state: QByteArray):
        self.settings.setValue("geometry/master_splitter", state)

    def get_bottom_splitter_state(self) -> Optional[QByteArray]:
        val = self.settings.value("geometry/bottom_splitter", None)
        return val if isinstance(val, QByteArray) else None

    def save_bottom_splitter_state(self, state: QByteArray):
        self.settings.setValue("geometry/bottom_splitter", state)

    # ─────────────────────────────────────────────────────────
    # Appearance & Themes
    # ─────────────────────────────────────────────────────────

    def get_theme_mode(self) -> str:
        """Returns 'light', 'dark', or 'system'."""
        return str(self.settings.value("appearance/theme_mode", "light"))

    def set_theme_mode(self, mode: str):
        self.settings.setValue("appearance/theme_mode", mode)

    def get_font_size(self) -> int:
        return int(self.settings.value("appearance/font_size", 9))

    def set_font_size(self, size: int):
        self.settings.setValue("appearance/font_size", size)

    # ─────────────────────────────────────────────────────────
    # Filter History & Bookmarks
    # ─────────────────────────────────────────────────────────

    def get_filter_history(self) -> List[str]:
        val = self.settings.value("filters/history", [])
        if isinstance(val, list):
            return [str(v) for v in val]
        return []

    def add_filter_history(self, filter_text: str):
        if not filter_text or not filter_text.strip():
            return
        history = self.get_filter_history()
        filter_text = filter_text.strip()
        if filter_text in history:
            history.remove(filter_text)
        history.insert(0, filter_text)
        self.settings.setValue("filters/history", history[:30])

    def get_filter_bookmarks(self) -> Dict[str, str]:
        """Returns dict of {label: filter_expr}."""
        val = self.settings.value("filters/bookmarks", {})
        if isinstance(val, dict):
            return {str(k): str(v) for k, v in val.items()}
        # Default security bookmarks
        return {
            "All Critical Threats": "threat in ('RANSOMWARE', 'KERNEL_ROOTKIT', 'CONTAINER_ESCAPE')",
            "Reverse Shells": "threat == 'REVERSE_SHELL' || syscall_id == 59 && comm in ('bash', 'sh', 'nc')",
            "Privilege Escalation": "threat == 'PRIVILEGE_ESCALATION' || syscall_id in (105, 106, 125, 308)",
            "Suspicious /tmp Executions": "file_path contains '/tmp' || file_path contains '/dev/shm'",
            "Sensitive Credentials Access": "file_path contains '/etc/shadow' || file_path contains '/root/.ssh'",
            "High Anomaly Scores": "confidence >= 0.80",
        }

    def save_filter_bookmarks(self, bookmarks: Dict[str, str]):
        self.settings.setValue("filters/bookmarks", bookmarks)

    # ─────────────────────────────────────────────────────────
    # Agent Connectivity Settings
    # ─────────────────────────────────────────────────────────

    def get_agent_ws_url(self) -> str:
        return str(self.settings.value("agent/ws_url", "ws://localhost:8900/ws"))

    def set_agent_ws_url(self, url: str):
        self.settings.setValue("agent/ws_url", url)

    def get_agent_rest_base(self) -> str:
        return str(self.settings.value("agent/rest_base", "http://localhost:8900"))

    def set_agent_rest_base(self, base_url: str):
        self.settings.setValue("agent/rest_base", base_url)

    # ─────────────────────────────────────────────────────────
    # Recent Captures
    # ─────────────────────────────────────────────────────────

    def get_recent_files(self) -> List[str]:
        val = self.settings.value("recent/capture_files", [])
        if isinstance(val, list):
            return [str(v) for v in val if os.path.exists(str(v))]
        return []

    def add_recent_file(self, filepath: str):
        if not filepath:
            return
        files = self.get_recent_files()
        if filepath in files:
            files.remove(filepath)
        files.insert(0, filepath)
        self.settings.setValue("recent/capture_files", files[:15])

    # ─────────────────────────────────────────────────────────
    # LLM Security Copilot Settings
    # ─────────────────────────────────────────────────────────

    def get_llm_provider(self) -> str:
        return str(self.settings.value("llm/provider", "auto"))

    def get_llm_model(self) -> str:
        return str(self.settings.value("llm/model", "gemini-2.5-flash"))

    def get_llm_api_key(self) -> str:
        return str(self.settings.value("llm/api_key", os.getenv("LLM_API_KEY", "")))

    def set_llm_config(self, provider: str, model: str, api_key: str):
        self.settings.setValue("llm/provider", provider)
        self.settings.setValue("llm/model", model)
        self.settings.setValue("llm/api_key", api_key)
