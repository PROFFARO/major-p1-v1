"""
Stratoshark Display Filter Entry Toolbar — Live Syntax Validation, Autocomplete, History, and Presets.
Direct implementation of Wireshark/Stratoshark display_filter_edit architecture.
"""

from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLineEdit, QToolButton, QCompleter, QMenu, QInputDialog
)
from PyQt6.QtGui import QIcon, QColor, QKeySequence, QAction, QFont
from PyQt6.QtCore import pyqtSignal, Qt, QStringListModel, QSettings

from stratoshark.core.theme import ThemeManager, get_monospace_font
from stratoshark.core.filter_engine import compile_filter, FIELD_ALIASES


class DisplayFilterEntry(QWidget):
    """
    Stratoshark Interactive Display Filter Entry Widget.
    Features:
    - Live Syntax Highlighting (Green = Valid AST, Red = Invalid AST)
    - Bookmark Button with Predefined Threat, Syscall, and Container Presets
    - History Dropdown with Persistent QSettings Memory
    - Contextual Field Autocomplete
    - One-Click Clear (✖) and Apply (➔)
    """

    filterApplied = pyqtSignal(str)
    filterCleared = pyqtSignal()

    PRESET_FILTERS = [
        ("🚨 All Security Threats", 'threat.name != "BENIGN"'),
        ("⚡ High-Confidence Threats (≥ 80%)", 'threat.confidence >= 0.8'),
        ("🤖 eBPF Agent & Security Engines", 'proc.name contains "ebpf"'),
        ("🐚 Process Spawns & Executions", 'evt.type == "execve"'),
        ("📂 File & Socket Operations", 'evt.type in ("openat", "read", "write", "socket", "connect")'),
        ("👑 Root User Privileges (UID 0)", 'user.uid == 0'),
        ("🖥️ Desktop & System Processes", 'proc.name in ("ebpf-ml-agent", "kwin_wayland", "antigravity", "systemd")'),
        ("🐳 Container Workloads", 'container.name != "host"'),
        ("🔒 Kernel LSM & Security Hooks", 'evt.type contains "security_"'),
    ]


    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = QSettings("Stratoshark", "DisplayFilter")
        self._history = self._load_history()
        self._custom_bookmarks = self._load_bookmarks()
        self._init_ui()
        ThemeManager.instance().themeChanged.connect(self._update_syntax_style)

    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(3)

        # 1. Bookmark Button (🔖)
        self.btn_bookmark = QToolButton(self)
        self.btn_bookmark.setText("🔖")
        self.btn_bookmark.setToolTip("Security & Forensic Filter Presets")
        self.btn_bookmark.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.btn_bookmark.setMenu(self._build_bookmark_menu())
        layout.addWidget(self.btn_bookmark)

        # 2. Filter Input Box
        self.entry = QLineEdit(self)
        self.entry.setObjectName("displayFilterLineEdit")
        self.entry.setPlaceholderText("Apply a display filter ... <Ctrl-/>")
        self.entry.setFont(get_monospace_font(size=9))
        self.entry.textChanged.connect(self._on_text_changed)
        self.entry.returnPressed.connect(self._on_apply)

        # Autocomplete dictionary
        completer_words = [
            # Canonical Fields
            "evt.type", "proc.name", "proc.pid", "proc.ppid", "user.uid", "user.gid",
            "fd.name", "exe.path", "net.dst", "net.port", "threat.name", "threat.confidence",
            "container.name", "syscall", "comm", "pid", "ppid", "uid", "target", "dst_ip",
            # Common Syscalls
            '"execve"', '"openat"', '"connect"', '"read"', '"write"', '"socket"', '"clone"', '"sys_exit"',
            # Common Threat Classes
            '"BENIGN"', '"PRIVILEGE_ESCALATION"', '"REVERSE_SHELL"', '"SUSPICIOUS_EXECUTION"',
            '"CONTAINER_ESCAPE"', '"DATA_EXFILTRATION"', '"KERNEL_ROOTKIT"',
            # Operators
            "==", "!=", ">=", "<=", ">", "<", "contains", "matches", "startswith", "endswith", "in", "not in",
            # Logicals
            "and", "or", "not", "&&", "||", "!"
        ]
        completer = QCompleter(completer_words, self)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.entry.setCompleter(completer)

        layout.addWidget(self.entry, stretch=1)

        # 3. History Dropdown Button (▼)
        self.btn_history = QToolButton(self)
        self.btn_history.setText("▼")
        self.btn_history.setToolTip("Recent Display Filters History")
        self.btn_history.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self._refresh_history_menu()
        layout.addWidget(self.btn_history)

        # 4. Clear Cross Button (✖)
        self.btn_clear = QToolButton(self)
        self.btn_clear.setText("✖")
        self.btn_clear.setToolTip("Clear display filter")
        self.btn_clear.clicked.connect(self._on_clear)
        layout.addWidget(self.btn_clear)

        # 5. Apply Arrow Button (➔)
        self.btn_apply = QToolButton(self)
        self.btn_apply.setText("➔")
        self.btn_apply.setToolTip("Apply display filter (Enter)")
        self.btn_apply.clicked.connect(self._on_apply)
        layout.addWidget(self.btn_apply)

        self._update_syntax_style()

    def _build_bookmark_menu(self) -> QMenu:
        menu = QMenu(self)

        # Default Presets
        for title, expr in self.PRESET_FILTERS:
            act = menu.addAction(title)
            act.triggered.connect(lambda checked, e=expr: self.set_filter_text(e))

        # Custom user bookmarks
        if self._custom_bookmarks:
            menu.addSeparator()
            menu.addAction("— Custom Bookmarks —").setEnabled(False)
            for title, expr in self._custom_bookmarks:
                act = menu.addAction(f"⭐ {title}")
                act.triggered.connect(lambda checked, e=expr: self.set_filter_text(e))

        menu.addSeparator()
        act_save = menu.addAction("➕ Save Current Filter as Bookmark...")
        act_save.triggered.connect(self._save_current_as_bookmark)

        return menu

    def _save_current_as_bookmark(self):
        text = self.entry.text().strip()
        if not text:
            return

        name, ok = QInputDialog.getText(self, "Save Filter Bookmark", "Bookmark Name:", text=text[:30])
        if ok and name.strip():
            self._custom_bookmarks.append((name.strip(), text))
            self._save_bookmarks()
            self.btn_bookmark.setMenu(self._build_bookmark_menu())

    def _refresh_history_menu(self):
        menu = QMenu(self)
        if not self._history:
            menu.addAction("No recent filters").setEnabled(False)
        else:
            for item in reversed(self._history[-15:]):
                act = menu.addAction(item)
                act.triggered.connect(lambda checked, expr=item: self.set_filter_text(expr))

            menu.addSeparator()
            act_clear = menu.addAction("Clear Filter History")
            act_clear.triggered.connect(self._clear_history)

        self.btn_history.setMenu(menu)

    def _on_text_changed(self, text: str):
        self._update_syntax_style()
        # Live real-time filter evaluation as user types
        self.filterApplied.emit(text.strip())


    def _on_apply(self):
        text = self.entry.text().strip()
        if text:
            if text in self._history:
                self._history.remove(text)
            self._history.append(text)
            self._save_history()
            self._refresh_history_menu()

        self.filterApplied.emit(text)

    def _on_clear(self):
        self.entry.clear()
        self.filterCleared.emit()
        self.filterApplied.emit("")

    def set_filter_text(self, text: str):
        self.entry.setText(text)
        self._on_apply()

    def _update_syntax_style(self):
        text = self.entry.text().strip()
        colors = ThemeManager.instance().get_palette_colors()

        if not text:
            # Neutral styling
            self.entry.setStyleSheet(f"""
                QLineEdit {{
                    background-color: {colors["bg_base"]};
                    color: {colors["fg_text"]};
                    border: 1px solid {colors["border"]};
                    border-radius: 3px;
                    padding: 3px 6px;
                }}
            """)
        else:
            try:
                node = compile_filter(text)
                if node:
                    # Valid Filter (Light Green / Dark Forest Green)
                    bg = "#D5F5E3" if not ThemeManager.is_dark() else "#144A29"
                    fg = "#0E5A28" if not ThemeManager.is_dark() else "#E8F8F0"
                    border = "#2ECC71" if not ThemeManager.is_dark() else "#27AE60"
                else:
                    # Invalid Filter (Light Red / Dark Crimson)
                    bg = "#FADBD8" if not ThemeManager.is_dark() else "#4A1414"
                    fg = "#78281F" if not ThemeManager.is_dark() else "#FCEAE8"
                    border = "#E74C3C" if not ThemeManager.is_dark() else "#C0392B"
            except Exception:
                bg = "#FADBD8" if not ThemeManager.is_dark() else "#4A1414"
                fg = "#78281F" if not ThemeManager.is_dark() else "#FCEAE8"
                border = "#E74C3C" if not ThemeManager.is_dark() else "#C0392B"

            self.entry.setStyleSheet(f"""
                QLineEdit {{
                    background-color: {bg};
                    color: {fg};
                    border: 1px solid {border};
                    border-radius: 3px;
                    padding: 3px 6px;
                    font-weight: 500;
                }}
            """)

    def _load_history(self) -> list:
        val = self.settings.value("recent_filters", [])
        return val if isinstance(val, list) else []

    def _save_history(self):
        self.settings.setValue("recent_filters", self._history[-25:])

    def _clear_history(self):
        self._history.clear()
        self._save_history()
        self._refresh_history_menu()

    def _load_bookmarks(self) -> list:
        val = self.settings.value("custom_bookmarks", [])
        return val if isinstance(val, list) else []

    def _save_bookmarks(self):
        self.settings.setValue("custom_bookmarks", self._custom_bookmarks)
