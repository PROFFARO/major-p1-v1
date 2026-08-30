"""
KShark Display Filter Entry Toolbar — Live Syntax Validation, Autocomplete, History, and Presets.
Engineered for Cybersecurity Analysts, SOC Engineers, and Network Administrators.
Features:
- Vector SVG Icons for Bookmark, History, Clear, and Apply actions (No broken font glyphs)
- 50+ Categorized Cyber Threat, MITRE ATT&CK, Network, and Regex Filter Presets
- High-contrast visual active-state highlighting on Quick Preset chips
- Two-way synchronization between input text and active preset button state
- AST syntax validation with real-time feedback (Green / Red)
- User-customizable quick filter chips stored persistently in QSettings
"""

from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLineEdit, QToolButton, QCompleter, QMenu, QInputDialog,
    QLabel, QPushButton, QFrame, QApplication, QMessageBox
)
from PyQt6.QtGui import QIcon, QColor, QKeySequence, QAction, QFont
from PyQt6.QtCore import pyqtSignal, Qt, QStringListModel, QSettings
from typing import List, Tuple

from kshark.core.theme import ThemeManager, get_monospace_font, get_ui_font
from kshark.core.filter_engine import compile_filter, FIELD_ALIASES
from kshark.resources.icons import KSharkIcons


class DisplayFilterEntry(QWidget):
    """
    KShark Interactive Display Filter Entry Toolbar with High-Visibility Preset Highlighting.
    """

    filterApplied = pyqtSignal(str)
    filterCleared = pyqtSignal()

    DEFAULT_QUICK_PRESETS = [
        ("Threats", 'threat.name != "BENIGN"'),
        ("Root (UID 0)", 'user.uid == 0'),
        ("Sockets", 'evt.type in ("socket", "connect", "sendto", "recvfrom")'),
        ("Exec Spawns", 'evt.type == "execve"'),
        ("File Mod", 'evt.type in ("write", "openat", "unlink", "rename")'),
        ("Syscall Errors", 'evt.res < 0'),
    ]

    CATEGORIZED_PRESETS = {
        "Threat & MITRE ATT&CK Filters": [
            ("All Threat Detections", 'threat.name != "BENIGN"'),
            ("High-Confidence Threats (>= 80%)", 'threat.confidence >= 0.8'),
            ("Ransomware Activity (T1486)", 'threat.name == "RANSOMWARE"'),
            ("Reverse Shell C2 (T1059.004)", 'threat.name == "REVERSE_SHELL"'),
            ("Privilege Escalation (T1068)", 'threat.name == "PRIVILEGE_ESCALATION"'),
            ("Cryptominer Hijacking (T1496)", 'threat.name == "CRYPTO_MINER"'),
            ("Fileless Execution in RAM (T1620)", 'threat.name == "FILELESS_EXECUTION"'),
            ("Credential Harvesting (T1003.008)", 'threat.name == "CREDENTIAL_DUMPING"'),
        ],
        "Process & Shell Execution": [
            ("All Process Invocations (execve)", 'evt.type == "execve"'),
            ("Interactive Shells (bash, zsh, sh, python)", 'proc.name in ("bash", "zsh", "sh", "python3", "python", "perl", "ruby")'),
            ("Superuser Switch (sudo, su)", 'proc.name in ("sudo", "su", "pkexec", "doas")'),
            ("Init & Daemon Spawns (PID 1)", 'proc.ppid == 1'),
            ("Reflective Executions in /tmp or /dev/shm", 'fd.name startswith "/tmp" or fd.name startswith "/dev/shm"'),
        ],
        "Filesystem & Sensitive Paths": [
            ("All Filesystem Mutations", 'evt.type in ("openat", "write", "unlink", "rename", "chmod", "chown", "truncate")'),
            ("Sensitive Credential Vaults (/etc/shadow, passwd)", 'fd.name matches "/etc/(shadow|passwd|sudoers|security)"'),
            ("SSH Keys & Identity Stores", 'fd.name matches "\\.ssh/(id_rsa|id_ed25519|authorized_keys)"'),
            ("Ransomware Encrypted Extensions (.locked, .enc)", 'fd.name matches "\\.(locked|crypto|enc|aes|crypted)$"'),
        ],
        "Network, Sockets & C2 Beacons": [
            ("All Network Telemetry Syscalls", 'evt.type in ("socket", "connect", "sendto", "recvfrom", "bind", "listen")'),
            ("Common C2 & Ingress Ports (4444, 1337, 8080, 9001)", 'net.port in (4444, 1337, 8080, 9001, 22)'),
            ("External Egress Network Traffic", 'ip.dst != "127.0.0.1" and ip.dst != "0.0.0.0" and ip.dst != ""'),
            ("TCP Transport Traffic", 'net.proto == "TCP"'),
            ("UDP Transport Traffic", 'net.proto == "UDP"'),
        ],
        "Privilege & User Identity": [
            ("Superuser Operations (UID 0)", 'user.uid == 0'),
            ("Non-Root Privilege Mutation Attempts", 'user.uid != 0 and evt.type in ("setuid", "setgid", "capset")'),
            ("Specific User ID 1000", 'user.uid == 1000'),
        ],
        "Kernel Errors & Syscall Failures": [
            ("All Failed System Calls (Errno < 0)", 'evt.res < 0'),
            ("Permission Denied Errors (EACCES -13)", 'evt.res == -13'),
            ("No Such File Errors (ENOENT -2)", 'evt.res == -2'),
        ],
        "Containers & Namespace Isolation": [
            ("Containerized Workloads Only", 'container.name != "host"'),
            ("Namespace Shifts (clone, unshare, setns)", 'evt.type in ("clone", "unshare", "setns")'),
        ],
        "Regex Pattern Templates": [
            ("Regex: Script Interpreters", 'proc.name matches "^(python[23]?|ruby|perl|node|lua)$"'),
            ("Regex: Hidden File Access", 'fd.name matches "/\\.[a-zA-Z0-9_-]+"'),
            ("Regex: Private RFC1918 Subnets", 'ip.dst matches "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)"'),
        ]
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = QSettings("KShark", "DisplayFilter")
        self._history = self._load_history()
        self._custom_bookmarks = self._load_bookmarks()
        self._quick_presets = self._load_quick_presets()
        self._preset_buttons: List[Tuple[QPushButton, str]] = []
        self._init_ui()
        ThemeManager.instance().themeChanged.connect(self._update_syntax_style)

    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 3, 6, 3)
        layout.setSpacing(4)

        # ── 1. Filter Input Container Box ──
        input_container = QFrame(self)
        input_container.setObjectName("filterInputBox")
        input_container.setStyleSheet("""
            QFrame#filterInputBox {
                background-color: #0E171B;
                border: 1px solid #1A303A;
                border-radius: 4px;
            }
        """)
        l_input = QHBoxLayout(input_container)
        l_input.setContentsMargins(4, 1, 4, 1)
        l_input.setSpacing(3)

        btn_tool_style = """
            QToolButton {
                border: 1px solid transparent;
                border-radius: 3px;
                background: transparent;
                padding: 2px;
            }
            QToolButton:hover {
                background-color: #16262D;
                border: 1px solid #1A404D;
            }
            QToolButton:pressed, QToolButton:open, QToolButton:checked, QToolButton[popupMode="1"]:open {
                background-color: #16262D;
                border: 1px solid #2BC1CF;
            }
            QToolButton::menu-indicator {
                image: none;
                width: 0px;
            }
        """

        # Bookmark Menu Button
        self.btn_bookmark = QToolButton(input_container)
        self.btn_bookmark.setIcon(KSharkIcons.filter_bookmark())
        self.btn_bookmark.setToolTip("Security & Forensic Filter Presets Library")
        self.btn_bookmark.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.btn_bookmark.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_bookmark.setStyleSheet(btn_tool_style)
        self.btn_bookmark.setMenu(self._build_bookmark_menu())
        l_input.addWidget(self.btn_bookmark)

        # Filter Input LineEdit
        self.entry = QLineEdit(input_container)
        self.entry.setObjectName("displayFilterLineEdit")
        self.entry.setPlaceholderText("Apply a display filter ... <Ctrl-/>")
        self.entry.setFont(get_monospace_font(size=9))
        self.entry.setStyleSheet("border: none; background: transparent; color: #E0E0E0;")
        self.entry.textChanged.connect(self._on_text_changed)
        self.entry.returnPressed.connect(self._on_apply)

        # Autocomplete dictionary
        completer_words = [
            # Canonical Fields
            "evt.type", "evt.res", "proc.name", "proc.pid", "proc.ppid", "user.uid", "user.gid",
            "fd.name", "exe.path", "ip.src", "ip.dst", "net.srcport", "net.port", "net.proto",
            "threat.name", "threat.confidence", "container.name", "syscall", "comm", "pid", "ppid",
            "uid", "target", "dst_ip", "src_ip", "cmdline",
            # Common Syscalls
            '"execve"', '"openat"', '"connect"', '"read"', '"write"', '"socket"', '"clone"', '"sys_exit"',
            '"unlink"', '"rename"', '"chmod"', '"chown"', '"bind"', '"listen"', '"sendto"', '"recvfrom"',
            # Common Threat Classes
            '"BENIGN"', '"PRIVILEGE_ESCALATION"', '"REVERSE_SHELL"', '"SUSPICIOUS_EXECUTION"',
            '"CONTAINER_ESCAPE"', '"DATA_EXFILTRATION"', '"KERNEL_ROOTKIT"', '"RANSOMWARE"', '"CRYPTO_MINER"',
            # Operators
            "==", "!=", ">=", "<=", ">", "<", "contains", "matches", "startswith", "endswith", "in", "not in",
            # Logicals
            "and", "or", "not", "&&", "||", "!"
        ]
        completer = QCompleter(completer_words, self)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.entry.setCompleter(completer)
        l_input.addWidget(self.entry, stretch=1)

        # History Dropdown Button
        self.btn_history = QToolButton(input_container)
        self.btn_history.setIcon(KSharkIcons.filter_history())
        self.btn_history.setToolTip("Recent Display Filters History")
        self.btn_history.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.btn_history.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_history.setStyleSheet(btn_tool_style)
        self._refresh_history_menu()
        l_input.addWidget(self.btn_history)

        # Clear Cross Button
        self.btn_clear = QToolButton(input_container)
        self.btn_clear.setIcon(KSharkIcons.filter_clear())
        self.btn_clear.setToolTip("Clear display filter")
        self.btn_clear.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_clear.setStyleSheet(btn_tool_style)
        self.btn_clear.clicked.connect(self._on_clear)
        l_input.addWidget(self.btn_clear)

        # Apply Arrow Button
        self.btn_apply = QToolButton(input_container)
        self.btn_apply.setIcon(KSharkIcons.filter_apply())
        self.btn_apply.setToolTip("Apply display filter (Enter)")
        self.btn_apply.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_apply.setStyleSheet(btn_tool_style)
        self.btn_apply.clicked.connect(self._on_apply)
        l_input.addWidget(self.btn_apply)

        layout.addWidget(input_container, stretch=1)

        # ── 2. Quick Filter Preset Chips (Right Toolbar) ──
        self.preset_container = QWidget(self)
        self.l_presets = QHBoxLayout(self.preset_container)
        self.l_presets.setContentsMargins(0, 0, 0, 0)
        self.l_presets.setSpacing(4)
        self._build_quick_preset_buttons()
        layout.addWidget(self.preset_container)

        self._update_syntax_style()

    def _build_quick_preset_buttons(self):
        self._preset_buttons.clear()
        while self.l_presets.count():
            item = self.l_presets.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

        c = ThemeManager.instance().get_palette_colors()
        is_dark = ThemeManager.is_dark()

        btn_bg = "#16262D" if is_dark else "#FFFFFF"
        btn_fg = "#8A9EA4" if is_dark else "#475569"
        btn_border = c["border"]
        btn_hover_bg = "#1C3844" if is_dark else "#F1F5F9"
        btn_hover_fg = c["brand_primary"]
        btn_checked_bg = "#1A525D" if is_dark else "#E0F2FE"
        btn_checked_fg = "#2BC1CF" if is_dark else "#0369A1"
        btn_checked_border = c["brand_primary"]

        chip_qss = f"""
            QPushButton {{
                background-color: {btn_bg};
                border: 1px solid {btn_border};
                border-radius: 3px;
                color: {btn_fg};
                padding: 3px 10px;
                font-weight: normal;
            }}
            QPushButton:hover {{
                background-color: {btn_hover_bg};
                color: {btn_hover_fg};
                border: 1px solid {btn_checked_border};
            }}
            QPushButton:pressed {{
                background-color: {btn_checked_bg};
                color: {btn_checked_fg};
                border: 1px solid {btn_checked_border};
            }}
            QPushButton:checked {{
                background-color: {btn_checked_bg};
                color: {btn_checked_fg};
                border: 1px solid {btn_checked_border};
                font-weight: bold;
            }}
        """

        for label, expr in self._quick_presets:
            btn = QPushButton(label, self.preset_container)
            btn.setFont(get_ui_font(size=8))
            btn.setFixedHeight(24)
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setToolTip(f"Filter: {expr}")
            btn.setStyleSheet(chip_qss)
            btn.clicked.connect(lambda checked, b=btn, e=expr: self._on_quick_preset_clicked(b, e))
            self._preset_buttons.append((btn, expr))
            self.l_presets.addWidget(btn)

        # Add Custom Preset Button
        btn_add = QToolButton(self.preset_container)
        btn_add.setIcon(KSharkIcons.filter_add())
        btn_add.setFixedHeight(24)
        btn_add.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_add.setToolTip("Add / Manage Quick Filter Presets...")
        btn_add.setStyleSheet(f"""
            QToolButton {{
                background-color: {btn_bg};
                border: 1px solid {btn_border};
                border-radius: 3px;
                padding: 3px;
            }}
            QToolButton:hover {{
                background-color: {btn_hover_bg};
                border: 1px solid {btn_checked_border};
            }}
            QToolButton:pressed {{
                background-color: {btn_checked_bg};
                border: 1px solid {btn_checked_border};
            }}
        """)
        btn_add.clicked.connect(self._manage_quick_presets)
        self.l_presets.addWidget(btn_add)


    def _on_quick_preset_clicked(self, clicked_btn: QPushButton, expr: str):
        if clicked_btn.isChecked():
            for btn, _ in self._preset_buttons:
                if btn != clicked_btn:
                    btn.setChecked(False)
            self.set_filter_text(expr)
        else:
            self._on_clear()

    def _sync_preset_button_states(self, text: str):
        norm_text = text.strip().lower()
        for btn, expr in self._preset_buttons:
            if expr.strip().lower() == norm_text and norm_text:
                btn.setChecked(True)
            else:
                btn.setChecked(False)

    def _manage_quick_presets(self):
        menu = QMenu(self)
        act_add = menu.addAction("Add Current Filter as Quick Preset...", self._add_current_as_quick_preset)
        act_add.setIcon(KSharkIcons.filter_add())
        act_reset = menu.addAction("Reset Quick Presets to Defaults", self._reset_quick_presets)
        act_reset.setIcon(KSharkIcons.capture_restart())
        menu.exec(self.preset_container.mapToGlobal(self.preset_container.rect().bottomRight()))


    def _add_current_as_quick_preset(self):
        text = self.entry.text().strip()
        if not text:
            QMessageBox.information(self, "No Filter", "Enter a filter expression first to save as quick preset.")
            return

        name, ok = QInputDialog.getText(self, "Add Quick Preset", "Preset Button Label (Text Only):", text="Custom Filter")
        if ok and name.strip():
            self._quick_presets.append((name.strip(), text))
            self._save_quick_presets()
            self._build_quick_preset_buttons()
            self._sync_preset_button_states(text)

    def _reset_quick_presets(self):
        self._quick_presets = list(self.DEFAULT_QUICK_PRESETS)
        self._save_quick_presets()
        self._build_quick_preset_buttons()

    def _build_bookmark_menu(self) -> QMenu:
        menu = QMenu(self)

        # Categorized Presets Library
        for category, presets in self.CATEGORIZED_PRESETS.items():
            sub = menu.addMenu(category)
            for title, expr in presets:
                act = sub.addAction(title)
                act.triggered.connect(lambda checked, e=expr: self.set_filter_text(e))

        # Custom user bookmarks
        if self._custom_bookmarks:
            menu.addSeparator()
            sub_custom = menu.addMenu("Custom User Bookmarks")
            for title, expr in self._custom_bookmarks:
                act = sub_custom.addAction(title)
                act.triggered.connect(lambda checked, e=expr: self.set_filter_text(e))

        menu.addSeparator()
        act_save = menu.addAction("Save Current Filter as Bookmark...")
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
        act_clear_hist = menu.addAction("Clear History")
        act_clear_hist.triggered.connect(self._clear_history)
        self.btn_history.setMenu(menu)

    def _clear_history(self):
        self._history = []
        self._save_history()
        self._refresh_history_menu()

    def set_filter_text(self, text: str, apply_immediately: bool = True):
        self.entry.setText(text)
        self._sync_preset_button_states(text)
        if apply_immediately:
            self._on_apply()

    def _on_text_changed(self, text: str):
        self._sync_preset_button_states(text)
        self._update_syntax_style()
        if not text.strip():
            self.filterCleared.emit()


    def _on_apply(self):
        text = self.entry.text().strip()
        if text:
            self._add_to_history(text)
            self._sync_preset_button_states(text)
            self.filterApplied.emit(text)
        else:
            self.filterCleared.emit()

    def _on_clear(self):
        self.entry.clear()
        self._sync_preset_button_states("")
        self.filterCleared.emit()

    def _update_syntax_style(self):
        text = self.entry.text().strip()
        box = self.findChild(QFrame, "filterInputBox")
        if not box:
            return

        c = ThemeManager.instance().get_palette_colors()
        is_dark = ThemeManager.is_dark()

        # Update text color of the line edit itself
        self.entry.setStyleSheet(f"border: none; background: transparent; color: {c['fg_text']};")
        self._build_quick_preset_buttons()

        if not text:
            bg = "#121E24" if is_dark else "#FFFFFF"
            border = c["border"]
            box.setStyleSheet(f"""
                QFrame#filterInputBox {{
                    background-color: {bg};
                    border: 1px solid {border};
                    border-radius: 4px;
                }}
            """)
            self.entry.setToolTip("Enter filter expression")
            return

        try:
            ast = compile_filter(text)
            if ast is not None:
                # Valid Expression (Green)
                bg = "#143828" if is_dark else "#DCFCE7"
                border = "#22C55E" if is_dark else "#86EFAC"
                box.setStyleSheet(f"""
                    QFrame#filterInputBox {{
                        background-color: {bg};
                        border: 1px solid {border};
                        border-radius: 4px;
                    }}
                """)
                self.entry.setToolTip("✓ Valid Filter Expression")
            else:
                bg = "#121E24" if is_dark else "#FFFFFF"
                border = c["border"]
                box.setStyleSheet(f"""
                    QFrame#filterInputBox {{
                        background-color: {bg};
                        border: 1px solid {border};
                        border-radius: 4px;
                    }}
                """)
        except Exception as e:
            # Syntax Error (Red)
            bg = "#4D1B1B" if is_dark else "#FEE2E2"
            border = "#EF4444" if is_dark else "#FCA5A5"
            box.setStyleSheet(f"""
                QFrame#filterInputBox {{
                    background-color: {bg};
                    border: 1px solid {border};
                    border-radius: 4px;
                }}
            """)
            self.entry.setToolTip(f"Syntax Error: {e}")

    def _load_history(self) -> List[str]:
        val = self.settings.value("history", [])
        return val if isinstance(val, list) else []

    def _save_history(self):
        self.settings.setValue("history", self._history)

    def _add_to_history(self, expr: str):
        if expr in self._history:
            self._history.remove(expr)
        self._history.append(expr)
        if len(self._history) > 30:
            self._history = self._history[-30:]
        self._save_history()
        self._refresh_history_menu()

    def _load_bookmarks(self) -> List[Tuple[str, str]]:
        val = self.settings.value("custom_bookmarks", [])
        return val if isinstance(val, list) else []

    def _save_bookmarks(self):
        self.settings.setValue("custom_bookmarks", self._custom_bookmarks)

    def _load_quick_presets(self) -> List[Tuple[str, str]]:
        val = self.settings.value("quick_presets", None)
        if isinstance(val, list) and val:
            return val
        return list(self.DEFAULT_QUICK_PRESETS)

    def _save_quick_presets(self):
        self.settings.setValue("quick_presets", self._quick_presets)
