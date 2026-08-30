"""
KShark Main Status Bar — Enterprise Linux Kernel & SOC Observability Status Bar.
Features:
- Live Engine State Indicator (● IDLE, ● CAPTURING, ● FROZEN)
- Segmented Sunken Observability Panels with Real Telemetry Facts
- Real-time Event Throughput (EPS / KBps), Filter Match Ratio & Kernel Buffer Health
- High-Visibility Threat Alert Panel with 1-Click Forensic Triage Jumps
- Interactive Time Display Format & Capture Profile Menus
- User-Customizable Panels (Right-Click Toggle & Persistent QSettings)
"""

import os
from PyQt6.QtWidgets import (
    QStatusBar, QLabel, QWidget, QHBoxLayout, QPushButton,
    QMenu, QInputDialog, QMessageBox, QFrame
)
from PyQt6.QtGui import QColor, QFont, QCursor, QAction
from PyQt6.QtCore import Qt, pyqtSignal, QSettings


from kshark.core.theme import ThemeManager, get_monospace_font, get_ui_font
from kshark.resources.icons import KSharkIcons


class MainStatusBar(QStatusBar):
    """
    Enterprise Linux Kernel & SOC Observability Status Bar.
    """

    timeFormatChanged = pyqtSignal(int)
    profileChanged = pyqtSignal(str)
    threatsClicked = pyqtSignal()
    eventsClicked = pyqtSignal()


    DEFAULT_PANEL_VISIBILITY = {
        "show_throughput": True,
        "show_events": True,
        "show_threats": True,
        "show_buffer": True,
        "show_time_format": True,
        "show_profile": True,
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ksharkStatusBar")
        self.settings = QSettings("KShark", "StatusBar")

        self.threat_count = 0
        self.eps = 0.0
        self.total_events = 0
        self.displayed_events = 0
        self.dropped_events = 0
        self.buffer_pct = 0.1
        self.current_time_format = "Relative"
        self.current_profile = "Default"
        self.capture_state = "IDLE"

        self._init_ui()
        self._load_preferences()
        ThemeManager.instance().themeChanged.connect(self._apply_theme)
        self._apply_theme()

    def _init_ui(self):
        self.setSizeGripEnabled(False)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

        # ── 1. Left Section: State Indicator + Dynamic Message ──
        left_container = QWidget(self)
        l_left = QHBoxLayout(left_container)
        l_left.setContentsMargins(6, 2, 6, 2)
        l_left.setSpacing(8)

        # State Indicator Pill
        self.lbl_state = QLabel(" ● IDLE ", self)
        self.lbl_state.setFont(get_monospace_font(size=8, bold=True))
        self.lbl_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_state.setFixedWidth(95)
        self.lbl_state.setFixedHeight(20)
        self.lbl_state.setStyleSheet("""
            background-color: #121E24;
            color: #8A9EA4;
            border: 1px solid #1E333D;
            border-radius: 3px;
            padding: 1px 4px;
        """)
        l_left.addWidget(self.lbl_state)

        # Main Status Message
        self.lbl_message = QLabel("Ready to capture kernel events", self)
        self.lbl_message.setFont(get_ui_font(size=8))
        l_left.addWidget(self.lbl_message, stretch=1)


        self.addWidget(left_container, stretch=1)

        # ── 2. Permanent Right Observability Panels ──

        # Panel 1: Throughput (EPS)
        self.panel_throughput = self._create_panel_widget()
        self.lbl_eps = QLabel("0.0 evt/s", self)
        self.lbl_eps.setFont(get_monospace_font(size=8))
        self.lbl_eps.setStyleSheet("color: #2BC1CF; font-weight: bold;")
        self.lbl_eps.setToolTip("Kernel Telemetry Ingestion Throughput (Events per Second)")
        self.panel_throughput.layout().addWidget(self.lbl_eps)
        self.addPermanentWidget(self.panel_throughput)

        # Panel 2: Events & Filter Counters
        self.panel_events = self._create_panel_widget()
        self.btn_events = QPushButton("Events: 0  Displayed: 0 (100.0%)", self)
        self.btn_events.setFlat(True)
        self.btn_events.setFont(get_monospace_font(size=8))
        self.btn_events.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_events.setStyleSheet("color: #D8E8EC; padding: 0 4px;")
        self.btn_events.setToolTip("Total Captured vs Displayed Events. Click to view Capture Statistics.")
        self.btn_events.clicked.connect(self.eventsClicked.emit)
        self.panel_events.layout().addWidget(self.btn_events)
        self.addPermanentWidget(self.panel_events)

        # Panel 3: Security Threats & Alert Level
        self.panel_threats = self._create_panel_widget()
        self.btn_threats = QPushButton("Threats: 0", self)
        self.btn_threats.setFlat(True)
        self.btn_threats.setFont(get_ui_font(size=8, bold=True))
        self.btn_threats.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_threats.setStyleSheet("color: #0E8A58; padding: 0 4px;")
        self.btn_threats.setToolTip("Active Threat Detections. Click to jump to Threat Forensics.")
        self.btn_threats.clicked.connect(self.threatsClicked.emit)
        self.panel_threats.layout().addWidget(self.btn_threats)
        self.addPermanentWidget(self.panel_threats)

        # Panel 4: eBPF Buffer Health
        self.panel_buffer = self._create_panel_widget()
        self.lbl_buffer = QLabel("RingBuffer: 0.1%", self)
        self.lbl_buffer.setFont(get_monospace_font(size=8))
        self.lbl_buffer.setStyleSheet("color: #8A9EA4;")
        self.lbl_buffer.setToolTip("eBPF RingBuffer Map Capacity Utilization (Kernel to Userspace Queue)")
        self.panel_buffer.layout().addWidget(self.lbl_buffer)
        self.addPermanentWidget(self.panel_buffer)

        # Panel 5: Time Format Selector
        self.panel_time = self._create_panel_widget()
        self.btn_time = QPushButton("Time: Relative ▾", self)
        self.btn_time.setFlat(True)
        self.btn_time.setFont(get_ui_font(size=8))
        self.btn_time.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_time.setStyleSheet("color: #D8E8EC; padding: 0 4px;")
        self.btn_time.setToolTip("Click to switch Event Timestamp Display Format")
        self.btn_time.setMenu(self._build_time_format_menu())
        self.panel_time.layout().addWidget(self.btn_time)
        self.addPermanentWidget(self.panel_time)

        # Panel 6: Capture Profile Selector
        self.panel_profile = self._create_panel_widget()
        self.btn_profile = QPushButton("Profile: Default ▾", self)
        self.btn_profile.setFlat(True)
        self.btn_profile.setFont(get_ui_font(size=8, bold=True))
        self.btn_profile.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_profile.setStyleSheet("color: #2BC1CF; padding: 0 4px;")
        self.btn_profile.setToolTip("Click to switch or manage Active Capture & Filtering Profiles")
        self.btn_profile.setMenu(self._build_profile_menu())
        self.panel_profile.layout().addWidget(self.btn_profile)
        self.addPermanentWidget(self.panel_profile)

    def _create_panel_widget(self) -> QFrame:
        panel = QFrame(self)
        panel.setObjectName("statusPanel")
        panel.setStyleSheet("""
            QFrame#statusPanel {
                background-color: #0E171B;
                border: 1px solid #1A303A;
                border-radius: 3px;
                margin: 2px 2px;
                padding: 0 4px;
            }
            QFrame#statusPanel:hover {
                border-color: #0E9AA7;
            }
        """)
        l = QHBoxLayout(panel)
        l.setContentsMargins(4, 1, 4, 1)
        l.setSpacing(4)
        return panel

    def _build_time_format_menu(self) -> QMenu:
        menu = QMenu(self)
        formats = [
            ("Relative (Seconds since capture start)", "Relative", 0),
            ("Time of Day (HH:MM:SS.nanoseconds)", "TimeOfDay", 1),
            ("Date and Time (YYYY-MM-DD HH:MM:SS)", "DateTime", 2),
            ("Epoch (Unix timestamp in seconds)", "Epoch", 3),
        ]
        for label, name, val in formats:
            act = menu.addAction(label)
            act.triggered.connect(lambda checked, n=name, v=val: self._set_time_format(n, v))
        return menu

    def _set_time_format(self, name: str, val: int = 0):
        self.current_time_format = name
        self.btn_time.setText(f"Time: {name} ▾")
        self.timeFormatChanged.emit(val)


    def _build_profile_menu(self) -> QMenu:
        menu = QMenu(self)
        profiles = [
            "Default (General Observability)",
            "Incident Response & Malware Triage",
            "Network Forensics & Sockets",
            "Process Lineage & PrivEsc Hunting",
            "Filesystem & Ransomware Guard",
        ]
        for prof in profiles:
            act = menu.addAction(prof)
            act.triggered.connect(lambda checked, p=prof: self._set_profile(p))

        menu.addSeparator()
        act_new = menu.addAction("New Profile...")
        act_new.triggered.connect(self._create_new_profile)
        return menu

    def _set_profile(self, profile_name: str):
        short_name = profile_name.split("(")[0].strip()
        self.current_profile = short_name
        self.btn_profile.setText(f"Profile: {short_name} ▾")
        self.profileChanged.emit(short_name)

    def _create_new_profile(self):
        name, ok = QInputDialog.getText(self, "New Profile", "Enter New Profile Name:")
        if ok and name.strip():
            self._set_profile(name.strip())

    def set_capture_state(self, state: str):
        """Sets the live engine capture state (IDLE, CAPTURING, FROZEN, PAUSED)."""
        self.capture_state = state.upper()
        is_dark = ThemeManager.is_dark()
        c = ThemeManager.instance().get_palette_colors()

        if self.capture_state == "CAPTURING":
            self.lbl_state.setText(" ● CAPTURING ")
            bg = "#0E8A58" if is_dark else "#DCFCE7"
            fg = "#FFFFFF" if is_dark else "#166534"
            border = "#14A86C" if is_dark else "#86EFAC"
            self.lbl_state.setStyleSheet(f"""
                background-color: {bg};
                color: {fg};
                border: 1px solid {border};
                border-radius: 3px;
                padding: 1px 6px;
            """)
        elif self.capture_state == "FROZEN":
            self.lbl_state.setText(" ● FROZEN ")
            bg = "#C0392B" if is_dark else "#FEE2E2"
            fg = "#FFFFFF" if is_dark else "#991B1B"
            border = "#E74C3C" if is_dark else "#FCA5A5"
            self.lbl_state.setStyleSheet(f"""
                background-color: {bg};
                color: {fg};
                border: 1px solid {border};
                border-radius: 3px;
                padding: 1px 6px;
            """)
        elif self.capture_state == "PAUSED":
            self.lbl_state.setText(" ● PAUSED ")
            bg = "#D35400" if is_dark else "#FEF3C7"
            fg = "#FFFFFF" if is_dark else "#92400E"
            border = "#E67E22" if is_dark else "#FCD34D"
            self.lbl_state.setStyleSheet(f"""
                background-color: {bg};
                color: {fg};
                border: 1px solid {border};
                border-radius: 3px;
                padding: 1px 6px;
            """)
        else:
            self.lbl_state.setText(" ● IDLE ")
            bg = "#121E24" if is_dark else "#F1F5F9"
            fg = "#8A9EA4" if is_dark else "#475569"
            border = "#1E333D" if is_dark else "#CBD5E1"
            self.lbl_state.setStyleSheet(f"""
                background-color: {bg};
                color: {fg};
                border: 1px solid {border};
                border-radius: 3px;
                padding: 1px 6px;
            """)

    def set_status_message(self, text: str, is_error: bool = False):
        colors = ThemeManager.instance().get_palette_colors()
        fg = colors["accent_danger"] if is_error else colors["fg_text"]
        self.lbl_message.setStyleSheet(f"color: {fg}; font-size: 8pt;")
        self.lbl_message.setText(text)

    def update_stats(self, total: int, displayed: int, threats: int = 0, eps: float = 0.0, dropped: int = 0, buffer_pct: float = 0.1):
        self.total_events = total
        self.displayed_events = displayed
        self.threat_count = threats
        self.eps = eps
        self.dropped_events = dropped
        self.buffer_pct = buffer_pct

        pct = (displayed / total * 100.0) if total > 0 else 100.0

        self.btn_events.setText(f"Events: {total:,}  Displayed: {displayed:,} ({pct:.1f}%)")
        self.lbl_eps.setText(f"{eps:.1f} evt/s")
        self.lbl_buffer.setText(f"RingBuffer: {buffer_pct:.1f}%")

        if threats > 0:
            self.btn_threats.setText(f"Threats: {threats:,} [HIGH]")
            self.btn_threats.setStyleSheet("color: #FFFFFF; background-color: #C0392B; border-radius: 2px; padding: 1px 6px; font-weight: bold;")
        else:
            c = ThemeManager.instance().get_palette_colors()
            self.btn_threats.setText("Threats: 0")
            self.btn_threats.setStyleSheet(f"color: {c['accent_success']}; padding: 0 4px; font-weight: bold; background: transparent; border: none;")

    def _show_context_menu(self, pos):
        menu = QMenu(self)

        lbl_menu = menu.addAction("Status Bar Observability Panels:")
        lbl_menu.setEnabled(False)
        menu.addSeparator()

        act_eps = menu.addAction("Show Ingestion Rate (EPS)")
        act_eps.setCheckable(True)
        act_eps.setChecked(self.panel_throughput.isVisible())
        act_eps.toggled.connect(lambda v: self._toggle_panel("show_throughput", self.panel_throughput, v))

        act_evts = menu.addAction("Show Event & Filter Counters")
        act_evts.setCheckable(True)
        act_evts.setChecked(self.panel_events.isVisible())
        act_evts.toggled.connect(lambda v: self._toggle_panel("show_events", self.panel_events, v))

        act_threats = menu.addAction("Show Security Threats Alert Panel")
        act_threats.setCheckable(True)
        act_threats.setChecked(self.panel_threats.isVisible())
        act_threats.toggled.connect(lambda v: self._toggle_panel("show_threats", self.panel_threats, v))

        act_buf = menu.addAction("Show eBPF RingBuffer Health")
        act_buf.setCheckable(True)
        act_buf.setChecked(self.panel_buffer.isVisible())
        act_buf.toggled.connect(lambda v: self._toggle_panel("show_buffer", self.panel_buffer, v))

        act_time = menu.addAction("Show Time Format Selector")
        act_time.setCheckable(True)
        act_time.setChecked(self.panel_time.isVisible())
        act_time.toggled.connect(lambda v: self._toggle_panel("show_time_format", self.panel_time, v))

        act_prof = menu.addAction("Show Active Profile Selector")
        act_prof.setCheckable(True)
        act_prof.setChecked(self.panel_profile.isVisible())
        act_prof.toggled.connect(lambda v: self._toggle_panel("show_profile", self.panel_profile, v))

        menu.addSeparator()
        act_reset = menu.addAction("Reset Status Bar Preferences to Default")
        act_reset.triggered.connect(self._reset_preferences)

        menu.exec(QCursor.pos())

    def _toggle_panel(self, key: str, panel: QWidget, visible: bool):
        panel.setVisible(visible)
        self.settings.setValue(key, visible)

    def _load_preferences(self):
        self.panel_throughput.setVisible(self.settings.value("show_throughput", True, type=bool))
        self.panel_events.setVisible(self.settings.value("show_events", True, type=bool))
        self.panel_threats.setVisible(self.settings.value("show_threats", True, type=bool))
        self.panel_buffer.setVisible(self.settings.value("show_buffer", True, type=bool))
        self.panel_time.setVisible(self.settings.value("show_time_format", True, type=bool))
        self.panel_profile.setVisible(self.settings.value("show_profile", True, type=bool))

    def _reset_preferences(self):
        for k, v in self.DEFAULT_PANEL_VISIBILITY.items():
            self.settings.setValue(k, v)
        self._load_preferences()

    def _apply_theme(self):
        c = ThemeManager.instance().get_palette_colors()
        is_dark = ThemeManager.is_dark()
        self.setStyleSheet(f"""
            QStatusBar#ksharkStatusBar {{
                background-color: {c['bg_window']};
                color: {c['fg_text']};
                border-top: 1px solid {c['border']};
            }}
        """)

        panel_bg = "#121E24" if is_dark else "#FFFFFF"
        panel_border = c["border"]
        panel_hover_border = c["brand_primary"]

        panel_qss = f"""
            QFrame#statusPanel {{
                background-color: {panel_bg};
                border: 1px solid {panel_border};
                border-radius: 3px;
                margin: 2px 2px;
                padding: 0 4px;
            }}
            QFrame#statusPanel:hover {{
                border-color: {panel_hover_border};
            }}
        """
        for p in (self.panel_throughput, self.panel_events, self.panel_threats, self.panel_buffer, self.panel_time, self.panel_profile):
            p.setStyleSheet(panel_qss)

        self.btn_events.setStyleSheet(f"color: {c['fg_text']}; padding: 0 4px; background: transparent; border: none;")
        self.lbl_eps.setStyleSheet(f"color: {c['brand_primary']}; font-weight: bold;")
        self.lbl_buffer.setStyleSheet(f"color: {c['fg_muted']};")
        self.btn_time.setStyleSheet(f"color: {c['fg_text']}; padding: 0 4px; background: transparent; border: none;")
        self.btn_profile.setStyleSheet(f"color: {c['brand_primary']}; padding: 0 4px; font-weight: bold; background: transparent; border: none;")
        self.set_capture_state(self.capture_state)
        self.set_status_message(self.lbl_message.text())
