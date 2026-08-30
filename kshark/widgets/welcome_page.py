"""
KShark Welcome Page — Modeled after Wireshark's landing page.
Minimal, monochromatic, information-dense. No decorative elements.
Single accent color used sparingly for interactive affordances only.
"""

import os
import platform
import subprocess
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QScrollArea, QFrame, QTableWidget, QTableWidgetItem,
    QHeaderView, QComboBox,
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt, pyqtSignal, QSettings

from kshark.core.theme import ThemeManager, get_ui_font, get_monospace_font
from kshark.resources.icons import KSharkIcons

# ---------------------------------------------------------------------------
# Palette — exactly two shades of one hue, plus neutral grays.
# ---------------------------------------------------------------------------
_ACCENT = "#2BC1CF"          # interactive elements only (links, active button)
_BG_PAGE = "transparent"
_BG_SECTION = "#0D1519"
_BG_INPUT = "#080D10"
_BORDER = "#1A2830"
_FG = "#C8D6DA"              # primary text
_FG_DIM = "#6E8088"          # secondary / labels
_FG_BRIGHT = "#E0ECEF"       # headings
_GREEN_BTN = "#117A4E"
_GREEN_BTN_HOVER = "#14925E"
_GREEN_BTN_BORDER = "#18A86A"


def _separator(parent) -> QFrame:
    """Thin horizontal rule."""
    line = QFrame(parent)
    line.setFrameShape(QFrame.Shape.HLine)
    line.setStyleSheet(f"color: {_BORDER};")
    line.setFixedHeight(1)
    return line


def _section_label(text: str, parent) -> QLabel:
    lbl = QLabel(text, parent)
    lbl.setFont(get_ui_font(size=9, bold=True))
    lbl.setStyleSheet(f"color: {_FG_DIM}; padding: 0; margin: 0;")
    return lbl


class WelcomePage(QWidget):
    """
    KShark landing page.

    Layout mirrors Wireshark: header → capture controls → filter →
    scenario table → system info table → footer links.
    Everything in a single scrollable column, no multi-column card grids,
    no colored accent borders, no emojis, no decorative frills.
    """

    startCaptureRequested = pyqtSignal()
    startCaptureOnProbe = pyqtSignal(str)
    openFileRequested = pyqtSignal()
    openRecentFile = pyqtSignal(str)
    configureCaptureRequested = pyqtSignal()
    launchScenarioRequested = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = QSettings("KShark", "WelcomePage")
        self._action_buttons = []
        self._scenario_buttons = []
        self._separators = []
        self._section_labels = []
        self._footer_buttons = []
        self._build()
        ThemeManager.instance().themeChanged.connect(self._apply_theme)
        self._apply_theme()

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------
    def _build(self):
        self.scroll = QScrollArea(self)
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setStyleSheet("QScrollArea{border:none;background:transparent;}")

        self.page = QWidget()
        root = QVBoxLayout(self.page)
        root.setContentsMargins(56, 40, 56, 32)
        root.setSpacing(0)

        # ── Header ──
        self.lbl_title = QLabel("KShark", self)
        self.lbl_title.setFont(get_ui_font(size=18, bold=True))
        root.addWidget(self.lbl_title)

        self.lbl_sub = QLabel(
            "Linux Kernel eBPF Security Telemetry & Forensic Analysis",
            self,
        )
        self.lbl_sub.setFont(get_ui_font(size=9))
        root.addWidget(self.lbl_sub)
        root.addSpacing(28)

        # ── Capture Controls ──
        lbl_cap = self._create_section_label("Capture")
        root.addWidget(lbl_cap)
        root.addSpacing(10)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        self.btn_start = self._action_btn("Start Live Capture", primary=True)
        self.btn_start.setIcon(KSharkIcons.capture_start())
        self.btn_start.clicked.connect(self._on_start_capture)
        btn_row.addWidget(self.btn_start)

        self.btn_open = self._action_btn("Open File…")
        self.btn_open.setIcon(KSharkIcons.file_open())
        self.btn_open.clicked.connect(self.openFileRequested.emit)
        btn_row.addWidget(self.btn_open)

        self.btn_cfg = self._action_btn("Capture Options…")
        self.btn_cfg.setIcon(KSharkIcons.capture_options())
        self.btn_cfg.clicked.connect(self.configureCaptureRequested.emit)
        btn_row.addWidget(self.btn_cfg)

        btn_row.addStretch(1)
        root.addLayout(btn_row)
        root.addSpacing(14)

        # ── Capture filter ──
        flt_row = QHBoxLayout()
        flt_row.setSpacing(6)

        self.lbl_flt = QLabel("using this filter:", self)
        self.lbl_flt.setFont(get_ui_font(size=8))
        flt_row.addWidget(self.lbl_flt)

        self.filter_input = QLineEdit(self)
        self.filter_input.setPlaceholderText(
            "e.g.  threat.name != \"BENIGN\"  or  user.uid == 0"
        )
        self.filter_input.setFont(get_monospace_font(size=8.5))
        self.filter_input.setFixedHeight(26)
        self.filter_input.returnPressed.connect(self._on_start_capture)
        flt_row.addWidget(self.filter_input, stretch=1)

        self.combo_presets = QComboBox(self)
        self.combo_presets.setFont(get_ui_font(size=8))
        self.combo_presets.setFixedHeight(26)
        self.combo_presets.addItems([
            "Preset: All Telemetry",
            "Preset: Threat Detections",
            "Preset: Outbound Sockets",
            "Preset: Root Operations (UID 0)",
            "Preset: Process Executions",
            "Preset: Filesystem Modifications",
        ])
        self.combo_presets.currentIndexChanged.connect(self._on_preset)
        flt_row.addWidget(self.combo_presets)

        root.addLayout(flt_row)
        root.addSpacing(28)
        sep1 = self._create_separator()
        root.addWidget(sep1)
        root.addSpacing(22)

        # ── Threat Hunting Scenarios ──
        lbl_scen = self._create_section_label("Forensic Triage Scenarios")
        root.addWidget(lbl_scen)
        root.addSpacing(10)

        self.tbl_scenarios = self._build_scenario_table()
        root.addWidget(self.tbl_scenarios)
        root.addSpacing(28)
        sep2 = self._create_separator()
        root.addWidget(sep2)
        root.addSpacing(22)

        # ── System & Kernel Info ──
        lbl_sys = self._create_section_label("System")
        root.addWidget(lbl_sys)
        root.addSpacing(10)

        self.tbl_system = self._build_system_table()
        root.addWidget(self.tbl_system)
        root.addSpacing(28)
        sep3 = self._create_separator()
        root.addWidget(sep3)
        root.addSpacing(16)

        # ── Footer links ──
        foot = QHBoxLayout()
        foot.setSpacing(16)

        for text in [
            "MITRE ATT&&CK Reference",
            "eBPF Probe Documentation",
            "ML Engine Details",
            "Incident Response Playbooks",
        ]:
            btn = QPushButton(text, self)
            btn.setFont(get_ui_font(size=7.5))
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self._footer_buttons.append(btn)
            foot.addWidget(btn)
        foot.addStretch(1)

        root.addLayout(foot)
        root.addStretch(1)

        self.scroll.setWidget(self.page)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self.scroll)

    def _create_separator(self) -> QFrame:
        line = QFrame(self)
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFixedHeight(1)
        self._separators.append(line)
        return line

    def _create_section_label(self, text: str) -> QLabel:
        lbl = QLabel(text, self)
        lbl.setFont(get_ui_font(size=9, bold=True))
        self._section_labels.append(lbl)
        return lbl

    # ------------------------------------------------------------------
    # Scenario table
    # ------------------------------------------------------------------
    def _build_scenario_table(self) -> QTableWidget:
        tbl = self._base_table(cols=3, headers=["Scenario", "Description", ""])
        tbl.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        tbl.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        tbl.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Fixed
        )
        tbl.horizontalHeader().resizeSection(2, 90)

        scenarios = [
            (
                "Threat & Anomaly Hunting",
                "Dual ML consensus (RF + XGBoost), Falco behavioral rules, MITRE ATT&CK categorization across all kernel probes.",
                'threat.name != "BENIGN"',
            ),
            (
                "Network C2 & Egress Triage",
                "TCP/UDP socket lifecycle, DNS queries, non-standard port listeners, and TLS handshake inspection.",
                'evt.type in ("socket","connect","sendto","recvfrom","bind","listen")',
            ),
            (
                "Process & Privilege Escalation",
                "Execution lineage, SUID/sudo transitions, namespace unshares, and interactive shell spawns.",
                'evt.type == "execve" or user.uid == 0',
            ),
            (
                "Filesystem Integrity Monitor",
                "High-entropy write bursts, sensitive path access (/etc/shadow, /etc/passwd), and mass file deletions.",
                'evt.type in ("write","openat","unlink","rename")',
            ),
        ]

        tbl.setRowCount(len(scenarios))
        for row, (name, desc, expr) in enumerate(scenarios):
            it_name = QTableWidgetItem(name)
            it_name.setFont(get_ui_font(size=8, bold=True))
            it_desc = QTableWidgetItem(desc)
            for it in (it_name, it_desc):
                it.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            tbl.setItem(row, 0, it_name)
            tbl.setItem(row, 1, it_desc)

            btn = QPushButton("Launch")
            btn.setFont(get_ui_font(size=8, bold=True))
            btn.setFixedHeight(22)
            btn.setFixedWidth(72)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(
                lambda checked, n=name, e=expr: self.launchScenarioRequested.emit(n, e)
            )
            self._scenario_buttons.append(btn)

            cell_widget = QWidget()
            cell_layout = QHBoxLayout(cell_widget)
            cell_layout.setContentsMargins(4, 2, 8, 2)
            cell_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cell_layout.addWidget(btn)
            tbl.setCellWidget(row, 2, cell_widget)

        tbl.setFixedHeight(len(scenarios) * 34 + 32)
        return tbl

    # ------------------------------------------------------------------
    # System info table
    # ------------------------------------------------------------------
    def _build_system_table(self) -> QTableWidget:
        tbl = self._base_table(cols=2, headers=["Property", "Value"])
        tbl.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        tbl.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )

        is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        k_rel = platform.release()
        arch = platform.machine()

        # Detect eBPF/BTF availability
        btf_path = Path("/sys/kernel/btf/vmlinux")
        btf_status = "Available" if btf_path.exists() else "Not found"

        # Detect JIT
        jit_status = "Unknown"
        jit_path = Path("/proc/sys/net/core/bpf_jit_enable")
        if jit_path.exists():
            try:
                val = jit_path.read_text().strip()
                jit_status = "Enabled" if val in ("1", "2") else "Disabled"
            except PermissionError:
                jit_status = "Permission denied"

        rows = [
            ("Kernel",            f"Linux {k_rel} ({arch})"),
            ("eBPF BTF (CO-RE)",  btf_status),
            ("BPF JIT Compiler",  jit_status),
            ("Security Context",  "Root (UID 0)" if is_root else f"User (UID {os.getuid()})"),
            ("Threat Engine",     "Random Forest + XGBoost + Isolation Forest consensus"),
            ("Storage Backend",   "Embedded DuckDB (columnar)"),
        ]

        tbl.setRowCount(len(rows))
        for r, (prop, val) in enumerate(rows):
            it_p = QTableWidgetItem(prop)
            it_p.setFont(get_ui_font(size=8))
            it_v = QTableWidgetItem(val)
            it_v.setFont(get_monospace_font(size=8))
            for it in (it_p, it_v):
                it.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            tbl.setItem(r, 0, it_p)
            tbl.setItem(r, 1, it_v)

        tbl.setFixedHeight(len(rows) * 34 + 32)
        return tbl

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _base_table(self, cols: int, headers: list[str]) -> QTableWidget:
        tbl = QTableWidget(self)
        tbl.setColumnCount(cols)
        tbl.setHorizontalHeaderLabels(headers)
        tbl.verticalHeader().setVisible(False)
        tbl.verticalHeader().setDefaultSectionSize(34)
        tbl.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        tbl.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        tbl.setAlternatingRowColors(True)
        tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        tbl.setShowGrid(False)
        tbl.setFont(get_ui_font(size=8))
        return tbl

    def _action_btn(self, text: str, primary: bool = False) -> QPushButton:
        btn = QPushButton(text, self)
        btn.setFont(get_ui_font(size=8.5, bold=primary))
        btn.setFixedHeight(30)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._action_buttons.append((btn, primary))
        return btn

    def _on_preset(self, idx: int):
        presets = [
            "",
            'threat.name != "BENIGN"',
            'net.port in (4444, 1337, 8080, 9001)',
            'user.uid == 0',
            'evt.type == "execve"',
            'evt.type in ("openat", "write", "unlink", "rename", "chmod")',
        ]
        if 0 <= idx < len(presets):
            self.filter_input.setText(presets[idx])

    def _on_start_capture(self):
        f = self.filter_input.text().strip()
        if f:
            self.launchScenarioRequested.emit("Custom Capture", f)
        else:
            self.startCaptureRequested.emit()

    def _apply_theme(self):
        c = ThemeManager.instance().get_palette_colors()
        is_dark = ThemeManager.is_dark()

        # Update Page Background
        self.setStyleSheet(f"background-color: {c['bg_window']};")
        self.page.setStyleSheet(f"background-color: {c['bg_window']};")

        # Header Titles
        self.lbl_title.setStyleSheet(f"color: {c['fg_text']}; background: transparent;")
        self.lbl_sub.setStyleSheet(f"color: {c['fg_muted']}; background: transparent;")
        self.lbl_flt.setStyleSheet(f"color: {c['fg_muted']}; background: transparent;")

        # Separators
        for sep in self._separators:
            sep.setStyleSheet(f"background-color: {c['border']};")

        # Section Labels
        for lbl in self._section_labels:
            lbl.setStyleSheet(f"color: {c['fg_muted']}; background: transparent;")

        # Action Buttons
        for btn, primary in self._action_buttons:
            if primary:
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background: {c['green_btn']};
                        border: 1px solid {c['green_btn_border']};
                        border-radius: 3px;
                        color: #FFFFFF;
                        padding: 3px 16px;
                    }}
                    QPushButton:hover {{
                        background: {c['green_btn_hover']};
                    }}
                    QPushButton:pressed {{
                        background: #0D6640;
                    }}
                """)
            else:
                btn_bg = "#182428" if is_dark else "#FFFFFF"
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background: {btn_bg};
                        border: 1px solid {c['border']};
                        border-radius: 3px;
                        color: {c['fg_text']};
                        padding: 3px 14px;
                    }}
                    QPushButton:hover {{
                        background: {c['bg_alt']};
                        border-color: {c['brand_primary']};
                        color: {c['brand_primary']};
                    }}
                """)

        # Filter Input & Preset Dropdown
        input_bg = "#111618" if is_dark else "#FFFFFF"
        self.filter_input.setStyleSheet(f"""
            QLineEdit {{
                background: {input_bg};
                border: 1px solid {c['border']};
                border-radius: 3px;
                color: {c['fg_text']};
                padding: 2px 8px;
            }}
            QLineEdit:focus {{
                border-color: {c['brand_primary']};
            }}
        """)
        self.combo_presets.setStyleSheet(f"""
            QComboBox {{
                background: {input_bg};
                border: 1px solid {c['border']};
                border-radius: 3px;
                color: {c['fg_text']};
                padding: 2px 8px;
            }}
            QComboBox:focus {{
                border-color: {c['brand_primary']};
            }}
        """)

        # Table Styling
        tbl_qss = f"""
            QTableWidget {{
                background-color: {c['bg_base']};
                alternate-background-color: {c['bg_alt']};
                border: 1px solid {c['border']};
                border-radius: 3px;
                color: {c['fg_text']};
                gridline-color: transparent;
            }}
            QHeaderView::section {{
                background-color: {c['bg_window']};
                color: {c['fg_muted']};
                border: none;
                border-bottom: 1px solid {c['border']};
                padding: 4px 8px;
                font-weight: bold;
            }}
            QTableWidget::item {{
                padding: 3px 8px;
                color: {c['fg_text']};
            }}
            QTableWidget::item:selected {{
                background-color: {c['selection_bg']};
                color: {c['selection_fg']};
            }}
        """
        self.tbl_scenarios.setStyleSheet(tbl_qss)
        self.tbl_system.setStyleSheet(tbl_qss)

        # Scenario Launch Buttons
        scen_btn_bg = "#102229" if is_dark else "#E0F2FE"
        scen_btn_fg = "#2BC1CF" if is_dark else "#0369A1"
        scen_btn_border = "#1E333D" if is_dark else "#BAE6FD"
        for btn in self._scenario_buttons:
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: {scen_btn_bg};
                    border: 1px solid {scen_btn_border};
                    border-radius: 2px;
                    color: {scen_btn_fg};
                    padding: 1px 6px;
                }}
                QPushButton:hover {{
                    background: {c['brand_primary']};
                    color: #FFFFFF;
                    border-color: {c['brand_primary']};
                }}
            """)

        # Footer Buttons
        for btn in self._footer_buttons:
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    color: {c['brand_primary']};
                    border: none;
                    padding: 0;
                }}
                QPushButton:hover {{
                    color: {c['brand_deep'] if not is_dark else '#FFFFFF'};
                    text-decoration: underline;
                }}
            """)
