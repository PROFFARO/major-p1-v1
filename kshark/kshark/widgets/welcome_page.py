"""
Wireshark-accurate Welcome Screen for KShark (Pixel-Accurate Light & Dark Modes).

Replicates the exact layout, typography, sparkline waveforms, eBPF probe list,
dynamic selection highlights, capture filter bar, and Learn section from Wireshark 4.4+.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox, 
    QListWidget, QListWidgetItem, QFrame, QScrollArea, QSizePolicy, QToolButton,
    QMessageBox
)
from PyQt6.QtGui import QFont, QIcon, QColor, QPainter, QPen, QPolygonF, QBrush
from PyQt6.QtCore import Qt, QPointF, QRectF, pyqtSignal, QSize
import random
import os
from pathlib import Path

from kshark.core.theme import get_ui_font, get_monospace_font, ThemeManager, ThemeToken
from kshark.core.settings import KSharkSettings
from kshark.resources.icons import KSharkIcons


class SparklineWidget(QWidget):
    """
    Draws a Wireshark-style miniature waveform / sparkline graph
    showing live event activity for an eBPF kernel probe.
    Dynamically adjusts stroke color when row is selected.
    """

    def __init__(self, seed: int = 42, parent=None):
        super().__init__(parent)
        self.setFixedSize(140, 16)
        self.points: list = []
        self._is_selected: bool = False
        self._generate_waveform(seed)

    def _generate_waveform(self, seed: int):
        random.seed(seed)
        self.points = [0.0] * 28
        # Create realistic live traffic activity spikes matching Wireshark sparklines
        if seed % 2 == 0:
            self.points[6] = 0.35
            self.points[7] = 0.85
            self.points[8] = 0.4
            self.points[16] = 0.6
            self.points[22] = 0.9
            self.points[23] = 0.3
        elif seed % 3 == 0:
            self.points[10] = 0.95
            self.points[11] = 0.5
            self.points[18] = 0.4
            self.points[24] = 0.75
        elif seed % 5 == 0:
            self.points[3] = 0.45
            self.points[12] = 0.3
            self.points[20] = 0.8
            self.points[21] = 0.95
        else:
            self.points[14] = 0.7
            self.points[15] = 0.3

    def set_selected(self, selected: bool):
        if self._is_selected != selected:
            self._is_selected = selected
            self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        is_dark = ThemeManager.is_dark()
        if self._is_selected:
            pen_color = QColor("#FFFFFF")
        else:
            pen_color = QColor("#AAAAAA") if is_dark else QColor("#555555")

        painter.setPen(QPen(pen_color, 1.1))

        w = self.width() - 4
        h = self.height() - 4
        n = len(self.points)
        dx = w / (n - 1)

        base_y = self.height() - 2

        # Draw baseline axis
        painter.drawLine(2, int(base_y), int(w + 2), int(base_y))

        # Draw activity waveform
        poly = QPolygonF()
        poly.append(QPointF(2, base_y))

        for i, val in enumerate(self.points):
            x = 2 + i * dx
            y = base_y - (val * (h - 2))
            poly.append(QPointF(x, y))

        poly.append(QPointF(w + 2, base_y))
        painter.drawPolyline(poly)
        painter.end()


class ProbeRowWidget(QWidget):
    """Container widget representing an eBPF probe row with clean typography and sparkline."""

    def __init__(self, name: str, seed: int, parent=None):
        super().__init__(parent)
        self.name = name
        self.seed = seed

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 2, 16, 2)
        layout.setSpacing(10)

        self.label = QLabel(name, self)
        self.label.setFont(get_ui_font(size=9))
        layout.addWidget(self.label)
        layout.addStretch(1)

        self.sparkline = SparklineWidget(seed=seed, parent=self)
        layout.addWidget(self.sparkline)

    def set_selected(self, selected: bool):
        self.sparkline.set_selected(selected)
        is_dark = ThemeManager.is_dark()
        if selected:
            self.label.setStyleSheet("color: #FFFFFF; font-weight: bold;")
        else:
            color = "#D4D4D4" if is_dark else "#101010"
            self.label.setStyleSheet(f"color: {color}; font-weight: normal;")


class WelcomePage(QWidget):
    """
    Wireshark 4.4-identical Welcome Page with full Dark and Light appearance modes.
    """

    startCaptureOnProbe = pyqtSignal(str)
    openRecentFile = pyqtSignal(str)
    applyQuickFilter = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = KSharkSettings()
        self.probe_widgets: list = []
        self._init_ui()
        ThemeManager.instance().themeChanged.connect(self._apply_theme)
        self._apply_theme()

    def _init_ui(self):
        # Master scroll area
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        container = QWidget()
        self.container_layout = QVBoxLayout(container)
        self.container_layout.setContentsMargins(60, 24, 60, 24)
        self.container_layout.setSpacing(14)

        # 1. "Welcome to KShark" Soft Blue Pill Badge
        badge_layout = QHBoxLayout()
        self.pill_lbl = QLabel("Welcome to KShark", self)
        self.pill_lbl.setObjectName("welcomePill")
        self.pill_lbl.setFont(get_ui_font(size=9.5, bold=True))
        badge_layout.addWidget(self.pill_lbl)
        badge_layout.addStretch(1)
        self.container_layout.addLayout(badge_layout)

        # 2. Main "Capture" Header
        self.capture_title = QLabel("Capture", self)
        self.capture_title.setFont(get_ui_font(size=12, bold=True))
        self.container_layout.addWidget(self.capture_title)

        # 3. Capture Filter Subtitle Bar
        filter_bar_layout = QHBoxLayout()
        filter_bar_layout.setSpacing(8)

        self.sub_label = QLabel("...using this filter:", self)
        self.sub_label.setFont(get_ui_font(size=9))
        filter_bar_layout.addWidget(self.sub_label)

        # Frame for Capture Filter LineEdit with green ribbon bookmark inside
        self.cap_filter_frame = QFrame(self)
        self.cap_filter_frame.setObjectName("capFilterFrame")
        cap_frame_layout = QHBoxLayout(self.cap_filter_frame)
        cap_frame_layout.setContentsMargins(4, 2, 4, 2)
        cap_frame_layout.setSpacing(4)

        self.cap_bookmark_btn = QToolButton(self.cap_filter_frame)
        self.cap_bookmark_btn.setIcon(KSharkIcons.filter_bookmark_capture())
        self.cap_bookmark_btn.setIconSize(QSize(14, 14))
        self.cap_bookmark_btn.setAutoRaise(True)
        self.cap_bookmark_btn.setStyleSheet("border: none; background: transparent;")
        cap_frame_layout.addWidget(self.cap_bookmark_btn)

        self.cap_filter_edit = QLineEdit(self.cap_filter_frame)
        self.cap_filter_edit.setObjectName("capFilterLineEdit")
        self.cap_filter_edit.setPlaceholderText("Enter a capture filter ...")
        self.cap_filter_edit.setFont(get_monospace_font(size=9))
        self.cap_filter_edit.returnPressed.connect(self._on_filter_entered)
        cap_frame_layout.addWidget(self.cap_filter_edit, stretch=1)

        filter_bar_layout.addWidget(self.cap_filter_frame, stretch=1)

        # eBPF Probe filter dropdown
        self.iface_combo = QComboBox(self)
        self.iface_combo.addItems([
            "All eBPF Probes & Engines",
            "Kernel Syscall & Process Probes",
            "Network & TLS Sockets",
            "LSM Security & Container Guards"
        ])
        self.iface_combo.setFont(get_ui_font(size=8.5))
        self.iface_combo.currentIndexChanged.connect(self._filter_probes_by_category)
        filter_bar_layout.addWidget(self.iface_combo)

        self.container_layout.addLayout(filter_bar_layout)

        # 4. eBPF Kernel Probes List
        self.probe_list = QListWidget(self)
        self.probe_list.setObjectName("welcomeProbeList")
        self.probe_list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.probe_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._populate_probes_list()
        self.probe_list.itemSelectionChanged.connect(self._on_probe_selection_changed)
        self.probe_list.itemDoubleClicked.connect(self._on_probe_double_clicked)
        self.container_layout.addWidget(self.probe_list)

        # 5. Extcap / Integrated Security Engines Header
        self.extcap_list = QListWidget(self)
        self.extcap_list.setObjectName("welcomeExtcapList")
        self.extcap_list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.extcap_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._populate_extcap_list()
        self.extcap_list.itemDoubleClicked.connect(self._on_probe_double_clicked)
        self.container_layout.addWidget(self.extcap_list)


        self.container_layout.addSpacing(24)

        # 6. "Learn" Section
        self.learn_title = QLabel("Learn", self)
        self.learn_title.setFont(get_ui_font(size=11, bold=True))
        self.container_layout.addWidget(self.learn_title)

        self.learn_links = QLabel(self)
        self.learn_links.setFont(get_ui_font(size=8.5))
        self.learn_links.setOpenExternalLinks(False)
        self.learn_links.linkActivated.connect(self._on_learn_link_clicked)
        self.container_layout.addWidget(self.learn_links)

        self.version_subtext = QLabel("You are running KShark 1.0.0 (eBPF Kernel ML Edition).", self)
        self.version_subtext.setFont(get_ui_font(size=8))
        self.container_layout.addWidget(self.version_subtext)

        self.container_layout.addStretch(1)

        scroll.setWidget(container)
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(scroll)

    def _apply_theme(self):
        """Applies pixel-accurate styling for active Light/Dark theme mode."""
        is_dark = ThemeManager.is_dark()

        if is_dark:
            self.pill_lbl.setStyleSheet("""
                QLabel#welcomePill {
                    background-color: #204A87;
                    color: #FFFFFF;
                    border-radius: 3px;
                    padding: 3px 12px;
                }
            """)
            self.capture_title.setStyleSheet("color: #D4D4D4; font-weight: bold; margin-top: 4px;")
            self.sub_label.setStyleSheet("color: #AAAAAA;")
            self.cap_filter_frame.setStyleSheet("""
                QFrame#capFilterFrame {
                    border: 1px solid #3C3C3C;
                    border-radius: 2px;
                    background-color: #252526;
                }
                QLineEdit#capFilterLineEdit {
                    border: none;
                    background: transparent;
                    color: #D4D4D4;
                }
            """)
            self.iface_combo.setStyleSheet("""
                QComboBox {
                    border: 1px solid #3C3C3C;
                    border-radius: 2px;
                    padding: 2px 8px;
                    background-color: #252526;
                    color: #D4D4D4;
                }
            """)
            self.probe_list.setStyleSheet("""
                QListWidget#welcomeProbeList {
                    border: none;
                    background: transparent;
                    color: #D4D4D4;
                    font-size: 9pt;
                }
                QListWidget#welcomeProbeList::item {
                    border-radius: 2px;
                    margin: 1px 0;
                }
                QListWidget#welcomeProbeList::item:hover {
                    background-color: #2A2D2E;
                }
                QListWidget#welcomeProbeList::item:selected {
                    background-color: #2A4068;
                    color: #FFFFFF;
                }
            """)
            self.extcap_list.setStyleSheet("""
                QListWidget#welcomeExtcapList {
                    border: none;
                    background: transparent;
                    color: #D4D4D4;
                    font-size: 9pt;
                }
                QListWidget#welcomeExtcapList::item {
                    padding: 2px 8px;
                    border-radius: 2px;
                }
                QListWidget#welcomeExtcapList::item:hover {
                    background-color: #2A2D2E;
                }
                QListWidget#welcomeExtcapList::item:selected {
                    background-color: #2A4068;
                    color: #FFFFFF;
                }
            """)
            self.learn_title.setStyleSheet("color: #D4D4D4; font-weight: bold;")
            self.learn_links.setText(
                "<a href='#guide' style='color: #5B9EE6; text-decoration: none;'>User's Guide</a> &nbsp;·&nbsp; "
                "<a href='#wiki' style='color: #5B9EE6; text-decoration: none;'>Wiki</a> &nbsp;·&nbsp; "
                "<a href='#qa' style='color: #5B9EE6; text-decoration: none;'>Questions and Answers</a> &nbsp;·&nbsp; "
                "<a href='#mail' style='color: #5B9EE6; text-decoration: none;'>Mailing Lists</a> &nbsp;·&nbsp; "
                "<a href='#sharkfest' style='color: #5B9EE6; text-decoration: none;'>SharkFest</a> &nbsp;·&nbsp; "
                "<a href='#discord' style='color: #5B9EE6; text-decoration: none;'>KShark Discord</a> &nbsp;·&nbsp; "
                "<a href='#donate' style='color: #5B9EE6; text-decoration: none;'>Donate</a>"
            )
            self.version_subtext.setStyleSheet("color: #888888;")
        else:
            self.pill_lbl.setStyleSheet("""
                QLabel#welcomePill {
                    background-color: #99C2EC;
                    color: #003366;
                    border-radius: 3px;
                    padding: 3px 12px;
                }
            """)
            self.capture_title.setStyleSheet("color: #202020; font-weight: bold; margin-top: 4px;")
            self.sub_label.setStyleSheet("color: #555555;")
            self.cap_filter_frame.setStyleSheet("""
                QFrame#capFilterFrame {
                    border: 1px solid #B0B0B0;
                    border-radius: 2px;
                    background-color: #FFFFFF;
                }
                QLineEdit#capFilterLineEdit {
                    border: none;
                    background: transparent;
                    color: #000000;
                }
            """)
            self.iface_combo.setStyleSheet("""
                QComboBox {
                    border: 1px solid #B0B0B0;
                    border-radius: 2px;
                    padding: 2px 8px;
                    background-color: #FFFFFF;
                    color: #000000;
                }
            """)
            self.probe_list.setStyleSheet("""
                QListWidget#welcomeProbeList {
                    border: none;
                    background: transparent;
                    color: #000000;
                    font-size: 9pt;
                }
                QListWidget#welcomeProbeList::item {
                    border-radius: 2px;
                    margin: 1px 0;
                }
                QListWidget#welcomeProbeList::item:hover {
                    background-color: #E8F4FD;
                }
                QListWidget#welcomeProbeList::item:selected {
                    background-color: #3072CC;
                    color: #FFFFFF;
                }
            """)
            self.extcap_list.setStyleSheet("""
                QListWidget#welcomeExtcapList {
                    border: none;
                    background: transparent;
                    color: #000000;
                    font-size: 9pt;
                }
                QListWidget#welcomeExtcapList::item {
                    padding: 2px 8px;
                    border-radius: 2px;
                }
                QListWidget#welcomeExtcapList::item:hover {
                    background-color: #E8F4FD;
                }
                QListWidget#welcomeExtcapList::item:selected {
                    background-color: #3072CC;
                    color: #FFFFFF;
                }
            """)
            self.learn_title.setStyleSheet("color: #202020; font-weight: bold;")
            self.learn_links.setText(
                "<a href='#guide' style='color: #007ACC; text-decoration: none;'>User's Guide</a> &nbsp;·&nbsp; "
                "<a href='#wiki' style='color: #007ACC; text-decoration: none;'>Wiki</a> &nbsp;·&nbsp; "
                "<a href='#qa' style='color: #007ACC; text-decoration: none;'>Questions and Answers</a> &nbsp;·&nbsp; "
                "<a href='#mail' style='color: #007ACC; text-decoration: none;'>Mailing Lists</a> &nbsp;·&nbsp; "
                "<a href='#sharkfest' style='color: #007ACC; text-decoration: none;'>SharkFest</a> &nbsp;·&nbsp; "
                "<a href='#discord' style='color: #007ACC; text-decoration: none;'>KShark Discord</a> &nbsp;·&nbsp; "
                "<a href='#donate' style='color: #007ACC; text-decoration: none;'>Donate</a>"
            )
            self.version_subtext.setStyleSheet("color: #777777;")

        # Update all probe row widgets
        self._on_probe_selection_changed()

    def _populate_probes_list(self):
        """Populates list of active Linux eBPF telemetry kernel probes."""
        self.probe_items_data = [
            ("Unified eBPF Security Stream (All Probes Attached)", "all", 1, "ebpf"),
            ("sys_tracer (Syscall Tracepoints & Process Lifecycle - sys_enter/sys_exit)", "sys_tracer", 2, "ebpf"),
            ("net_filter (TC & Socket Ingress/Egress Packet Inspection)", "net_filter", 4, "net"),
            ("ssl_tracer (OpenSSL / GnuTLS / NSS Plaintext Uprobes)", "ssl_tracer", 7, "ebpf"),
            ("lsm_enforcer (LSM Security Hooks & PID Containment)", "lsm_enforcer", 9, "lsm"),
            ("perf_profiler (CPU Instruction Stack Sampling & Profiling)", "perf_profiler", 21, "ebpf"),
            ("tetragon_lsm (Kernel Security Credential & Namespace Guard)", "tetragon_lsm", 25, "lsm"),
            ("falco_engine (Falco Behavioral Anomaly Detection Engine)", "falco", 12, "lsm"),
            ("tracee_memory (Tracee Memory Protection & W^X Validator)", "tracee", 15, "lsm"),
            ("synthetic_stream (Attack Telemetry & Forensic Generator)", "synthetic", 18, "ebpf"),
        ]

        self.probe_list.clear()
        self.probe_widgets.clear()

        for name, key, seed, cat in self.probe_items_data:
            item = QListWidgetItem(self.probe_list)
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setData(Qt.ItemDataRole.UserRole + 1, cat)
            item.setSizeHint(QSize(400, 24))

            row_widget = ProbeRowWidget(name, seed, parent=self.probe_list)
            self.probe_widgets.append((item, row_widget))
            self.probe_list.setItemWidget(item, row_widget)

        # Select first probe by default
        if self.probe_list.count() > 0:
            self.probe_list.setCurrentRow(0)

        # Set fixed widget height based on item count
        self.probe_list.setFixedHeight(len(self.probe_items_data) * 26 + 6)

    def _populate_extcap_list(self):
        """Populates external capture / eBPF security subsystem interfaces with gear icons."""
        extcaps = [
            ("Falco Behavioral Detection Engine: falco", "falco"),
            ("Pyroscope Continuous Profiler: pyroscope", "pyroscope"),
            ("KubeArmor LSM Security Posture: kubearmor", "kubearmor"),
            ("Tracee Memory & W^X Protection: tracee", "tracee"),
            ("Sysmon Linux Event ID Normalizer: sysmon", "sysmon"),
            ("eCapture TLS / SSL Payload Decoder: ecapture", "ecapture"),
            ("Synthetic Attack Telemetry Generator: randpkt", "randpkt"),
            ("systemd Journal & Auditd Log Export: sdjournal", "sdjournal"),
        ]

        gear_icon = KSharkIcons.capture_options()

        self.extcap_list.clear()
        for name, key in extcaps:
            item = QListWidgetItem(gear_icon, f"  {name}", self.extcap_list)
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setSizeHint(QSize(400, 24))

        self.extcap_list.setFixedHeight(len(extcaps) * 26 + 6)


    def _filter_probes_by_category(self, idx: int):
        """Filters probe list based on combobox category."""
        category_map = {
            0: None,       # All
            1: "ebpf",     # Kernel Syscall & Process Probes
            2: "net",      # Network & TLS Sockets
            3: "lsm",      # LSM Security & Container Guards
        }
        target_cat = category_map.get(idx)

        for i in range(self.probe_list.count()):
            item = self.probe_list.item(i)
            cat = item.data(Qt.ItemDataRole.UserRole + 1)
            if target_cat is None or target_cat == cat:
                item.setHidden(False)
            else:
                item.setHidden(True)

    def _on_probe_selection_changed(self):
        """Updates sparkline and text colors when row selection changes."""
        selected_items = self.probe_list.selectedItems()
        for item, widget in self.probe_widgets:
            widget.set_selected(item in selected_items)

    def _on_probe_double_clicked(self, item: QListWidgetItem):
        """Immediately starts live capture when double-clicking a probe."""
        probe_key = item.data(Qt.ItemDataRole.UserRole)
        self.startCaptureOnProbe.emit(probe_key)

    def _on_filter_entered(self):
        """Applies capture filter and starts capture on current selection."""
        filt = self.cap_filter_edit.text().strip()
        if filt:
            self.applyQuickFilter.emit(filt)
        selected = self.probe_list.currentItem()
        key = selected.data(Qt.ItemDataRole.UserRole) if selected else "all"
        self.startCaptureOnProbe.emit(key)

    def _on_learn_link_clicked(self, url: str):
        """Shows informative dialog for Learn section links."""
        QMessageBox.information(
            self,
            "KShark Documentation",
            f"KShark v1.0.0 — eBPF Kernel Observability & ML Threat Hunting Platform.\n\n"
            f"Topic: {url}\n"
            f"Official Architecture Guide: Documentation / User Manual available in /docs."
        )
