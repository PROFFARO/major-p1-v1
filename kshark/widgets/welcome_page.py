"""
KShark Welcome Page — System Call & eBPF Kernel Probes Capture Dashboard.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QLineEdit, QComboBox, QScrollArea, QFrame, QSizePolicy, QMessageBox
)
from PyQt6.QtGui import QPainter, QPen, QColor, QFont, QPolygonF
from PyQt6.QtCore import Qt, QPointF, pyqtSignal, QSize
import random

from kshark.core.theme import ThemeManager, get_ui_font, get_monospace_font
from kshark.core.settings import KSharkSettings
from kshark.resources.icons import KSharkIcons


class SparklineWidget(QWidget):
    """Mini sparkline graph showing live activity waveform."""

    def __init__(self, seed: int = 0, parent=None):
        super().__init__(parent)
        self.setFixedSize(50, 16)
        self._selected = False
        rng = random.Random(seed)
        self._points = [rng.randint(2, 14) for _ in range(8)]

    def set_selected(self, selected: bool):
        self._selected = selected
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        if self._selected:
            pen = QPen(QColor("#FFFFFF"), 1.4)
        else:
            is_dark = ThemeManager.is_dark()
            pen = QPen(QColor("#2BC1CF" if is_dark else "#0E9AA7"), 1.4)

        painter.setPen(pen)
        w = self.width()
        h = self.height()
        n = len(self._points)
        poly = QPolygonF()
        for i, val in enumerate(self._points):
            x = (i / (n - 1)) * (w - 4) + 2
            y = h - (val / 16.0) * (h - 4) - 2
            poly.append(QPointF(x, y))

        painter.drawPolyline(poly)
        painter.end()


class ProbeRowWidget(QWidget):
    """Container widget representing a probe row with clean typography and sparkline."""

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
            color = "#D8E8EC" if is_dark else "#102A30"
            self.label.setStyleSheet(f"color: {color}; font-weight: normal;")


class WelcomePage(QWidget):
    """
    KShark Official Welcome Page with full Dark and Light appearance modes.
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
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        container = QWidget()
        self.container_layout = QVBoxLayout(container)
        self.container_layout.setContentsMargins(60, 24, 60, 24)
        self.container_layout.setSpacing(8)

        # 1. Main Header
        self.title_label = QLabel("Capture", self)
        self.title_label.setFont(get_ui_font(size=14, bold=True))
        self.container_layout.addWidget(self.title_label)

        # 2. Capture Filter Sub-Header Bar
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(8)

        self.filter_hint = QLabel("...using this filter:", self)
        self.filter_hint.setFont(get_ui_font(size=9))
        filter_layout.addWidget(self.filter_hint)

        self.cap_filter_input = QLineEdit(self)
        self.cap_filter_input.setObjectName("welcomeCaptureFilterInput")
        self.cap_filter_input.setPlaceholderText("Enter a capture filter ...")
        self.cap_filter_input.setFont(get_monospace_font(size=9))
        filter_layout.addWidget(self.cap_filter_input, stretch=1)

        self.category_combo = QComboBox(self)
        self.category_combo.setObjectName("welcomeCategoryCombo")
        self.category_combo.addItems([
            "All eBPF Probes & Engines",
            "Kernel Syscall & Process Probes",
            "Network & TLS Sockets",
            "LSM Security & Container Guards"
        ])
        self.category_combo.currentIndexChanged.connect(self._filter_probes_by_category)
        filter_layout.addWidget(self.category_combo)

        self.container_layout.addLayout(filter_layout)
        self.container_layout.addSpacing(6)

        # 3. eBPF Probes List
        self.probe_list = QListWidget(self)
        self.probe_list.setObjectName("welcomeProbeList")
        self.probe_list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.probe_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._populate_probes_list()
        self.probe_list.itemSelectionChanged.connect(self._on_probe_selection_changed)
        self.probe_list.itemDoubleClicked.connect(self._on_probe_double_clicked)
        self.container_layout.addWidget(self.probe_list)

        # 4. Extcap Engines Header
        self.extcap_list = QListWidget(self)
        self.extcap_list.setObjectName("welcomeExtcapList")
        self.extcap_list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.extcap_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._populate_extcap_list()
        self.extcap_list.itemDoubleClicked.connect(self._on_probe_double_clicked)
        self.container_layout.addWidget(self.extcap_list)

        self.container_layout.addSpacing(24)

        # 5. "Learn" Section
        self.learn_title = QLabel("Learn", self)
        self.learn_title.setFont(get_ui_font(size=14, bold=True))
        self.container_layout.addWidget(self.learn_title)

        learn_links = [
            ("User's Guide", "kshark://guide", "How to capture, filter, and dissect Linux system calls & container activity"),
            ("eBPF Probes Reference", "kshark://probes", "Understanding tracepoints, TC ingress/egress, SSL uprobes, and LSM hooks"),
            ("ML Threat Detection Engine", "kshark://ml", "Dual XGBoost + PyTorch behavioral model consensus architecture"),
            ("Security Copilot Reference", "kshark://copilot", "Interacting with the local LLM Security Analyst in real-time"),
        ]

        for title, uri, desc in learn_links:
            row = QHBoxLayout()
            link_lbl = QLabel(f'<a href="{uri}" style="text-decoration: none; color: #0E9AA7; font-weight: bold;">{title}</a>')
            link_lbl.setOpenExternalLinks(False)
            link_lbl.linkActivated.connect(self._on_learn_link_clicked)
            desc_lbl = QLabel(f"— {desc}")
            desc_lbl.setStyleSheet("color: #8A9EA4;")
            row.addWidget(link_lbl)
            row.addWidget(desc_lbl)
            row.addStretch(1)
            self.container_layout.addLayout(row)

        self.container_layout.addStretch(1)
        scroll.setWidget(container)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(scroll)

    def _populate_probes_list(self):
        self.probe_items_data = [
            ("Unified eBPF Security Stream (All Probes Attached)", "all", 101),
            ("sys_tracer (Syscall Tracepoints & Process Lifecycle - sys_enter/sys_exit)", "sys_tracer", 102),
            ("net_filter (TC & Socket Ingress/Egress Packet Inspection)", "net_filter", 103),
            ("ssl_tracer (OpenSSL / GnuTLS / NSS Plaintext Uprobes)", "ssl_tracer", 104),
            ("lsm_enforcer (LSM Security Hooks & PID Containment)", "lsm_enforcer", 105),
            ("perf_profiler (CPU Instruction Stack Sampling & Profiling)", "perf_profiler", 106),
            ("tetragon_lsm (Kernel Security Credential & Namespace Guard)", "tetragon_lsm", 107),
            ("falco_engine (Falco Behavioral Anomaly Detection Engine)", "falco_engine", 108),
            ("tracee_memory (Tracee Memory Protection & W^X Validator)", "tracee_memory", 109),
            ("synthetic_stream (Attack Telemetry & Forensic Generator)", "synthetic_stream", 110),
        ]

        self.probe_list.clear()
        self.probe_widgets.clear()

        for name, key, seed in self.probe_items_data:
            item = QListWidgetItem(self.probe_list)
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setSizeHint(QSize(400, 24))

            widget = ProbeRowWidget(name, seed, self.probe_list)
            self.probe_list.setItemWidget(item, widget)
            self.probe_widgets.append((item, widget))

        if self.probe_list.count() > 0:
            self.probe_list.setCurrentRow(0)

        self.probe_list.setFixedHeight(len(self.probe_items_data) * 26 + 6)

    def _populate_extcap_list(self):
        extcaps = [
            ("Falco Behavioral Detection Engine: falco", "falco"),
            ("Pyroscope Continuous Profiler: pyroscope", "pyroscope"),
            ("KubeArmor LSM Security Posture: kubearmor", "kubearmor"),
            ("Tracee Memory & W^X Protection: tracee", "tracee"),
            ("Sysmon Linux Event ID Normalizer: sysmon", "sysmon"),
            ("eCapture TLS / SSL Payload Decoder: ecapture", "ecapture"),
        ]

        gear_icon = KSharkIcons.capture_options()

        self.extcap_list.clear()
        for name, key in extcaps:
            item = QListWidgetItem(gear_icon, f"  {name}", self.extcap_list)
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setSizeHint(QSize(400, 24))

        self.extcap_list.setFixedHeight(len(extcaps) * 26 + 6)

    def _filter_probes_by_category(self, idx: int):
        category_map = {
            0: ["all", "sys_tracer", "net_filter", "ssl_tracer", "lsm_enforcer", "perf_profiler", "tetragon_lsm", "falco_engine", "tracee_memory", "synthetic_stream"],
            1: ["all", "sys_tracer", "perf_profiler", "synthetic_stream"],
            2: ["all", "net_filter", "ssl_tracer"],
            3: ["all", "lsm_enforcer", "tetragon_lsm", "falco_engine", "tracee_memory"],
        }
        allowed = category_map.get(idx, [])
        for item, widget in self.probe_widgets:
            key = item.data(Qt.ItemDataRole.UserRole)
            item.setHidden(key not in allowed)

    def _on_probe_selection_changed(self):
        current_item = self.probe_list.currentItem()
        for item, widget in self.probe_widgets:
            widget.set_selected(item == current_item)

    def _on_probe_double_clicked(self, item: QListWidgetItem):
        key = item.data(Qt.ItemDataRole.UserRole) or "all"
        self.startCaptureOnProbe.emit(key)

    def _on_learn_link_clicked(self, url_str: str):
        guides = {
            "kshark://guide": ("KShark User's Guide", "KShark captures system calls and logs from Linux kernel eBPF probes.\n\nDouble-click any probe to stream live events."),
            "kshark://probes": ("eBPF Probes Architecture", "• sys_tracer: Monitors sys_enter/sys_exit tracepoints\n• net_filter: Inspects TC socket traffic\n• ssl_tracer: Plaintext TLS payload uprobes\n• lsm_enforcer: Kernel security containment hooks"),
            "kshark://ml": ("ML Threat Consensus", "• Random Forest / XGBoost: Rapid anomaly classification\n• PyTorch Deep Neural Network: Sequential behavior modeling\n• Consensus Engine: Zero-false-positive forensic alerts"),
            "kshark://copilot": ("Security Copilot Analyst", "Integrated local LLM security analyst ready to triage anomalies and suggest containment commands."),
        }
        title, text = guides.get(url_str, ("KShark Help", "Documentation topic."))
        QMessageBox.information(self, title, text)

    def _apply_theme(self):
        c = ThemeManager.instance().get_palette_colors()
        is_dark = ThemeManager.is_dark()

        self.setStyleSheet(f"""
            QWidget {{
                background-color: {c['bg_window']};
                color: {c['fg_text']};
            }}
            QListWidget {{
                background-color: {c['bg_base']};
                border: 1px solid {c['border']};
                border-radius: 4px;
                outline: none;
            }}
            QListWidget::item {{
                padding: 3px 6px;
                border-radius: 2px;
            }}
            QListWidget::item:selected {{
                background-color: {c['selection_bg']};
                color: #FFFFFF;
            }}
            QLineEdit#welcomeCaptureFilterInput {{
                background-color: {c['bg_base']};
                color: {c['fg_text']};
                border: 1px solid {c['border']};
                border-radius: 3px;
                padding: 3px 8px;
            }}
            QComboBox#welcomeCategoryCombo {{
                background-color: {c['bg_base']};
                color: {c['fg_text']};
                border: 1px solid {c['border']};
                border-radius: 3px;
                padding: 3px 8px;
            }}
        """)
        self._on_probe_selection_changed()
