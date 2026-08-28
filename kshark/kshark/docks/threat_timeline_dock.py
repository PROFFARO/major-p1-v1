"""
Real-time Threat Timeline & IO Graph Dock for KShark (Wireshark IO Graph Equivalent).
"""

from PyQt6.QtWidgets import QDockWidget, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox
from PyQt6.QtCore import Qt, QTimer
import time
from typing import Dict, Any, List
import collections

try:
    import pyqtgraph as pg
    PG_AVAILABLE = True
except ImportError:
    PG_AVAILABLE = False


class ThreatTimelineDock(QDockWidget):
    """
    Dockable live throughput curve and threat alert burst timeline.
    """

    def __init__(self, parent=None):
        super().__init__("Real-time IO Graph & Threat Timeline", parent)
        self.setObjectName("threatTimelineDock")
        self.setAllowedAreas(Qt.DockWidgetArea.TopDockWidgetArea | Qt.DockWidgetArea.BottomDockWidgetArea)

        self._max_points = 120
        self._timestamps = collections.deque(maxlen=self._max_points)
        self._eps_values = collections.deque(maxlen=self._max_points)
        self._threat_scatter_x = []
        self._threat_scatter_y = []

        self._init_ui()

    def _init_ui(self):
        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)

        # 1. Controls Top Bar
        ctrl_bar = QHBoxLayout()
        ctrl_bar.addWidget(QLabel("Metric Channel:"), 0)

        self.channel_combo = QComboBox(self)
        self.channel_combo.addItems(["Total Telemetry (EPS)", "Threat Detection Alerts", "Active PID Feature Windows"])
        self.channel_combo.setStyleSheet("font-size: 8.5pt;")
        ctrl_bar.addWidget(self.channel_combo, 0)
        ctrl_bar.addStretch(1)

        self.live_rate_lbl = QLabel("Live: 0.0 EPS")
        self.live_rate_lbl.setStyleSheet("font-weight: bold; color: #007ACC; font-size: 8.5pt;")
        ctrl_bar.addWidget(self.live_rate_lbl)

        layout.addLayout(ctrl_bar)

        # 2. PyQtGraph Real-time Plot Widget
        if PG_AVAILABLE:
            pg.setConfigOption('background', '#FFFFFF')
            pg.setConfigOption('foreground', '#333333')
            self.plot_widget = pg.PlotWidget(self)
            self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
            self.plot_widget.setLabel('left', 'Throughput (EPS)')
            self.plot_widget.setLabel('bottom', 'Time (Seconds ago)')

            self.curve = self.plot_widget.plot(
                pen=pg.mkPen(color="#007ACC", width=2),
                brush=pg.mkBrush(color=(0, 122, 204, 50)),
                fillLevel=0
            )

            self.threat_scatter = pg.ScatterPlotItem(
                size=12,
                pen=pg.mkPen(color="#8B0000", width=1),
                brush=pg.mkBrush(color="#FF4444"),
                symbol='d'
            )
            self.plot_widget.addItem(self.threat_scatter)
            layout.addWidget(self.plot_widget, stretch=1)
        else:
            fallback_lbl = QLabel("pyqtgraph library not installed — install via `pip install pyqtgraph` for interactive IO graphs.")
            layout.addWidget(fallback_lbl, stretch=1)

        self.setWidget(container)

    def add_stats_point(self, stats: Dict[str, Any]):
        """Updates live throughput curve with latest stats."""
        eps = float(stats.get("events_per_second", 0.0))
        self.live_rate_lbl.setText(f"Live: {eps:.1f} EPS")

        self._eps_values.append(eps)
        x_vals = list(range(-len(self._eps_values) + 1, 1))

        if PG_AVAILABLE:
            self.curve.setData(x_vals, list(self._eps_values))

    def record_threat_marker(self, alert: Dict[str, Any]):
        """Places a red diamond marker on the IO graph at current time."""
        current_eps = self._eps_values[-1] if self._eps_values else 1.0
        self._threat_scatter_x.append(0)
        self._threat_scatter_y.append(current_eps)

        if PG_AVAILABLE:
            # Shift older scatter points leftward
            shifted_x = [x - 1 for x in self._threat_scatter_x]
            self._threat_scatter_x = [x for x in shifted_x if x >= -self._max_points]
            self._threat_scatter_y = self._threat_scatter_y[-len(self._threat_scatter_x):]

            self.threat_scatter.setData(self._threat_scatter_x, self._threat_scatter_y)
