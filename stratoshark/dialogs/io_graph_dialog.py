"""
Stratoshark IO Graph Dialog — Live Throughput, Events/Sec, and Threat Timeline Graph.
Direct port of ui/stratoshark/stratoshark_io_graph_dialog.cpp.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QCheckBox, QFrame, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtGui import QPainter, QPen, QColor, QBrush, QPolygonF
from PyQt6.QtCore import Qt, QPointF, QTimer
import collections

from stratoshark.core.theme import ThemeManager, get_monospace_font


class IOGraphCanvas(QFrame):
    """Real-time timeline canvas graphing EPS and threat spikes."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setMinimumHeight(220)
        self._history = collections.deque(maxlen=100)
        self._threat_history = collections.deque(maxlen=100)

        # Seed with initial points
        for _ in range(50):
            self._history.append(0.0)
            self._threat_history.append(0.0)

    def add_point(self, eps: float, threats: float = 0.0):
        self._history.append(eps)
        self._threat_history.append(threats)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        c = ThemeManager.instance().get_palette_colors()

        # Background
        painter.fillRect(0, 0, w, h, QColor(c["bg_base"]))

        # Grid lines
        painter.setPen(QPen(QColor(c["border"]), 1, Qt.PenStyle.DotLine))
        for y in range(40, h, 40):
            painter.drawLine(0, y, w, y)

        if len(self._history) < 2:
            painter.end()
            return

        max_val = max(max(self._history), 10.0)
        step = (w - 20) / (len(self._history) - 1)

        # 1. Total EPS Curve (Teal #0E9AA7)
        pen_eps = QPen(QColor(c["brand_primary"]), 2)
        painter.setPen(pen_eps)
        poly = QPolygonF()
        for i, val in enumerate(self._history):
            x = 10 + i * step
            y = h - 20 - (val / max_val) * (h - 40)
            poly.append(QPointF(x, y))
        painter.drawPolyline(poly)

        # 2. Threat Spikes (Red #C92A2A)
        pen_threat = QPen(QColor(c["accent_danger"]), 2)
        painter.setPen(pen_threat)
        threat_poly = QPolygonF()
        for i, val in enumerate(self._threat_history):
            x = 10 + i * step
            y = h - 20 - (val / max_val) * (h - 40)
            threat_poly.append(QPointF(x, y))
        painter.drawPolyline(threat_poly)

        # Legend
        painter.setPen(QColor(c["fg_text"]))
        painter.setFont(get_monospace_font(size=8))
        painter.drawText(15, 20, f"All Events (EPS) — Peak: {max_val:.1f}")
        painter.setPen(QColor(c["accent_danger"]))
        painter.drawText(180, 20, "Threat Spikes")

        painter.end()


class StratosharkIOGraphDialog(QDialog):
    """
    Stratoshark IO Graph Dialog matching ui/stratoshark/stratoshark_io_graph_dialog.cpp.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Stratoshark · IO Graphs")
        self.resize(750, 480)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Graph Canvas
        self.canvas = IOGraphCanvas(self)
        layout.addWidget(self.canvas, stretch=1)

        # Controls & Graph Configuration Table
        table = QTableWidget(2, 5, self)
        table.setHorizontalHeaderLabels(["Graph", "Enabled", "Color", "Display Filter", "Calculation"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setItem(0, 0, QTableWidgetItem("All Events"))
        table.setItem(0, 1, QTableWidgetItem("✔"))
        table.setItem(0, 2, QTableWidgetItem("Teal"))
        table.setItem(0, 3, QTableWidgetItem(""))
        table.setItem(0, 4, QTableWidgetItem("Events/s"))

        table.setItem(1, 0, QTableWidgetItem("Threats"))
        table.setItem(1, 1, QTableWidgetItem("✔"))
        table.setItem(1, 2, QTableWidgetItem("Red"))
        table.setItem(1, 3, QTableWidgetItem("threat_name != 'BENIGN'"))
        table.setItem(1, 4, QTableWidgetItem("COUNT(*)"))
        table.setFixedHeight(110)
        layout.addWidget(table)

        # Bottom Buttons
        btn_bar = QHBoxLayout()
        btn_bar.addStretch(1)
        btn_close = QPushButton("Close", self)
        btn_close.clicked.connect(self.accept)
        btn_bar.addWidget(btn_close)
        layout.addLayout(btn_bar)

    def record_stats(self, eps: float, threats: float = 0.0):
        self.canvas.add_point(eps, threats)
