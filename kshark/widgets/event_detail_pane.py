"""
KShark Event Detail Pane — Dissection Protocol & Kernel Telemetry Inspector.
Provides search filtering, section expand/collapse, copy actions, and high-visibility hierarchy.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTreeView, QHeaderView, QApplication, QMessageBox, QMenu
)
from PyQt6.QtGui import QFont, QIcon, QColor
from PyQt6.QtCore import Qt, pyqtSignal

from kshark.models.detail_tree_model import DetailTreeModel
from kshark.core.theme import get_ui_font, get_monospace_font


class EventDetailPane(QWidget):
    """
    Enhanced Dissection Detail Pane with integrated search and dissection controls.
    """

    filterExpressionRequested = pyqtSignal(str, str)

    def __init__(self, model: DetailTreeModel, parent=None):
        super().__init__(parent)
        self.model = model
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        # Header toolbar
        bar = QHBoxLayout()
        bar.setContentsMargins(6, 4, 6, 4)
        bar.setSpacing(6)

        lbl_title = QLabel("🔬 Event Dissection")
        lbl_title.setFont(get_ui_font(size=9, bold=True))
        lbl_title.setStyleSheet("color: #0E9AA7;")

        # Quick field search filter
        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Quick field search...")

        self.search_entry.setFont(get_ui_font(size=8))
        self.search_entry.setFixedHeight(22)
        self.search_entry.textChanged.connect(self._on_search_changed)

        btn_expand = QPushButton("Expand All")
        btn_expand.setFont(get_ui_font(size=8))
        btn_expand.setFixedHeight(22)
        btn_expand.clicked.connect(self.expand_all)

        btn_collapse = QPushButton("Collapse All")
        btn_collapse.setFont(get_ui_font(size=8))
        btn_collapse.setFixedHeight(22)
        btn_collapse.clicked.connect(self.collapse_all)

        bar.addWidget(lbl_title)
        bar.addWidget(self.search_entry, stretch=1)
        bar.addWidget(btn_expand)
        bar.addWidget(btn_collapse)

        layout.addLayout(bar)

        # Main Tree View
        self.tree_view = QTreeView(self)
        self.tree_view.setObjectName("detailTreeView")
        self.tree_view.setModel(self.model)
        self.tree_view.setHeaderHidden(False)
        self.tree_view.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tree_view.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tree_view.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.tree_view.setAlternatingRowColors(True)
        self.tree_view.setAnimated(True)
        self.tree_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

        layout.addWidget(self.tree_view)

    def expand_all(self):
        self.tree_view.expandAll()

    def collapse_all(self):
        self.tree_view.collapseAll()

    def _on_search_changed(self, text: str):
        self.model.set_search_filter(text)
        if text.strip():
            self.tree_view.expandAll()
