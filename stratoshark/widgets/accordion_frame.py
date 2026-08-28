"""
Stratoshark Accordion Frames — Go To Event Frame matching ui/stratoshark/stratoshark_main_window.ui.
"""

from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSpacerItem, QSizePolicy
from PyQt6.QtCore import pyqtSignal, Qt


class GoToFrame(QFrame):
    """
    Stratoshark Go To Event # Accordion Frame.
    """

    goToEventTriggered = pyqtSignal(int)  # 1-indexed event number
    cancelTriggered = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("goToFrame")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self._init_ui()

    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 3, 8, 3)
        layout.setSpacing(8)

        layout.addSpacerItem(QSpacerItem(40, 10, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))

        self.label = QLabel("Event:", self)
        layout.addWidget(self.label)

        self.input_field = QLineEdit(self)
        self.input_field.setPlaceholderText("Event #")
        self.input_field.setFixedWidth(120)
        self.input_field.returnPressed.connect(self._on_go)
        layout.addWidget(self.input_field)

        self.btn_go = QPushButton("Go to event", self)
        self.btn_go.setDefault(True)
        self.btn_go.clicked.connect(self._on_go)
        layout.addWidget(self.btn_go)

        self.btn_cancel = QPushButton("Cancel", self)
        self.btn_cancel.clicked.connect(self._on_cancel)
        layout.addWidget(self.btn_cancel)

    def _on_go(self):
        text = self.input_field.text().strip()
        try:
            val = int(text)
            if val > 0:
                self.goToEventTriggered.emit(val)
                self.hide()
        except ValueError:
            pass

    def _on_cancel(self):
        self.hide()
        self.cancelTriggered.emit()
