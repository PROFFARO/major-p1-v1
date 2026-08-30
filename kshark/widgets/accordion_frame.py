"""
KShark Accordion Frames — Go To Packet / Event Frame matching Wireshark UX.
"""

from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSpacerItem, QSizePolicy
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QKeyEvent

from kshark.resources.icons import KSharkIcons
from kshark.core.theme import get_ui_font


class GoToFrame(QFrame):
    """
    KShark 'Go to specified packet' Accordion Frame.
    Matches Wireshark's Go to Packet bar with high fidelity.
    """

    goToEventTriggered = pyqtSignal(int)  # 1-indexed packet / event number
    cancelTriggered = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("goToFrame")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self._init_ui()

    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 4, 12, 4)
        layout.setSpacing(8)

        layout.addSpacerItem(QSpacerItem(40, 10, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))

        self.label = QLabel("Packet number:", self)
        self.label.setFont(get_ui_font(size=8.5, bold=True))
        layout.addWidget(self.label)

        self.input_field = QLineEdit(self)
        self.input_field.setPlaceholderText("e.g. 1")
        self.input_field.setFixedWidth(130)
        self.input_field.setFont(get_ui_font(size=8.5))
        self.input_field.returnPressed.connect(self._on_go)
        layout.addWidget(self.input_field)

        self.btn_go = QPushButton("Go to packet", self)
        self.btn_go.setIcon(KSharkIcons.go_to_packet())
        self.btn_go.setFont(get_ui_font(size=8.5, bold=True))
        self.btn_go.setDefault(True)
        self.btn_go.clicked.connect(self._on_go)
        layout.addWidget(self.btn_go)

        self.btn_cancel = QPushButton("Cancel", self)
        self.btn_cancel.setFont(get_ui_font(size=8.5))
        self.btn_cancel.clicked.connect(self._on_cancel)
        layout.addWidget(self.btn_cancel)

    def show_with_focus(self):
        """Displays the frame and focuses the packet number input field."""
        self.show()
        self.input_field.selectAll()
        self.input_field.setFocus()

    def keyPressEvent(self, event: QKeyEvent):
        if event.key() == Qt.Key.Key_Escape:
            self._on_cancel()
            event.accept()
            return
        super().keyPressEvent(event)

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

