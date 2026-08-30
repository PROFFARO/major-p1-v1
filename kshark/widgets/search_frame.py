"""
KShark Search Frame — Search Event Packets by Filter, Hex, String, or Regex.
Direct port of ui/kshark/kshark_search_frame.cpp & ui/kshark/kshark_main_window.ui.
"""

from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QRadioButton, QButtonGroup, QComboBox, QCheckBox
)
from PyQt6.QtCore import pyqtSignal, Qt

from kshark.resources.icons import KSharkIcons


class KSharkSearchFrame(QFrame):
    """
    KShark find/search toolbar frame matching ui/kshark/kshark_search_frame.cpp.
    """

    findTriggered = pyqtSignal(str, str, str, bool)  # (query, search_type, direction, case_sensitive)
    cancelTriggered = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ksharkSearchFrame")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self._init_ui()

    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(8)

        # Search Target Radio Buttons
        self.btn_group = QButtonGroup(self)

        self.rb_filter = QRadioButton("Display filter", self)
        self.rb_hex = QRadioButton("Hex value", self)
        self.rb_string = QRadioButton("String", self)
        self.rb_regex = QRadioButton("Regular Expression", self)
        self.rb_string.setChecked(True)

        self.btn_group.addButton(self.rb_filter)
        self.btn_group.addButton(self.rb_hex)
        self.btn_group.addButton(self.rb_string)
        self.btn_group.addButton(self.rb_regex)

        layout.addWidget(self.rb_filter)
        layout.addWidget(self.rb_hex)
        layout.addWidget(self.rb_string)
        layout.addWidget(self.rb_regex)

        # Search Query Input
        self.search_input = QLineEdit(self)
        self.search_input.setPlaceholderText("Search in event list, details, or bytes...")
        self.search_input.returnPressed.connect(self._on_find_next)
        layout.addWidget(self.search_input, stretch=1)

        # Case Sensitivity
        self.cb_case = QCheckBox("Case sensitive", self)
        layout.addWidget(self.cb_case)

        # Direction (Up / Down)
        self.combo_dir = QComboBox(self)
        self.combo_dir.addItems(["Down", "Up"])
        layout.addWidget(self.combo_dir)

        # Action Buttons
        self.btn_find = QPushButton("Find", self)
        self.btn_find.setDefault(True)
        self.btn_find.clicked.connect(self._on_find_next)
        layout.addWidget(self.btn_find)

        self.btn_cancel = QPushButton("Cancel", self)
        self.btn_cancel.clicked.connect(self._on_cancel)
        layout.addWidget(self.btn_cancel)

    def _get_search_type(self) -> str:
        if self.rb_filter.isChecked():
            return "filter"
        elif self.rb_hex.isChecked():
            return "hex"
        elif self.rb_regex.isChecked():
            return "regex"
        return "string"

    def _on_find_next(self):
        query = self.search_input.text().strip()
        if not query:
            return
        stype = self._get_search_type()
        direction = self.combo_dir.currentText().lower()
        case_sens = self.cb_case.isChecked()
        self.findTriggered.emit(query, stype, direction, case_sens)

    def _on_cancel(self):
        self.hide()
        self.cancelTriggered.emit()
