"""
Stratoshark Main Toolbar — Pixel-Accurate Action Controls.
"""

from PyQt6.QtWidgets import QToolBar, QWidget
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtCore import pyqtSignal, Qt, QSize

from stratoshark.resources.icons import StratosharkIcons


class MainToolBar(QToolBar):
    """
    Top Action Toolbar for Stratoshark.
    """

    startCaptureTriggered = pyqtSignal()
    stopCaptureTriggered = pyqtSignal()
    restartCaptureTriggered = pyqtSignal()
    captureOptionsTriggered = pyqtSignal()

    openFileTriggered = pyqtSignal()
    saveFileTriggered = pyqtSignal()
    closeFileTriggered = pyqtSignal()
    reloadFileTriggered = pyqtSignal()

    findTriggered = pyqtSignal()
    goPrevTriggered = pyqtSignal()
    goNextTriggered = pyqtSignal()
    goFirstTriggered = pyqtSignal()
    goLastTriggered = pyqtSignal()

    autoScrollToggled = pyqtSignal(bool)
    colorizeToggled = pyqtSignal(bool)

    zoomInTriggered = pyqtSignal()
    zoomOutTriggered = pyqtSignal()
    zoom100Triggered = pyqtSignal()
    resizeColumnsTriggered = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__("Main Toolbar", parent)
        self.setObjectName("mainToolBar")
        self.setIconSize(QSize(16, 16))
        self.setMovable(False)
        self.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)
        self._init_actions()

    def _init_actions(self):
        # 1. Capture Controls
        self.act_start = self.addAction(StratosharkIcons.capture_start(), "Start capturing kernel events")
        self.act_start.triggered.connect(self.startCaptureTriggered)

        self.act_stop = self.addAction(StratosharkIcons.capture_stop(), "Stop capturing kernel events")
        self.act_stop.triggered.connect(self.stopCaptureTriggered)
        self.act_stop.setEnabled(False)

        self.act_restart = self.addAction(StratosharkIcons.capture_restart(), "Restart live capture")
        self.act_restart.triggered.connect(self.restartCaptureTriggered)
        self.act_restart.setEnabled(False)

        self.act_options = self.addAction(StratosharkIcons.capture_options(), "Capture options...")
        self.act_options.triggered.connect(self.captureOptionsTriggered)

        self.addSeparator()

        # 2. File Controls
        self.act_open = self.addAction(StratosharkIcons.file_open(), "Open a capture file... (Ctrl+O)")
        self.act_open.triggered.connect(self.openFileTriggered)

        self.act_save = self.addAction(StratosharkIcons.file_save(), "Save this capture file (Ctrl+S)")
        self.act_save.triggered.connect(self.saveFileTriggered)

        self.act_close = self.addAction(StratosharkIcons.file_close(), "Close this capture file (Ctrl+W)")
        self.act_close.triggered.connect(self.closeFileTriggered)

        self.act_reload = self.addAction(StratosharkIcons.file_reload(), "Reload this capture file (Ctrl+R)")
        self.act_reload.triggered.connect(self.reloadFileTriggered)

        self.addSeparator()

        # 3. Navigation Controls
        self.act_find = self.addAction(StratosharkIcons.search_find(), "Find an event... (Ctrl+F)")
        self.act_find.triggered.connect(self.findTriggered)

        self.act_prev = self.addAction(StratosharkIcons.go_previous(), "Go to the previous event (Ctrl+Down)")
        self.act_prev.triggered.connect(self.goPrevTriggered)

        self.act_next = self.addAction(StratosharkIcons.go_next(), "Go to the next event (Ctrl+Up)")
        self.act_next.triggered.connect(self.goNextTriggered)

        self.act_first = self.addAction(StratosharkIcons.go_first(), "Go to the first event (Ctrl+Home)")
        self.act_first.triggered.connect(self.goFirstTriggered)

        self.act_last = self.addAction(StratosharkIcons.go_last(), "Go to the last event (Ctrl+End)")
        self.act_last.triggered.connect(self.goLastTriggered)

        self.act_autoscroll = self.addAction(StratosharkIcons.auto_scroll(), "Automatically scroll to the last event")
        self.act_autoscroll.setCheckable(True)
        self.act_autoscroll.setChecked(True)
        self.act_autoscroll.toggled.connect(self.autoScrollToggled)

        self.act_colorize = self.addAction(StratosharkIcons.colorize(), "Colorize event list")
        self.act_colorize.setCheckable(True)
        self.act_colorize.setChecked(True)
        self.act_colorize.toggled.connect(self.colorizeToggled)

        self.addSeparator()

        # 4. View Controls
        self.act_zoom_in = self.addAction(StratosharkIcons.zoom_in(), "Zoom in (Ctrl++)")
        self.act_zoom_in.triggered.connect(self.zoomInTriggered)

        self.act_zoom_out = self.addAction(StratosharkIcons.zoom_out(), "Zoom out (Ctrl+-)")
        self.act_zoom_out.triggered.connect(self.zoomOutTriggered)

        self.act_zoom_100 = self.addAction(StratosharkIcons.zoom_100(), "Normal size 100% (Ctrl+0)")
        self.act_zoom_100.triggered.connect(self.zoom100Triggered)

        self.act_resize_cols = self.addAction(StratosharkIcons.resize_columns(), "Resize all columns to fit content")
        self.act_resize_cols.triggered.connect(self.resizeColumnsTriggered)

    def set_capturing_state(self, is_capturing: bool):
        self.act_start.setEnabled(not is_capturing)
        self.act_stop.setEnabled(is_capturing)
        self.act_restart.setEnabled(is_capturing)
