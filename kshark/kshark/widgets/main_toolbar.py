"""
Wireshark-accurate Main Toolbar for KShark.

Actions:
  - Capture: Start, Stop, Restart, Options
  - File: Open, Save, Close, Reload
  - Navigation: Find, Prev, Next, Go To, First, Last, Auto-scroll
  - View: Colorize, Zoom In, Zoom Out, Auto-Resize Columns
"""

from PyQt6.QtWidgets import QToolBar, QWidget
from PyQt6.QtGui import QAction, QIcon, QKeySequence
from PyQt6.QtCore import Qt, pyqtSignal

from kshark.resources.icons import KSharkIcons


class MainToolBar(QToolBar):
    """
    Primary top action toolbar matching Wireshark icon layout.
    """

    startCaptureTriggered = pyqtSignal()
    stopCaptureTriggered = pyqtSignal()
    restartCaptureTriggered = pyqtSignal()
    captureOptionsTriggered = pyqtSignal()
    openFileTriggered = pyqtSignal()
    saveFileTriggered = pyqtSignal()
    closeFileTriggered = pyqtSignal()
    reloadTriggered = pyqtSignal()
    findEventTriggered = pyqtSignal()
    goPrevTriggered = pyqtSignal()
    goNextTriggered = pyqtSignal()
    goToTriggered = pyqtSignal()
    goFirstTriggered = pyqtSignal()
    goLastTriggered = pyqtSignal()
    autoScrollToggled = pyqtSignal(bool)
    colorizeToggled = pyqtSignal(bool)
    zoomInTriggered = pyqtSignal()
    zoomOutTriggered = pyqtSignal()
    resizeColumnsTriggered = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__("Main Toolbar", parent)
        self.setObjectName("mainToolBar")
        self.setMovable(False)
        self.setFloatable(False)
        self.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)

        self._init_actions()


    def _init_actions(self):
        # 1. Capture Group
        self.act_start = self.addAction(KSharkIcons.capture_start(), "Start Live Capture (Ctrl+E)")
        self.act_start.setShortcut(QKeySequence("Ctrl+E"))
        self.act_start.triggered.connect(self.startCaptureTriggered.emit)

        self.act_stop = self.addAction(KSharkIcons.capture_stop(), "Stop Capture (Ctrl+E)")
        self.act_stop.setEnabled(False)
        self.act_stop.triggered.connect(self.stopCaptureTriggered.emit)

        self.act_restart = self.addAction(KSharkIcons.capture_restart(), "Restart Current Capture")
        self.act_restart.triggered.connect(self.restartCaptureTriggered.emit)

        self.act_options = self.addAction(KSharkIcons.capture_options(), "Capture Options & Probes")
        self.act_options.triggered.connect(self.captureOptionsTriggered.emit)

        self.addSeparator()

        # 2. File Group
        self.act_open = self.addAction(KSharkIcons.file_open(), "Open Capture DB (Ctrl+O)")
        self.act_open.setShortcut(QKeySequence("Ctrl+O"))
        self.act_open.triggered.connect(self.openFileTriggered.emit)

        self.act_save = self.addAction(KSharkIcons.file_save(), "Save / Export Events (Ctrl+S)")
        self.act_save.setShortcut(QKeySequence("Ctrl+S"))
        self.act_save.triggered.connect(self.saveFileTriggered.emit)

        self.act_close = self.addAction(KSharkIcons.file_close(), "Close Capture (Ctrl+W)")
        self.act_close.setShortcut(QKeySequence("Ctrl+W"))
        self.act_close.triggered.connect(self.closeFileTriggered.emit)

        self.act_reload = self.addAction(KSharkIcons.file_reload(), "Reload Capture (Ctrl+R)")
        self.act_reload.setShortcut(QKeySequence("Ctrl+R"))
        self.act_reload.triggered.connect(self.reloadTriggered.emit)

        self.addSeparator()

        # 3. Navigation Group
        self.act_find = self.addAction(KSharkIcons.nav_find(), "Find Event (Ctrl+F)")
        self.act_find.setShortcut(QKeySequence("Ctrl+F"))
        self.act_find.triggered.connect(self.findEventTriggered.emit)

        self.act_prev = self.addAction(KSharkIcons.nav_prev(), "Previous Event (Ctrl+Up)")
        self.act_prev.setShortcut(QKeySequence("Ctrl+Up"))
        self.act_prev.triggered.connect(self.goPrevTriggered.emit)

        self.act_next = self.addAction(KSharkIcons.nav_next(), "Next Event (Ctrl+Down)")
        self.act_next.setShortcut(QKeySequence("Ctrl+Down"))
        self.act_next.triggered.connect(self.goNextTriggered.emit)

        self.act_goto = self.addAction(KSharkIcons.nav_goto(), "Go to Event Number (Ctrl+G)")
        self.act_goto.setShortcut(QKeySequence("Ctrl+G"))
        self.act_goto.triggered.connect(self.goToTriggered.emit)

        self.act_first = self.addAction(KSharkIcons.nav_first(), "First Event (Ctrl+Home)")
        self.act_first.setShortcut(QKeySequence("Ctrl+Home"))
        self.act_first.triggered.connect(self.goFirstTriggered.emit)

        self.act_last = self.addAction(KSharkIcons.nav_last(), "Last Event (Ctrl+End)")
        self.act_last.setShortcut(QKeySequence("Ctrl+End"))
        self.act_last.triggered.connect(self.goLastTriggered.emit)

        self.act_autoscroll = self.addAction(KSharkIcons.autoscroll(), "Auto-Scroll to Live Events")
        self.act_autoscroll.setCheckable(True)
        self.act_autoscroll.setChecked(True)
        self.act_autoscroll.toggled.connect(self.autoScrollToggled.emit)

        self.addSeparator()

        # 4. View / Colorize Group
        self.act_colorize = self.addAction(KSharkIcons.colorize(), "Colorize Event List")
        self.act_colorize.setCheckable(True)
        self.act_colorize.setChecked(True)
        self.act_colorize.toggled.connect(self.colorizeToggled.emit)

        self.act_zoom_in = self.addAction(KSharkIcons.zoom_in(), "Zoom In (Ctrl++)")
        self.act_zoom_in.setShortcut(QKeySequence("Ctrl++"))
        self.act_zoom_in.triggered.connect(self.zoomInTriggered.emit)

        self.act_zoom_out = self.addAction(KSharkIcons.zoom_out(), "Zoom Out (Ctrl+-)")
        self.act_zoom_out.setShortcut(QKeySequence("Ctrl+-"))
        self.act_zoom_out.triggered.connect(self.zoomOutTriggered.emit)

        self.act_zoom_100 = self.addAction(KSharkIcons.zoom_100(), "Normal Size (100%) (Ctrl+0)")
        self.act_zoom_100.setShortcut(QKeySequence("Ctrl+0"))

        self.act_resize_cols = self.addAction(KSharkIcons.resize_columns(), "Auto-Resize Columns")
        self.act_resize_cols.triggered.connect(self.resizeColumnsTriggered.emit)

    def set_capturing_state(self, is_capturing: bool):
        """Toggles Start/Stop button states during capture lifecycle."""
        self.act_start.setEnabled(not is_capturing)
        self.act_stop.setEnabled(is_capturing)

