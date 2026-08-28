"""
Application Lifecycle & Bootstrap for KShark.
"""

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
import sys
import signal
import logging

from kshark.core.theme import ThemeManager, get_ui_font
from kshark.core.settings import KSharkSettings
from kshark.main_window import KSharkMainWindow

logger = logging.getLogger("kshark.app")


class KSharkApplication(QApplication):
    """
    Root QApplication configuring desktop environment, font rendering,
    and Linux display server attributes (Wayland/X11).
    """

    def __init__(self, argv: list):
        super().__init__(argv)
        self.setApplicationName("KShark")
        self.setOrganizationName("KShark")
        self.setApplicationVersion("1.0.0")

        # Apply theme (Light or Dark)
        settings = KSharkSettings()
        theme_mode = settings.get_theme_mode()

        if "--dark" in argv:
            is_dark = True
        elif "--light" in argv:
            is_dark = False
        else:
            is_dark = (theme_mode == "dark")

        ThemeManager.set_theme(dark=is_dark)



def run_kshark(argv=None) -> int:
    """Entry point to launch the KShark desktop application."""
    if argv is None:
        argv = sys.argv

    # Allow clean Ctrl+C termination in terminal
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    app = KSharkApplication(argv)
    main_win = KSharkMainWindow()
    main_win.show()

    return app.exec()
