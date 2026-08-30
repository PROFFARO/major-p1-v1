"""
High-Precision Scroll Views for KShark (Trackpad & Mouse Wheel Support).

Provides seamless sub-pixel trackpad gesture scrolling and stepped mouse-wheel
navigation across filtered and unfiltered telemetry tables and hierarchical trees.
"""

from PyQt6.QtWidgets import QTableView, QTreeView, QTableWidget, QAbstractItemView
from PyQt6.QtCore import Qt


class KSharkTableView(QTableView):
    """
    High-performance QTableView with native trackpad high-precision pixelDelta
    and stepped mouse-wheel scrolling support across filtered and unfiltered models.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

    def wheelEvent(self, event):
        # 1. High-precision trackpad pixel delta (libinput/Wayland/macOS gestures)
        p_delta = event.pixelDelta()
        if not p_delta.isNull():
            if p_delta.y() != 0:
                sb = self.verticalScrollBar()
                sb.setValue(sb.value() - p_delta.y())
            if p_delta.x() != 0:
                hsb = self.horizontalScrollBar()
                hsb.setValue(hsb.value() - p_delta.x())
            event.accept()
            return

        # 2. Angle delta (stepped mouse wheel & fractional trackpad gestures)
        a_delta = event.angleDelta()
        if not a_delta.isNull():
            if a_delta.y() != 0:
                sb = self.verticalScrollBar()
                if abs(a_delta.y()) >= 120:
                    row_h = max(20, self.verticalHeader().defaultSectionSize())
                    step = int((a_delta.y() / 120.0) * (row_h * 2.5))
                else:
                    step = int(a_delta.y() * 0.8)
                if step == 0:
                    step = 1 if a_delta.y() > 0 else -1
                sb.setValue(sb.value() - step)

            if a_delta.x() != 0:
                hsb = self.horizontalScrollBar()
                if abs(a_delta.x()) >= 120:
                    step_x = int((a_delta.x() / 120.0) * 40)
                else:
                    step_x = int(a_delta.x() * 0.8)
                if step_x == 0:
                    step_x = 1 if a_delta.x() > 0 else -1
                hsb.setValue(hsb.value() - step_x)

            event.accept()
            return

        super().wheelEvent(event)


class KSharkTreeView(QTreeView):
    """
    High-performance QTreeView with native trackpad high-precision pixelDelta
    and stepped mouse-wheel scrolling support for hierarchical dissection trees.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

    def wheelEvent(self, event):
        # 1. High-precision trackpad pixel delta
        p_delta = event.pixelDelta()
        if not p_delta.isNull():
            if p_delta.y() != 0:
                sb = self.verticalScrollBar()
                sb.setValue(sb.value() - p_delta.y())
            if p_delta.x() != 0:
                hsb = self.horizontalScrollBar()
                hsb.setValue(hsb.value() - p_delta.x())
            event.accept()
            return

        # 2. Angle delta (mouse wheel & trackpad angle deltas)
        a_delta = event.angleDelta()
        if not a_delta.isNull():
            if a_delta.y() != 0:
                sb = self.verticalScrollBar()
                if abs(a_delta.y()) >= 120:
                    step = int((a_delta.y() / 120.0) * 36)
                else:
                    step = int(a_delta.y() * 0.8)
                if step == 0:
                    step = 1 if a_delta.y() > 0 else -1
                sb.setValue(sb.value() - step)

            if a_delta.x() != 0:
                hsb = self.horizontalScrollBar()
                if abs(a_delta.x()) >= 120:
                    step_x = int((a_delta.x() / 120.0) * 36)
                else:
                    step_x = int(a_delta.x() * 0.8)
                if step_x == 0:
                    step_x = 1 if a_delta.x() > 0 else -1
                hsb.setValue(hsb.value() - step_x)

            event.accept()
            return

        super().wheelEvent(event)


class KSharkTableWidget(QTableWidget):
    """
    High-performance QTableWidget with native trackpad and mouse-wheel scrolling support.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

    def wheelEvent(self, event):
        p_delta = event.pixelDelta()
        if not p_delta.isNull():
            if p_delta.y() != 0:
                sb = self.verticalScrollBar()
                sb.setValue(sb.value() - p_delta.y())
            if p_delta.x() != 0:
                hsb = self.horizontalScrollBar()
                hsb.setValue(hsb.value() - p_delta.x())
            event.accept()
            return

        a_delta = event.angleDelta()
        if not a_delta.isNull():
            if a_delta.y() != 0:
                sb = self.verticalScrollBar()
                step = int((a_delta.y() / 120.0) * 30) if abs(a_delta.y()) >= 120 else int(a_delta.y() * 0.8)
                if step == 0:
                    step = 1 if a_delta.y() > 0 else -1
                sb.setValue(sb.value() - step)

            if a_delta.x() != 0:
                hsb = self.horizontalScrollBar()
                step_x = int((a_delta.x() / 120.0) * 30) if abs(a_delta.x()) >= 120 else int(a_delta.x() * 0.8)
                if step_x == 0:
                    step_x = 1 if a_delta.x() > 0 else -1
                hsb.setValue(hsb.value() - step_x)

            event.accept()
            return

        super().wheelEvent(event)
