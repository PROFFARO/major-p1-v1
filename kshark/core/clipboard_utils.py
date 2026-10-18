"""
KShark Universal Clipboard Utilities & Event Filter.
Provides robust multi-platform clipboard synchronization (X11 Selection + System Clipboard),
password field copy/cut bypass, and universal keyboard shortcuts (Ctrl+C, Ctrl+V, Ctrl+X, Ctrl+A).
"""

import re
import logging
from typing import Optional
from PyQt6.QtCore import QObject, QEvent, Qt, QPoint, QRect
from PyQt6.QtWidgets import (
    QApplication, QLineEdit, QTextEdit, QPlainTextEdit, QTextBrowser,
    QMenu, QToolTip, QWidget
)
from PyQt6.QtGui import QClipboard, QKeySequence, QAction

logger = logging.getLogger(__name__)


class ClipboardUtils:
    """Centralized clipboard operations supporting both Standard and Linux Selection clipboards."""

    @staticmethod
    def get_text() -> str:
        """
        Retrieves text from system clipboard with fallback to X11 primary selection.
        """
        cb = QApplication.clipboard()
        if not cb:
            return ""

        # 1. Primary application clipboard (Ctrl+C)
        text = cb.text(QClipboard.Mode.Clipboard)
        if not text and cb.supportsSelection():
            # 2. X11 / Wayland mouse selection clipboard
            try:
                text = cb.text(QClipboard.Mode.Selection)
            except Exception:
                pass

        return text or ""

    @staticmethod
    def set_text(text: str) -> bool:
        """
        Sets text to both standard clipboard and X11 selection buffer (if supported).
        """
        cb = QApplication.clipboard()
        if not cb:
            return False

        try:
            cb.setText(text, QClipboard.Mode.Clipboard)
            # Sync to selection mode on Linux X11/Wayland if supported
            if cb.supportsSelection():
                cb.setText(text, QClipboard.Mode.Selection)
            return True
        except Exception as e:
            logger.debug(f"Failed to sync clipboard: {e}")
            return False

    @staticmethod
    def attach_line_edit_context_menu(line_edit: QLineEdit, is_password: bool = False, on_clear: Optional[callable] = None):
        """
        Attaches a high-contrast context menu to a QLineEdit with guaranteed Copy, Paste, Cut, Select All.
        """
        line_edit.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

        def _show_menu(pos: QPoint):
            menu = QMenu(line_edit)
            
            # Undo / Redo
            act_undo = menu.addAction("Undo")
            act_undo.setShortcut(QKeySequence("Ctrl+Z"))
            act_undo.setEnabled(line_edit.isUndoAvailable())
            act_undo.triggered.connect(line_edit.undo)

            act_redo = menu.addAction("Redo")
            act_redo.setShortcut(QKeySequence("Ctrl+Y"))
            act_redo.setEnabled(line_edit.isRedoAvailable())
            act_redo.triggered.connect(line_edit.redo)

            menu.addSeparator()

            # Cut
            act_cut = menu.addAction("Cut")
            act_cut.setShortcut(QKeySequence("Ctrl+X"))
            has_sel = bool(line_edit.selectedText())
            act_cut.setEnabled(not line_edit.isReadOnly() and (has_sel or (is_password and bool(line_edit.text()))))
            
            def _do_cut():
                sel = line_edit.selectedText()
                if not sel and is_password:
                    sel = line_edit.text()
                if sel:
                    ClipboardUtils.set_text(sel)
                    line_edit.del_() if line_edit.selectedText() else line_edit.clear()

            act_cut.triggered.connect(_do_cut if is_password else line_edit.cut)

            # Copy
            act_copy = menu.addAction("Copy")
            act_copy.setShortcut(QKeySequence("Ctrl+C"))
            has_text = bool(line_edit.text())
            act_copy.setEnabled(has_sel or (is_password and has_text))

            def _do_copy():
                sel = line_edit.selectedText()
                if not sel and is_password:
                    sel = line_edit.text()
                if sel:
                    ClipboardUtils.set_text(sel)
                    QToolTip.showText(
                        line_edit.mapToGlobal(pos),
                        "Copied to Clipboard!",
                        line_edit,
                        QRect(),
                        1500
                    )

            act_copy.triggered.connect(_do_copy if is_password else line_edit.copy)

            # Paste
            act_paste = menu.addAction("Paste")
            act_paste.setShortcut(QKeySequence("Ctrl+V"))
            cb_has_text = bool(ClipboardUtils.get_text())
            act_paste.setEnabled(not line_edit.isReadOnly() and cb_has_text)

            def _do_paste():
                raw = ClipboardUtils.get_text()
                if raw:
                    clean = raw.strip().strip("'\"") if is_password else raw.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
                    line_edit.insert(clean)

            act_paste.triggered.connect(_do_paste)

            menu.addSeparator()

            # Select All
            act_select_all = menu.addAction("Select All")
            act_select_all.setShortcut(QKeySequence("Ctrl+A"))
            act_select_all.setEnabled(has_text)
            act_select_all.triggered.connect(line_edit.selectAll)

            # Clear
            act_clear = menu.addAction("Clear")
            act_clear.setEnabled(not line_edit.isReadOnly() and has_text)
            if on_clear:
                act_clear.triggered.connect(on_clear)
            else:
                act_clear.triggered.connect(line_edit.clear)

            menu.exec(line_edit.mapToGlobal(pos))

        line_edit.customContextMenuRequested.connect(_show_menu)


class UniversalClipboardEventFilter(QObject):
    """
    Global event filter installed on QApplication to guarantee standard Copy, Paste, Cut,
    and Select All actions across every dialog, widget, and input field in KShark.
    """

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if event.type() == QEvent.Type.KeyPress:
            modifiers = event.modifiers()
            if modifiers in (Qt.KeyboardModifier.ControlModifier, Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier):
                key = event.key()

                target = QApplication.focusWidget() or (obj if isinstance(obj, QWidget) else None)

                # ── 1. Ctrl+V: Paste ──
                if key == Qt.Key.Key_V and modifiers == Qt.KeyboardModifier.ControlModifier:
                    if isinstance(target, QLineEdit) and not target.isReadOnly():
                        txt = ClipboardUtils.get_text()
                        if txt:
                            if target.echoMode() == QLineEdit.EchoMode.Password or "key" in target.objectName().lower():
                                txt = txt.strip().strip("'\"")
                            else:
                                txt = txt.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
                            target.insert(txt)
                            return True
                    elif isinstance(target, (QTextEdit, QPlainTextEdit)) and not target.isReadOnly():
                        txt = ClipboardUtils.get_text()
                        if txt:
                            target.insertPlainText(txt)
                            return True

                # ── 2. Ctrl+C: Copy ──
                elif key == Qt.Key.Key_C and modifiers == Qt.KeyboardModifier.ControlModifier:
                    if isinstance(target, QLineEdit) and target.echoMode() == QLineEdit.EchoMode.Password:
                        sel = target.selectedText() or target.text()
                        if sel:
                            ClipboardUtils.set_text(sel)
                            if target.parentWidget():
                                QToolTip.showText(
                                    target.mapToGlobal(QPoint(0, target.height())),
                                    "Copied to Clipboard!",
                                    target,
                                    QRect(),
                                    1500
                                )
                            return True

                # ── 3. Ctrl+X: Cut ──
                elif key == Qt.Key.Key_X and modifiers == Qt.KeyboardModifier.ControlModifier:
                    if isinstance(target, QLineEdit) and target.echoMode() == QLineEdit.EchoMode.Password and not target.isReadOnly():
                        sel = target.selectedText()
                        if not sel:
                            sel = target.text()
                            target.clear()
                        else:
                            target.del_()
                        if sel:
                            ClipboardUtils.set_text(sel)
                            return True

        return super().eventFilter(obj, event)
