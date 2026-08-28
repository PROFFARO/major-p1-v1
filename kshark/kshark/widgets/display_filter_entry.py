"""
Wireshark-identical Display Filter Entry Bar for KShark.

Replicates the exact layout, glyphs, inline bookmark ribbon, right-arrow apply button,
and '+' filter button from Wireshark 4.4+.
"""

from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLineEdit, QToolButton, QMenu, QCompleter, QSizePolicy, QFrame
)
from PyQt6.QtGui import QAction, QColor, QPalette, QIcon, QPainter, QBrush, QPen, QPolygonF
from PyQt6.QtCore import Qt, pyqtSignal, QStringListModel, QPointF, QSize
from typing import Optional

from kshark.core.filter_engine import validate_filter, FILTER_FIELDS
from kshark.core.theme import WIRESHARK_COLORS, ThemeManager, get_monospace_font, get_ui_font
from kshark.core.settings import KSharkSettings
from kshark.resources.icons import KSharkIcons


class FilterApplyButton(QToolButton):
    """
    Wireshark-styled blue apply button containing white right-arrow and dropdown indicator.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(28, 20)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("""
            QToolButton {
                background-color: #3072CC;
                border: 1px solid #1E5AA8;
                border-radius: 2px;
                padding: 0px;
            }
            QToolButton:hover {
                background-color: #4084E0;
            }
            QToolButton:pressed {
                background-color: #1E5AA8;
            }
        """)

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # White right-pointing arrow
        painter.setBrush(QBrush(QColor("#FFFFFF")))
        painter.setPen(Qt.PenStyle.NoPen)

        # Arrow shaft + head
        painter.drawRect(6, 9, 8, 2)
        arrow_head = QPolygonF([
            QPointF(12, 6),
            QPointF(17, 10),
            QPointF(12, 14)
        ])
        painter.drawPolygon(arrow_head)

        # Small dropdown triangle on the right
        dropdown = QPolygonF([
            QPointF(20, 8),
            QPointF(24, 8),
            QPointF(22, 12)
        ])
        painter.drawPolygon(dropdown)
        painter.end()


class DisplayFilterEntry(QWidget):
    """
    Wireshark-identical Display Filter Bar.
    """

    filterApplied = pyqtSignal(str)
    filterSyntaxStatus = pyqtSignal(bool, str)  # (is_valid, error_msg)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = KSharkSettings()
        self._init_ui()
        self._setup_completer()

    def _init_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(4, 2, 4, 2)
        main_layout.setSpacing(4)

        # Main filter frame container (combines ribbon, line edit, clear button, and blue apply button)
        self.filter_frame = QFrame(self)
        self.filter_frame.setObjectName("filterFrame")
        self.filter_frame.setStyleSheet("""
            QFrame#filterFrame {
                background-color: #FFFFFF;
                border: 1px solid #B0B0B0;
                border-radius: 2px;
            }
        """)
        frame_layout = QHBoxLayout(self.filter_frame)
        frame_layout.setContentsMargins(4, 1, 2, 1)
        frame_layout.setSpacing(2)

        # 1. Bookmark Ribbon Button
        self.bookmark_btn = QToolButton(self.filter_frame)
        self.bookmark_btn.setIcon(KSharkIcons.filter_bookmark())
        self.bookmark_btn.setIconSize(QSize(14, 14))
        self.bookmark_btn.setAutoRaise(True)
        self.bookmark_btn.setToolTip("Saved display filter bookmarks")
        self.bookmark_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.bookmark_btn.setStyleSheet("border: none; background: transparent; padding: 0px 2px;")
        self._rebuild_bookmark_menu()
        frame_layout.addWidget(self.bookmark_btn)

        # 2. Main Filter Line Edit
        self.line_edit = QLineEdit(self.filter_frame)
        self.line_edit.setObjectName("displayFilterLineEdit")
        self.line_edit.setFont(get_monospace_font(size=8.5))
        self.line_edit.setPlaceholderText("Apply a display filter ... <Ctrl-/>")
        self.line_edit.setStyleSheet("""
            QLineEdit#displayFilterLineEdit {
                border: none;
                background: transparent;
                padding: 1px 4px;
                color: #000000;
            }
        """)
        self.line_edit.textChanged.connect(self._on_text_changed)
        self.line_edit.returnPressed.connect(self.apply_filter)
        frame_layout.addWidget(self.line_edit, stretch=1)

        # 3. Clear Button (X)
        self.clear_btn = QToolButton(self.filter_frame)
        self.clear_btn.setIcon(KSharkIcons.filter_clear())
        self.clear_btn.setIconSize(QSize(12, 12))
        self.clear_btn.setAutoRaise(True)
        self.clear_btn.setToolTip("Clear display filter")
        self.clear_btn.setStyleSheet("border: none; background: transparent; padding: 0px 2px;")
        self.clear_btn.clicked.connect(self.clear_filter)
        self.clear_btn.setVisible(False)
        frame_layout.addWidget(self.clear_btn)

        # 4. Right-Arrow Blue Apply Button
        self.apply_btn = FilterApplyButton(self.filter_frame)
        self.apply_btn.setToolTip("Apply display filter (Enter)")
        self.apply_btn.clicked.connect(self.apply_filter)
        frame_layout.addWidget(self.apply_btn)

        main_layout.addWidget(self.filter_frame, stretch=1)

        # 5. Plus (+) Button for Saved Filter Expressions
        self.add_btn = QToolButton(self)
        self.add_btn.setText("+")
        self.add_btn.setFont(get_ui_font(size=10, bold=True))
        self.add_btn.setFixedSize(20, 20)
        self.add_btn.setToolTip("Add a display filter button…")
        self.add_btn.setStyleSheet("""
            QToolButton {
                border: 1px solid #B0B0B0;
                border-radius: 2px;
                background-color: #F6F6F6;
                color: #333333;
                font-weight: bold;
            }
            QToolButton:hover {
                background-color: #E8E8E8;
            }
            QToolButton:pressed {
                background-color: #D0D0D0;
            }
        """)
        self.add_btn.clicked.connect(self._bookmark_current_filter)
        main_layout.addWidget(self.add_btn)

        ThemeManager.instance().themeChanged.connect(self._on_theme_changed)
        self._on_theme_changed()

    def _on_theme_changed(self):
        """Refreshes styling on theme change."""
        self._update_syntax_style(self.line_edit.text())

    def _setup_completer(self):
        """Constructs autocomplete suggestions for field names and common operators."""
        suggestions = []
        for field in FILTER_FIELDS.keys():
            suggestions.append(field)
            suggestions.append(f"{field} ==")
            suggestions.append(f"{field} !=")
            if FILTER_FIELDS[field] in (int, float):
                suggestions.append(f"{field} >=")
                suggestions.append(f"{field} <=")
            elif FILTER_FIELDS[field] == str:
                suggestions.append(f"{field} contains")

        for threat in ("RANSOMWARE", "PRIVILEGE_ESCALATION", "REVERSE_SHELL", "DATA_EXFILTRATION", 
                       "KERNEL_ROOTKIT", "CRYPTO_MINER", "BRUTE_FORCE", "CONTAINER_ESCAPE"):
            suggestions.append(f'threat == "{threat}"')

        model = QStringListModel(suggestions, self)
        completer = QCompleter(model, self)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.line_edit.setCompleter(completer)

    def _rebuild_bookmark_menu(self):
        """Rebuilds bookmark dropdown menu from saved settings."""
        menu = QMenu(self)
        bookmarks = self.settings.get_filter_bookmarks()

        for label, expr in bookmarks.items():
            action = menu.addAction(f"{label} ({expr})")
            action.triggered.connect(lambda checked, e=expr: self.set_filter_text(e, auto_apply=True))

        menu.addSeparator()
        save_action = menu.addAction("Bookmark Current Filter...")
        save_action.triggered.connect(self._bookmark_current_filter)

        self.bookmark_btn.setMenu(menu)

    def _bookmark_current_filter(self):
        """Saves current filter to bookmarks."""
        expr = self.line_edit.text().strip()
        if not expr:
            return
        bookmarks = self.settings.get_filter_bookmarks()
        bookmarks[expr] = expr
        self.settings.save_filter_bookmarks(bookmarks)
        self._rebuild_bookmark_menu()

    def _on_text_changed(self, text: str):
        """Validates filter expression in real-time as user types."""
        self.clear_btn.setVisible(bool(text.strip()))
        self._update_syntax_style(text)

    def _update_syntax_style(self, text: str):
        """Updates line-edit background color based on syntax validity."""
        is_dark = ThemeManager.is_dark()

        # Update + button style
        if is_dark:
            self.add_btn.setStyleSheet("""
                QToolButton {
                    border: 1px solid #3C3C3C;
                    border-radius: 2px;
                    background-color: #2D2D2D;
                    color: #D4D4D4;
                    font-weight: bold;
                }
                QToolButton:hover {
                    background-color: #383838;
                }
            """)
        else:
            self.add_btn.setStyleSheet("""
                QToolButton {
                    border: 1px solid #B0B0B0;
                    border-radius: 2px;
                    background-color: #F6F6F6;
                    color: #333333;
                    font-weight: bold;
                }
                QToolButton:hover {
                    background-color: #E8E8E8;
                }
            """)

        if not text or not text.strip():
            # Normal state
            if is_dark:
                self.filter_frame.setStyleSheet("""
                    QFrame#filterFrame {
                        background-color: #252526;
                        border: 1px solid #3C3C3C;
                        border-radius: 2px;
                    }
                """)
                self.line_edit.setStyleSheet("QLineEdit#displayFilterLineEdit { border: none; background: transparent; color: #D4D4D4; }")
            else:
                self.filter_frame.setStyleSheet("""
                    QFrame#filterFrame {
                        background-color: #FFFFFF;
                        border: 1px solid #B0B0B0;
                        border-radius: 2px;
                    }
                """)
                self.line_edit.setStyleSheet("QLineEdit#displayFilterLineEdit { border: none; background: transparent; color: #000000; }")

            self.filterSyntaxStatus.emit(True, "")
            return

        is_valid, err_msg = validate_filter(text)

        if is_valid:
            bg = WIRESHARK_COLORS["dark_filter_valid_bg"] if is_dark else WIRESHARK_COLORS["filter_valid_bg"]
            fg = WIRESHARK_COLORS["dark_filter_valid_fg"] if is_dark else WIRESHARK_COLORS["filter_valid_fg"]
            border = "#3A7A06" if is_dark else "#2E7D32"
            self.filter_frame.setStyleSheet(f"""
                QFrame#filterFrame {{
                    background-color: {bg};
                    border: 1px solid {border};
                    border-radius: 2px;
                }}
            """)
            self.line_edit.setStyleSheet(f"QLineEdit#displayFilterLineEdit {{ border: none; background: transparent; color: {fg}; font-weight: bold; }}")
            self.filterSyntaxStatus.emit(True, "")
        else:
            bg = WIRESHARK_COLORS["dark_filter_invalid_bg"] if is_dark else WIRESHARK_COLORS["filter_invalid_bg"]
            fg = WIRESHARK_COLORS["dark_filter_invalid_fg"] if is_dark else WIRESHARK_COLORS["filter_invalid_fg"]
            border = "#7A1818" if is_dark else "#C62828"
            self.filter_frame.setStyleSheet(f"""
                QFrame#filterFrame {{
                    background-color: {bg};
                    border: 1px solid {border};
                    border-radius: 2px;
                }}
            """)
            self.line_edit.setStyleSheet(f"QLineEdit#displayFilterLineEdit {{ border: none; background: transparent; color: {fg}; }}")
            self.filterSyntaxStatus.emit(False, err_msg)


    def apply_filter(self):
        """Emits filterApplied signal with current text."""
        expr = self.line_edit.text().strip()
        if expr:
            self.settings.add_filter_history(expr)
        self.filterApplied.emit(expr)

    def clear_filter(self):
        """Clears filter text and applies empty filter (show all)."""
        self.line_edit.clear()
        self.apply_filter()

    def set_filter_text(self, text: str, auto_apply: bool = False):
        """Sets the filter text programmatically."""
        self.line_edit.setText(text)
        if auto_apply:
            self.apply_filter()
