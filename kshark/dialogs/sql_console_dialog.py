"""
KShark Interactive SQL Query Console Dialog (DuckDB / SQLite Columnar Engine).
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt
import sqlite3

try:
    import duckdb
    _HAS_DUCKDB = True
except ImportError:
    duckdb = None
    _HAS_DUCKDB = False

from kshark.core.theme import get_monospace_font, get_ui_font


class SQLConsoleDialog(QDialog):
    """
    Interactive SQL query interface for live telemetry events.
    Uses DuckDB if available, otherwise falls back to SQLite in-memory engine.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        engine_name = "DuckDB" if _HAS_DUCKDB else "SQLite"
        self.setWindowTitle(f"KShark · {engine_name} SQL Console")
        self.resize(750, 480)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        engine_desc = "DuckDB (Columnar OLAP)" if _HAS_DUCKDB else "SQLite (In-Memory Engine)"
        layout.addWidget(QLabel(f"Execute SQL Analytics on live telemetry events (Engine: <b>{engine_desc}</b>):"))

        self.query_editor = QTextEdit(self)
        self.query_editor.setFont(get_monospace_font(size=9))
        self.query_editor.setPlainText("SELECT comm, count(*) as event_count FROM events GROUP BY comm ORDER BY event_count DESC LIMIT 10;")
        self.query_editor.setMaximumHeight(80)
        layout.addWidget(self.query_editor)

        btn_bar = QHBoxLayout()
        self.btn_run = QPushButton("▶ Run Query", self)
        self.btn_run.setFont(get_ui_font(size=8.5, bold=True))
        self.btn_run.clicked.connect(self._run_query)
        btn_bar.addWidget(self.btn_run)
        btn_bar.addStretch(1)
        layout.addLayout(btn_bar)

        self.table = QTableWidget(self)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setFont(get_monospace_font(size=8.5))
        layout.addWidget(self.table, stretch=1)

        btn_close_bar = QHBoxLayout()
        btn_close_bar.addStretch(1)
        btn_close = QPushButton("Close", self)
        btn_close.setFont(get_ui_font(size=8.5))
        btn_close.clicked.connect(self.accept)
        btn_close_bar.addWidget(btn_close)
        layout.addLayout(btn_close_bar)

    def _run_query(self):
        sql = self.query_editor.toPlainText().strip()
        if not sql:
            return

        try:
            # ── Retrieve actual captured events from parent window ──
            events = []
            parent = self.parent()
            if parent is not None and hasattr(parent, "table_model"):
                events = list(parent.table_model._events)

            if not events:
                self.table.setRowCount(1)
                self.table.setColumnCount(1)
                self.table.setHorizontalHeaderLabels(["Info"])
                self.table.setItem(0, 0, QTableWidgetItem(
                    "No events captured — start a live capture or open a file first."))
                return

            if _HAS_DUCKDB:
                import pandas as pd
                df = pd.DataFrame(events)
                conn = duckdb.connect(":memory:")
                conn.register("events", df)
                result = conn.execute(sql).df()

                self.table.setRowCount(len(result))
                self.table.setColumnCount(len(result.columns))
                self.table.setHorizontalHeaderLabels([str(c) for c in result.columns])

                for r_idx, row in result.iterrows():
                    for c_idx, val in enumerate(row):
                        self.table.setItem(r_idx, c_idx, QTableWidgetItem(str(val)))
            else:
                # SQLite fallback
                conn = sqlite3.connect(":memory:")
                cur = conn.cursor()

                # Determine all column names from events
                all_cols = set()
                for ev in events:
                    all_cols.update(ev.keys())
                col_list = sorted(list(all_cols))

                # Create table
                col_defs = ", ".join([f'"{c}" TEXT' for c in col_list])
                cur.execute(f"CREATE TABLE events ({col_defs})")

                # Insert events
                placeholders = ", ".join(["?"] * len(col_list))
                rows_data = []
                for ev in events:
                    row = [str(ev.get(c, "")) for c in col_list]
                    rows_data.append(row)

                cur.executemany(f"INSERT INTO events VALUES ({placeholders})", rows_data)
                conn.commit()

                # Execute user query
                cur.execute(sql)
                headers = [desc[0] for desc in cur.description] if cur.description else ["Result"]
                rows = cur.fetchall()

                self.table.setRowCount(len(rows))
                self.table.setColumnCount(len(headers))
                self.table.setHorizontalHeaderLabels(headers)

                for r_idx, row in enumerate(rows):
                    for c_idx, val in enumerate(row):
                        self.table.setItem(r_idx, c_idx, QTableWidgetItem(str(val)))

        except Exception as e:
            self.table.setRowCount(1)
            self.table.setColumnCount(1)
            self.table.setHorizontalHeaderLabels(["Error"])
            self.table.setItem(0, 0, QTableWidgetItem(str(e)))
