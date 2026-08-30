"""
KShark Interactive DuckDB SQL Query Console Dialog.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt
import duckdb

from kshark.core.theme import get_monospace_font


class SQLConsoleDialog(QDialog):
    """
    Interactive DuckDB SQL query interface.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("KShark · DuckDB SQL Console")
        self.resize(750, 480)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        layout.addWidget(QLabel("Execute DuckDB SQL Analytics on telemetry events:"))

        self.query_editor = QTextEdit(self)
        self.query_editor.setFont(get_monospace_font(size=9))
        self.query_editor.setPlainText("SELECT comm, count(*) as event_count FROM telemetry_events GROUP BY comm ORDER BY event_count DESC LIMIT 10;")
        self.query_editor.setMaximumHeight(80)
        layout.addWidget(self.query_editor)

        btn_bar = QHBoxLayout()
        self.btn_run = QPushButton("▶ Run Query", self)
        self.btn_run.clicked.connect(self._run_query)
        btn_bar.addWidget(self.btn_run)
        btn_bar.addStretch(1)
        layout.addLayout(btn_bar)

        self.table = QTableWidget(self)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, stretch=1)

        btn_close_bar = QHBoxLayout()
        btn_close_bar.addStretch(1)
        btn_close = QPushButton("Close", self)
        btn_close.clicked.connect(self.accept)
        btn_close_bar.addWidget(btn_close)
        layout.addLayout(btn_close_bar)

    def _run_query(self):
        sql = self.query_editor.toPlainText().strip()
        if not sql:
            return

        try:
            conn = duckdb.connect(":memory:")
            # Sample virtual table if database is in-memory
            conn.execute("CREATE TABLE telemetry_events (comm VARCHAR, pid INT, syscall VARCHAR);")
            conn.execute("INSERT INTO telemetry_events VALUES ('python3', 1001, 'execve'), ('curl', 1002, 'openat'), ('firefox', 1003, 'connect');")
            df = conn.execute(sql).df()

            self.table.setRowCount(len(df))
            self.table.setColumnCount(len(df.columns))
            self.table.setHorizontalHeaderLabels([str(c) for c in df.columns])

            for r_idx, row in df.iterrows():
                for c_idx, val in enumerate(row):
                    self.table.setItem(r_idx, c_idx, QTableWidgetItem(str(val)))
        except Exception as e:
            self.table.setRowCount(1)
            self.table.setColumnCount(1)
            self.table.setHorizontalHeaderLabels(["Error"])
            self.table.setItem(0, 0, QTableWidgetItem(str(e)))
