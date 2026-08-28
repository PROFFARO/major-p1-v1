"""
DuckDB Analytical SQL Console Dialog for KShark (Wireshark Statistics & SQL Query Equivalent).
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton, QTableWidget, 
    QTableWidgetItem, QLabel, QComboBox, QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt
import time
from typing import Optional

from ml_engine.storage import DatabaseManager
from kshark.core.theme import get_monospace_font


class SQLConsoleDialog(QDialog):
    """
    Direct Analytical SQL Query Workbench against DuckDB telemetry storage.
    """

    TEMPLATES = {
        "Top 10 Executed Processes": "SELECT comm, exe_path, COUNT(*) AS exec_count FROM telemetry_events GROUP BY comm, exe_path ORDER BY exec_count DESC LIMIT 10;",
        "Top 10 Outbound Network Destinations": "SELECT dst_ip, dst_port, COUNT(*) AS conn_count FROM telemetry_events WHERE dst_ip != '0.0.0.0' GROUP BY dst_ip, dst_port ORDER BY conn_count DESC LIMIT 10;",
        "Syscall Frequency Breakdown": "SELECT syscall_id, COUNT(*) AS frequency FROM telemetry_events GROUP BY syscall_id ORDER BY frequency DESC LIMIT 20;",
        "Anomalous Feature Windows (Confidence >= 80%)": "SELECT pid, agreed_threat, confidence, rf_prediction, xgb_prediction, iso_score FROM feature_windows WHERE confidence >= 0.80 ORDER BY confidence DESC LIMIT 50;",
        "Recent Suspicious /tmp Executions": "SELECT timestamp_ns, pid, comm, exe_path, file_path FROM telemetry_events WHERE file_path LIKE '%/tmp%' OR exe_path LIKE '%/tmp%' LIMIT 50;",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("KShark · DuckDB Analytical SQL Console")
        self.resize(850, 560)
        self.db_mgr = DatabaseManager()
        self._last_rows = []

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # 1. Template Chooser Top Bar
        top_bar = QHBoxLayout()
        top_bar.addWidget(QLabel("Query Template:"), 0)

        self.template_combo = QComboBox(self)
        self.template_combo.addItems(list(self.TEMPLATES.keys()))
        self.template_combo.currentIndexChanged.connect(self._on_template_selected)
        top_bar.addWidget(self.template_combo, 1)

        layout.addLayout(top_bar)

        # 2. SQL Query Editor
        self.query_edit = QTextEdit(self)
        self.query_edit.setFont(get_monospace_font(size=9.5))
        self.query_edit.setPlaceholderText("Enter read-only SQL query (SELECT ...) and press Run Query or Ctrl+Enter")
        self.query_edit.setFixedHeight(110)
        self.query_edit.setPlainText(self.TEMPLATES["Top 10 Executed Processes"])
        layout.addWidget(self.query_edit)

        # 3. Action Bar (Run, Export CSV, Runtime indicator)
        act_bar = QHBoxLayout()
        self.run_btn = QPushButton("▶  Run Query (Ctrl+Enter)")
        self.run_btn.setStyleSheet("background-color: #007ACC; color: #FFFFFF; font-weight: bold; padding: 5px 12px;")
        self.run_btn.clicked.connect(self.run_query)
        act_bar.addWidget(self.run_btn)

        self.export_csv_btn = QPushButton("Export CSV...")
        self.export_csv_btn.clicked.connect(self._export_csv)
        act_bar.addWidget(self.export_csv_btn)

        self.export_parquet_btn = QPushButton("Export Parquet...")
        self.export_parquet_btn.clicked.connect(self._export_parquet)
        act_bar.addWidget(self.export_parquet_btn)

        act_bar.addStretch(1)
        self.stats_lbl = QLabel("Ready")
        self.stats_lbl.setStyleSheet("color: #666666; font-size: 8.5pt;")
        act_bar.addWidget(self.stats_lbl)

        layout.addLayout(act_bar)

        # 4. Results Table
        self.results_table = QTableWidget(self)
        self.results_table.setFont(get_monospace_font(size=8.5))
        layout.addWidget(self.results_table, stretch=1)

    def _on_template_selected(self, index: int):
        key = self.template_combo.currentText()
        if key in self.TEMPLATES:
            self.query_edit.setPlainText(self.TEMPLATES[key])

    def run_query(self):
        """Executes analytical SQL query against DuckDB."""
        sql = self.query_edit.toPlainText().strip()
        if not sql:
            return

        # Security check: disallow modifying queries
        sql_upper = sql.upper()
        if not (sql_upper.startswith("SELECT") or sql_upper.startswith("WITH") or sql_upper.startswith("SHOW") or sql_upper.startswith("DESCRIBE")):
            QMessageBox.warning(self, "Security Error", "Only read-only analytical queries (SELECT / WITH / SHOW) are permitted.")
            return

        start_time = time.perf_counter()
        try:
            rows = self.db_mgr.duckdb.query_sql(sql, limit=5000)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            self._last_rows = rows
            self._populate_results(rows)
            self.stats_lbl.setText(f"Returned {len(rows):,} rows in {elapsed_ms:.1f} ms")
        except Exception as e:
            self.stats_lbl.setText("Query failed")
            QMessageBox.critical(self, "DuckDB SQL Error", str(e))

    def _populate_results(self, rows: list):
        self.results_table.clear()
        if not rows:
            self.results_table.setRowCount(0)
            self.results_table.setColumnCount(0)
            return

        cols = list(rows[0].keys())
        self.results_table.setColumnCount(len(cols))
        self.results_table.setRowCount(len(rows))
        self.results_table.setHorizontalHeaderLabels(cols)

        for r_idx, row_dict in enumerate(rows):
            for c_idx, col_name in enumerate(cols):
                val = row_dict.get(col_name, "")
                item = QTableWidgetItem(str(val))
                self.results_table.setItem(r_idx, c_idx, item)

    def _export_csv(self):
        if not self._last_rows:
            QMessageBox.information(self, "Export", "No query results to export.")
            return
        fp, _ = QFileDialog.getSaveFileName(self, "Export Results as CSV", "kshark_query_results.csv", "CSV Files (*.csv)")
        if fp:
            sql = self.query_edit.toPlainText().strip()
            self.db_mgr.duckdb.export_query(sql, "csv", fp)
            QMessageBox.information(self, "Export Success", f"Successfully exported to {fp}")

    def _export_parquet(self):
        if not self._last_rows:
            QMessageBox.information(self, "Export", "No query results to export.")
            return
        fp, _ = QFileDialog.getSaveFileName(self, "Export Results as Parquet", "kshark_query_results.parquet", "Parquet Files (*.parquet)")
        if fp:
            sql = self.query_edit.toPlainText().strip()
            self.db_mgr.duckdb.export_query(sql, "parquet", fp)
            QMessageBox.information(self, "Export Success", f"Successfully exported to {fp}")
