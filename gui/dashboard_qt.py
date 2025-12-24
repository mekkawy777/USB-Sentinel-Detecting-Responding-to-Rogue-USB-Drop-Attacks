import sys
import os
import queue
import subprocess

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTableWidget, QTableWidgetItem, QComboBox
)
from PyQt6.QtCore import Qt, QTimer

from core.engine import UsbSentinelCore

SAFE_VIEW_DIR = "safe_view"   # NEW


class Dashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("USB Sentinel EDR – Enterprise Dashboard")
        self.resize(1300, 700)

        self.event_queue = queue.Queue()
        self.core = UsbSentinelCore(self.event_queue, self.popup)

        self._build_ui()
        self._start_timer()

    # =========================
    # UI
    # =========================
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # ===== Toolbar =====
        top = QHBoxLayout()

        self.btn_start = QPushButton("▶ Start")
        self.btn_stop = QPushButton("■ Stop")

        self.btn_safe_view = QPushButton("📂 Open Safe View")   # NEW

        self.btn_start.clicked.connect(self.start_agent)
        self.btn_stop.clicked.connect(self.stop_agent)
        self.btn_safe_view.clicked.connect(self.open_safe_view)  # NEW

        self.level_filter = QComboBox()
        self.level_filter.addItems(["ALL", "INFO", "WARNING", "CRITICAL"])

        self.status = QLabel("Status: Idle")
        self.status.setStyleSheet("color: lightgreen;")

        top.addWidget(self.btn_start)
        top.addWidget(self.btn_stop)
        top.addWidget(self.btn_safe_view)   # NEW
        top.addWidget(QLabel("Filter level:"))
        top.addWidget(self.level_filter)
        top.addStretch()
        top.addWidget(self.status)

        layout.addLayout(top)

        # ===== Table =====
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Time", "Level", "Action", "File Path", "ML", "VT"]
        )

        self.table.setColumnWidth(0, 160)
        self.table.setColumnWidth(1, 90)
        self.table.setColumnWidth(2, 240)
        self.table.setColumnWidth(3, 540)
        self.table.setColumnWidth(4, 80)
        self.table.setColumnWidth(5, 80)

        self.table.verticalHeader().setDefaultSectionSize(28)
        self.table.setAlternatingRowColors(True)

        self.table.setStyleSheet("""
        QTableWidget {
            background-color: #121212;
            color: #EAEAEA;
            gridline-color: #2A2A2A;
            font-size: 13px;
        }
        QHeaderView::section {
            background-color: #1F1F1F;
            color: white;
            padding: 6px;
            border: 1px solid #2A2A2A;
        }
        QTableWidget::item:selected {
            background-color: #2D4F7C;
        }
        """)

        layout.addWidget(self.table)

    # =========================
    # Controls
    # =========================
    def start_agent(self):
        self.core.start()
        self.status.setText("🟢 Status: Monitoring")

    def stop_agent(self):
        self.core.stop()
        self.status.setText("🔴 Status: Stopped")

    def popup(self, msg):
        pass

    # =========================
    # SAFE VIEW BUTTON
    # =========================
    def open_safe_view(self):
        """
        Opens safe_view directory or selected SAFE file
        """
        if not os.path.exists(SAFE_VIEW_DIR):
            return

        selected = self.table.currentRow()

        # لو فيه صف متحدد وجاي من safe_view
        if selected >= 0:
            item = self.table.item(selected, 3)  # File Path column
            if item:
                path = item.text()
                if path and "safe_view" in path and os.path.exists(path):
                    self._open_path(path)
                    return

        # غير كده افتح فولدر safe_view
        self._open_path(SAFE_VIEW_DIR)

    def _open_path(self, path):
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", path])
            elif sys.platform.startswith("win"):
                os.startfile(path)
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception:
            pass

    # =========================
    # Event Processing
    # =========================
    def _start_timer(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.process_events)
        self.timer.start(200)

    def process_events(self):
        while not self.event_queue.empty():
            kind, payload = self.event_queue.get()

            if kind == "LOG":
                self.handle_log(payload)

    def handle_log(self, e: dict):
        level_filter = self.level_filter.currentText()
        if level_filter != "ALL" and e.get("level") != level_filter:
            return

        row = self.table.rowCount()
        self.table.insertRow(row)

        extra = e.get("extra", {})

        time_item = QTableWidgetItem(e.get("timestamp", ""))
        level_item = QTableWidgetItem(e.get("level", ""))
        action_item = QTableWidgetItem(e.get("message", ""))
        file_item = QTableWidgetItem(e.get("file_path", ""))

        if e.get("file_path"):
            file_item.setToolTip(e.get("file_path"))

        ml = extra.get("ml_score")
        vt = extra.get("vt_malicious")

        ml_item = QTableWidgetItem(
            "SAFE" if ml is not None and ml < 0.4 else
            f"{ml:.2f}" if ml is not None else "-"
        )

        vt_item = QTableWidgetItem(str(vt) if vt is not None else "-")

        level = e.get("level", "")
        color = (
            Qt.GlobalColor.red if level == "CRITICAL"
            else Qt.GlobalColor.yellow if level == "WARNING"
            else Qt.GlobalColor.green
        )

        for item in [
            time_item, level_item, action_item,
            file_item, ml_item, vt_item
        ]:
            item.setForeground(color)

        self.table.setItem(row, 0, time_item)
        self.table.setItem(row, 1, level_item)
        self.table.setItem(row, 2, action_item)
        self.table.setItem(row, 3, file_item)
        self.table.setItem(row, 4, ml_item)
        self.table.setItem(row, 5, vt_item)

        self.table.scrollToBottom()


# =========================
# Main
# =========================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Dashboard()
    win.show()
    sys.exit(app.exec())
