"""Application bootstrap helpers."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from guinmap.ui.main_window import MainWindow


def run() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("GuiNmap")
    app.setOrganizationName("GuiNmap")

    window = MainWindow()
    window.show()

    return app.exec()
