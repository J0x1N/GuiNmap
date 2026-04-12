"""Main desktop window for the project shell."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("GuiNmap")
        self.resize(1280, 760)
        self.setMinimumSize(1080, 680)
        self._configure_actions()
        self._configure_window()

    def _configure_actions(self) -> None:
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)

        file_menu = self.menuBar().addMenu("File")
        file_menu.addAction(exit_action)

    def _configure_window(self) -> None:
        root = QWidget()
        layout = QHBoxLayout(root)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        navigation = self._build_navigation()
        content = self._build_content()

        layout.addWidget(navigation)
        layout.addWidget(content, stretch=1)

        self.setCentralWidget(root)
        self.statusBar().showMessage("Phase 1: architecture and project shell")
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #f3f7fb;
            }
            QWidget {
                font-family: 'Segoe UI';
                color: #172033;
            }
            QFrame#navPanel {
                background: qlineargradient(
                    x1: 0,
                    y1: 0,
                    x2: 0,
                    y2: 1,
                    stop: 0 #0f172a,
                    stop: 1 #15233d
                );
                border-radius: 18px;
            }
            QFrame#card {
                background-color: #ffffff;
                border: 1px solid #d7e0ea;
                border-radius: 16px;
            }
            QListWidget {
                background: transparent;
                border: none;
                color: #e2e8f0;
                font-size: 14px;
                padding: 8px 0;
            }
            QListWidget::item {
                padding: 10px 12px;
                border-radius: 10px;
                margin: 2px 0;
            }
            QListWidget::item:selected {
                background-color: rgba(56, 189, 248, 0.18);
            }
            QPushButton {
                background-color: #0f766e;
                color: white;
                border: none;
                border-radius: 10px;
                padding: 10px 16px;
                font-weight: 600;
            }
            QPushButton:disabled {
                background-color: #9ca3af;
            }
            QTextEdit {
                background-color: #f8fbff;
                border: 1px solid #d7e0ea;
                border-radius: 12px;
                padding: 10px;
            }
            """
        )

    def _build_navigation(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("navPanel")
        panel.setFixedWidth(250)

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        title = QLabel("GuiNmap")
        title.setStyleSheet("font-size: 24px; font-weight: 700; color: white;")

        subtitle = QLabel("Modern Nmap workflow")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("font-size: 13px; color: #94a3b8;")

        phase = QLabel("Current phase\nFoundation and architecture")
        phase.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        phase.setStyleSheet(
            "background-color: rgba(15, 118, 110, 0.28);"
            "border-radius: 12px;"
            "padding: 12px;"
            "color: #d1fae5;"
            "font-weight: 600;"
        )

        sections = QListWidget()
        sections.addItems(
            [
                "Architecture",
                "Scan Builder",
                "Profiles",
                "Execution",
                "Results",
                "Reports",
            ]
        )
        sections.setCurrentRow(0)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(phase)
        layout.addWidget(sections, stretch=1)

        return panel

    def _build_content(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)

        header = QLabel("Foundation layer ready for iterative development")
        header.setStyleSheet("font-size: 28px; font-weight: 700; color: #0f172a;")

        description = QLabel(
            "This first iteration focuses on architecture, packaging, and the core "
            "interfaces needed to integrate Nmap safely and parse structured results."
        )
        description.setWordWrap(True)
        description.setStyleSheet("font-size: 14px; color: #475569;")

        action_row = QHBoxLayout()
        review_button = QPushButton("Review architecture")
        review_button.setEnabled(False)
        launch_button = QPushButton("Scan flow in phase 3")
        launch_button.setEnabled(False)
        action_row.addWidget(review_button)
        action_row.addWidget(launch_button)
        action_row.addStretch(1)

        card_grid = QGridLayout()
        card_grid.setHorizontalSpacing(18)
        card_grid.setVerticalSpacing(18)
        card_grid.addWidget(
            self._build_card(
                "Target definition",
                "Profiles will capture targets, port ranges, timing templates, and "
                "advanced arguments without relying on shell parsing.",
            ),
            0,
            0,
        )
        card_grid.addWidget(
            self._build_card(
                "Execution strategy",
                "The application will call the system Nmap binary through a safe "
                "argument list and collect XML output as the canonical scan artifact.",
            ),
            0,
            1,
        )
        card_grid.addWidget(
            self._build_card(
                "Result pipeline",
                "Completed scans will be converted into typed domain models so the "
                "GUI can render tables, host cards, and report exports consistently.",
            ),
            1,
            0,
            1,
            2,
        )

        preview = QTextEdit()
        preview.setReadOnly(True)
        preview.setPlainText(
            "Phase 1 notes\n\n"
            "- PySide6 selected as the desktop toolkit.\n"
            "- Direct subprocess integration selected over wrapper libraries.\n"
            "- XML selected as the source of truth for completed scan results.\n"
            "- Windows capability checks will be added before privileged scan modes."
        )

        layout.addWidget(header)
        layout.addWidget(description)
        layout.addLayout(action_row)
        layout.addLayout(card_grid)
        layout.addWidget(preview, stretch=1)

        return container

    def _build_card(self, title: str, body: str) -> QFrame:
        card = QFrame()
        card.setObjectName("card")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(10)

        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 18px; font-weight: 700; color: #0f172a;")

        body_label = QLabel(body)
        body_label.setWordWrap(True)
        body_label.setStyleSheet("font-size: 13px; color: #475569;")

        layout.addWidget(title_label)
        layout.addWidget(body_label)
        layout.addStretch(1)

        return card
