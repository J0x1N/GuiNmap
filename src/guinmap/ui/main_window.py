"""Main desktop window for the phase 2 interaction shell."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFrame,
    QFormLayout,
    QGridLayout,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("GuiNmap")
        self.resize(1400, 860)
        self.setMinimumSize(1180, 760)
        self._configure_actions()
        self._configure_window()

    def _configure_actions(self) -> None:
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)

        about_phase_action = QAction("Phase 2 Overview", self)
        about_phase_action.setEnabled(False)

        file_menu = self.menuBar().addMenu("File")
        file_menu.addAction(exit_action)

        help_menu = self.menuBar().addMenu("Help")
        help_menu.addAction(about_phase_action)

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
        self.statusBar().showMessage("Phase 2: UI system and interaction shell")
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #edf3f8;
            }
            QWidget {
                font-family: 'Segoe UI';
                color: #152033;
            }
            QFrame#navPanel {
                background: qlineargradient(
                    x1: 0,
                    y1: 0,
                    x2: 0,
                    y2: 1,
                    stop: 0 #0d1b2a,
                    stop: 1 #17324d
                );
                border-radius: 18px;
            }
            QFrame#heroCard {
                background: qlineargradient(
                    x1: 0,
                    y1: 0,
                    x2: 1,
                    y2: 1,
                    stop: 0 #ffffff,
                    stop: 1 #f2f8fc
                );
                border: 1px solid #d3e0eb;
                border-radius: 22px;
            }
            QFrame#sectionCard {
                background-color: #ffffff;
                border: 1px solid #d7e1ea;
                border-radius: 16px;
            }
            QFrame#profileCard {
                background-color: #f7fbfe;
                border: 1px solid #d7e1ea;
                border-radius: 14px;
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
            QPushButton#secondaryButton {
                background-color: #dbe9f2;
                color: #12324b;
            }
            QLineEdit,
            QComboBox,
            QPlainTextEdit,
            QTableWidget {
                background-color: #f8fbff;
                border: 1px solid #d7e0ea;
                border-radius: 12px;
                padding: 8px;
            }
            QTableWidget {
                gridline-color: #dbe5ee;
            }
            QHeaderView::section {
                background-color: #e9f2f8;
                color: #183149;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #d0dde8;
                font-weight: 600;
            }
            QProgressBar {
                background-color: #dbe6ef;
                border: none;
                border-radius: 8px;
                text-align: center;
                min-height: 16px;
            }
            QProgressBar::chunk {
                background-color: #0f766e;
                border-radius: 8px;
            }
            QLabel#badge {
                background-color: #dff3ef;
                color: #0f5f59;
                border-radius: 10px;
                padding: 6px 10px;
                font-size: 11px;
                font-weight: 700;
            }
            QLabel#heroTitle {
                font-size: 30px;
                font-weight: 700;
                color: #0f172a;
            }
            QLabel#heroBody {
                font-size: 14px;
                color: #475569;
            }
            QLabel#sectionTitle {
                font-size: 20px;
                font-weight: 700;
                color: #0f172a;
            }
            QLabel#sectionBody {
                font-size: 13px;
                color: #5b6b7c;
            }
            QLabel#metricValue {
                font-size: 26px;
                font-weight: 700;
                color: #0f172a;
            }
            QLabel#metricLabel {
                font-size: 12px;
                color: #64748b;
            }
            QCheckBox {
                spacing: 8px;
            }
            """
        )

    def _build_navigation(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("navPanel")
        panel.setFixedWidth(270)

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        title = QLabel("GuiNmap")
        title.setStyleSheet("font-size: 24px; font-weight: 700; color: white;")

        subtitle = QLabel("Modern Nmap workflow with structured scan design")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("font-size: 13px; color: #94a3b8;")

        phase = QLabel("Current phase\nUI system and interaction shell")
        phase.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        phase.setStyleSheet(
            "background-color: rgba(15, 118, 110, 0.28);"
            "border-radius: 12px;"
            "padding: 12px;"
            "color: #d1fae5;"
            "font-weight: 600;"
        )

        stack_note = QLabel(
            "Python 3.11\nPySide6 desktop UI\nNmap subprocess + XML results"
        )
        stack_note.setStyleSheet(
            "background-color: rgba(219, 234, 254, 0.10);"
            "border: 1px solid rgba(148, 163, 184, 0.20);"
            "border-radius: 12px;"
            "padding: 12px;"
            "color: #cbd5e1;"
            "font-size: 12px;"
        )

        sections = QListWidget()
        sections.addItems(
            [
                "Overview",
                "Scan Builder",
                "Profiles",
                "Execution",
                "Results",
                "Documentation",
            ]
        )
        sections.setCurrentRow(1)

        footer = QLabel(
            "Windows awareness is built into the design so privileged scans can "
            "later fall back cleanly when raw socket features are unavailable."
        )
        footer.setWordWrap(True)
        footer.setStyleSheet("font-size: 12px; color: #94a3b8;")

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(phase)
        layout.addWidget(stack_note)
        layout.addWidget(sections, stretch=1)
        layout.addWidget(footer)

        return panel

    def _build_content(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)

        layout.addWidget(self._build_header())

        upper_grid = QGridLayout()
        upper_grid.setHorizontalSpacing(18)
        upper_grid.setVerticalSpacing(18)
        upper_grid.addWidget(self._build_scan_builder_panel(), 0, 0, 2, 1)
        upper_grid.addWidget(self._build_profiles_panel(), 0, 1)
        upper_grid.addWidget(self._build_execution_panel(), 1, 1)
        upper_grid.setColumnStretch(0, 3)
        upper_grid.setColumnStretch(1, 2)

        lower_grid = QGridLayout()
        lower_grid.setHorizontalSpacing(18)
        lower_grid.addWidget(self._build_results_panel(), 0, 0)
        lower_grid.addWidget(self._build_console_panel(), 0, 1)
        lower_grid.setColumnStretch(0, 3)
        lower_grid.setColumnStretch(1, 2)

        layout.addLayout(upper_grid)
        layout.addLayout(lower_grid, 1)

        return container

    def _build_header(self) -> QFrame:
        card = QFrame()
        card.setObjectName("heroCard")

        layout = QHBoxLayout(card)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(24)

        left_column = QVBoxLayout()
        left_column.setSpacing(12)

        badge = QLabel("PHASE 2")
        badge.setObjectName("badge")

        title = QLabel("UI system designed around the real Nmap workflow")
        title.setObjectName("heroTitle")
        title.setWordWrap(True)

        body = QLabel(
            "The window is no longer a generic placeholder. It now reflects the "
            "planned workflow: define a scan, choose a profile, preview execution, "
            "and inspect structured results generated from XML."
        )
        body.setObjectName("heroBody")
        body.setWordWrap(True)

        actions = QHBoxLayout()
        preview_button = QPushButton("Review UI structure")
        preview_button.setEnabled(False)
        docs_button = QPushButton("Local docs loaded")
        docs_button.setObjectName("secondaryButton")
        docs_button.setEnabled(False)
        actions.addWidget(preview_button)
        actions.addWidget(docs_button)
        actions.addStretch(1)

        left_column.addWidget(badge)
        left_column.addWidget(title)
        left_column.addWidget(body)
        left_column.addLayout(actions)

        metrics = QGridLayout()
        metrics.setHorizontalSpacing(20)
        metrics.setVerticalSpacing(14)
        metrics.addWidget(self._build_metric_tile("4", "Core panels"), 0, 0)
        metrics.addWidget(self._build_metric_tile("XML", "Result source"), 0, 1)
        metrics.addWidget(self._build_metric_tile("T3/T4", "Default timing focus"), 1, 0)
        metrics.addWidget(self._build_metric_tile("Windows", "Privilege-aware UX"), 1, 1)

        layout.addLayout(left_column, 3)
        layout.addLayout(metrics, 2)

        return card

    def _build_metric_tile(self, value: str, label: str) -> QFrame:
        card = QFrame()
        card.setObjectName("profileCard")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(4)

        value_label = QLabel(value)
        value_label.setObjectName("metricValue")

        body_label = QLabel(label)
        body_label.setObjectName("metricLabel")
        body_label.setWordWrap(True)

        layout.addWidget(value_label)
        layout.addWidget(body_label)

        return card

    def _build_scan_builder_panel(self) -> QFrame:
        card, layout = self._create_section_card(
            "Scan Builder",
            "Phase 3 will bind these widgets to typed scan profiles and generate a "
            "validated Nmap argument list with XML output by default.",
        )

        form = QFormLayout()
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(12)

        target_input = QLineEdit()
        target_input.setPlaceholderText("scanme.nmap.org, 192.168.1.0/24, 10.0.0.10")

        ports_input = QLineEdit()
        ports_input.setPlaceholderText("22,80,443 or 1-1024")

        scan_type = QComboBox()
        scan_type.addItems(
            [
                "Default TCP connect",
                "TCP SYN (privileged)",
                "UDP scan",
                "Host discovery only",
            ]
        )

        timing = QComboBox()
        timing.addItems(["T3 Normal", "T4 Aggressive", "Custom tuning later"])

        profile = QComboBox()
        profile.addItems(
            [
                "Quick discovery",
                "Balanced TCP inventory",
                "Service fingerprint",
                "Deep assessment",
            ]
        )

        form.addRow("Targets", target_input)
        form.addRow("Ports", ports_input)
        form.addRow("Scan type", scan_type)
        form.addRow("Timing", timing)
        form.addRow("Preset profile", profile)

        option_row = QHBoxLayout()
        option_row.setSpacing(16)

        service_check = QCheckBox("Service detection (-sV)")
        service_check.setChecked(True)
        os_check = QCheckBox("OS detection (-O)")
        default_scripts_check = QCheckBox("Default NSE (-sC)")
        traceroute_check = QCheckBox("Traceroute")

        option_row.addWidget(service_check)
        option_row.addWidget(os_check)
        option_row.addWidget(default_scripts_check)
        option_row.addWidget(traceroute_check)
        option_row.addStretch(1)

        advanced_args = QPlainTextEdit()
        advanced_args.setPlaceholderText(
            "Optional advanced args, one logical group per line. Example:\n"
            "--reason\n--stats-every 5s\n--open"
        )
        advanced_args.setFixedHeight(96)

        command_preview = QPlainTextEdit()
        command_preview.setReadOnly(True)
        command_preview.setFixedHeight(120)
        command_preview.setPlainText(
            "nmap -oX <temp file> --stats-every 5s -T4 -sT -sV --reason "
            "-p 22,80,443 scanme.nmap.org"
        )

        button_row = QHBoxLayout()
        validate_button = QPushButton("Validate profile")
        preview_button = QPushButton("Preview command")
        preview_button.setObjectName("secondaryButton")
        run_button = QPushButton("Run scan")
        run_button.setEnabled(False)
        button_row.addWidget(validate_button)
        button_row.addWidget(preview_button)
        button_row.addWidget(run_button)
        button_row.addStretch(1)

        layout.addLayout(form)
        layout.addLayout(option_row)
        layout.addWidget(self._build_inline_label("Advanced arguments"))
        layout.addWidget(advanced_args)
        layout.addWidget(self._build_inline_label("Generated command preview"))
        layout.addWidget(command_preview)
        layout.addLayout(button_row)

        return card

    def _build_profiles_panel(self) -> QFrame:
        card, layout = self._create_section_card(
            "Profiles",
            "The product will start with opinionated profiles that expose good "
            "defaults instead of forcing every user to learn dozens of Nmap flags upfront.",
        )

        layout.addWidget(
            self._build_profile_card(
                "Quick discovery",
                "Map live hosts first with low friction and minimal noise.",
                "-sn -PE -PS443 -PA80",
            )
        )
        layout.addWidget(
            self._build_profile_card(
                "Balanced TCP inventory",
                "Windows-friendly baseline for service inventory and reporting.",
                "-sT -sV -T3 --reason",
            )
        )
        layout.addWidget(
            self._build_profile_card(
                "Fast service fingerprint",
                "Sharper TCP pass for responsive networks where speed matters.",
                "-sS -sV -T4 --top-ports 100",
            )
        )

        warning = QLabel(
            "Privileged modes will be capability-checked later so the GUI can fall "
            "back to safer behavior instead of failing with opaque errors."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet("font-size: 12px; color: #64748b;")
        layout.addWidget(warning)

        return card

    def _build_profile_card(self, title: str, body: str, command: str) -> QFrame:
        card = QFrame()
        card.setObjectName("profileCard")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(6)

        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 16px; font-weight: 700; color: #0f172a;")

        body_label = QLabel(body)
        body_label.setWordWrap(True)
        body_label.setStyleSheet("font-size: 12px; color: #536578;")

        command_label = QLabel(command)
        command_label.setStyleSheet(
            "font-family: Consolas; font-size: 12px; color: #0f5f59;"
            "background-color: #e4f4f1; border-radius: 8px; padding: 6px 8px;"
        )

        layout.addWidget(title_label)
        layout.addWidget(body_label)
        layout.addWidget(command_label)

        return card

    def _build_execution_panel(self) -> QFrame:
        card, layout = self._create_section_card(
            "Execution model",
            "The UI already reserves space for progress, environment feedback, and "
            "process status so phase 3 can wire the real subprocess executor cleanly.",
        )

        progress = QProgressBar()
        progress.setRange(0, 100)
        progress.setValue(35)
        progress.setFormat("UI readiness 35% - process wiring starts in phase 3")

        status_notes = QPlainTextEdit()
        status_notes.setReadOnly(True)
        status_notes.setFixedHeight(136)
        status_notes.setPlainText(
            "Execution flow\n"
            "1. Validate structured profile fields\n"
            "2. Create temporary XML artifact path\n"
            "3. Start nmap with shell=False\n"
            "4. Capture progress with --stats-every\n"
            "5. Parse XML into domain models\n"
            "6. Render host and port details in result views"
        )

        environment_note = QLabel(
            "Windows note: SYN scan, OS detection, and some raw-packet workflows may "
            "require elevation and Npcap. The GUI should surface that explicitly."
        )
        environment_note.setWordWrap(True)
        environment_note.setStyleSheet("font-size: 12px; color: #64748b;")

        layout.addWidget(progress)
        layout.addWidget(status_notes)
        layout.addWidget(environment_note)

        return card

    def _build_results_panel(self) -> QFrame:
        card, layout = self._create_section_card(
            "Results preview",
            "The final application will render typed results from XML, not brittle "
            "parsing of interactive terminal text.",
        )

        table = QTableWidget(3, 5)
        table.setHorizontalHeaderLabels(["Host", "Proto", "Port", "State", "Service"])
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)

        rows = [
            ["192.168.1.1", "tcp", "443", "open", "https"],
            ["192.168.1.10", "tcp", "22", "open", "ssh"],
            ["192.168.1.15", "udp", "53", "open|filtered", "dns"],
        ]

        for row_index, row in enumerate(rows):
            for column_index, value in enumerate(row):
                table.setItem(row_index, column_index, QTableWidgetItem(value))

        detail_note = QLabel(
            "Expected later: host cards, port drill-down, service metadata, reasons, "
            "and export-ready report views."
        )
        detail_note.setWordWrap(True)
        detail_note.setStyleSheet("font-size: 12px; color: #64748b;")

        layout.addWidget(table)
        layout.addWidget(detail_note)

        return card

    def _build_console_panel(self) -> QFrame:
        card, layout = self._create_section_card(
            "Runtime console",
            "This panel will later merge process lifecycle messages, periodic stats, "
            "and parser events into a single operator-friendly timeline.",
        )

        console = QPlainTextEdit()
        console.setReadOnly(True)
        console.setPlainText(
            "[phase-2] Local Nmap reference stored in documentation.txt\n"
            "[phase-2] XML remains the canonical result artifact\n"
            "[phase-2] --stats-every will drive progress updates\n"
            "[phase-3] Subprocess execution and cancellation are not wired yet\n"
            "[phase-4] XML parsing will populate typed result models"
        )

        layout.addWidget(console)

        return card

    def _create_section_card(self, title: str, body: str) -> tuple[QFrame, QVBoxLayout]:
        card = QFrame()
        card.setObjectName("sectionCard")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        title_label = QLabel(title)
        title_label.setObjectName("sectionTitle")

        body_label = QLabel(body)
        body_label.setObjectName("sectionBody")
        body_label.setWordWrap(True)

        layout.addWidget(title_label)
        layout.addWidget(body_label)

        return card, layout

    def _build_inline_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setStyleSheet("font-size: 12px; font-weight: 600; color: #334155;")
        return label

