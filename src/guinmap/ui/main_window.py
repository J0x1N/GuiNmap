"""Main desktop window for the interactive Nmap workflow."""

from __future__ import annotations

import subprocess

from PySide6.QtCore import Qt, QThread, Slot
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from guinmap.application import (
    EnvironmentDiagnostics,
    EnvironmentDiagnosticsService,
    ScanExecution,
    ScanPreset,
    ScanProfileBuilder,
    ScanProfileDraft,
    ScanService,
    get_scan_presets,
)
from guinmap.domain.scan_profile import ScanProfile
from guinmap.domain.scan_result import HostResult, PortResult, ScanResult
from guinmap.ui.scan_worker import ScanWorker

SCAN_TYPE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Nmap default behavior", "default"),
    ("TCP connect (-sT)", "connect"),
    ("TCP SYN (-sS)", "syn"),
    ("UDP scan (-sU)", "udp"),
    ("Host discovery only (-sn)", "ping"),
)

TIMING_OPTIONS: tuple[tuple[str, int], ...] = (
    ("T0 Paranoid", 0),
    ("T1 Sneaky", 1),
    ("T2 Polite", 2),
    ("T3 Normal", 3),
    ("T4 Aggressive", 4),
    ("T5 Insane", 5),
)


class MainWindow(QMainWindow):
    def __init__(
        self,
        *,
        scan_service: ScanService | None = None,
        diagnostics_service: EnvironmentDiagnosticsService | None = None,
        profile_builder: ScanProfileBuilder | None = None,
    ) -> None:
        super().__init__()
        self._presets = get_scan_presets()
        self._scan_service = ScanService() if scan_service is None else scan_service
        self._diagnostics_service = (
            EnvironmentDiagnosticsService()
            if diagnostics_service is None
            else diagnostics_service
        )
        self._profile_builder = ScanProfileBuilder() if profile_builder is None else profile_builder
        self._diagnostics: EnvironmentDiagnostics | None = None
        self._current_profile: ScanProfile | None = None
        self._latest_execution: ScanExecution | None = None
        self._latest_result: ScanResult | None = None
        self._scan_thread: QThread | None = None
        self._scan_worker: ScanWorker | None = None
        self._syncing_form = False

        self._create_widgets()

        self.setWindowTitle("GuiNmap")
        self.resize(1400, 900)
        self.setMinimumSize(1200, 780)
        self._configure_actions()
        self._configure_window()
        self._connect_signals()

        if self._presets:
            self._apply_preset(self._presets[0])

        self._refresh_environment_diagnostics(log_to_console=True)
        self._preview_command(show_feedback=False)

    def _create_widgets(self) -> None:
        self._scan_name_input = QLineEdit()
        self._scan_name_input.setPlaceholderText("Balanced inventory - internal segment")

        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText(
            "scanme.nmap.org, 192.168.1.0/24, 10.0.0.10"
        )

        self._ports_input = QLineEdit()
        self._ports_input.setPlaceholderText("22,80,443 or 1-1024")

        self._scan_type_combo = QComboBox()
        for scan_type_label, scan_type_value in SCAN_TYPE_OPTIONS:
            self._scan_type_combo.addItem(scan_type_label, scan_type_value)

        self._timing_combo = QComboBox()
        for timing_label, timing_value in TIMING_OPTIONS:
            self._timing_combo.addItem(timing_label, timing_value)

        self._preset_combo = QComboBox()
        for preset in self._presets:
            self._preset_combo.addItem(preset.label, preset.key)

        self._service_check = QCheckBox("Service detection (-sV)")
        self._os_check = QCheckBox("OS detection (-O)")
        self._default_scripts_check = QCheckBox("Default NSE (-sC)")
        self._traceroute_check = QCheckBox("Traceroute (--traceroute)")

        self._advanced_args_edit = QPlainTextEdit()
        self._advanced_args_edit.setPlaceholderText(
            "One logical group per line. Examples:\n"
            "-sA\n"
            "--script vuln and safe\n"
            "--script-args unsafe=1\n"
            "-Pn --reason --top-ports 100"
        )
        self._advanced_args_edit.setMinimumHeight(110)

        self._command_preview = QPlainTextEdit()
        self._command_preview.setReadOnly(True)
        self._command_preview.setMinimumHeight(110)

        self._validate_button = QPushButton("Validate profile")
        self._preview_button = QPushButton("Preview command")
        self._preview_button.setObjectName("secondaryButton")
        self._run_button = QPushButton("Run scan")

        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setFormat("Ready for validation and execution")

        self._status_notes = QPlainTextEdit()
        self._status_notes.setReadOnly(True)
        self._status_notes.setMinimumHeight(150)

        self._environment_note = QLabel()
        self._environment_note.setWordWrap(True)
        self._environment_note.setStyleSheet("font-size: 12px; color: #64748b;")

        self._refresh_environment_button = QPushButton("Refresh environment")
        self._refresh_environment_button.setObjectName("secondaryButton")

        self._results_table = QTableWidget(0, 6)
        self._results_table.setHorizontalHeaderLabels(
            ["Host", "Host state", "Proto", "Port", "Port state", "Service"]
        )
        self._results_table.verticalHeader().setVisible(False)
        self._results_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self._results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._results_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._results_table.setAlternatingRowColors(True)
        self._results_table.setMinimumHeight(200)

        self._results_note = QLabel(
            "Run a scan or load a later XML artifact to populate typed host and port data."
        )
        self._results_note.setWordWrap(True)
        self._results_note.setStyleSheet("font-size: 12px; color: #64748b;")

        self._console = QPlainTextEdit()
        self._console.setReadOnly(True)
        self._console.setMinimumHeight(210)
        self._console.setPlainText(
            "[startup] GuiNmap initialized\n"
            "[startup] Structured fields cover common workflows\n"
            "[startup] Advanced arguments pass through to Nmap for full option coverage"
        )

    def _configure_actions(self) -> None:
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)

        about_phase_action = QAction("Phase 3 Overview", self)
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
        content_scroll = QScrollArea()
        content_scroll.setWidgetResizable(True)
        content_scroll.setFrameShape(QFrame.Shape.NoFrame)
        content_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content_scroll.setWidget(content)

        layout.addWidget(navigation)
        layout.addWidget(content_scroll, stretch=1)

        self.setCentralWidget(root)
        self.statusBar().showMessage("Phase 3: background execution and diagnostics")
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
            QScrollArea {
                background: transparent;
                border: none;
            }
            QScrollArea > QWidget > QWidget {
                background: transparent;
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

    def _connect_signals(self) -> None:
        self._preset_combo.currentIndexChanged.connect(self._handle_preset_changed)
        self._scan_type_combo.currentIndexChanged.connect(self._handle_scan_type_changed)
        self._validate_button.clicked.connect(self._handle_validate_clicked)
        self._preview_button.clicked.connect(self._handle_preview_clicked)
        self._run_button.clicked.connect(self._run_scan)
        self._refresh_environment_button.clicked.connect(self._handle_refresh_environment)

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

        phase = QLabel("Current phase\nExecution wiring and diagnostics")
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
            "Advanced arguments keep the GUI compatible with the broader Nmap surface, "
            "while diagnostics highlight Windows capability limits before launch."
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
        lower_grid.setVerticalSpacing(18)
        lower_grid.addWidget(self._build_results_panel(), 0, 0)
        lower_grid.addWidget(self._build_console_panel(), 0, 1)
        lower_grid.setColumnStretch(0, 3)
        lower_grid.setColumnStretch(1, 2)

        layout.addLayout(upper_grid)
        layout.addLayout(lower_grid)
        layout.addStretch(1)

        return container

    def _build_header(self) -> QFrame:
        card = QFrame()
        card.setObjectName("heroCard")

        layout = QHBoxLayout(card)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(24)

        left_column = QVBoxLayout()
        left_column.setSpacing(12)

        badge = QLabel("PHASE 3")
        badge.setObjectName("badge")

        title = QLabel("Real execution and diagnostics wired around the Nmap workflow")
        title.setObjectName("heroTitle")
        title.setWordWrap(True)

        body = QLabel(
            "The window now validates scan profiles, previews the exact command, runs "
            "Nmap in the background, and renders typed results parsed from XML artifacts."
        )
        body.setObjectName("heroBody")
        body.setWordWrap(True)

        actions = QHBoxLayout()
        execution_button = QPushButton("Background execution wired")
        execution_button.setEnabled(False)
        diagnostics_button = QPushButton("Diagnostics active")
        diagnostics_button.setObjectName("secondaryButton")
        diagnostics_button.setEnabled(False)
        actions.addWidget(execution_button)
        actions.addWidget(diagnostics_button)
        actions.addStretch(1)

        left_column.addWidget(badge)
        left_column.addWidget(title)
        left_column.addWidget(body)
        left_column.addLayout(actions)

        metrics = QGridLayout()
        metrics.setHorizontalSpacing(20)
        metrics.setVerticalSpacing(14)
        metrics.addWidget(self._build_metric_tile("XML", "Canonical result source"), 0, 0)
        metrics.addWidget(self._build_metric_tile("Live", "Background execution"), 0, 1)
        metrics.addWidget(self._build_metric_tile("T0-T5", "Full timing templates"), 1, 0)
        metrics.addWidget(self._build_metric_tile("Args", "Full Nmap passthrough"), 1, 1)

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
            "Structured controls cover the common path. Advanced arguments remain a direct "
            "escape hatch for the full Nmap option surface when you need rare combinations.",
        )

        form = QFormLayout()
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(12)
        form.addRow("Scan name", self._scan_name_input)
        form.addRow("Targets", self._target_input)
        form.addRow("Ports", self._ports_input)
        form.addRow("Scan type", self._scan_type_combo)
        form.addRow("Timing", self._timing_combo)
        form.addRow("Preset profile", self._preset_combo)

        option_grid = QGridLayout()
        option_grid.setHorizontalSpacing(16)
        option_grid.setVerticalSpacing(8)
        option_grid.addWidget(self._service_check, 0, 0)
        option_grid.addWidget(self._os_check, 0, 1)
        option_grid.addWidget(self._default_scripts_check, 1, 0)
        option_grid.addWidget(self._traceroute_check, 1, 1)
        option_grid.setColumnStretch(0, 1)
        option_grid.setColumnStretch(1, 1)

        capability_hint = QLabel(
            "To express rarer scan types such as -sA, -sW, idle scan workflows, custom "
            "script expressions, or uncommon host-discovery combinations, keep the scan type "
            "on 'Nmap default behavior' and pass the exact flags below."
        )
        capability_hint.setWordWrap(True)
        capability_hint.setStyleSheet("font-size: 12px; color: #64748b;")

        button_row = QHBoxLayout()
        button_row.setSpacing(12)
        button_row.addWidget(self._validate_button)
        button_row.addWidget(self._preview_button)
        button_row.addWidget(self._run_button)
        button_row.addStretch(1)

        layout.addLayout(form)
        layout.addLayout(option_grid)
        layout.addWidget(capability_hint)
        layout.addWidget(self._build_inline_label("Advanced arguments"))
        layout.addWidget(self._advanced_args_edit)
        layout.addWidget(self._build_inline_label("Generated command preview"))
        layout.addWidget(self._command_preview)
        layout.addLayout(button_row)

        return card

    def _build_profiles_panel(self) -> QFrame:
        card, layout = self._create_section_card(
            "Profiles",
            "Presets remain starting points, not limits. Apply one as a baseline and then "
            "extend or override it with the full Nmap flag surface through advanced arguments.",
        )

        for preset in self._presets:
            layout.addWidget(self._build_profile_card(preset))

        warning = QLabel(
            "Capability warnings are surfaced before launch so advanced scans do not fail as "
            "opaque surprises on Windows or in non-privileged sessions."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet("font-size: 12px; color: #64748b;")
        layout.addWidget(warning)

        return card

    def _build_profile_card(self, preset: ScanPreset) -> QFrame:
        card = QFrame()
        card.setObjectName("profileCard")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(6)

        title_label = QLabel(preset.label)
        title_label.setStyleSheet("font-size: 16px; font-weight: 700; color: #0f172a;")

        body_label = QLabel(preset.description)
        body_label.setWordWrap(True)
        body_label.setStyleSheet("font-size: 12px; color: #536578;")

        command_label = QLabel(preset.command_preview)
        command_label.setWordWrap(True)
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
            "Scans now run in a background worker. The UI remains responsive while process "
            "output streams into the runtime console and XML results are parsed at completion.",
        )

        button_row = QHBoxLayout()
        button_row.addWidget(self._refresh_environment_button)
        button_row.addStretch(1)

        layout.addWidget(self._progress)
        layout.addLayout(button_row)
        layout.addWidget(self._status_notes)
        layout.addWidget(self._environment_note)

        return card

    def _build_results_panel(self) -> QFrame:
        card, layout = self._create_section_card(
            "Results preview",
            "Completed scans populate this view from typed XML models instead of brittle parsing "
            "of interactive terminal text.",
        )

        layout.addWidget(self._results_table)
        layout.addWidget(self._results_note)

        return card

    def _build_console_panel(self) -> QFrame:
        card, layout = self._create_section_card(
            "Runtime console",
            "Diagnostics, command previews, Nmap output, and XML parsing milestones all feed into "
            "this operator-friendly timeline.",
        )

        layout.addWidget(self._console)

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

    @Slot()
    def _handle_preset_changed(self) -> None:
        if self._syncing_form:
            return

        preset = self._selected_preset()
        if preset is None:
            return

        self._apply_preset(preset)
        self._preview_command(show_feedback=False)

    @Slot()
    def _handle_scan_type_changed(self) -> None:
        if self._syncing_form:
            return

        self._sync_scan_type_controls()

    @Slot()
    def _handle_validate_clicked(self) -> None:
        self._validate_profile(show_feedback=True)

    @Slot()
    def _handle_preview_clicked(self) -> None:
        profile = self._validate_profile(show_feedback=False)
        if profile is None:
            return

        self.statusBar().showMessage("Command preview updated.", 5000)
        self._append_console_line("[preview] Command preview refreshed")
        self._set_status_notes(self._build_ready_summary(profile))

    @Slot()
    def _handle_refresh_environment(self) -> None:
        self._refresh_environment_diagnostics(log_to_console=True)
        self._preview_command(show_feedback=False)
        self.statusBar().showMessage("Environment diagnostics refreshed.", 5000)

    def _preview_command(self, *, show_feedback: bool) -> ScanProfile | None:
        return self._validate_profile(show_feedback=show_feedback)

    def _apply_preset(self, preset: ScanPreset) -> None:
        self._syncing_form = True

        self._scan_name_input.setText(preset.label)
        self._ports_input.setText(preset.ports or "")
        self._set_combo_value(self._scan_type_combo, preset.scan_type)
        self._set_combo_value(self._timing_combo, preset.timing_template)
        self._service_check.setChecked(preset.enable_service_detection)
        self._os_check.setChecked(preset.enable_os_detection)
        self._default_scripts_check.setChecked("default" in preset.script_selection)
        self._traceroute_check.setChecked("--traceroute" in preset.extra_args)

        advanced_args = [argument for argument in preset.extra_args if argument != "--traceroute"]
        self._advanced_args_edit.setPlainText(" ".join(advanced_args))

        self._syncing_form = False
        self._sync_scan_type_controls()

    def _selected_preset(self) -> ScanPreset | None:
        preset_key = self._preset_combo.currentData()
        for preset in self._presets:
            if preset.key == preset_key:
                return preset

        return None

    def _set_combo_value(self, combo: QComboBox, expected_value: object) -> None:
        for index in range(combo.count()):
            if combo.itemData(index) == expected_value:
                combo.setCurrentIndex(index)
                return

    def _sync_scan_type_controls(self) -> None:
        is_ping = self._current_scan_type() == "ping"

        if is_ping:
            self._ports_input.clear()
            self._service_check.setChecked(False)
            self._os_check.setChecked(False)

        self._ports_input.setEnabled(not is_ping)
        self._service_check.setEnabled(not is_ping)
        self._os_check.setEnabled(not is_ping)

    def _current_scan_type(self) -> str:
        return str(self._scan_type_combo.currentData() or "default")

    def _current_timing_template(self) -> int:
        return int(self._timing_combo.currentData() or 3)

    def _build_profile_from_form(self) -> ScanProfile:
        profile_name = (
            self._scan_name_input.text().strip()
            or self._preset_combo.currentText()
            or "Custom scan"
        )

        draft = ScanProfileDraft(
            name=profile_name,
            targets_text=self._target_input.text(),
            scan_type=self._current_scan_type(),
            ports_text=self._ports_input.text(),
            timing_template=self._current_timing_template(),
            enable_service_detection=self._service_check.isChecked(),
            enable_os_detection=self._os_check.isChecked(),
            enable_default_scripts=self._default_scripts_check.isChecked(),
            enable_traceroute=self._traceroute_check.isChecked(),
            advanced_args_text=self._advanced_args_edit.toPlainText(),
        )

        return self._profile_builder.build(draft)

    def _validate_profile(self, *, show_feedback: bool) -> ScanProfile | None:
        try:
            profile = self._build_profile_from_form()
        except ValueError as exc:
            self._current_profile = None
            self._run_button.setEnabled(False)
            self._command_preview.setPlainText(str(exc))
            self._set_status_notes(
                "Advanced arguments could not be parsed. Fix the line shown in the preview pane "
                "before running the scan."
            )
            self.statusBar().showMessage("Advanced arguments are invalid.", 5000)
            self._append_console_line(f"[validation] {exc}")
            return None

        validation = self._scan_service.validator.validate(profile)
        if not validation.is_valid:
            issues = "\n".join(
                f"- {issue.field}: {issue.message}" for issue in validation.issues
            )
            self._current_profile = None
            self._run_button.setEnabled(False)
            self._command_preview.setPlainText(f"Profile validation failed.\n{issues}")
            self._set_status_notes(f"Validation issues detected:\n{issues}")
            self.statusBar().showMessage("Profile validation failed.", 5000)
            self._append_console_line("[validation] Profile validation failed")
            return None

        command = self._scan_service.executor.build_command(profile, "<temp file>")
        self._current_profile = profile
        self._command_preview.setPlainText(subprocess.list2cmdline(command))
        self._set_status_notes(self._build_ready_summary(profile))
        self._run_button.setEnabled(self._can_run_scan())

        if show_feedback:
            self.statusBar().showMessage("Profile validated successfully.", 5000)
            self._append_console_line("[validation] Profile validated successfully")

        return profile

    def _build_ready_summary(self, profile: ScanProfile) -> str:
        lines = [
            f"Profile: {profile.name}",
            f"Targets: {', '.join(profile.targets)}",
            f"Scan type: {profile.scan_type}",
            f"Timing template: T{profile.timing_template}",
        ]

        if profile.ports:
            lines.append(f"Ports: {profile.ports}")

        optional_features: list[str] = []
        if profile.enable_service_detection:
            optional_features.append("service detection")
        if profile.enable_os_detection:
            optional_features.append("OS detection")
        if "-sC" in profile.extra_args:
            optional_features.append("default NSE")
        if "--traceroute" in profile.extra_args:
            optional_features.append("traceroute")

        if optional_features:
            lines.append(f"Structured features: {', '.join(optional_features)}")

        passthrough_args = [
            argument
            for argument in profile.extra_args
            if argument not in {"-sC", "--traceroute"}
        ]
        if passthrough_args:
            lines.append(f"Advanced passthrough args: {' '.join(passthrough_args)}")

        for warning in self._profile_warnings(profile):
            lines.append(f"Warning: {warning}")

        if self._diagnostics is not None and not self._diagnostics.binary_available:
            lines.append("Nmap is not currently available in PATH or via the configured binary.")

        return "\n".join(lines)

    def _profile_warnings(self, profile: ScanProfile) -> list[str]:
        if self._diagnostics is None:
            return []

        warnings: list[str] = []
        raw_packet_sensitive = {"syn", "udp"}

        if (
            profile.scan_type in raw_packet_sensitive
            and not self._diagnostics.raw_packet_scans_available
        ):
            warnings.append(
                "This scan type may require raw-packet capabilities that are not currently "
                "available. Consider TCP connect (-sT) or keep the explicit choice if you "
                "want to try anyway."
            )

        if profile.enable_os_detection and not self._diagnostics.raw_packet_scans_available:
            warnings.append(
                "OS detection is more reliable with raw-packet privileges and may fail in the "
                "current environment."
            )

        return warnings

    def _can_run_scan(self) -> bool:
        return (
            self._scan_thread is None
            and self._diagnostics is not None
            and self._diagnostics.binary_available
            and self._current_profile is not None
        )

    @Slot()
    def _run_scan(self) -> None:
        profile = self._validate_profile(show_feedback=False)
        if profile is None:
            return

        self._refresh_environment_diagnostics(log_to_console=False)
        if self._diagnostics is None or not self._diagnostics.binary_available:
            self._run_button.setEnabled(False)
            self._set_status_notes(
                "Nmap is not available. Install Nmap or point the executor to a valid binary, "
                "then refresh the environment diagnostics."
            )
            self._append_console_line("[run] Nmap binary is not available; scan launch aborted")
            self.statusBar().showMessage("Nmap binary not available.", 5000)
            return

        self._latest_execution = None
        self._latest_result = None
        self._render_result(None)
        self._set_scan_running_state(True)
        self._set_status_notes(
            f"Running {profile.name}. Output is streaming in the runtime console while the "
            "GUI stays responsive."
        )

        command_preview = subprocess.list2cmdline(
            self._scan_service.executor.build_command(profile, "<temp file>")
        )
        self._append_console_line(f"[run] Starting scan '{profile.name}'")
        self._append_console_line(f"[run] {command_preview}")
        for warning in self._profile_warnings(profile):
            self._append_console_line(f"[warning] {warning}")

        self._scan_thread = QThread(self)
        self._scan_worker = ScanWorker(self._scan_service, profile)
        self._scan_worker.moveToThread(self._scan_thread)

        self._scan_thread.started.connect(self._scan_worker.run)
        self._scan_worker.output_received.connect(self._handle_scan_output)
        self._scan_worker.completed.connect(self._handle_scan_completed)
        self._scan_worker.failed.connect(self._handle_scan_failed)
        self._scan_worker.finished.connect(self._scan_thread.quit)
        self._scan_worker.finished.connect(self._scan_worker.deleteLater)
        self._scan_thread.finished.connect(self._handle_scan_thread_finished)
        self._scan_thread.finished.connect(self._scan_thread.deleteLater)

        self._scan_thread.start()
        self.statusBar().showMessage("Scan started in the background.")

    def _set_scan_running_state(self, running: bool) -> None:
        for widget in self._form_widgets():
            widget.setEnabled(not running)

        if running:
            self._progress.setRange(0, 0)
            self._progress.setFormat("Nmap is running...")
        else:
            self._progress.setRange(0, 100)
            self._sync_scan_type_controls()
            self._run_button.setEnabled(self._can_run_scan())

    def _form_widgets(self) -> tuple[QWidget, ...]:
        return (
            self._scan_name_input,
            self._target_input,
            self._ports_input,
            self._scan_type_combo,
            self._timing_combo,
            self._preset_combo,
            self._service_check,
            self._os_check,
            self._default_scripts_check,
            self._traceroute_check,
            self._advanced_args_edit,
            self._validate_button,
            self._preview_button,
            self._refresh_environment_button,
            self._run_button,
        )

    @Slot(str)
    def _handle_scan_output(self, line: str) -> None:
        self._append_console_line(line)
        if line.startswith("Stats:"):
            self._progress.setFormat(line)
            self.statusBar().showMessage(line)

    @Slot(object)
    def _handle_scan_completed(self, execution: object) -> None:
        scan_execution = execution
        if not isinstance(scan_execution, ScanExecution):
            return

        self._latest_execution = scan_execution
        self._latest_result = scan_execution.result
        self._current_profile = scan_execution.profile
        self._progress.setRange(0, 100)
        self._progress.setValue(100)
        self._progress.setFormat("Scan completed")
        self._command_preview.setPlainText(scan_execution.command_preview)
        self._render_result(scan_execution.result)
        self._set_status_notes(self._build_completion_summary(scan_execution))
        self._append_console_line(f"[done] XML artifact: {scan_execution.xml_output_path}")
        self._append_console_line("[done] Scan completed successfully")
        self.statusBar().showMessage("Scan completed successfully.", 5000)
        self._set_scan_running_state(False)

    @Slot(str, object)
    def _handle_scan_failed(self, message: str, execution: object) -> None:
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setFormat("Scan failed")
        self._render_result(None)

        if isinstance(execution, ScanExecution):
            self._latest_execution = execution
            self._command_preview.setPlainText(execution.command_preview)

        self._set_status_notes(
            "The scan did not complete successfully. Review the runtime console and the command "
            "preview to correct the profile or environment."
        )
        self._append_console_line(f"[error] {message}")
        self.statusBar().showMessage(message, 7000)
        self._set_scan_running_state(False)

    @Slot()
    def _handle_scan_thread_finished(self) -> None:
        self._scan_worker = None
        self._scan_thread = None
        self._run_button.setEnabled(self._can_run_scan())

    def _build_completion_summary(self, execution: ScanExecution) -> str:
        result = execution.result
        if result is None:
            return (
                f"{execution.profile.name} finished and produced an XML artifact, but no parsed "
                "result object was available."
            )

        host_count = len(result.hosts)
        port_count = sum(len(host.ports) for host in result.hosts)
        lines = [
            f"Profile: {execution.profile.name}",
            f"Hosts parsed: {host_count}",
            f"Ports parsed: {port_count}",
            f"XML artifact: {execution.xml_output_path}",
        ]

        if result.stats.summary:
            lines.append(f"Nmap summary: {result.stats.summary}")

        return "\n".join(lines)

    def _refresh_environment_diagnostics(self, *, log_to_console: bool) -> None:
        self._diagnostics = self._diagnostics_service.inspect()

        binary_status = self._diagnostics.resolved_binary_path or "not found"
        admin_state = "unknown"
        if self._diagnostics.is_admin is True:
            admin_state = "administrator"
        elif self._diagnostics.is_admin is False:
            admin_state = "not elevated"

        issue_lines = [
            f"{issue.level.upper()}: {issue.message}" for issue in self._diagnostics.issues
        ]
        diagnostics_lines = [
            f"Platform: {self._diagnostics.platform_name}",
            f"Configured binary: {self._diagnostics.configured_binary}",
            f"Resolved binary: {binary_status}",
            f"Privileges: {admin_state}",
            f"Recommended explicit scan type: {self._diagnostics.recommended_scan_type}",
        ]
        diagnostics_lines.extend(issue_lines)

        self._environment_note.setText("\n".join(diagnostics_lines))

        if log_to_console:
            self._append_console_line("[diagnostics] Environment refreshed")
            for line in diagnostics_lines:
                self._append_console_line(f"[diagnostics] {line}")

        self._run_button.setEnabled(self._can_run_scan())

    def _render_result(self, result: ScanResult | None) -> None:
        self._results_table.setRowCount(0)

        if result is None:
            self._results_note.setText(
                "Run a scan to populate typed host and port rows from the XML artifact."
            )
            return

        rows = self._build_result_rows(result)
        self._results_table.setRowCount(len(rows))

        for row_index, row in enumerate(rows):
            for column_index, value in enumerate(row):
                self._results_table.setItem(row_index, column_index, QTableWidgetItem(value))

        host_count = len(result.hosts)
        port_count = sum(len(host.ports) for host in result.hosts)
        summary = f"Parsed {host_count} host(s) and {port_count} port row(s) from XML."
        if result.stats.summary:
            summary = f"{summary} {result.stats.summary}"

        self._results_note.setText(summary)

    def _build_result_rows(self, result: ScanResult) -> list[tuple[str, str, str, str, str, str]]:
        rows: list[tuple[str, str, str, str, str, str]] = []

        for host in result.hosts:
            host_label = self._host_label(host)
            if not host.ports:
                rows.append((host_label, host.state, "-", "-", "-", "-"))
                continue

            for port in host.ports:
                rows.append(
                    (
                        host_label,
                        host.state,
                        port.protocol,
                        str(port.port),
                        port.state,
                        self._service_label(port),
                    )
                )

        return rows

    def _host_label(self, host: HostResult) -> str:
        if host.hostnames:
            return f"{host.hostnames[0]} ({host.address})"

        return host.address

    def _service_label(self, port: PortResult) -> str:
        parts = [value for value in [port.service, port.product, port.version] if value]
        if not parts:
            return "unknown"

        return " | ".join(parts)

    def _set_status_notes(self, text: str) -> None:
        self._status_notes.setPlainText(text)

    def _append_console_line(self, text: str) -> None:
        self._console.appendPlainText(text)
