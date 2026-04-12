"""Main desktop window for the interactive Nmap workflow."""

from __future__ import annotations

import subprocess
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Slot
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
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
    LoadedScanResult,
    ScanExecution,
    ScanPreset,
    ScanProfileBuilder,
    ScanProfileDraft,
    ScanReportExporter,
    ScanReportExportResult,
    ScanResultLoader,
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
        result_loader: ScanResultLoader | None = None,
        report_exporter: ScanReportExporter | None = None,
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
        self._result_loader = ScanResultLoader() if result_loader is None else result_loader
        self._report_exporter = (
            ScanReportExporter() if report_exporter is None else report_exporter
        )
        self._diagnostics: EnvironmentDiagnostics | None = None
        self._current_profile: ScanProfile | None = None
        self._latest_execution: ScanExecution | None = None
        self._latest_result: ScanResult | None = None
        self._current_result_source_xml: Path | None = None
        self._last_report_export: ScanReportExportResult | None = None
        self._scan_thread: QThread | None = None
        self._scan_worker: ScanWorker | None = None
        self._syncing_form = False

        self._create_widgets()

        self.setWindowTitle("GuiNmap")
        self.resize(1460, 980)
        self.setMinimumSize(1240, 820)
        self._configure_actions()
        self._configure_window()
        self._connect_signals()

        if self._presets:
            self._apply_preset(self._presets[0])

        self._refresh_environment_diagnostics(log_to_console=True)
        self._set_status_notes(
            "Define targets and choose the Nmap option families you need. The command preview "
            "will update after validation or explicit preview."
        )
        self._update_result_action_buttons()

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
            "Cross-family exact arguments. Examples:\n"
            "-sA\n"
            "--spoof-mac Cisco\n"
            "-oA reports/internal-edge"
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

        self._skip_host_discovery_check = QCheckBox("Skip host discovery (-Pn)")
        self._disable_dns_resolution_check = QCheckBox("Disable DNS resolution (-n)")
        self._host_discovery_args_edit = self._create_family_args_editor(
            "Examples:\n-PE\n-PS80,443\n-PA3389\n-PU53"
        )

        self._top_ports_input = QLineEdit()
        self._top_ports_input.setPlaceholderText("100")
        self._exclude_ports_input = QLineEdit()
        self._exclude_ports_input.setPlaceholderText("135,139,445")
        self._port_strategy_args_edit = self._create_family_args_editor(
            "Examples:\n-sA\n-sW\n-sN\n-sF\n-sX\n-sI zombie:probe"
        )

        self._script_expression_input = QLineEdit()
        self._script_expression_input.setPlaceholderText("safe and vuln")
        self._script_arguments_input = QLineEdit()
        self._script_arguments_input.setPlaceholderText("unsafe=1,user=demo")
        self._nse_args_edit = self._create_family_args_editor(
            "Examples:\n--script-help default\n--script-trace"
        )

        self._decoys_input = QLineEdit()
        self._decoys_input.setPlaceholderText("ME,10.0.0.5,10.0.0.6")
        self._source_port_input = QLineEdit()
        self._source_port_input.setPlaceholderText("53")
        self._evasion_args_edit = self._create_family_args_editor(
            "Examples:\n-f\n--mtu 24\n-S 10.0.0.50\n--spoof-mac Cisco"
        )

        self._min_rate_input = QLineEdit()
        self._min_rate_input.setPlaceholderText("300")
        self._max_rate_input = QLineEdit()
        self._max_rate_input.setPlaceholderText("1000")
        self._host_timeout_input = QLineEdit()
        self._host_timeout_input.setPlaceholderText("30s")
        self._stats_interval_input = QLineEdit()
        self._stats_interval_input.setPlaceholderText("2s")
        self._performance_args_edit = self._create_family_args_editor(
            "Examples:\n--min-hostgroup 16\n--max-retries 2\n--defeat-rst-ratelimit"
        )

        self._normal_output_path_input = QLineEdit()
        self._normal_output_path_input.setPlaceholderText("reports/internal-edge.nmap")
        self._grepable_output_path_input = QLineEdit()
        self._grepable_output_path_input.setPlaceholderText("reports/internal-edge.gnmap")
        self._verbose_output_check = QCheckBox("Verbose output (-v)")
        self._packet_trace_check = QCheckBox("Packet trace (--packet-trace)")
        self._output_args_edit = self._create_family_args_editor(
            "Examples:\n--append-output\n-oA reports/internal-edge\n-d2"
        )

        self._load_xml_button = QPushButton("Load XML file")
        self._load_xml_button.setObjectName("secondaryButton")
        self._load_latest_xml_button = QPushButton("Load latest XML")
        self._load_latest_xml_button.setObjectName("secondaryButton")
        self._export_current_button = QPushButton("Export current reports")
        self._export_current_button.setObjectName("secondaryButton")
        self._export_latest_button = QPushButton("Export latest available")
        self._export_latest_button.setObjectName("secondaryButton")

        self._artifact_status_label = QLabel("No XML artifact loaded yet.")
        self._artifact_status_label.setWordWrap(True)
        self._artifact_status_label.setStyleSheet("font-size: 12px; color: #64748b;")

        self._report_status_label = QLabel(
            "Reports will be written under the reports directory when exported."
        )
        self._report_status_label.setWordWrap(True)
        self._report_status_label.setStyleSheet("font-size: 12px; color: #64748b;")

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
        self._results_table.setMinimumHeight(240)

        self._results_note = QLabel(
            "Run or load a scan to populate typed host and port data from XML."
        )
        self._results_note.setWordWrap(True)
        self._results_note.setStyleSheet("font-size: 12px; color: #64748b;")

        self._console = QPlainTextEdit()
        self._console.setReadOnly(True)
        self._console.setMinimumHeight(220)
        self._console.setPlainText(
            "[startup] GuiNmap initialized\n"
            "[startup] Common workflows use structured controls\n"
            "[startup] Family editors preserve coverage for broader Nmap combinations"
        )

    def _configure_actions(self) -> None:
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)

        about_phase_action = QAction("Phase 4 Overview", self)
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
        self.statusBar().showMessage("Phase 4: option families and artifact actions")
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
        self._load_xml_button.clicked.connect(self._handle_load_xml_clicked)
        self._load_latest_xml_button.clicked.connect(self._handle_load_latest_xml_clicked)
        self._export_current_button.clicked.connect(self._handle_export_current_clicked)
        self._export_latest_button.clicked.connect(self._handle_export_latest_clicked)

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

        phase = QLabel("Current phase\nFamilies, artifacts, and live execution")
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
                "Nmap Families",
                "Execution",
                "Results",
                "Documentation",
            ]
        )
        sections.setCurrentRow(1)

        footer = QLabel(
            "Common tasks stay guided, but the family editors and passthrough fields let the "
            "GUI represent much broader Nmap combinations without dropping to a raw shell."
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
        layout.addWidget(self._build_option_families_panel())
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

        badge = QLabel("PHASE 4")
        badge.setObjectName("badge")

        title = QLabel("Broader Nmap coverage and XML artifact actions inside the GUI")
        title.setObjectName("heroTitle")
        title.setWordWrap(True)

        body = QLabel(
            "The window now combines structured execution, grouped Nmap option families, XML "
            "artifact loading, and report exporting without leaving the desktop workflow."
        )
        body.setObjectName("heroBody")
        body.setWordWrap(True)

        actions = QHBoxLayout()
        families_button = QPushButton("Families organized")
        families_button.setEnabled(False)
        artifact_button = QPushButton("Artifact actions ready")
        artifact_button.setObjectName("secondaryButton")
        artifact_button.setEnabled(False)
        actions.addWidget(families_button)
        actions.addWidget(artifact_button)
        actions.addStretch(1)

        left_column.addWidget(badge)
        left_column.addWidget(title)
        left_column.addWidget(body)
        left_column.addLayout(actions)

        metrics = QGridLayout()
        metrics.setHorizontalSpacing(20)
        metrics.setVerticalSpacing(14)
        metrics.addWidget(self._build_metric_tile("Families", "Nmap option groups"), 0, 0)
        metrics.addWidget(self._build_metric_tile("XML", "Load or run artifacts"), 0, 1)
        metrics.addWidget(self._build_metric_tile("Reports", "JSON + Markdown export"), 1, 0)
        metrics.addWidget(self._build_metric_tile("Live", "Background execution"), 1, 1)

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
            "This remains the guided path for the most common workflows. Use the family editors "
            "below when you need broader scan techniques, NSE variants, evasion, output, or "
            "performance tuning.",
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
            "When a dedicated control is not present, you still have complete reach through the "
            "family editors and the cross-family passthrough area. GuiNmap keeps XML under its "
            "own control, so avoid passing -oX manually."
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
        layout.addWidget(self._build_inline_label("Cross-family passthrough arguments"))
        layout.addWidget(self._advanced_args_edit)
        layout.addWidget(self._build_inline_label("Generated command preview"))
        layout.addWidget(self._command_preview)
        layout.addLayout(button_row)

        return card

    def _build_profiles_panel(self) -> QFrame:
        card, layout = self._create_section_card(
            "Profiles",
            "Presets stay useful as baselines. You can apply one, then use the families panel to "
            "expand into more specialized Nmap combinations without starting from scratch.",
        )

        for preset in self._presets:
            layout.addWidget(self._build_profile_card(preset))

        warning = QLabel(
            "Capability warnings surface before launch, but explicit advanced combinations stay "
            "possible when you intentionally choose them."
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
            "Scans run in a background worker. You can also load existing XML artifacts and export "
            "reports from the current or latest available result set.",
        )

        button_row = QHBoxLayout()
        button_row.addWidget(self._refresh_environment_button)
        button_row.addStretch(1)

        layout.addWidget(self._progress)
        layout.addLayout(button_row)
        layout.addWidget(self._status_notes)
        layout.addWidget(self._environment_note)

        return card

    def _build_option_families_panel(self) -> QFrame:
        card, layout = self._create_section_card(
            "Nmap Option Families",
            "These grouped editors keep the GUI organized while still letting you express much "
            "broader Nmap behavior. Each family offers a few guided fields plus exact family "
            "arguments for the remaining surface area.",
        )

        families_grid = QGridLayout()
        families_grid.setHorizontalSpacing(16)
        families_grid.setVerticalSpacing(16)
        families_grid.addWidget(self._build_host_discovery_family_card(), 0, 0)
        families_grid.addWidget(self._build_scan_variants_family_card(), 0, 1)
        families_grid.addWidget(self._build_nse_family_card(), 0, 2)
        families_grid.addWidget(self._build_evasion_family_card(), 1, 0)
        families_grid.addWidget(self._build_performance_family_card(), 1, 1)
        families_grid.addWidget(self._build_output_family_card(), 1, 2)

        for column in range(3):
            families_grid.setColumnStretch(column, 1)

        layout.addLayout(families_grid)
        return card

    def _build_host_discovery_family_card(self) -> QFrame:
        card, layout = self._create_family_card(
            "Host discovery",
            "Control how Nmap decides whether a host is alive before deeper work begins.",
        )

        toggles = QGridLayout()
        toggles.setHorizontalSpacing(12)
        toggles.setVerticalSpacing(6)
        toggles.addWidget(self._skip_host_discovery_check, 0, 0)
        toggles.addWidget(self._disable_dns_resolution_check, 0, 1)

        layout.addLayout(toggles)
        layout.addWidget(self._build_inline_label("Exact host-discovery arguments"))
        layout.addWidget(self._host_discovery_args_edit)
        return card

    def _build_scan_variants_family_card(self) -> QFrame:
        card, layout = self._create_family_card(
            "Scan variants and ports",
            "Use this family for ACK, Window, Maimon, Null/FIN/Xmas, idle scans, and other port "
            "selection strategies that go beyond the base scan-type combo.",
        )

        form = QFormLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)
        form.addRow("Top ports", self._top_ports_input)
        form.addRow("Exclude ports", self._exclude_ports_input)

        layout.addLayout(form)
        layout.addWidget(self._build_inline_label("Exact scan/port arguments"))
        layout.addWidget(self._port_strategy_args_edit)
        return card

    def _build_nse_family_card(self) -> QFrame:
        card, layout = self._create_family_card(
            "NSE and scripts",
            "Combine script categories, named scripts, and script arguments without leaving the "
            "GUI workflow.",
        )

        form = QFormLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)
        form.addRow("Script expression", self._script_expression_input)
        form.addRow("Script args", self._script_arguments_input)

        layout.addLayout(form)
        layout.addWidget(self._build_inline_label("Exact NSE arguments"))
        layout.addWidget(self._nse_args_edit)
        return card

    def _build_evasion_family_card(self) -> QFrame:
        card, layout = self._create_family_card(
            "Evasion and spoofing",
            "Express decoys, source-port manipulation, packet fragmentation, spoofing, and related "
            "operator-controlled evasive behavior.",
        )

        form = QFormLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)
        form.addRow("Decoys (-D)", self._decoys_input)
        form.addRow("Source port", self._source_port_input)

        layout.addLayout(form)
        layout.addWidget(self._build_inline_label("Exact evasion arguments"))
        layout.addWidget(self._evasion_args_edit)
        return card

    def _build_performance_family_card(self) -> QFrame:
        card, layout = self._create_family_card(
            "Performance",
            "Fine-tune rates, timeouts, and batching when you need behavior beyond the timing "
            "template selector.",
        )

        form = QFormLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)
        form.addRow("Min rate", self._min_rate_input)
        form.addRow("Max rate", self._max_rate_input)
        form.addRow("Host timeout", self._host_timeout_input)
        form.addRow("Stats interval", self._stats_interval_input)

        layout.addLayout(form)
        layout.addWidget(self._build_inline_label("Exact performance arguments"))
        layout.addWidget(self._performance_args_edit)
        return card

    def _build_output_family_card(self) -> QFrame:
        card, layout = self._create_family_card(
            "Output and verbosity",
            "Keep XML under GuiNmap control while still allowing normal output, grepable output, "
            "verbosity, and broader reporting or debug flags.",
        )

        toggles = QGridLayout()
        toggles.setHorizontalSpacing(12)
        toggles.setVerticalSpacing(6)
        toggles.addWidget(self._verbose_output_check, 0, 0)
        toggles.addWidget(self._packet_trace_check, 0, 1)

        form = QFormLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)
        form.addRow("Normal output (-oN)", self._normal_output_path_input)
        form.addRow("Grepable output (-oG)", self._grepable_output_path_input)

        layout.addLayout(toggles)
        layout.addLayout(form)
        layout.addWidget(self._build_inline_label("Exact output arguments"))
        layout.addWidget(self._output_args_edit)
        return card

    def _build_results_panel(self) -> QFrame:
        card, layout = self._create_section_card(
            "Results and artifacts",
            "This area can render the current live result, load an existing XML artifact from "
            "disk, "
            "or export JSON and Markdown reports from the active result set.",
        )

        button_row = QHBoxLayout()
        button_row.setSpacing(10)
        button_row.addWidget(self._load_xml_button)
        button_row.addWidget(self._load_latest_xml_button)
        button_row.addWidget(self._export_current_button)
        button_row.addWidget(self._export_latest_button)
        button_row.addStretch(1)

        layout.addLayout(button_row)
        layout.addWidget(self._artifact_status_label)
        layout.addWidget(self._report_status_label)
        layout.addWidget(self._results_table)
        layout.addWidget(self._results_note)

        return card

    def _build_console_panel(self) -> QFrame:
        card, layout = self._create_section_card(
            "Runtime console",
            "Diagnostics, preview updates, Nmap output, XML loads, and report exports all appear "
            "in this operator-facing timeline.",
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

    def _create_family_card(self, title: str, body: str) -> tuple[QFrame, QVBoxLayout]:
        card = QFrame()
        card.setObjectName("profileCard")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 15px; font-weight: 700; color: #0f172a;")

        body_label = QLabel(body)
        body_label.setWordWrap(True)
        body_label.setStyleSheet("font-size: 12px; color: #536578;")

        layout.addWidget(title_label)
        layout.addWidget(body_label)

        return card, layout

    def _build_inline_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setStyleSheet("font-size: 12px; font-weight: 600; color: #334155;")
        return label

    def _create_family_args_editor(self, placeholder: str) -> QPlainTextEdit:
        editor = QPlainTextEdit()
        editor.setPlaceholderText(placeholder)
        editor.setMinimumHeight(86)
        return editor

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
        profile = self._validate_profile(show_feedback=True)
        if profile is None:
            return

        self.statusBar().showMessage("Command preview updated.", 5000)
        self._append_console_line("[preview] Command preview refreshed")

    @Slot()
    def _handle_refresh_environment(self) -> None:
        self._refresh_environment_diagnostics(log_to_console=True)
        self._preview_command(show_feedback=False)
        self.statusBar().showMessage("Environment diagnostics refreshed.", 5000)

    @Slot()
    def _handle_load_xml_clicked(self) -> None:
        start_dir = str(self._scan_service.artifacts_dir)
        selected_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Nmap XML artifact",
            start_dir,
            "Nmap XML (*.xml);;XML files (*.xml);;All files (*)",
        )
        if not selected_path:
            return

        self._load_xml_artifact(Path(selected_path), log_to_console=True)

    @Slot()
    def _handle_load_latest_xml_clicked(self) -> None:
        self._load_latest_available_xml(log_to_console=True)

    @Slot()
    def _handle_export_current_clicked(self) -> None:
        self._export_current_reports(log_to_console=True)

    @Slot()
    def _handle_export_latest_clicked(self) -> None:
        self._export_latest_available_reports(log_to_console=True)

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

        self._reset_family_inputs()
        advanced_args = [arg for arg in preset.extra_args if arg != "--traceroute"]
        self._advanced_args_edit.setPlainText(" ".join(advanced_args))

        self._syncing_form = False
        self._sync_scan_type_controls()

    def _reset_family_inputs(self) -> None:
        self._skip_host_discovery_check.setChecked(False)
        self._disable_dns_resolution_check.setChecked(False)
        self._host_discovery_args_edit.clear()
        self._top_ports_input.clear()
        self._exclude_ports_input.clear()
        self._port_strategy_args_edit.clear()
        self._script_expression_input.clear()
        self._script_arguments_input.clear()
        self._nse_args_edit.clear()
        self._decoys_input.clear()
        self._source_port_input.clear()
        self._evasion_args_edit.clear()
        self._min_rate_input.clear()
        self._max_rate_input.clear()
        self._host_timeout_input.clear()
        self._stats_interval_input.clear()
        self._performance_args_edit.clear()
        self._normal_output_path_input.clear()
        self._grepable_output_path_input.clear()
        self._verbose_output_check.setChecked(False)
        self._packet_trace_check.setChecked(False)
        self._output_args_edit.clear()

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
            skip_host_discovery=self._skip_host_discovery_check.isChecked(),
            disable_dns_resolution=self._disable_dns_resolution_check.isChecked(),
            top_ports_text=self._top_ports_input.text(),
            exclude_ports_text=self._exclude_ports_input.text(),
            script_expression=self._script_expression_input.text(),
            script_arguments_text=self._script_arguments_input.text(),
            decoys_text=self._decoys_input.text(),
            source_port_text=self._source_port_input.text(),
            min_rate_text=self._min_rate_input.text(),
            max_rate_text=self._max_rate_input.text(),
            host_timeout_text=self._host_timeout_input.text(),
            stats_interval_text=self._stats_interval_input.text(),
            normal_output_path=self._normal_output_path_input.text(),
            grepable_output_path=self._grepable_output_path_input.text(),
            enable_verbose_output=self._verbose_output_check.isChecked(),
            enable_packet_trace=self._packet_trace_check.isChecked(),
            host_discovery_args_text=self._host_discovery_args_edit.toPlainText(),
            port_strategy_args_text=self._port_strategy_args_edit.toPlainText(),
            nse_args_text=self._nse_args_edit.toPlainText(),
            evasion_args_text=self._evasion_args_edit.toPlainText(),
            performance_args_text=self._performance_args_edit.toPlainText(),
            output_args_text=self._output_args_edit.toPlainText(),
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
                "One of the family or passthrough editors contains an invalid argument line. "
                "Fix the quoted or split value before running the scan."
            )
            if show_feedback:
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
            if show_feedback:
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
            lines.append(f"Extra arguments: {' '.join(passthrough_args)}")

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
        profile = self._validate_profile(show_feedback=True)
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
        self._current_result_source_xml = None
        self._render_result(None)
        self._set_scan_running_state(True)
        self._set_status_notes(
            f"Running {profile.name}. Output is streaming in the runtime console while the GUI "
            "stays responsive."
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

    def _scan_locked_widgets(self) -> tuple[QWidget, ...]:
        return (
            *self._form_widgets(),
            self._load_xml_button,
            self._load_latest_xml_button,
            self._export_current_button,
            self._export_latest_button,
        )

    def _set_scan_running_state(self, running: bool) -> None:
        for widget in self._scan_locked_widgets():
            widget.setEnabled(not running)

        if running:
            self._progress.setRange(0, 0)
            self._progress.setFormat("Nmap is running...")
        else:
            self._progress.setRange(0, 100)
            self._sync_scan_type_controls()
            self._run_button.setEnabled(self._can_run_scan())
            self._update_result_action_buttons()

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
            self._skip_host_discovery_check,
            self._disable_dns_resolution_check,
            self._top_ports_input,
            self._exclude_ports_input,
            self._script_expression_input,
            self._script_arguments_input,
            self._decoys_input,
            self._source_port_input,
            self._min_rate_input,
            self._max_rate_input,
            self._host_timeout_input,
            self._stats_interval_input,
            self._normal_output_path_input,
            self._grepable_output_path_input,
            self._verbose_output_check,
            self._packet_trace_check,
            self._host_discovery_args_edit,
            self._port_strategy_args_edit,
            self._nse_args_edit,
            self._evasion_args_edit,
            self._performance_args_edit,
            self._output_args_edit,
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
        self._current_result_source_xml = scan_execution.xml_output_path
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
        self._update_result_action_buttons()

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
        self._update_result_action_buttons()

    def _render_result(self, result: ScanResult | None) -> None:
        self._results_table.setRowCount(0)

        if result is None:
            self._results_note.setText(
                "Run or load a scan to populate typed host and port rows from XML."
            )
            self._update_artifact_summary()
            self._update_result_action_buttons()
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
        self._update_artifact_summary()
        self._update_result_action_buttons()

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

    def _update_artifact_summary(self) -> None:
        if self._current_result_source_xml is None:
            self._artifact_status_label.setText("No XML artifact loaded yet.")
        else:
            self._artifact_status_label.setText(
                f"Current XML artifact: {self._current_result_source_xml}"
            )

        if self._last_report_export is None:
            self._report_status_label.setText(
                "Reports will be written under the reports directory when exported."
            )
        else:
            self._report_status_label.setText(
                "Latest export: "
                f"{self._last_report_export.json_report_path} and "
                f"{self._last_report_export.markdown_report_path}"
            )

    def _update_result_action_buttons(self) -> None:
        scan_running = self._scan_thread is not None
        has_current_result = self._latest_result is not None

        self._load_xml_button.setEnabled(not scan_running)
        self._load_latest_xml_button.setEnabled(not scan_running)
        self._export_latest_button.setEnabled(not scan_running)
        self._export_current_button.setEnabled(not scan_running and has_current_result)

    def _load_xml_artifact(
        self,
        xml_path: Path,
        *,
        log_to_console: bool,
    ) -> LoadedScanResult | None:
        try:
            loaded = self._result_loader.load_from_xml_file(xml_path)
        except Exception as exc:
            self.statusBar().showMessage(f"Failed to load XML: {exc}", 7000)
            if log_to_console:
                self._append_console_line(f"[error] Failed to load XML: {exc}")
            return None

        self._apply_loaded_result(loaded, log_to_console=log_to_console)
        self.statusBar().showMessage("XML artifact loaded.", 5000)
        return loaded

    def _load_latest_available_xml(self, *, log_to_console: bool) -> LoadedScanResult | None:
        try:
            loaded = self._result_loader.load_latest_available()
        except Exception as exc:
            self.statusBar().showMessage(f"Failed to load latest XML: {exc}", 7000)
            if log_to_console:
                self._append_console_line(f"[error] Failed to load latest XML: {exc}")
            return None

        self._apply_loaded_result(loaded, log_to_console=log_to_console)
        self.statusBar().showMessage("Latest available XML loaded.", 5000)
        return loaded

    def _apply_loaded_result(self, loaded: LoadedScanResult, *, log_to_console: bool) -> None:
        self._latest_execution = None
        self._latest_result = loaded.scan_result
        self._current_result_source_xml = loaded.source_xml_path
        self._command_preview.setPlainText(loaded.scan_result.command or "unknown")
        self._render_result(loaded.scan_result)
        self._set_status_notes(self._build_loaded_result_summary(loaded))
        self._progress.setRange(0, 100)
        self._progress.setValue(100)
        self._progress.setFormat("XML artifact loaded")

        if log_to_console:
            self._append_console_line(f"[load] XML artifact loaded: {loaded.source_xml_path}")
            if loaded.used_fallback_source:
                self._append_console_line("[load] Fallback sample XML was used")

    def _build_loaded_result_summary(self, loaded: LoadedScanResult) -> str:
        host_count = len(loaded.scan_result.hosts)
        port_count = sum(len(host.ports) for host in loaded.scan_result.hosts)
        lines = [
            f"XML artifact: {loaded.source_xml_path}",
            f"Hosts parsed: {host_count}",
            f"Ports parsed: {port_count}",
        ]

        if loaded.used_fallback_source:
            lines.append("Source type: bundled fallback sample")

        if loaded.scan_result.stats.summary:
            lines.append(f"Nmap summary: {loaded.scan_result.stats.summary}")

        return "\n".join(lines)

    def _export_current_reports(self, *, log_to_console: bool) -> ScanReportExportResult | None:
        if self._latest_result is None:
            self.statusBar().showMessage("No current result is loaded for export.", 5000)
            if log_to_console:
                self._append_console_line("[export] No current result is available for export")
            return None

        export_result = self._report_exporter.export_scan_result(
            self._latest_result,
            source_xml_path=self._current_result_source_xml,
        )
        self._apply_export_result(export_result, log_to_console=log_to_console)
        self.statusBar().showMessage("Current reports exported.", 5000)
        return export_result

    def _export_latest_available_reports(
        self,
        *,
        log_to_console: bool,
    ) -> ScanReportExportResult | None:
        try:
            export_result = self._report_exporter.export_latest_available()
        except Exception as exc:
            self.statusBar().showMessage(f"Failed to export latest reports: {exc}", 7000)
            if log_to_console:
                self._append_console_line(f"[error] Failed to export latest reports: {exc}")
            return None

        self._apply_export_result(export_result, log_to_console=log_to_console)
        self.statusBar().showMessage("Latest available reports exported.", 5000)
        return export_result

    def _apply_export_result(
        self,
        export_result: ScanReportExportResult,
        *,
        log_to_console: bool,
    ) -> None:
        self._last_report_export = export_result
        self._update_artifact_summary()
        if log_to_console:
            self._append_console_line(
                f"[export] JSON report: {export_result.json_report_path}"
            )
            self._append_console_line(
                f"[export] Markdown report: {export_result.markdown_report_path}"
            )
