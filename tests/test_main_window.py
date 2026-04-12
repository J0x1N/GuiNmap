from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from guinmap.application import AppSettingsService, ScanExecution
from guinmap.application.environment_diagnostics import EnvironmentDiagnostics
from guinmap.application.report_exporter import ScanReportExporter
from guinmap.application.scan_result_loader import ScanResultLoader
from guinmap.application.scan_service import ScanService
from guinmap.domain.scan_profile import ScanProfile
from guinmap.infrastructure.nmap_executor import NmapExecutor
from guinmap.infrastructure.settings_repository import JsonSettingsRepository
from guinmap.ui.main_window import MainWindow


class FakeDiagnosticsService:
    def inspect(self) -> EnvironmentDiagnostics:
        return EnvironmentDiagnostics(
            platform_name="Windows",
            configured_binary="nmap",
            resolved_binary_path=r"C:\Program Files\Nmap\nmap.exe",
            binary_available=True,
            is_admin=True,
            raw_packet_scans_available=True,
            recommended_scan_type="syn",
        )


@pytest.fixture(scope="module")
def app() -> Generator[QApplication, None, None]:
    qapp = QApplication.instance() or QApplication([])
    yield qapp


def write_sample_xml(xml_path: Path) -> None:
    xml_path.write_text(
        """<?xml version="1.0"?>
<nmaprun
    scanner="nmap"
    args="nmap -oX sample.xml target"
    startstr="Sat Apr 12 11:00:00 2026"
    version="7.99SVN"
>
    <host>
        <status state="up" reason="syn-ack" />
        <address addr="192.168.1.10" addrtype="ipv4" />
        <hostnames>
            <hostname name="demo.local" type="user" />
        </hostnames>
        <ports>
            <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack" />
                <service name="https" product="Test Server" version="1.0" method="probed" conf="10">
                    <cpe>cpe:/a:test:test_server:1.0</cpe>
                </service>
                <script id="http-title" output="GuiNmap test target" />
            </port>
        </ports>
        <hostscript>
            <script id="uptime" output="host up for less than a minute" />
        </hostscript>
    </host>
    <runstats>
        <finished
            timestr="Sat Apr 12 11:00:05 2026"
            elapsed="5.00"
            exit="success"
            summary="Nmap done: 1 IP address (1 host up) scanned in 5.00 seconds"
        />
        <hosts up="1" down="0" total="1" />
    </runstats>
</nmaprun>
""",
        encoding="utf-8",
    )


def test_preview_command_supports_advanced_scan_types(app: QApplication) -> None:
    window = MainWindow(
        scan_service=ScanService(executor=NmapExecutor(binary="nmap")),
        diagnostics_service=FakeDiagnosticsService(),
    )

    window._scan_name_input.setText("ACK discovery")
    window._target_input.setText("scanme.nmap.org")
    window._set_combo_value(window._scan_type_combo, "default")
    window._advanced_args_edit.setPlainText("-sA\n--reason")

    profile = window._validate_profile(show_feedback=False)

    assert profile is not None
    assert profile.scan_type == "default"
    assert profile.extra_args == ["-sA", "--reason"]
    assert "-sA --reason" in window._command_preview.toPlainText()
    assert window._run_button.isEnabled() is True

    window.close()


def test_preview_command_includes_family_controls(app: QApplication) -> None:
    window = MainWindow(
        scan_service=ScanService(executor=NmapExecutor(binary="nmap")),
        diagnostics_service=FakeDiagnosticsService(),
    )

    window._scan_name_input.setText("Family demo")
    window._target_input.setText("scanme.nmap.org")
    window._top_ports_input.setText("50")
    window._script_expression_input.setText("safe and vuln")
    window._min_rate_input.setText("500")
    window._verbose_output_check.setChecked(True)
    window._port_strategy_args_edit.setPlainText("-sA")

    profile = window._validate_profile(show_feedback=False)

    assert profile is not None
    assert "--top-ports 50" in window._command_preview.toPlainText()
    assert "--script \"safe and vuln\"" in window._command_preview.toPlainText()
    assert "--min-rate 500" in window._command_preview.toPlainText()
    assert "-v" in window._command_preview.toPlainText()
    assert "-sA" in window._command_preview.toPlainText()

    window.close()


def test_ping_mode_disables_incompatible_form_controls(app: QApplication) -> None:
    window = MainWindow(
        scan_service=ScanService(executor=NmapExecutor(binary="nmap")),
        diagnostics_service=FakeDiagnosticsService(),
    )

    window._ports_input.setText("80,443")
    window._service_check.setChecked(True)
    window._os_check.setChecked(True)
    window._set_combo_value(window._scan_type_combo, "ping")
    window._handle_scan_type_changed()

    assert window._ports_input.isEnabled() is False
    assert window._service_check.isEnabled() is False
    assert window._os_check.isEnabled() is False
    assert window._ports_input.text() == ""
    assert window._service_check.isChecked() is False
    assert window._os_check.isChecked() is False

    window.close()


def test_window_can_load_xml_and_export_current_reports(
    app: QApplication,
    tmp_path: Path,
) -> None:
    xml_path = tmp_path / "sample.xml"
    write_sample_xml(xml_path)

    window = MainWindow(
        scan_service=ScanService(executor=NmapExecutor(binary="nmap")),
        diagnostics_service=FakeDiagnosticsService(),
        result_loader=ScanResultLoader(
            scans_dir=tmp_path / "artifacts",
            default_xml_source=xml_path,
        ),
        report_exporter=ScanReportExporter(reports_dir=tmp_path / "reports"),
    )

    loaded = window._load_xml_artifact(xml_path, log_to_console=False)
    export_result = window._export_current_reports(log_to_console=False)

    assert loaded is not None
    assert export_result is not None
    assert window._results_table.rowCount() == 1
    assert window._artifact_status_label.text().endswith(str(xml_path))
    assert "demo.local" in window._host_detail_view.toPlainText()
    assert "443/tcp" in window._result_selection_label.text()
    assert "http-title" in window._script_detail_view.toPlainText()
    assert str(xml_path) in window._metadata_detail_view.toPlainText()
    assert export_result.json_report_path.exists()
    assert export_result.markdown_report_path.exists()

    window.close()


def test_window_saves_and_reloads_persistent_preferences(
    app: QApplication,
    tmp_path: Path,
) -> None:
    settings_service = AppSettingsService(
        repository=JsonSettingsRepository(settings_path=tmp_path / "settings.json")
    )
    binary_path = tmp_path / "nmap.exe"
    artifacts_dir = tmp_path / "saved-artifacts"
    reports_dir = tmp_path / "saved-reports"

    window = MainWindow(
        scan_service=ScanService(executor=NmapExecutor(binary="nmap")),
        diagnostics_service=FakeDiagnosticsService(),
        settings_service=settings_service,
    )

    window._settings_binary_input.setText(str(binary_path))
    window._settings_stats_interval_input.setText("2s")
    window._settings_artifacts_dir_input.setText(str(artifacts_dir))
    window._settings_reports_dir_input.setText(str(reports_dir))
    window._set_combo_value(window._settings_language_combo, "es")
    window._set_combo_value(window._settings_default_scan_type_combo, "udp")
    window._set_combo_value(window._settings_default_timing_combo, 4)

    saved = window._save_settings(log_to_console=False)

    assert saved is not None
    assert window._scan_service.executor.binary == str(binary_path)
    assert window._scan_service.executor.stats_interval == "2s"
    assert window._result_loader.scans_dir == artifacts_dir
    assert window._report_exporter.reports_dir == reports_dir
    assert saved.language_code == "es"
    assert window._scan_type_combo.currentData() == "udp"
    assert window._timing_combo.currentData() == 4

    window.close()

    reopened = MainWindow(
        scan_service=ScanService(executor=NmapExecutor(binary="nmap")),
        diagnostics_service=FakeDiagnosticsService(),
        settings_service=settings_service,
    )

    assert reopened._settings_binary_input.text() == str(binary_path)
    assert reopened._settings_stats_interval_input.text() == "2s"
    assert reopened._settings_artifacts_dir_input.text() == str(artifacts_dir)
    assert reopened._settings_reports_dir_input.text() == str(reports_dir)
    assert reopened._settings_language_combo.currentData() == "es"
    assert reopened._settings_default_scan_type_combo.currentData() == "udp"
    assert reopened._settings_default_timing_combo.currentData() == 4
    assert reopened._scan_service.executor.binary == str(binary_path)
    assert reopened._report_exporter.reports_dir == reports_dir
    assert reopened._run_button.text() == "Ejecutar escaneo"
    assert reopened._save_settings_button.text() == "Guardar preferencias"
    assert reopened._advanced_toggle_button.text() == "Mostrar familias avanzadas de Nmap"

    reopened.close()


def test_window_hides_advanced_families_until_requested(app: QApplication) -> None:
    window = MainWindow(
        scan_service=ScanService(executor=NmapExecutor(binary="nmap")),
        diagnostics_service=FakeDiagnosticsService(),
    )

    assert window._option_families_panel.isHidden() is True
    assert window._advanced_toggle_button.isChecked() is False

    window._advanced_toggle_button.click()

    assert window._option_families_panel.isHidden() is False
    assert window._advanced_toggle_button.isChecked() is True

    window.close()


def test_window_requests_scan_cancellation(app: QApplication) -> None:
    window = MainWindow(
        scan_service=ScanService(executor=NmapExecutor(binary="nmap")),
        diagnostics_service=FakeDiagnosticsService(),
    )

    class DummyWorker:
        def __init__(self) -> None:
            self.cancel_calls = 0

        def cancel(self) -> None:
            self.cancel_calls += 1

    worker = DummyWorker()
    window._scan_worker = worker  # type: ignore[assignment]
    window._scan_thread = object()  # type: ignore[assignment]

    window._set_scan_running_state(True)
    window._handle_cancel_scan_clicked()

    assert worker.cancel_calls == 1
    assert window._cancel_button.isEnabled() is False
    assert window._progress.format() == "Cancelling scan..."
    assert "Cancellation" in window._status_notes.toPlainText()

    execution = ScanExecution(
        profile=ScanProfile(name="Cancelled", targets=["127.0.0.1"]),
        command=["nmap", "127.0.0.1"],
        xml_output_path=Path("cancelled.xml"),
        return_code=-1,
        was_cancelled=True,
    )

    window._handle_scan_failed("Scan cancelled by operator.", execution)

    assert window._progress.format() == "Scan cancelled"
    assert "cancelled by the operator" in window._status_notes.toPlainText()

    window.close()


def test_completed_scan_selects_first_row_for_detail_views(
    app: QApplication,
    tmp_path: Path,
) -> None:
    xml_path = tmp_path / "sample.xml"
    write_sample_xml(xml_path)

    window = MainWindow(
        scan_service=ScanService(executor=NmapExecutor(binary="nmap")),
        diagnostics_service=FakeDiagnosticsService(),
        report_exporter=ScanReportExporter(reports_dir=tmp_path / "reports"),
    )

    result = ScanResultLoader(default_xml_source=xml_path).load_from_xml_file(xml_path).scan_result
    execution = ScanExecution(
        profile=ScanProfile(name="Sample", targets=["192.168.1.10"]),
        command=["nmap", "-oX", str(xml_path), "192.168.1.10"],
        xml_output_path=xml_path,
        return_code=0,
        result=result,
    )

    window._handle_scan_completed(execution)

    assert window._results_table.rowCount() == 1
    assert "demo.local" in window._host_detail_view.toPlainText()
    assert "Test Server" in window._port_detail_view.toPlainText()
    assert "uptime" in window._script_detail_view.toPlainText()
    assert "sample.xml" in window._metadata_detail_view.toPlainText()

    window.close()