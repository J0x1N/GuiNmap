from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from guinmap.application.environment_diagnostics import EnvironmentDiagnostics
from guinmap.application.report_exporter import ScanReportExporter
from guinmap.application.scan_result_loader import ScanResultLoader
from guinmap.application.scan_service import ScanService
from guinmap.infrastructure.nmap_executor import NmapExecutor
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
<nmaprun scanner="nmap" args="nmap -oX sample.xml target" startstr="Sat Apr 12 11:00:00 2026">
    <host>
        <status state="up" reason="syn-ack" />
        <address addr="192.168.1.10" addrtype="ipv4" />
        <hostnames>
            <hostname name="demo.local" type="user" />
        </hostnames>
        <ports>
            <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack" />
                <service name="https" product="Test Server" version="1.0" />
            </port>
        </ports>
    </host>
    <runstats>
        <finished timestr="Sat Apr 12 11:00:05 2026" />
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
    assert export_result.json_report_path.exists()
    assert export_result.markdown_report_path.exists()

    window.close()