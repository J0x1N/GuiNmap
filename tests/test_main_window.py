from __future__ import annotations

from collections.abc import Generator

import pytest
from PySide6.QtWidgets import QApplication

from guinmap.application.environment_diagnostics import EnvironmentDiagnostics
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