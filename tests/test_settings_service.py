from pathlib import Path

from guinmap.application.environment_diagnostics import EnvironmentDiagnosticsService
from guinmap.application.report_exporter import ScanReportExporter
from guinmap.application.scan_result_loader import ScanResultLoader
from guinmap.application.scan_service import ScanService
from guinmap.application.settings_service import AppSettingsService
from guinmap.domain.app_settings import AppSettings
from guinmap.infrastructure.nmap_executor import NmapExecutor
from guinmap.infrastructure.settings_repository import JsonSettingsRepository


def test_settings_service_saves_loads_and_applies_runtime(tmp_path: Path) -> None:
    repository = JsonSettingsRepository(settings_path=tmp_path / "settings.json")
    service = AppSettingsService(repository=repository)
    settings = AppSettings(
        nmap_binary=str(tmp_path / "bin" / "nmap.exe"),
        stats_interval="2s",
        artifacts_dir=tmp_path / "artifacts" / "scans",
        reports_dir=tmp_path / "reports",
        language_code="es",
        preferred_scan_type="udp",
        preferred_timing_template=4,
    )

    saved = service.save(settings)
    loaded = service.load()

    scan_service = ScanService(executor=NmapExecutor(binary="nmap"))
    diagnostics_service = EnvironmentDiagnosticsService(executor=NmapExecutor(binary="nmap"))
    result_loader = ScanResultLoader()
    report_exporter = ScanReportExporter()
    applied = service.configure_runtime(
        loaded,
        scan_service=scan_service,
        diagnostics_service=diagnostics_service,
        result_loader=result_loader,
        report_exporter=report_exporter,
    )

    assert saved == loaded
    assert applied == loaded
    assert repository.settings_path.exists()
    assert scan_service.executor.binary == settings.nmap_binary
    assert scan_service.executor.stats_interval == settings.stats_interval
    assert scan_service.artifacts_dir == settings.artifacts_dir
    assert diagnostics_service.executor.binary == settings.nmap_binary
    assert result_loader.scans_dir == settings.artifacts_dir
    assert report_exporter.reports_dir == settings.reports_dir
    assert loaded.language_code == "es"


def test_settings_service_normalizes_invalid_preferences(tmp_path: Path) -> None:
    repository = JsonSettingsRepository(settings_path=tmp_path / "settings.json")
    service = AppSettingsService(repository=repository)

    normalized = service.normalize(
        AppSettings(
            nmap_binary=" ",
            stats_interval=" ",
            language_code="de",
            preferred_scan_type="invalid-scan-type",
            preferred_timing_template=99,
        )
    )

    assert normalized.nmap_binary == "nmap"
    assert normalized.stats_interval == "5s"
    assert normalized.language_code == "en"
    assert normalized.preferred_scan_type == "default"
    assert normalized.preferred_timing_template == 3