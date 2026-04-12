"""Load, save, and apply persistent operator settings."""

from __future__ import annotations

from dataclasses import dataclass, field

from guinmap.application.environment_diagnostics import EnvironmentDiagnosticsService
from guinmap.application.report_exporter import ScanReportExporter
from guinmap.application.scan_result_loader import ScanResultLoader
from guinmap.application.scan_service import ScanService
from guinmap.domain.app_settings import AppSettings
from guinmap.infrastructure.settings_repository import JsonSettingsRepository

VALID_LANGUAGE_CODES = {"en", "es"}
VALID_SCAN_TYPES = {"default", "connect", "syn", "udp", "ping"}
VALID_TIMING_TEMPLATES = {0, 1, 2, 3, 4, 5}


@dataclass(slots=True)
class AppSettingsService:
    repository: JsonSettingsRepository = field(default_factory=JsonSettingsRepository)

    def load(self) -> AppSettings:
        return self.normalize(self.repository.load())

    def save(self, settings: AppSettings) -> AppSettings:
        normalized = self.normalize(settings)
        self.repository.save(normalized)
        return normalized

    def normalize(self, settings: AppSettings) -> AppSettings:
        nmap_binary = settings.nmap_binary.strip() or "nmap"
        stats_interval = settings.stats_interval.strip() or "5s"
        language_code = settings.language_code
        if language_code not in VALID_LANGUAGE_CODES:
            language_code = "en"

        preferred_scan_type = settings.preferred_scan_type
        if preferred_scan_type not in VALID_SCAN_TYPES:
            preferred_scan_type = "default"

        preferred_timing_template = settings.preferred_timing_template
        if preferred_timing_template not in VALID_TIMING_TEMPLATES:
            preferred_timing_template = 3

        return AppSettings(
            nmap_binary=nmap_binary,
            stats_interval=stats_interval,
            artifacts_dir=settings.artifacts_dir,
            reports_dir=settings.reports_dir,
            language_code=language_code,
            preferred_scan_type=preferred_scan_type,
            preferred_timing_template=preferred_timing_template,
        )

    def configure_runtime(
        self,
        settings: AppSettings,
        *,
        scan_service: ScanService,
        diagnostics_service: EnvironmentDiagnosticsService,
        result_loader: ScanResultLoader,
        report_exporter: ScanReportExporter,
    ) -> AppSettings:
        normalized = self.normalize(settings)
        scan_service.executor.binary = normalized.nmap_binary
        scan_service.executor.stats_interval = normalized.stats_interval
        scan_service.artifacts_dir = normalized.artifacts_dir

        diagnostics_executor = getattr(diagnostics_service, "executor", None)
        if diagnostics_executor is not None:
            diagnostics_executor.binary = normalized.nmap_binary

        result_loader.scans_dir = normalized.artifacts_dir
        report_exporter.reports_dir = normalized.reports_dir
        return normalized