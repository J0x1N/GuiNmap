"""Persist GuiNmap settings as JSON on disk."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from guinmap.domain.app_settings import AppSettings


def default_settings_path() -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "GuiNmap" / "settings.json"

    return Path.home() / ".guinmap" / "settings.json"


@dataclass(slots=True)
class JsonSettingsRepository:
    settings_path: Path = field(default_factory=default_settings_path)

    def load(self) -> AppSettings:
        if not self.settings_path.exists():
            return AppSettings()

        payload = json.loads(self.settings_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("The settings file must contain a JSON object.")

        return AppSettings(
            nmap_binary=str(payload.get("nmap_binary") or AppSettings().nmap_binary),
            stats_interval=str(payload.get("stats_interval") or AppSettings().stats_interval),
            artifacts_dir=Path(
                str(payload.get("artifacts_dir") or AppSettings().artifacts_dir)
            ),
            reports_dir=Path(str(payload.get("reports_dir") or AppSettings().reports_dir)),
            language_code=str(payload.get("language_code") or AppSettings().language_code),
            preferred_scan_type=str(
                payload.get("preferred_scan_type") or AppSettings().preferred_scan_type
            ),
            preferred_timing_template=int(
                payload.get("preferred_timing_template")
                or AppSettings().preferred_timing_template
            ),
        )

    def save(self, settings: AppSettings) -> None:
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "nmap_binary": settings.nmap_binary,
            "stats_interval": settings.stats_interval,
            "artifacts_dir": str(settings.artifacts_dir),
            "reports_dir": str(settings.reports_dir),
            "language_code": settings.language_code,
            "preferred_scan_type": settings.preferred_scan_type,
            "preferred_timing_template": settings.preferred_timing_template,
        }
        self.settings_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )