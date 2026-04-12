"""Persistent operator settings for the desktop workflow."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppSettings:
    nmap_binary: str = "nmap"
    stats_interval: str = "5s"
    artifacts_dir: Path = field(default_factory=lambda: Path("artifacts/scans"))
    reports_dir: Path = field(default_factory=lambda: Path("reports"))
    language_code: str = "en"
    preferred_scan_type: str = "default"
    preferred_timing_template: int = 3