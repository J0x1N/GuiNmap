"""Scan configuration models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ScanProfile:
    name: str
    targets: list[str]
    scan_type: str = "default"
    ports: str | None = None
    timing_template: int = 3
    enable_service_detection: bool = False
    enable_os_detection: bool = False
    script_selection: list[str] = field(default_factory=list)
    extra_args: list[str] = field(default_factory=list)
