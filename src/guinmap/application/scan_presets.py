"""Curated scan presets for the GuiNmap workflow."""

from __future__ import annotations

from dataclasses import dataclass

from guinmap.domain.scan_profile import ScanProfile


@dataclass(frozen=True, slots=True)
class ScanPreset:
    key: str
    label: str
    description: str
    command_preview: str
    scan_type: str = "default"
    ports: str | None = None
    timing_template: int = 3
    enable_service_detection: bool = False
    enable_os_detection: bool = False
    script_selection: tuple[str, ...] = ()
    extra_args: tuple[str, ...] = ()

    def to_profile(
        self,
        targets: list[str] | None = None,
        *,
        name: str | None = None,
    ) -> ScanProfile:
        return ScanProfile(
            name=self.label if name is None else name,
            targets=[] if targets is None else list(targets),
            scan_type=self.scan_type,
            ports=self.ports,
            timing_template=self.timing_template,
            enable_service_detection=self.enable_service_detection,
            enable_os_detection=self.enable_os_detection,
            script_selection=list(self.script_selection),
            extra_args=list(self.extra_args),
        )


DEFAULT_SCAN_PRESETS: tuple[ScanPreset, ...] = (
    ScanPreset(
        key="quick-discovery",
        label="Quick discovery",
        description="Map live hosts first with low friction and minimal noise.",
        command_preview="nmap -sn -PE -PS443 -PA80 -T3 <targets>",
        scan_type="ping",
        timing_template=3,
        extra_args=("-PE", "-PS443", "-PA80"),
    ),
    ScanPreset(
        key="balanced-tcp-inventory",
        label="Balanced TCP inventory",
        description="Windows-friendly baseline for service inventory and reporting.",
        command_preview="nmap -sT -sV -T3 --reason <targets>",
        scan_type="connect",
        timing_template=3,
        enable_service_detection=True,
        extra_args=("--reason",),
    ),
    ScanPreset(
        key="fast-service-fingerprint",
        label="Fast service fingerprint",
        description="Sharper TCP pass for responsive networks where speed matters.",
        command_preview="nmap -sS -sV -T4 --top-ports 100 --reason <targets>",
        scan_type="syn",
        timing_template=4,
        enable_service_detection=True,
        extra_args=("--top-ports", "100", "--reason"),
    ),
    ScanPreset(
        key="deep-assessment",
        label="Deep assessment",
        description="Broader operator preset for richer service, OS, and route context.",
        command_preview="nmap -sT -sV -O -sC --traceroute --reason -T3 <targets>",
        scan_type="connect",
        timing_template=3,
        enable_service_detection=True,
        enable_os_detection=True,
        script_selection=("default",),
        extra_args=("--traceroute", "--reason"),
    ),
)


def get_scan_presets() -> tuple[ScanPreset, ...]:
    return DEFAULT_SCAN_PRESETS


def get_scan_preset(key: str) -> ScanPreset | None:
    for preset in DEFAULT_SCAN_PRESETS:
        if preset.key == key:
            return preset

    return None
