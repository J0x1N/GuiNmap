"""Build safe Nmap command lines from structured scan profiles."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from guinmap.domain.scan_profile import ScanProfile


SCAN_TYPE_FLAGS: dict[str, list[str]] = {
    "default": [],
    "connect": ["-sT"],
    "syn": ["-sS"],
    "udp": ["-sU"],
}


@dataclass(slots=True)
class NmapExecutor:
    binary: str = "nmap"
    stats_interval: str = "5s"

    def build_command(self, profile: ScanProfile, xml_output_path: Path) -> list[str]:
        if not profile.targets:
            raise ValueError("At least one target must be provided.")

        if profile.scan_type not in SCAN_TYPE_FLAGS:
            raise ValueError(f"Unsupported scan type: {profile.scan_type}")

        command = [self.binary, "-oX", str(xml_output_path), "--stats-every", self.stats_interval]
        command.extend(SCAN_TYPE_FLAGS[profile.scan_type])

        if profile.timing_template in {0, 1, 2, 3, 4, 5}:
            command.extend(["-T", str(profile.timing_template)])

        if profile.ports:
            command.extend(["-p", profile.ports])

        if profile.enable_service_detection:
            command.append("-sV")

        if profile.enable_os_detection:
            command.append("-O")

        if profile.script_selection:
            command.extend(["--script", ",".join(profile.script_selection)])

        command.extend(profile.extra_args)
        command.extend(profile.targets)

        return command
