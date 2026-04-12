"""Build safe Nmap command lines from structured scan profiles."""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from guinmap.domain.scan_profile import ScanProfile

SCAN_TYPE_FLAGS: dict[str, list[str]] = {
    "default": [],
    "connect": ["-sT"],
    "syn": ["-sS"],
    "udp": ["-sU"],
    "ping": ["-sn"],
}

DEFAULT_WINDOWS_BINARY_LOCATIONS: tuple[Path, ...] = (
    Path(r"C:\Program Files\Nmap\nmap.exe"),
    Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
)


@dataclass(slots=True)
class NmapExecutor:
    binary: str = "nmap"
    binary_arguments: list[str] = field(default_factory=list)
    stats_interval: str = "5s"
    noninteractive: bool = True
    fallback_binary_locations: tuple[Path, ...] = DEFAULT_WINDOWS_BINARY_LOCATIONS

    def is_available(self) -> bool:
        return self.resolve_binary_path() is not None

    def resolve_binary_path(self) -> str | None:
        binary_path = Path(self.binary)

        if binary_path.is_file():
            return str(binary_path)

        resolved = shutil.which(self.binary)
        if resolved is not None:
            return resolved

        binary_name = binary_path.name.lower()
        if binary_name not in {"nmap", "nmap.exe"}:
            return None

        for candidate in self.fallback_binary_locations:
            if candidate.is_file():
                return str(candidate)

        return None

    def build_command(self, profile: ScanProfile, xml_output_path: Path | str) -> list[str]:
        if not profile.targets:
            raise ValueError("At least one target must be provided.")

        if profile.scan_type not in SCAN_TYPE_FLAGS:
            raise ValueError(f"Unsupported scan type: {profile.scan_type}")

        if profile.timing_template not in {0, 1, 2, 3, 4, 5}:
            raise ValueError("Timing template must be between 0 and 5.")

        command = [
            self.resolve_binary_path() or self.binary,
            *self.binary_arguments,
            "-oX",
            str(xml_output_path),
        ]

        if self.noninteractive:
            command.append("--noninteractive")

        command.extend(["--stats-every", self.stats_interval])
        command.extend(SCAN_TYPE_FLAGS[profile.scan_type])
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
