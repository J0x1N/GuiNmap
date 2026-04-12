"""Inspect runtime environment capabilities relevant to Nmap execution."""

from __future__ import annotations

import ctypes
import platform
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from guinmap.infrastructure.nmap_executor import NmapExecutor


@dataclass(frozen=True, slots=True)
class EnvironmentIssue:
    level: str
    message: str


@dataclass(frozen=True, slots=True)
class EnvironmentDiagnostics:
    platform_name: str
    configured_binary: str
    resolved_binary_path: str | None
    binary_available: bool
    is_admin: bool | None
    raw_packet_scans_available: bool
    recommended_scan_type: str
    issues: tuple[EnvironmentIssue, ...] = ()


def default_admin_provider() -> bool | None:
    system_name = platform.system().lower()

    if system_name.startswith("win"):
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return None

    try:
        return hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0
    except (AttributeError, OSError):
        return None


@dataclass(slots=True)
class EnvironmentDiagnosticsService:
    executor: NmapExecutor = field(default_factory=NmapExecutor)
    admin_provider: Callable[[], bool | None] = default_admin_provider
    platform_provider: Callable[[], str] = platform.system

    def inspect(self) -> EnvironmentDiagnostics:
        platform_name = self.platform_provider()
        resolved_binary_path = self.executor.resolve_binary_path()
        binary_available = resolved_binary_path is not None
        is_admin = self.admin_provider()
        is_windows = platform_name.lower().startswith("win")
        raw_packet_scans_available = binary_available and is_admin is True
        recommended_scan_type = "syn" if raw_packet_scans_available else "connect"

        issues: list[EnvironmentIssue] = []

        if not binary_available:
            issues.append(
                EnvironmentIssue(
                    level="error",
                    message=(
                        f"The configured Nmap binary '{self.executor.binary}' is not available."
                    ),
                )
            )

        if binary_available and self._uses_fallback_install_path(resolved_binary_path):
            issues.append(
                EnvironmentIssue(
                    level="info",
                    message=(
                        "GuiNmap auto-detected the standard Windows Nmap installation at "
                        f"'{resolved_binary_path}'."
                    ),
                )
            )

        if is_windows:
            issues.append(
                EnvironmentIssue(
                    level="info",
                    message=(
                        "Windows scan capabilities may depend on Npcap and administrative "
                        "privileges for raw-packet features."
                    ),
                )
            )

        if binary_available and not raw_packet_scans_available:
            issues.append(
                EnvironmentIssue(
                    level="warning",
                    message=(
                        "Raw-packet scans are not currently available. Prefer TCP connect "
                        "scan (-sT) as the safe fallback."
                    ),
                )
            )

        if binary_available and raw_packet_scans_available:
            issues.append(
                EnvironmentIssue(
                    level="info",
                    message="Raw-packet scan modes should be available in this environment.",
                )
            )

        return EnvironmentDiagnostics(
            platform_name=platform_name,
            configured_binary=self.executor.binary,
            resolved_binary_path=resolved_binary_path,
            binary_available=binary_available,
            is_admin=is_admin,
            raw_packet_scans_available=raw_packet_scans_available,
            recommended_scan_type=recommended_scan_type,
            issues=tuple(issues),
        )

    def _uses_fallback_install_path(self, resolved_binary_path: str | None) -> bool:
        if resolved_binary_path is None:
            return False

        binary_path = Path(self.executor.binary)
        if binary_path.is_file():
            return False

        return any(
            str(candidate) == resolved_binary_path
            for candidate in self.executor.fallback_binary_locations
        )
