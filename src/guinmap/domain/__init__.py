"""Domain models for GuiNmap."""

from guinmap.domain.scan_profile import ScanProfile
from guinmap.domain.scan_result import (
	ExtraportsSummary,
	HostResult,
	PortResult,
	ScanResult,
	ScanStats,
	ScriptResult,
)

__all__ = [
	"ExtraportsSummary",
	"HostResult",
	"PortResult",
	"ScanProfile",
	"ScanResult",
	"ScanStats",
	"ScriptResult",
]
