"""Domain models for GuiNmap."""

from guinmap.domain.scan_profile import ScanProfile
from guinmap.domain.scan_result import HostResult, PortResult, ScanResult

__all__ = ["HostResult", "PortResult", "ScanProfile", "ScanResult"]
