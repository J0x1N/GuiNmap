"""Typed scan result models used by the UI and infrastructure layers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ScriptResult:
    script_id: str
    output: str | None = None


@dataclass(slots=True)
class ExtraportsSummary:
    state: str
    count: int


@dataclass(slots=True)
class ScanStats:
    total_hosts: int | None = None
    up_hosts: int | None = None
    down_hosts: int | None = None
    elapsed_seconds: float | None = None
    exit_status: str | None = None
    summary: str | None = None


@dataclass(slots=True)
class PortResult:
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    service_method: str | None = None
    service_confidence: int | None = None
    reason: str | None = None
    cpes: list[str] = field(default_factory=list)
    scripts: list[ScriptResult] = field(default_factory=list)


@dataclass(slots=True)
class HostResult:
    address: str
    state: str
    address_type: str | None = None
    reason: str | None = None
    hostnames: list[str] = field(default_factory=list)
    ports: list[PortResult] = field(default_factory=list)
    host_scripts: list[ScriptResult] = field(default_factory=list)
    extraports: list[ExtraportsSummary] = field(default_factory=list)


@dataclass(slots=True)
class ScanResult:
    command: str
    started_at: str | None = None
    finished_at: str | None = None
    scanner: str | None = None
    version: str | None = None
    stats: ScanStats = field(default_factory=ScanStats)
    hosts: list[HostResult] = field(default_factory=list)
