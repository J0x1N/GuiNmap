"""Typed scan result models used by the UI and infrastructure layers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class PortResult:
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    reason: str | None = None


@dataclass(slots=True)
class HostResult:
    address: str
    state: str
    reason: str | None = None
    hostnames: list[str] = field(default_factory=list)
    ports: list[PortResult] = field(default_factory=list)


@dataclass(slots=True)
class ScanResult:
    command: str
    started_at: str | None = None
    finished_at: str | None = None
    hosts: list[HostResult] = field(default_factory=list)
