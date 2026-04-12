"""Parse Nmap XML output into typed domain models."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from guinmap.domain.scan_result import (
    ExtraportsSummary,
    HostResult,
    PortResult,
    ScanResult,
    ScanStats,
    ScriptResult,
)


class NmapXmlParser:
    def parse_file(self, xml_path: Path) -> ScanResult:
        root = ET.parse(xml_path).getroot()
        finished_node = root.find("runstats/finished")
        hosts_node = root.find("runstats/hosts")

        return ScanResult(
            command=root.get("args", ""),
            started_at=root.get("startstr"),
            finished_at=None
            if finished_node is None
            else finished_node.get("endstr") or finished_node.get("timestr"),
            scanner=root.get("scanner"),
            version=root.get("version"),
            stats=ScanStats(
                total_hosts=self._parse_int(
                    None if hosts_node is None else hosts_node.get("total")
                ),
                up_hosts=self._parse_int(None if hosts_node is None else hosts_node.get("up")),
                down_hosts=self._parse_int(
                    None if hosts_node is None else hosts_node.get("down")
                ),
                elapsed_seconds=self._parse_float(
                    None if finished_node is None else finished_node.get("elapsed")
                ),
                exit_status=None if finished_node is None else finished_node.get("exit"),
                summary=None if finished_node is None else finished_node.get("summary"),
            ),
            hosts=[self._parse_host(host_node) for host_node in root.findall("host")],
        )

    def _parse_host(self, host_node: ET.Element) -> HostResult:
        status_node = host_node.find("status")
        addresses = host_node.findall("address")
        hostnames = [
            hostname.get("name", "")
            for hostname in host_node.findall("hostnames/hostname")
            if hostname.get("name")
        ]

        address, address_type = self._select_address(addresses)

        return HostResult(
            address=address,
            address_type=address_type,
            state=status_node.get("state", "unknown") if status_node is not None else "unknown",
            reason=status_node.get("reason") if status_node is not None else None,
            hostnames=hostnames,
            ports=[self._parse_port(port_node) for port_node in host_node.findall("ports/port")],
            host_scripts=[
                self._parse_script(script_node)
                for script_node in host_node.findall("hostscript/script")
            ],
            extraports=[
                self._parse_extraports(extraports_node)
                for extraports_node in host_node.findall("ports/extraports")
            ],
        )

    def _parse_port(self, port_node: ET.Element) -> PortResult:
        state_node = port_node.find("state")
        service_node = port_node.find("service")

        return PortResult(
            port=int(port_node.get("portid", "0")),
            protocol=port_node.get("protocol", "unknown"),
            state=state_node.get("state", "unknown") if state_node is not None else "unknown",
            service=service_node.get("name") if service_node is not None else None,
            product=service_node.get("product") if service_node is not None else None,
            version=service_node.get("version") if service_node is not None else None,
            extra_info=service_node.get("extrainfo") if service_node is not None else None,
            service_method=service_node.get("method") if service_node is not None else None,
            service_confidence=self._parse_int(
                service_node.get("conf") if service_node is not None else None
            ),
            reason=state_node.get("reason") if state_node is not None else None,
            cpes=[cpe.text for cpe in port_node.findall("service/cpe") if cpe.text],
            scripts=[
                self._parse_script(script_node) for script_node in port_node.findall("script")
            ],
        )

    def _parse_script(self, script_node: ET.Element) -> ScriptResult:
        return ScriptResult(
            script_id=script_node.get("id", "unknown"),
            output=script_node.get("output"),
        )

    def _parse_extraports(self, extraports_node: ET.Element) -> ExtraportsSummary:
        return ExtraportsSummary(
            state=extraports_node.get("state", "unknown"),
            count=self._parse_int(extraports_node.get("count")) or 0,
        )

    def _select_address(self, addresses: list[ET.Element]) -> tuple[str, str | None]:
        for address in addresses:
            if address.get("addrtype") in {"ipv4", "ipv6"}:
                return address.get("addr", "unknown"), address.get("addrtype")

        if addresses:
            return addresses[0].get("addr", "unknown"), addresses[0].get("addrtype")

        return "unknown", None

    def _parse_int(self, value: str | None) -> int | None:
        if value is None:
            return None

        return int(value)

    def _parse_float(self, value: str | None) -> float | None:
        if value is None:
            return None

        return float(value)
