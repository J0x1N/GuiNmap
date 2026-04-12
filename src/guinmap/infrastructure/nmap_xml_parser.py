"""Parse Nmap XML output into typed domain models."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from guinmap.domain.scan_result import HostResult, PortResult, ScanResult


class NmapXmlParser:
    def parse_file(self, xml_path: Path) -> ScanResult:
        root = ET.parse(xml_path).getroot()
        finished_node = root.find("runstats/finished")

        return ScanResult(
            command=root.get("args", ""),
            started_at=root.get("startstr"),
            finished_at=None
            if finished_node is None
            else finished_node.get("endstr") or finished_node.get("timestr"),
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

        address = self._select_address(addresses)

        return HostResult(
            address=address,
            state=status_node.get("state", "unknown") if status_node is not None else "unknown",
            reason=status_node.get("reason") if status_node is not None else None,
            hostnames=hostnames,
            ports=[self._parse_port(port_node) for port_node in host_node.findall("ports/port")],
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
            reason=state_node.get("reason") if state_node is not None else None,
        )

    def _select_address(self, addresses: list[ET.Element]) -> str:
        for address in addresses:
            if address.get("addrtype") in {"ipv4", "ipv6"}:
                return address.get("addr", "unknown")

        if addresses:
            return addresses[0].get("addr", "unknown")

        return "unknown"
