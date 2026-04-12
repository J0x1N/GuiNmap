"""Export typed scan results to portable report formats."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from guinmap.domain.scan_result import HostResult, PortResult, ScanResult, ScriptResult
from guinmap.infrastructure.nmap_xml_parser import NmapXmlParser


@dataclass(frozen=True, slots=True)
class ScanReportExportResult:
    source_xml_path: Path
    json_report_path: Path
    markdown_report_path: Path
    used_fallback_source: bool = False


@dataclass(slots=True)
class ScanReportExporter:
    reports_dir: Path = Path("reports")
    default_xml_source: Path = Path("docs/examples/sample-nmap-scan.xml")

    def render_json(self, scan_result: ScanResult) -> str:
        return json.dumps(asdict(scan_result), indent=2, ensure_ascii=False) + "\n"

    def export_json(self, scan_result: ScanResult, output_path: Path | None = None) -> Path:
        path = self._resolve_output_path(scan_result, output_path, ".json")
        path.write_text(self.render_json(scan_result), encoding="utf-8")
        return path

    def render_markdown(self, scan_result: ScanResult) -> str:
        lines = ["# GuiNmap Scan Report", ""]

        lines.extend(self._render_summary(scan_result))
        lines.append("")
        lines.append("## Hosts")
        lines.append("")

        if not scan_result.hosts:
            lines.append("No hosts were parsed from the XML artifact.")
            lines.append("")
            return "\n".join(lines)

        for host in scan_result.hosts:
            lines.extend(self._render_host(host))

        return "\n".join(lines).rstrip() + "\n"

    def export_markdown(self, scan_result: ScanResult, output_path: Path | None = None) -> Path:
        path = self._resolve_output_path(scan_result, output_path, ".md")
        path.write_text(self.render_markdown(scan_result), encoding="utf-8")
        return path

    def export_from_xml_file(
        self,
        xml_path: Path,
        *,
        parser: NmapXmlParser | None = None,
    ) -> ScanReportExportResult:
        scan_result = (parser or NmapXmlParser()).parse_file(xml_path)
        json_output_path, markdown_output_path = self._build_pair_output_paths(scan_result)

        json_report_path = self.export_json(scan_result, json_output_path)
        markdown_report_path = self.export_markdown(scan_result, markdown_output_path)

        return ScanReportExportResult(
            source_xml_path=xml_path,
            json_report_path=json_report_path,
            markdown_report_path=markdown_report_path,
        )

    def export_latest_available(
        self,
        scans_dir: Path = Path("artifacts/scans"),
        *,
        parser: NmapXmlParser | None = None,
    ) -> ScanReportExportResult:
        source_xml_path, used_fallback_source = self._resolve_source_xml(scans_dir)
        export_result = self.export_from_xml_file(source_xml_path, parser=parser)

        return ScanReportExportResult(
            source_xml_path=export_result.source_xml_path,
            json_report_path=export_result.json_report_path,
            markdown_report_path=export_result.markdown_report_path,
            used_fallback_source=used_fallback_source,
        )

    def _render_summary(self, scan_result: ScanResult) -> list[str]:
        stats = scan_result.stats
        scanner_label = scan_result.scanner or "unknown"
        if scan_result.version:
            scanner_label = f"{scanner_label} {scan_result.version}"

        lines = [
            "## Scan Summary",
            "",
            f"- Command: {scan_result.command or 'unknown'}",
            f"- Scanner: {scanner_label}",
            f"- Started: {scan_result.started_at or 'unknown'}",
            f"- Finished: {scan_result.finished_at or 'unknown'}",
            f"- Total hosts: {self._display_value(stats.total_hosts)}",
            f"- Up hosts: {self._display_value(stats.up_hosts)}",
            f"- Down hosts: {self._display_value(stats.down_hosts)}",
            f"- Elapsed seconds: {self._display_value(stats.elapsed_seconds)}",
            f"- Exit status: {stats.exit_status or 'unknown'}",
        ]

        if stats.summary:
            lines.append(f"- Summary: {stats.summary}")

        return lines

    def _render_host(self, host: HostResult) -> list[str]:
        title = host.address
        if host.hostnames:
            title = f"{host.hostnames[0]} ({host.address})"

        lines = [f"### {title}", ""]
        lines.append(f"- Address type: {host.address_type or 'unknown'}")
        lines.append(f"- State: {host.state}")

        if host.reason:
            lines.append(f"- Reason: {host.reason}")

        if len(host.hostnames) > 1:
            lines.append(f"- Additional hostnames: {', '.join(host.hostnames[1:])}")

        if host.extraports:
            summary = ", ".join(
                f"{item.count} {item.state}" for item in host.extraports
            )
            lines.append(f"- Extraports: {summary}")

        if host.host_scripts:
            lines.append("- Host scripts:")
            lines.extend(self._render_scripts(host.host_scripts))

        lines.append("")

        if not host.ports:
            lines.append("No individual ports were reported for this host.")
            lines.append("")
            return lines

        lines.append("#### Ports")
        lines.append("")

        for port in host.ports:
            lines.extend(self._render_port(port))

        return lines

    def _render_port(self, port: PortResult) -> list[str]:
        lines = [f"##### {port.port}/{port.protocol}", ""]
        lines.append(f"- State: {port.state}")

        if port.reason:
            lines.append(f"- Reason: {port.reason}")

        if port.service:
            lines.append(f"- Service: {port.service}")

        if port.product:
            lines.append(f"- Product: {port.product}")

        if port.version:
            lines.append(f"- Version: {port.version}")

        if port.extra_info:
            lines.append(f"- Extra info: {port.extra_info}")

        if port.service_method:
            lines.append(f"- Detection method: {port.service_method}")

        if port.service_confidence is not None:
            lines.append(f"- Service confidence: {port.service_confidence}")

        if port.cpes:
            lines.append(f"- CPEs: {', '.join(port.cpes)}")

        if port.scripts:
            lines.append("- Port scripts:")
            lines.extend(self._render_scripts(port.scripts))

        lines.append("")
        return lines

    def _render_scripts(self, scripts: list[ScriptResult]) -> list[str]:
        lines: list[str] = []

        for script in scripts:
            if script.output:
                lines.append(f"  - {script.script_id}: {script.output}")
            else:
                lines.append(f"  - {script.script_id}")

        return lines

    def _resolve_output_path(
        self,
        scan_result: ScanResult,
        output_path: Path | None,
        suffix: str,
    ) -> Path:
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            return output_path

        self.reports_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        slug_source = scan_result.hosts[0].address if scan_result.hosts else "scan-report"
        slug = self._slugify(slug_source)
        return self.reports_dir / f"{timestamp}-{slug}{suffix}"

    def _build_pair_output_paths(self, scan_result: ScanResult) -> tuple[Path, Path]:
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        slug_source = scan_result.hosts[0].address if scan_result.hosts else "scan-report"
        slug = self._slugify(slug_source)
        base_path = self.reports_dir / f"{timestamp}-{slug}"

        return base_path.with_suffix(".json"), base_path.with_suffix(".md")

    def _resolve_source_xml(self, scans_dir: Path) -> tuple[Path, bool]:
        if scans_dir.exists():
            xml_candidates = sorted(scans_dir.glob("*.xml"))
            if xml_candidates:
                return xml_candidates[-1], False

        if self.default_xml_source.exists():
            return self.default_xml_source, True

        raise FileNotFoundError(
            "No XML scan artifacts were found under artifacts/scans and the bundled sample "
            "XML file is also missing."
        )

    def _slugify(self, value: str) -> str:
        normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip().lower())
        cleaned = normalized.strip("-._")
        return cleaned or "scan-report"

    def _display_value(self, value: object | None) -> str:
        if value is None:
            return "unknown"

        return str(value)
