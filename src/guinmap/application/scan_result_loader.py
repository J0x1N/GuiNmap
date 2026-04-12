"""Load typed scan results from XML artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from guinmap.domain.scan_result import ScanResult
from guinmap.infrastructure.nmap_xml_parser import NmapXmlParser


@dataclass(frozen=True, slots=True)
class LoadedScanResult:
    source_xml_path: Path
    scan_result: ScanResult
    used_fallback_source: bool = False


@dataclass(slots=True)
class ScanResultLoader:
    parser: NmapXmlParser = field(default_factory=NmapXmlParser)
    scans_dir: Path = Path("artifacts/scans")
    default_xml_source: Path = Path("docs/examples/sample-nmap-scan.xml")

    def load_from_xml_file(self, xml_path: Path) -> LoadedScanResult:
        return LoadedScanResult(
            source_xml_path=xml_path,
            scan_result=self.parser.parse_file(xml_path),
        )

    def load_latest_available(
        self,
        scans_dir: Path | None = None,
    ) -> LoadedScanResult:
        source_xml_path, used_fallback_source = self._resolve_source_xml(
            self.scans_dir if scans_dir is None else scans_dir
        )
        loaded = self.load_from_xml_file(source_xml_path)

        return LoadedScanResult(
            source_xml_path=loaded.source_xml_path,
            scan_result=loaded.scan_result,
            used_fallback_source=used_fallback_source,
        )

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