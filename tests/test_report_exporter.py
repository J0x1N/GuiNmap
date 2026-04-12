from pathlib import Path

from guinmap.application.report_exporter import ScanReportExporter
from guinmap.domain.scan_result import (
    ExtraportsSummary,
    HostResult,
    PortResult,
    ScanResult,
    ScanStats,
    ScriptResult,
)


def build_sample_result() -> ScanResult:
    return ScanResult(
        command="nmap -sT -sV -oX sample.xml scanme.nmap.org",
        started_at="Sat Apr 12 11:00:00 2026",
        finished_at="Sat Apr 12 11:00:05 2026",
        scanner="nmap",
        version="7.99SVN",
        stats=ScanStats(
            total_hosts=1,
            up_hosts=1,
            down_hosts=0,
            elapsed_seconds=5.4,
            exit_status="success",
            summary="Nmap done: 1 IP address (1 host up) scanned in 5.40 seconds",
        ),
        hosts=[
            HostResult(
                address="192.168.1.10",
                state="up",
                address_type="ipv4",
                reason="syn-ack",
                hostnames=["demo.local"],
                extraports=[ExtraportsSummary(state="closed", count=997)],
                host_scripts=[
                    ScriptResult(script_id="uptime", output="host up for less than a minute")
                ],
                ports=[
                    PortResult(
                        port=80,
                        protocol="tcp",
                        state="open",
                        service="http",
                        product="Apache httpd",
                        version="2.4.58",
                        extra_info="(Ubuntu)",
                        service_method="probed",
                        service_confidence=10,
                        reason="syn-ack",
                        cpes=["cpe:/a:apache:http_server:2.4.58"],
                        scripts=[
                            ScriptResult(
                                script_id="http-title",
                                output="GuiNmap test target",
                            )
                        ],
                    )
                ],
            )
        ],
    )


def test_render_json_serializes_nested_scan_result() -> None:
    exporter = ScanReportExporter()
    report = exporter.render_json(build_sample_result())

    assert '"scanner": "nmap"' in report
    assert '"total_hosts": 1' in report
    assert '"script_id": "http-title"' in report
    assert '"address_type": "ipv4"' in report


def test_render_markdown_produces_human_readable_sections() -> None:
    exporter = ScanReportExporter()
    report = exporter.render_markdown(build_sample_result())

    assert "# GuiNmap Scan Report" in report
    assert "## Scan Summary" in report
    assert "### demo.local (192.168.1.10)" in report
    assert "- Extraports: 997 closed" in report
    assert "##### 80/tcp" in report
    assert "- Port scripts:" in report
    assert "  - http-title: GuiNmap test target" in report


def test_export_json_and_markdown_write_files(tmp_path: Path) -> None:
    exporter = ScanReportExporter(reports_dir=tmp_path / "reports")
    scan_result = build_sample_result()

    json_path = exporter.export_json(scan_result)
    markdown_path = exporter.export_markdown(scan_result)

    assert json_path.exists()
    assert markdown_path.exists()
    assert json_path.suffix == ".json"
    assert markdown_path.suffix == ".md"
    assert "demo.local" in markdown_path.read_text(encoding="utf-8")


def test_export_from_xml_file_writes_both_reports(tmp_path: Path) -> None:
        xml_path = tmp_path / "sample.xml"
        xml_path.write_text(
                """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX sample.xml target" startstr="Sat Apr 12 11:00:00 2026">
    <host>
        <status state="up" reason="syn-ack" />
        <address addr="192.168.1.10" addrtype="ipv4" />
        <hostnames>
            <hostname name="demo.local" type="user" />
        </hostnames>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="open" reason="syn-ack" />
                <service name="http" product="Apache httpd" version="2.4.58" />
            </port>
        </ports>
    </host>
</nmaprun>
""",
                encoding="utf-8",
        )

        exporter = ScanReportExporter(reports_dir=tmp_path / "reports")
        export_result = exporter.export_from_xml_file(xml_path)

        assert export_result.source_xml_path == xml_path
        assert export_result.used_fallback_source is False
        assert export_result.json_report_path.exists()
        assert export_result.markdown_report_path.exists()
        assert "demo.local" in export_result.markdown_report_path.read_text(encoding="utf-8")


def test_export_latest_available_falls_back_to_sample_xml(tmp_path: Path) -> None:
        sample_xml = tmp_path / "sample-fallback.xml"
        sample_xml.write_text(
                """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX sample.xml fallback" startstr="Sat Apr 12 12:00:00 2026">
    <host>
        <status state="up" reason="echo-reply" />
        <address addr="127.0.0.1" addrtype="ipv4" />
    </host>
</nmaprun>
""",
                encoding="utf-8",
        )

        exporter = ScanReportExporter(
                reports_dir=tmp_path / "reports",
                default_xml_source=sample_xml,
        )

        export_result = exporter.export_latest_available(scans_dir=tmp_path / "artifacts")

        assert export_result.source_xml_path == sample_xml
        assert export_result.used_fallback_source is True
        assert export_result.json_report_path.exists()
        assert export_result.markdown_report_path.exists()
