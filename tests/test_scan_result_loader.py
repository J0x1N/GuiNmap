from pathlib import Path

from guinmap.application.scan_result_loader import ScanResultLoader


def test_load_from_xml_file_parses_scan_result(tmp_path: Path) -> None:
    xml_path = tmp_path / "sample.xml"
    xml_path.write_text(
        """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX sample.xml target" startstr="Sat Apr 12 11:00:00 2026">
    <host>
        <status state="up" reason="syn-ack" />
        <address addr="192.168.1.10" addrtype="ipv4" />
    </host>
</nmaprun>
""",
        encoding="utf-8",
    )

    loaded = ScanResultLoader().load_from_xml_file(xml_path)

    assert loaded.source_xml_path == xml_path
    assert loaded.scan_result.hosts[0].address == "192.168.1.10"
    assert loaded.used_fallback_source is False


def test_load_latest_available_falls_back_to_sample_xml(tmp_path: Path) -> None:
    fallback_xml = tmp_path / "fallback.xml"
    fallback_xml.write_text(
        """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX fallback.xml target" startstr="Sat Apr 12 12:00:00 2026">
    <host>
        <status state="up" reason="echo-reply" />
        <address addr="127.0.0.1" addrtype="ipv4" />
    </host>
</nmaprun>
""",
        encoding="utf-8",
    )

    loader = ScanResultLoader(
        scans_dir=tmp_path / "artifacts",
        default_xml_source=fallback_xml,
    )

    loaded = loader.load_latest_available()

    assert loaded.source_xml_path == fallback_xml
    assert loaded.used_fallback_source is True
    assert loaded.scan_result.hosts[0].address == "127.0.0.1"