from pathlib import Path

from guinmap.infrastructure.nmap_xml_parser import NmapXmlParser


def test_parse_file_reads_hosts_and_ports(tmp_path: Path) -> None:
    xml_path = tmp_path / "sample.xml"
    xml_path.write_text(
        """<?xml version="1.0"?>
<nmaprun args="nmap -oX sample.xml scanme.nmap.org" startstr="Sat Apr 12 11:00:00 2026">
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
      <port protocol="udp" portid="53">
        <state state="open|filtered" reason="no-response" />
        <service name="domain" />
      </port>
    </ports>
  </host>
  <runstats>
    <finished timestr="Sat Apr 12 11:00:05 2026" />
  </runstats>
</nmaprun>
""",
        encoding="utf-8",
    )

    result = NmapXmlParser().parse_file(xml_path)

    assert result.command == "nmap -oX sample.xml scanme.nmap.org"
    assert result.started_at == "Sat Apr 12 11:00:00 2026"
    assert result.finished_at == "Sat Apr 12 11:00:05 2026"
    assert len(result.hosts) == 1

    host = result.hosts[0]
    assert host.address == "192.168.1.10"
    assert host.state == "up"
    assert host.reason == "syn-ack"
    assert host.hostnames == ["demo.local"]
    assert [port.port for port in host.ports] == [80, 53]
    assert host.ports[0].service == "http"
    assert host.ports[0].product == "Apache httpd"
    assert host.ports[1].state == "open|filtered"
