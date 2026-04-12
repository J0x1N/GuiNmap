from pathlib import Path

from guinmap.infrastructure.nmap_xml_parser import NmapXmlParser


def test_parse_file_reads_hosts_and_ports(tmp_path: Path) -> None:
    xml_path = tmp_path / "sample.xml"
    xml_path.write_text(
        """<?xml version="1.0"?>
<nmaprun
  scanner="nmap"
  args="nmap -oX sample.xml scanme.nmap.org"
  startstr="Sat Apr 12 11:00:00 2026"
  version="7.99SVN"
>
  <host>
    <status state="up" reason="syn-ack" />
    <address addr="00:11:22:33:44:55" addrtype="mac" />
    <address addr="192.168.1.10" addrtype="ipv4" />
    <hostnames>
      <hostname name="demo.local" type="user" />
    </hostnames>
    <ports>
      <extraports state="closed" count="997" />
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" />
        <service
          name="http"
          product="Apache httpd"
          version="2.4.58"
          extrainfo="(Ubuntu)"
          method="probed"
          conf="10"
        >
          <cpe>cpe:/a:apache:http_server:2.4.58</cpe>
        </service>
        <script id="http-title" output="GuiNmap test target" />
      </port>
      <port protocol="udp" portid="53">
        <state state="open|filtered" reason="no-response" />
        <service name="domain" />
      </port>
    </ports>
    <hostscript>
      <script id="uptime" output="host up for less than a minute" />
    </hostscript>
  </host>
  <runstats>
    <finished
      timestr="Sat Apr 12 11:00:05 2026"
      elapsed="5.40"
      exit="success"
      summary="Nmap done: 1 IP address (1 host up) scanned in 5.40 seconds"
    />
    <hosts up="1" down="0" total="1" />
  </runstats>
</nmaprun>
""",
        encoding="utf-8",
    )

    result = NmapXmlParser().parse_file(xml_path)

    assert result.command == "nmap -oX sample.xml scanme.nmap.org"
    assert result.started_at == "Sat Apr 12 11:00:00 2026"
    assert result.finished_at == "Sat Apr 12 11:00:05 2026"
    assert result.scanner == "nmap"
    assert result.version == "7.99SVN"
    assert result.stats.total_hosts == 1
    assert result.stats.up_hosts == 1
    assert result.stats.down_hosts == 0
    assert result.stats.elapsed_seconds == 5.40
    assert result.stats.exit_status == "success"
    assert result.stats.summary == "Nmap done: 1 IP address (1 host up) scanned in 5.40 seconds"
    assert len(result.hosts) == 1

    host = result.hosts[0]
    assert host.address == "192.168.1.10"
    assert host.address_type == "ipv4"
    assert host.state == "up"
    assert host.reason == "syn-ack"
    assert host.hostnames == ["demo.local"]
    assert host.extraports[0].state == "closed"
    assert host.extraports[0].count == 997
    assert host.host_scripts[0].script_id == "uptime"
    assert host.host_scripts[0].output == "host up for less than a minute"
    assert [port.port for port in host.ports] == [80, 53]
    assert host.ports[0].service == "http"
    assert host.ports[0].product == "Apache httpd"
    assert host.ports[0].version == "2.4.58"
    assert host.ports[0].extra_info == "(Ubuntu)"
    assert host.ports[0].service_method == "probed"
    assert host.ports[0].service_confidence == 10
    assert host.ports[0].cpes == ["cpe:/a:apache:http_server:2.4.58"]
    assert host.ports[0].scripts[0].script_id == "http-title"
    assert host.ports[0].scripts[0].output == "GuiNmap test target"
    assert host.ports[1].state == "open|filtered"


def test_parse_file_falls_back_to_first_non_ip_address_when_needed(tmp_path: Path) -> None:
    xml_path = tmp_path / "fallback.xml"
    xml_path.write_text(
        """<?xml version="1.0"?>
<nmaprun args="nmap -oX fallback.xml target" startstr="Sat Apr 12 11:10:00 2026">
  <host>
    <status state="up" reason="arp-response" />
    <address addr="00:11:22:33:44:55" addrtype="mac" />
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )

    result = NmapXmlParser().parse_file(xml_path)

    assert result.hosts[0].address == "00:11:22:33:44:55"
    assert result.hosts[0].address_type == "mac"
