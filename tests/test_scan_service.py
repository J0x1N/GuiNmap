import sys
import threading
from pathlib import Path

import pytest

from guinmap.application.scan_service import (
    ScanCancelledError,
    ScanExecutionError,
    ScanService,
)
from guinmap.domain.scan_profile import ScanProfile
from guinmap.infrastructure.nmap_executor import NmapExecutor

FAKE_XML_OUTPUT = """<?xml version="1.0"?>
<nmaprun args="fake nmap" startstr="Sat Apr 12 12:00:00 2026">
    <host>
        <status state="up" reason="echo-reply" />
        <address addr="127.0.0.1" addrtype="ipv4" />
        <ports>
            <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack" />
                <service name="https" product="Test Server" version="1.0" />
            </port>
        </ports>
    </host>
    <runstats>
        <finished timestr="Sat Apr 12 12:00:01 2026" />
    </runstats>
</nmaprun>
"""


def test_run_executes_binary_and_parses_xml(tmp_path: Path) -> None:
    fake_nmap = tmp_path / "fake_nmap.py"
    fake_nmap.write_text(
        "\n".join(
            [
                "from pathlib import Path",
                "import sys",
                "",
                "args = sys.argv[1:]",
                "xml_path = Path(args[args.index('-oX') + 1])",
                f"xml_path.write_text({FAKE_XML_OUTPUT!r}, encoding='utf-8')",
                "print('Stats: 0:00:01 elapsed; 1 host completed (1 up)')",
                "",
            ]
        ),
        encoding="utf-8",
    )

    service = ScanService(
        executor=NmapExecutor(
            binary=sys.executable,
            binary_arguments=[str(fake_nmap)],
            stats_interval="1s",
        ),
        artifacts_dir=tmp_path / "artifacts",
    )
    profile = ScanProfile(
        name="Smoke Test",
        targets=["127.0.0.1"],
        scan_type="connect",
        ports="443",
        timing_template=3,
        enable_service_detection=True,
    )

    streamed_lines: list[str] = []
    execution = service.run(profile, on_output=streamed_lines.append)

    assert execution.return_code == 0
    assert execution.xml_output_path.exists()
    assert execution.result is not None
    assert execution.result.hosts[0].address == "127.0.0.1"
    assert execution.result.hosts[0].ports[0].service == "https"
    assert execution.output_lines == ["Stats: 0:00:01 elapsed; 1 host completed (1 up)"]
    assert streamed_lines == execution.output_lines


def test_run_fails_when_binary_is_missing(tmp_path: Path) -> None:
    service = ScanService(
        executor=NmapExecutor(binary="definitely-not-a-real-nmap-binary"),
        artifacts_dir=tmp_path / "artifacts",
    )
    profile = ScanProfile(name="Missing", targets=["127.0.0.1"])

    with pytest.raises(FileNotFoundError):
        service.run(profile)


def test_run_raises_clear_error_on_non_zero_exit(tmp_path: Path) -> None:
    fake_nmap = tmp_path / "fake_failure.py"
    fake_nmap.write_text("import sys\nprint('fatal error')\nsys.exit(2)\n", encoding="utf-8")

    service = ScanService(
        executor=NmapExecutor(binary=sys.executable, binary_arguments=[str(fake_nmap)]),
        artifacts_dir=tmp_path / "artifacts",
    )
    profile = ScanProfile(name="Failure", targets=["127.0.0.1"])

    with pytest.raises(ScanExecutionError, match="exited with code 2"):
        service.run(profile)


def test_run_can_be_cancelled_while_process_is_active(tmp_path: Path) -> None:
    fake_nmap = tmp_path / "fake_long_running.py"
    fake_nmap.write_text(
        "\n".join(
            [
                "from pathlib import Path",
                "import sys",
                "import time",
                "",
                "args = sys.argv[1:]",
                "xml_path = Path(args[args.index('-oX') + 1])",
                "print('Stats: waiting for cancellation', flush=True)",
                "time.sleep(30)",
                f"xml_path.write_text({FAKE_XML_OUTPUT!r}, encoding='utf-8')",
            ]
        ),
        encoding="utf-8",
    )

    service = ScanService(
        executor=NmapExecutor(
            binary=sys.executable,
            binary_arguments=[str(fake_nmap)],
            stats_interval="1s",
        ),
        artifacts_dir=tmp_path / "artifacts",
    )
    profile = ScanProfile(name="Cancelled", targets=["127.0.0.1"])

    output_seen = threading.Event()
    raised: list[BaseException] = []

    def run_scan() -> None:
        try:
            service.run(
                profile,
                on_output=lambda _line: output_seen.set(),
            )
        except BaseException as exc:  # noqa: BLE001
            raised.append(exc)

    thread = threading.Thread(target=run_scan)
    thread.start()

    assert output_seen.wait(timeout=5)
    assert service.cancel_current_scan() is True

    thread.join(timeout=5)
    assert thread.is_alive() is False
    assert len(raised) == 1
    assert isinstance(raised[0], ScanCancelledError)
    assert raised[0].execution is not None
    assert raised[0].execution.was_cancelled is True
    assert raised[0].execution.xml_output_path.exists() is False
