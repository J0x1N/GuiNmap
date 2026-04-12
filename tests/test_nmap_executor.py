from pathlib import Path

import pytest

from guinmap.domain.scan_profile import ScanProfile
from guinmap.infrastructure.nmap_executor import NmapExecutor


def test_build_command_includes_expected_flags() -> None:
    profile = ScanProfile(
        name="Service fingerprint",
        targets=["scanme.nmap.org"],
        scan_type="connect",
        ports="22,80,443",
        timing_template=4,
        enable_service_detection=True,
        enable_os_detection=True,
        script_selection=["default", "safe"],
        extra_args=["--reason"],
    )
    executor = NmapExecutor(binary="nmap")
    xml_output_path = Path("artifacts/scans/test.xml")

    command = executor.build_command(profile, xml_output_path)

    assert command == [
        "nmap",
        "-oX",
        str(xml_output_path),
        "--noninteractive",
        "--stats-every",
        "5s",
        "-sT",
        "-T",
        "4",
        "-p",
        "22,80,443",
        "-sV",
        "-O",
        "--script",
        "default,safe",
        "--reason",
        "scanme.nmap.org",
    ]


def test_build_command_rejects_invalid_timing_template() -> None:
    profile = ScanProfile(name="Invalid", targets=["127.0.0.1"], timing_template=9)
    executor = NmapExecutor()

    with pytest.raises(ValueError, match="Timing template"):
        executor.build_command(profile, Path("scan.xml"))
