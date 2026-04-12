from pathlib import Path

from guinmap.application.environment_diagnostics import EnvironmentDiagnosticsService
from guinmap.infrastructure.nmap_executor import NmapExecutor


def test_inspect_reports_missing_binary() -> None:
    service = EnvironmentDiagnosticsService(
        executor=NmapExecutor(binary="definitely-not-a-real-nmap-binary"),
        admin_provider=lambda: False,
        platform_provider=lambda: "Windows",
    )

    diagnostics = service.inspect()

    assert diagnostics.binary_available is False
    assert diagnostics.resolved_binary_path is None
    assert diagnostics.raw_packet_scans_available is False
    assert diagnostics.recommended_scan_type == "connect"
    assert any(issue.level == "error" for issue in diagnostics.issues)


def test_inspect_prefers_syn_when_binary_exists_and_admin_is_available(tmp_path: Path) -> None:
    fake_binary = tmp_path / "nmap.exe"
    fake_binary.write_text("placeholder", encoding="utf-8")

    service = EnvironmentDiagnosticsService(
        executor=NmapExecutor(binary=str(fake_binary)),
        admin_provider=lambda: True,
        platform_provider=lambda: "Windows",
    )

    diagnostics = service.inspect()

    assert diagnostics.binary_available is True
    assert diagnostics.resolved_binary_path == str(fake_binary)
    assert diagnostics.raw_packet_scans_available is True
    assert diagnostics.recommended_scan_type == "syn"
    assert any("Raw-packet scan modes" in issue.message for issue in diagnostics.issues)


def test_inspect_recommends_connect_when_binary_exists_without_admin(tmp_path: Path) -> None:
    fake_binary = tmp_path / "nmap.exe"
    fake_binary.write_text("placeholder", encoding="utf-8")

    service = EnvironmentDiagnosticsService(
        executor=NmapExecutor(binary=str(fake_binary)),
        admin_provider=lambda: False,
        platform_provider=lambda: "Windows",
    )

    diagnostics = service.inspect()

    assert diagnostics.binary_available is True
    assert diagnostics.raw_packet_scans_available is False
    assert diagnostics.recommended_scan_type == "connect"
    assert any("TCP connect scan (-sT)" in issue.message for issue in diagnostics.issues)


def test_inspect_reports_auto_detected_windows_install(tmp_path: Path) -> None:
    fallback_binary = tmp_path / "Nmap" / "nmap.exe"
    fallback_binary.parent.mkdir(parents=True, exist_ok=True)
    fallback_binary.write_text("placeholder", encoding="utf-8")

    service = EnvironmentDiagnosticsService(
        executor=NmapExecutor(
            binary="nmap",
            fallback_binary_locations=(fallback_binary,),
        ),
        admin_provider=lambda: False,
        platform_provider=lambda: "Windows",
    )

    diagnostics = service.inspect()

    assert diagnostics.binary_available is True
    assert diagnostics.resolved_binary_path == str(fallback_binary)
    assert any("auto-detected" in issue.message for issue in diagnostics.issues)
