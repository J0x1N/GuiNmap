import pytest

from guinmap.application.scan_profile_validator import (
    ScanProfileValidationError,
    ScanProfileValidator,
)
from guinmap.application.scan_service import ScanService
from guinmap.domain.scan_profile import ScanProfile


def test_validator_accepts_balanced_profile() -> None:
    validator = ScanProfileValidator()
    profile = ScanProfile(
        name="Balanced",
        targets=["scanme.nmap.org"],
        scan_type="connect",
        ports="80,443",
        timing_template=3,
        enable_service_detection=True,
    )

    result = validator.validate(profile)

    assert result.is_valid is True
    assert result.issues == ()


def test_validator_rejects_empty_targets() -> None:
    validator = ScanProfileValidator()
    profile = ScanProfile(name="No Targets", targets=["   "])

    result = validator.validate(profile)

    assert result.is_valid is False
    assert any(issue.field == "targets" for issue in result.issues)


def test_validator_rejects_ping_incompatible_flags() -> None:
    validator = ScanProfileValidator()
    profile = ScanProfile(
        name="Ping only",
        targets=["127.0.0.1"],
        scan_type="ping",
        ports="80",
        enable_service_detection=True,
        enable_os_detection=True,
    )

    result = validator.validate(profile)

    assert result.is_valid is False
    assert any(issue.field == "ports" for issue in result.issues)
    assert any(issue.field == "enable_service_detection" for issue in result.issues)
    assert any(issue.field == "enable_os_detection" for issue in result.issues)


def test_scan_service_rejects_invalid_profile_before_process_execution(tmp_path) -> None:
    service = ScanService(artifacts_dir=tmp_path / "artifacts")
    profile = ScanProfile(name="   ", targets=[])

    with pytest.raises(ScanProfileValidationError, match="name:|targets:"):
        service.run(profile)


def test_validator_rejects_manual_xml_output_override() -> None:
    validator = ScanProfileValidator()
    profile = ScanProfile(
        name="Manual XML",
        targets=["127.0.0.1"],
        extra_args=["-oX", "custom.xml"],
    )

    result = validator.validate(profile)

    assert result.is_valid is False
    assert any("-oX" in issue.message for issue in result.issues)