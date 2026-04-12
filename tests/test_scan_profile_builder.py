import pytest

from guinmap.application.scan_profile_builder import ScanProfileBuilder, ScanProfileDraft


def test_build_supports_full_nmap_passthrough_arguments() -> None:
    builder = ScanProfileBuilder()

    profile = builder.build(
        ScanProfileDraft(
            name="Advanced ACK scan",
            targets_text="scanme.nmap.org, 192.168.1.0/24\n10.0.0.10",
            scan_type="default",
            ports_text="80,443",
            timing_template=4,
            enable_service_detection=True,
            enable_default_scripts=True,
            enable_traceroute=True,
            advanced_args_text='-sA\n--script "safe and vuln"\n--script-args unsafe=1',
        )
    )

    assert profile.name == "Advanced ACK scan"
    assert profile.targets == ["scanme.nmap.org", "192.168.1.0/24", "10.0.0.10"]
    assert profile.scan_type == "default"
    assert profile.ports == "80,443"
    assert profile.timing_template == 4
    assert profile.enable_service_detection is True
    assert profile.enable_os_detection is False
    assert profile.extra_args == [
        "-sA",
        "--script",
        "safe and vuln",
        "--script-args",
        "unsafe=1",
        "-sC",
        "--traceroute",
    ]


def test_build_does_not_duplicate_structured_flags_when_user_also_supplies_them() -> None:
    builder = ScanProfileBuilder()

    profile = builder.build(
        ScanProfileDraft(
            name="No duplicates",
            targets_text="127.0.0.1",
            enable_default_scripts=True,
            enable_traceroute=True,
            advanced_args_text="-sC\n--traceroute\n--reason",
        )
    )

    assert profile.extra_args == ["-sC", "--traceroute", "--reason"]


def test_build_raises_clear_error_for_unbalanced_quotes() -> None:
    builder = ScanProfileBuilder()

    with pytest.raises(ValueError, match="Invalid advanced argument line"):
        builder.build(
            ScanProfileDraft(
                name="Broken",
                targets_text="127.0.0.1",
                advanced_args_text='--script "safe and',
            )
        )