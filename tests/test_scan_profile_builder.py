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
            skip_host_discovery=True,
            top_ports_text="100",
            script_expression="safe and vuln",
            script_arguments_text="unsafe=1",
            decoys_text="ME,10.0.0.5",
            min_rate_text="300",
            normal_output_path="reports/demo.nmap",
            enable_default_scripts=True,
            enable_traceroute=True,
            host_discovery_args_text="-PE",
            port_strategy_args_text="-sA",
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
        "-Pn",
        "--top-ports",
        "100",
        "--script",
        "safe and vuln",
        "--script-args",
        "unsafe=1",
        "-D",
        "ME,10.0.0.5",
        "--min-rate",
        "300",
        "-oN",
        "reports/demo.nmap",
        "-sC",
        "--traceroute",
        "-PE",
        "-sA",
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


def test_build_supports_grouped_family_arguments_without_duplicates() -> None:
    builder = ScanProfileBuilder()

    profile = builder.build(
        ScanProfileDraft(
            name="Family grouping",
            targets_text="127.0.0.1",
            disable_dns_resolution=True,
            enable_packet_trace=True,
            enable_verbose_output=True,
            stats_interval_text="2s",
            output_args_text="--packet-trace",
            performance_args_text="--min-hostgroup 16",
            advanced_args_text="-n\n-v",
        )
    )

    assert profile.extra_args == [
        "--stats-every",
        "2s",
        "--min-hostgroup",
        "16",
        "--packet-trace",
        "-n",
        "-v",
    ]