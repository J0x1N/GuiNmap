"""Compose structured scan profiles from UI-friendly form data."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from guinmap.domain.scan_profile import ScanProfile


@dataclass(frozen=True, slots=True)
class ScanProfileDraft:
    name: str
    targets_text: str
    scan_type: str = "default"
    ports_text: str = ""
    timing_template: int = 3
    enable_service_detection: bool = False
    enable_os_detection: bool = False
    enable_default_scripts: bool = False
    enable_traceroute: bool = False
    skip_host_discovery: bool = False
    disable_dns_resolution: bool = False
    top_ports_text: str = ""
    exclude_ports_text: str = ""
    script_expression: str = ""
    script_arguments_text: str = ""
    decoys_text: str = ""
    source_port_text: str = ""
    min_rate_text: str = ""
    max_rate_text: str = ""
    host_timeout_text: str = ""
    stats_interval_text: str = ""
    normal_output_path: str = ""
    grepable_output_path: str = ""
    enable_verbose_output: bool = False
    enable_packet_trace: bool = False
    host_discovery_args_text: str = ""
    port_strategy_args_text: str = ""
    nse_args_text: str = ""
    evasion_args_text: str = ""
    performance_args_text: str = ""
    output_args_text: str = ""
    advanced_args_text: str = ""


class ScanProfileBuilder:
    def build(self, draft: ScanProfileDraft) -> ScanProfile:
        user_args: list[str] = []
        self._extend_parsed_args(user_args, draft.host_discovery_args_text)
        self._extend_parsed_args(user_args, draft.port_strategy_args_text)
        self._extend_parsed_args(user_args, draft.nse_args_text)
        self._extend_parsed_args(user_args, draft.evasion_args_text)
        self._extend_parsed_args(user_args, draft.performance_args_text)
        self._extend_parsed_args(user_args, draft.output_args_text)
        self._extend_parsed_args(user_args, draft.advanced_args_text)

        structured_args: list[str] = []

        if draft.skip_host_discovery:
            self._append_flag_if_missing(structured_args, user_args, "-Pn")

        if draft.disable_dns_resolution:
            self._append_flag_if_missing(structured_args, user_args, "-n")

        if draft.top_ports_text.strip():
            self._append_option_if_missing(
                structured_args,
                user_args,
                "--top-ports",
                draft.top_ports_text.strip(),
            )

        if draft.exclude_ports_text.strip():
            self._append_option_if_missing(
                structured_args,
                user_args,
                "--exclude-ports",
                draft.exclude_ports_text.strip(),
            )

        if draft.script_expression.strip():
            self._append_option_if_missing(
                structured_args,
                user_args,
                "--script",
                draft.script_expression.strip(),
            )

        if draft.script_arguments_text.strip():
            self._append_option_if_missing(
                structured_args,
                user_args,
                "--script-args",
                draft.script_arguments_text.strip(),
            )

        if draft.decoys_text.strip():
            self._append_option_if_missing(
                structured_args,
                user_args,
                "-D",
                draft.decoys_text.strip(),
            )

        if draft.source_port_text.strip():
            self._append_option_if_missing(
                structured_args,
                user_args,
                "--source-port",
                draft.source_port_text.strip(),
            )

        if draft.min_rate_text.strip():
            self._append_option_if_missing(
                structured_args,
                user_args,
                "--min-rate",
                draft.min_rate_text.strip(),
            )

        if draft.max_rate_text.strip():
            self._append_option_if_missing(
                structured_args,
                user_args,
                "--max-rate",
                draft.max_rate_text.strip(),
            )

        if draft.host_timeout_text.strip():
            self._append_option_if_missing(
                structured_args,
                user_args,
                "--host-timeout",
                draft.host_timeout_text.strip(),
            )

        if draft.stats_interval_text.strip():
            self._append_option_if_missing(
                structured_args,
                user_args,
                "--stats-every",
                draft.stats_interval_text.strip(),
            )

        if draft.normal_output_path.strip():
            self._append_option_if_missing(
                structured_args,
                user_args,
                "-oN",
                draft.normal_output_path.strip(),
            )

        if draft.grepable_output_path.strip():
            self._append_option_if_missing(
                structured_args,
                user_args,
                "-oG",
                draft.grepable_output_path.strip(),
            )

        if draft.enable_verbose_output:
            self._append_flag_if_missing(structured_args, user_args, "-v")

        if draft.enable_packet_trace:
            self._append_flag_if_missing(structured_args, user_args, "--packet-trace")

        if draft.enable_default_scripts:
            self._append_flag_if_missing(structured_args, user_args, "-sC")

        if draft.enable_traceroute:
            self._append_flag_if_missing(structured_args, user_args, "--traceroute")

        extra_args = [*structured_args, *user_args]

        return ScanProfile(
            name=draft.name.strip(),
            targets=self._parse_targets(draft.targets_text),
            scan_type=draft.scan_type,
            ports=draft.ports_text.strip() or None,
            timing_template=draft.timing_template,
            enable_service_detection=draft.enable_service_detection,
            enable_os_detection=draft.enable_os_detection,
            extra_args=extra_args,
        )

    def _parse_targets(self, targets_text: str) -> list[str]:
        return [
            token
            for token in re.split(r"[,\s]+", targets_text.strip())
            if token
        ]

    def _extend_parsed_args(self, arguments: list[str], args_text: str) -> None:
        for raw_line in args_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            try:
                arguments.extend(shlex.split(line, posix=True))
            except ValueError as exc:
                raise ValueError(f"Invalid advanced argument line '{line}': {exc}") from exc

    def _append_flag_if_missing(
        self,
        arguments: list[str],
        existing_arguments: list[str],
        flag: str,
    ) -> None:
        if flag not in arguments and flag not in existing_arguments:
            arguments.append(flag)

    def _append_option_if_missing(
        self,
        arguments: list[str],
        existing_arguments: list[str],
        flag: str,
        value: str,
    ) -> None:
        if flag in arguments or flag in existing_arguments:
            return

        arguments.extend([flag, value])