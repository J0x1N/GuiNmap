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
    advanced_args_text: str = ""


class ScanProfileBuilder:
    def build(self, draft: ScanProfileDraft) -> ScanProfile:
        extra_args = self._parse_extra_args(draft.advanced_args_text)

        if draft.enable_default_scripts:
            self._append_flag_if_missing(extra_args, "-sC")

        if draft.enable_traceroute:
            self._append_flag_if_missing(extra_args, "--traceroute")

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

    def _parse_extra_args(self, advanced_args_text: str) -> list[str]:
        parsed_arguments: list[str] = []

        for raw_line in advanced_args_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            try:
                parsed_arguments.extend(shlex.split(line, posix=True))
            except ValueError as exc:
                raise ValueError(f"Invalid advanced argument line '{line}': {exc}") from exc

        return parsed_arguments

    def _append_flag_if_missing(self, arguments: list[str], flag: str) -> None:
        if flag not in arguments:
            arguments.append(flag)