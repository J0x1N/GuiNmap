"""Use cases for executing scans and collecting XML artifacts."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from guinmap.application.scan_profile_validator import ScanProfileValidator
from guinmap.domain.scan_profile import ScanProfile
from guinmap.domain.scan_result import ScanResult
from guinmap.infrastructure.nmap_executor import NmapExecutor
from guinmap.infrastructure.nmap_xml_parser import NmapXmlParser

OutputHandler = Callable[[str], None]


@dataclass(slots=True)
class ScanExecution:
    profile: ScanProfile
    command: list[str]
    xml_output_path: Path
    return_code: int
    output_lines: list[str] = field(default_factory=list)
    result: ScanResult | None = None

    @property
    def command_preview(self) -> str:
        return subprocess.list2cmdline(self.command)


class ScanExecutionError(RuntimeError):
    def __init__(self, message: str, execution: ScanExecution | None = None) -> None:
        super().__init__(message)
        self.execution = execution


@dataclass(slots=True)
class ScanService:
    executor: NmapExecutor = field(default_factory=NmapExecutor)
    parser: NmapXmlParser = field(default_factory=NmapXmlParser)
    validator: ScanProfileValidator = field(default_factory=ScanProfileValidator)
    artifacts_dir: Path = Path("artifacts/scans")

    def run(self, profile: ScanProfile, on_output: OutputHandler | None = None) -> ScanExecution:
        self.validator.ensure_valid(profile)
        self._ensure_binary_available()

        xml_output_path = self._build_output_path(profile.name)
        command = self.executor.build_command(profile, xml_output_path)
        output_lines: list[str] = []

        with subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        ) as process:
            if process.stdout is not None:
                for raw_line in process.stdout:
                    line = raw_line.rstrip()
                    if not line:
                        continue

                    output_lines.append(line)
                    if on_output is not None:
                        on_output(line)

            return_code = process.wait()

        execution = ScanExecution(
            profile=profile,
            command=command,
            xml_output_path=xml_output_path,
            return_code=return_code,
            output_lines=output_lines,
        )

        if return_code != 0:
            raise ScanExecutionError(
                f"Nmap exited with code {return_code}. Check runtime output for details.",
                execution,
            )

        if not xml_output_path.exists():
            raise ScanExecutionError("Nmap finished without producing the XML artifact.", execution)

        execution.result = self.parser.parse_file(xml_output_path)
        return execution

    def _ensure_binary_available(self) -> None:
        if not self.executor.is_available():
            raise FileNotFoundError(
                f"The configured Nmap binary '{self.executor.binary}' could not be found."
            )

    def _build_output_path(self, profile_name: str) -> Path:
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        slug = self._slugify(profile_name)
        return self.artifacts_dir / f"{timestamp}-{slug}.xml"

    def _slugify(self, value: str) -> str:
        normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip().lower())
        cleaned = normalized.strip("-._")
        if cleaned:
            return cleaned

        return "scan"
