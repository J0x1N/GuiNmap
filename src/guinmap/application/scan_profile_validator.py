"""Validation helpers for structured scan profiles."""

from __future__ import annotations

from dataclasses import dataclass

from guinmap.domain.scan_profile import ScanProfile

SUPPORTED_SCAN_TYPES = {"default", "connect", "syn", "udp", "ping"}


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    field: str
    message: str


@dataclass(frozen=True, slots=True)
class ScanProfileValidationResult:
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def is_valid(self) -> bool:
        return not self.issues


class ScanProfileValidationError(ValueError):
    def __init__(self, result: ScanProfileValidationResult) -> None:
        message = "; ".join(f"{issue.field}: {issue.message}" for issue in result.issues)
        super().__init__(message)
        self.result = result


class ScanProfileValidator:
    def validate(self, profile: ScanProfile) -> ScanProfileValidationResult:
        issues: list[ValidationIssue] = []

        if not profile.name.strip():
            issues.append(ValidationIssue("name", "Profile name cannot be empty."))

        normalized_targets = [target.strip() for target in profile.targets if target.strip()]
        if not normalized_targets:
            issues.append(ValidationIssue("targets", "At least one target must be provided."))

        if profile.scan_type not in SUPPORTED_SCAN_TYPES:
            issues.append(
                ValidationIssue(
                    "scan_type",
                    f"Unsupported scan type '{profile.scan_type}'.",
                )
            )

        if profile.timing_template not in {0, 1, 2, 3, 4, 5}:
            issues.append(
                ValidationIssue("timing_template", "Timing template must be between 0 and 5.")
            )

        if profile.ports is not None and not profile.ports.strip():
            issues.append(ValidationIssue("ports", "Ports cannot be blank when provided."))

        if any(not script.strip() for script in profile.script_selection):
            issues.append(ValidationIssue("script_selection", "Script names cannot be blank."))

        if any(not argument.strip() for argument in profile.extra_args):
            issues.append(ValidationIssue("extra_args", "Advanced arguments cannot be blank."))

        if profile.scan_type == "ping":
            if profile.ports:
                issues.append(
                    ValidationIssue(
                        "ports",
                        "Ping profiles disable port scanning, so ports should not be set.",
                    )
                )

            if profile.enable_service_detection:
                issues.append(
                    ValidationIssue(
                        "enable_service_detection",
                        "Service detection is incompatible with ping-only profiles.",
                    )
                )

            if profile.enable_os_detection:
                issues.append(
                    ValidationIssue(
                        "enable_os_detection",
                        "OS detection is incompatible with ping-only profiles.",
                    )
                )

        return ScanProfileValidationResult(tuple(issues))

    def ensure_valid(self, profile: ScanProfile) -> None:
        result = self.validate(profile)
        if not result.is_valid:
            raise ScanProfileValidationError(result)
