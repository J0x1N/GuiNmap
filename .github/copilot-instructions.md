# Project Guidelines

## Mission

GuiNmap is a TFG project whose goal is to build the best desktop GUI for Nmap:
modern, maintainable, ordered, secure, efficient, and faithful to how Nmap
really works.

Prefer decisions that improve correctness, operator trust, and long-term
extensibility over quick shortcuts.

## Architecture

- Keep layer boundaries strict:
  `ui/` for PySide6 presentation,
  `application/` for orchestration and validation,
  `infrastructure/` for Nmap process and XML handling,
  `domain/` for typed models only.
- Respect dependency direction: `ui -> application -> infrastructure/domain` and
  `infrastructure -> domain`.
- Treat Nmap XML as the canonical result artifact. Do not use interactive stdout
  as the final source of truth for scan results.
- Build Nmap invocations as `list[str]` and execute them with `shell=False`.
- Validate `ScanProfile` before starting any subprocess.
- Preserve exact Nmap states such as `open|filtered` and `closed|filtered`.

See [docs/architecture.md](docs/architecture.md) for the system boundaries and
technical rationale.

## Build and Test

Prefer the workspace virtual environment when it exists.

Core commands:

```powershell
python -m pip install -e .[dev]
python -m pytest
python -m ruff check .
python -m mypy src
python -m guinmap.main
```

See [docs/testing.md](docs/testing.md) for the Windows workflow, smoke tests,
and phase-by-phase validation.

## Conventions

- Use `@dataclass(slots=True)` for domain and validation result models.
- Keep domain objects small, typed, and free of orchestration logic.
- Keep subprocess and XML responsibilities in `infrastructure/`.
- Keep use-case orchestration in `application/`.
- Prefer realistic tests with `tmp_path` and fake binaries over heavy mocking.
- Keep generated scan artifacts under `artifacts/scans/`.
- When behavior changes, update tests and the relevant docs rather than adding
  undocumented rules.

Use these files as implementation patterns:
- [src/guinmap/application/scan_service.py](src/guinmap/application/scan_service.py)
- [src/guinmap/application/scan_profile_validator.py](src/guinmap/application/scan_profile_validator.py)
- [src/guinmap/infrastructure/nmap_executor.py](src/guinmap/infrastructure/nmap_executor.py)
- [src/guinmap/infrastructure/nmap_xml_parser.py](src/guinmap/infrastructure/nmap_xml_parser.py)

## Windows and Nmap Constraints

- Do not assume `nmap` is installed or available in `PATH`; check availability.
- On Windows, raw-packet features may require Npcap and administrative
  privileges.
- Prefer clear capability detection and safe fallback behavior, especially to
  TCP connect scan (`-sT`), over silent failure.
- Do not auto-elevate or hide privilege-related problems.
- Real scan execution must not block the GUI thread. Use a Qt-friendly worker
  approach when wiring the UI to subprocess execution.

See [docs/ui-system.md](docs/ui-system.md) for the intended GUI workflow and
Windows-specific UX expectations.

## Documentation

- Link to existing docs instead of duplicating them.
- Use [documentation.txt](documentation.txt) as the local, attributed Nmap
  reference for option semantics and product decisions.
- Keep instructions concise and project-specific. Avoid generic advice that is
  already enforced by Ruff, Mypy, or tests.

## Safety

This project must only support authorized scanning workflows. Keep UX, wording,
and feature design aligned with legitimate administration, auditing, and
learning use cases.