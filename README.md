# GuiNmap

GuiNmap is a modern desktop interface for Nmap focused on clean architecture,
structured results, and a professional user experience.

The project is intentionally being developed in phases so it can serve both as an
academic final degree project and as a portfolio-grade GitHub repository.

## Technology decisions

- **Language:** Python 3.11+
- **GUI toolkit:** PySide6
- **Nmap integration:** direct subprocess execution of the system `nmap` binary
- **Result processing:** XML output parsing with Python's standard library
- **Quality tooling:** Ruff, Pytest, and Mypy

## Why PySide6

PySide6 provides a modern desktop stack, solid documentation, long-term industry
relevance, and an LGPL licensing model that is much more comfortable than PyQt6
for an academic and public portfolio project. It also scales better than
CustomTkinter once the interface grows into dockable views, richer widgets,
threaded scan workflows, and structured result exploration.

## Why direct Nmap execution instead of python-nmap

This project will integrate with the real Nmap CLI through `subprocess` rather
than relying on wrapper libraries such as `python-nmap`.

That choice keeps the application closer to the official Nmap feature set,
avoids wrapper lag when new flags or behaviors are added, and makes the GUI more
transparent for advanced users who already know the tool. The official Nmap
documentation explicitly recommends XML output for programmatic processing, so
the application will treat XML as the canonical source of truth for completed
scan results.

## Development phases

1. Foundation and architecture
2. UI shell and interaction design
3. Nmap execution engine
4. XML parsing and result domain modeling
5. Scan profiles, validation, and workflow UX
6. Reporting, exports, and scan history
7. Testing, hardening, packaging, and release readiness

## Phase 1 deliverables

- Python project bootstrap with packaging metadata
- Initial modular package layout
- Desktop window skeleton for the future GUI
- Domain models for scan profiles and scan results
- Nmap command builder and XML parser skeleton
- Architecture documentation and technical decisions

## Local prerequisites

- Python 3.11 or newer
- Nmap installed and available in `PATH`
- On Windows, Npcap installed together with Nmap
- Administrative privileges for scan modes that require raw packet access

## Ethical and legal use

This project must only be used against systems and networks where explicit
authorization exists.
