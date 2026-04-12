# Architecture Overview

## Design goals

The application should remain understandable, testable, and easy to extend while
covering real Nmap functionality instead of a small subset.

The architecture is deliberately modular from day one, but not over-engineered.
Each module owns a concrete responsibility and the boundaries map directly to the
product roadmap.

## Chosen stack

- **Python 3.11+** as the main language
- **PySide6** for the desktop GUI
- **System Nmap binary** as the scanning engine
- **XML output** as the machine-readable result format
- **ElementTree** for the first XML parsing layer

## Why this is the right stack for the TFG

PySide6 gives the project a more professional ceiling than Tk-based solutions.
It supports complex widgets, threading patterns, model-view components, and a UI
that can evolve into a serious desktop product.

Direct Nmap execution is preferable to wrapper libraries because the GUI should
mirror the official tool rather than a secondary abstraction that may lag behind.
The official Nmap documentation recommends XML for programmatic consumption, so
the application will parse XML instead of scraping terminal text.

## Nmap integration strategy

The GUI will not call shell strings. It will build an argument list and execute
Nmap with `shell=False`.

The application will initially request XML output through `-oX <temporary file>`.
This is cleaner for a GUI than parsing interactive text, and it avoids coupling
the parser to unstable human-readable output.

Progress tracking will be handled separately through runtime process monitoring
and Nmap options such as `--stats-every`.

## Windows-specific considerations

Some scan types, especially SYN scan (`-sS`), depend on privileges and packet
capture support. On Windows, the project should detect environment capabilities
and guide the user when a requested scan requires elevation, Npcap, or a safer
fallback such as TCP connect scan (`-sT`).

## Planned package structure

```text
src/guinmap/
  app.py
  main.py
  application/
    environment_diagnostics.py
    report_exporter.py
    scan_profile_builder.py
    scan_result_loader.py
    scan_presets.py
    scan_profile_validator.py
    scan_service.py
  ui/
    main_window.py
    scan_worker.py
  domain/
    scan_profile.py
    scan_result.py
  infrastructure/
    nmap_executor.py
    nmap_xml_parser.py
```

## Responsibility split

- **application/** coordinates use cases such as launching scans, validating profiles,
  composing profiles from UI input, loading XML artifacts, defining presets,
  exporting reports, checking environment capabilities, and handling artifacts.
- **ui/** contains widgets, windows, dialogs, and presentation logic.
- **domain/** contains the core data structures the rest of the app works with.
- **infrastructure/** contains Nmap process orchestration and XML parsing.

The `application/` layer is now in place as the first thin orchestration layer
between the UI and the infrastructure modules.

## Initial scan pipeline

1. The user selects or builds a scan profile in the GUI.
2. The UI converts form state into a validated profile in the application layer.
3. The execution layer builds an Nmap argument list.
4. A Qt worker runs Nmap in the background and streams output back to the UI.
5. Nmap writes XML results and the parser converts them into internal models.
6. The UI can also load existing XML artifacts through the application layer.
7. The UI renders typed result models and can export JSON and Markdown reports.

## Phase 1 exit criteria

- Repository structure is in place
- Technical choices are documented
- A minimal desktop shell starts from a single entry point
- Domain and infrastructure modules can grow without refactoring the project root
