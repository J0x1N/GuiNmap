# Testing Guide

## Goal

This project is being built iteratively, so testing should happen at two levels:

1. fast local checks after every code change
2. occasional real smoke tests with the system `nmap` binary

## Recommended workflow on Windows

### 1. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .[dev]
```

### 2. Run the automated test suite

```powershell
pytest
```

What this covers today:
- command construction in `NmapExecutor`
- XML parsing in `NmapXmlParser`
- environment diagnostics and scan-type recommendations
- persistent settings save/load and runtime application
- language preference persistence for English and Spanish
- profile composition from structured UI fields plus advanced passthrough args
- XML artifact loading from the application layer
- JSON and Markdown report exporting from typed scan results
- execution flow and cancellation in `ScanService` using fake Nmap binaries
- GUI preview behavior and scan-type form constraints
- GUI XML loading, persistent preferences, hidden advanced families, cancellation controls, and result detail selection

This means you can validate the project logic even if Nmap is not installed yet.

### 3. Launch the GUI shell

```powershell
python -m guinmap.main
```

What to check:
- the window opens without crashing
- the main sections render correctly
- the Scan Builder, Operator Preferences, Execution, Results, and Runtime panels are visible
- the advanced Nmap families panel starts hidden and appears after pressing the reveal control
- the command preview updates after pressing `Preview command`
- the `Run scan` button stays disabled when Nmap is not available
- the `Cancel scan` button is only enabled while a scan is active
- `Load latest XML` works even before a real scan exists, thanks to the sample fallback
- changing the language preference to Spanish and reopening the window switches visible labels to Spanish
- selecting a result row updates the host, port, scripts, and metadata detail panels

### 4. Run a real smoke test with Nmap installed

Only do this against systems you are authorized to scan.

Minimal example against the official Nmap test target:

```powershell
python -c "from guinmap.application.scan_service import ScanService; from guinmap.domain.scan_profile import ScanProfile; service = ScanService(); execution = service.run(ScanProfile(name='smoke', targets=['scanme.nmap.org'], scan_type='connect', ports='80,443', timing_template=3, enable_service_detection=True)); print(execution.command_preview); print(execution.xml_output_path); print(len(execution.result.hosts))"
```

What to check:
- the command preview is printed
- an XML file appears under `artifacts/scans`
- at least one host is parsed into the result object

### 5. Run an environment diagnostics smoke test

This is useful even when Nmap is not installed yet.

```powershell
python -c "from guinmap.application.environment_diagnostics import EnvironmentDiagnosticsService; diagnostics = EnvironmentDiagnosticsService().inspect(); print(diagnostics.binary_available); print(diagnostics.recommended_scan_type); print([issue.message for issue in diagnostics.issues])"
```

What to check:
- `binary_available` matches the real machine state
- the recommended scan type is `connect` when raw-packet modes are not ready
- the issue list is understandable and actionable

### 6. Run a report export smoke test

This now works even if you have not produced a real scan yet. The exporter will
use the latest XML from `artifacts/scans` when available, and otherwise fall
back to the bundled sample XML under `docs/examples`.

```powershell
python -c "from guinmap.application.report_exporter import ScanReportExporter; result = ScanReportExporter().export_latest_available(); print(result.source_xml_path); print(result.used_fallback_source); print(result.json_report_path); print(result.markdown_report_path)"
```

What to check:
- the printed XML source path exists
- `used_fallback_source` is `True` when no real scan XML exists yet
- one `.json` file appears under `reports`
- one `.md` file appears under `reports`
- the Markdown report includes hosts, ports, and script output when present
- the JSON report preserves nested fields from `ScanResult`

## What to test after each phase

### After architecture changes

- `pytest`
- `python -m guinmap.main`

### After execution-layer changes

- `pytest`
- one real smoke test with the system `nmap`

### After parser changes

- `pytest`
- inspect generated XML under `artifacts/scans`
- verify host, port, and service data matches the XML

### After reporting or export changes

- `pytest`
- run the report export smoke test
- inspect generated files under `reports`

### After environment or hardening changes

- `pytest`
- run the environment diagnostics smoke test
- verify the recommended scan type and warnings make sense for the current machine

### After UI bindings are added

- `pytest`
- `python -m guinmap.main`
- one manual GUI-run smoke test

What to check:
- a valid profile produces a readable command preview
- grouped family fields appear in the preview when populated
- advanced arguments appear in the preview exactly as intended
- saved preferences update the configured binary and output directories after reload
- the selected language is restored after reopening the window
- the UI stays responsive while a real scan is running
- a running scan can be cancelled and returns the execution panel to a usable state
- results populate from XML after the scan completes
- loading an XML file updates the results table without launching a scan
- selecting a row updates the detail cards with real host, script, and metadata content
- exporting current reports writes both JSON and Markdown outputs

## Practical review checklist

- Does the generated command match the selected profile?
- Can unusual Nmap combinations still be expressed through advanced arguments?
- Can XML artifacts be loaded and reviewed without rerunning a scan?
- Can saved preferences be reloaded and applied without restarting the app?
- Does the language preference reopen the window in the expected language?
- Are advanced controls hidden until explicitly requested so the first screen stays focused?
- Can an active scan be cancelled cleanly without freezing the window?
- Does the XML file exist when the scan finishes?
- Does a non-zero Nmap exit code produce a clear error?
- Do parsed hosts and ports preserve exact Nmap states like `open|filtered`?
- Do exported reports preserve the important scan metadata and nested result details?
- Does selecting a result row expose the expected host, port, script, and metadata detail?
- Does environment diagnostics explain missing Nmap, privileges, or fallback behavior clearly?
- Does the UI still open after backend changes?
