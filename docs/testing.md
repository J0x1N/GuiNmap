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
- execution flow in `ScanService` using a fake Nmap binary

This means you can validate the project logic even if Nmap is not installed yet.

### 3. Launch the GUI shell

```powershell
python -m guinmap.main
```

What to check:
- the window opens without crashing
- the main sections render correctly
- the Scan Builder, Profiles, Execution, Results, and Runtime panels are visible

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

### After UI bindings are added

- `pytest`
- `python -m guinmap.main`
- one manual GUI-run smoke test

## Practical review checklist

- Does the generated command match the selected profile?
- Does the XML file exist when the scan finishes?
- Does a non-zero Nmap exit code produce a clear error?
- Do parsed hosts and ports preserve exact Nmap states like `open|filtered`?
- Does the UI still open after backend changes?
