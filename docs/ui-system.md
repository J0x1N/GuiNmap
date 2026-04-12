# UI System

## Goals

The interface should feel like a professional desktop tool rather than a thin
wrapper around a terminal command.

The user experience must help a beginner start with safe defaults while still
leaving room for advanced Nmap workflows.

## Main window structure

The current shell is organized into five product-facing areas:

1. Left navigation for workflow orientation
2. Hero area for status and project context
3. Scan Builder panel for structured input fields
4. Profile, preferences, and execution panels for operator guidance
5. Results and runtime panels for post-execution feedback

This split mirrors how the application will evolve during later phases.

## Interaction model

The GUI should not ask the user to write raw shell commands as the main path.
Instead, it should build commands from typed inputs and only expose the generated
command as a preview for transparency.

At the same time, the product must remain faithful to the full Nmap surface. The
design therefore uses a hybrid model: structured controls for common workflows,
family-specific editors for major Nmap domains, and advanced arguments that pass
directly through to Nmap for rare or highly specific combinations.

The expected workflow is:

1. Select a preset or start from a blank profile
2. Define targets and ports
3. Choose scan type and timing
4. Reveal advanced Nmap families only if the basic workflow is not enough
5. Enable optional features such as service detection or NSE
6. Validate the profile before execution
7. Launch the scan in a background worker and monitor progress
8. Inspect structured results derived from XML
9. Drill into host, port, script, and metadata details from the selected row

## Design language

- Background: pale blue-gray workspace to reduce contrast fatigue
- Navigation: dark navy vertical anchor area
- Accent: teal for active controls and readiness state
- Cards: white panels with subtle borders instead of heavy shadows
- Typography: Segoe UI for native Windows readability

The goal is a clean operator interface with a security-tool tone, not a generic
consumer app aesthetic.

## Product panels

### Scan Builder

This panel owns the minimum set of structured inputs needed to create a valid
scan profile:

- targets
- ports
- scan type
- timing template
- preset profile
- advanced arguments

It also shows a generated command preview. That preview is important because the
application should remain understandable to users who already know Nmap.

The advanced-arguments field is not a fallback for broken UI design. It is a
deliberate compatibility layer so the application can remain complete even
before every niche Nmap option has a dedicated widget.

### Nmap families

The GUI now includes grouped editors for major Nmap option families:

- host discovery
- scan variants and port strategy
- NSE and scripts
- evasion and spoofing
- performance
- output and verbosity

Each family should offer a small number of guided fields for common cases plus
an exact-arguments editor for the rest of that family.

The families panel is now hidden by default and revealed through an explicit
control in the main workflow. This keeps the initial screen focused on the most
common path and reduces the sense that the UI contains decorative or unused
controls.

### Profiles

Profiles should expose curated workflows rather than every Nmap option at once.
The initial profile strategy is:

- Quick discovery
- Balanced TCP inventory
- Fast service fingerprint
- Deep assessment later

This keeps the beginner path clear while still mapping to real Nmap concepts.
Preset definitions should live in the application layer so the UI consumes a
shared source of truth rather than repeating hardcoded labels and commands.
Presets should remain editable baselines rather than locked templates.

### Execution

The execution area needs to carry three responsibilities:

- progress feedback
- environment capability warnings
- process lifecycle events

This is especially important on Windows because some scan modes depend on raw
packet privileges and Npcap.
Environment diagnostics should come from the application layer so the UI can
show actionable warnings before a scan starts, instead of discovering basic
environment problems only after subprocess launch fails.
Real scan execution should run outside the GUI thread and stream operator-facing
output back into the runtime console.
The same execution area should also allow the operator to cancel a running scan
without freezing the window or leaving the form in an inconsistent state.
On Windows, the runtime should also accept the standard Nmap installation path
as a valid binary source even when `nmap` is not exposed through `PATH`.

### Operator preferences

The GUI now includes a dedicated preferences panel for runtime configuration:

- Nmap binary path
- stats interval used for runtime progress output
- XML artifact directory
- report export directory
- interface language (`English` or `Español`)
- preferred scan type and timing template

These settings should persist between sessions. Runtime settings apply directly
to diagnostics, scan execution, artifact loading, and report export. Language
selection currently applies fully when the window is opened again.

### Results

Results should be driven by typed models, not raw text parsing. The current
state now includes a host and port table populated from parsed XML plus
selection-driven drill-down panels for:

- host detail
- port detail
- script output
- scan and artifact metadata
- export/report actions

The results area should also support loading existing XML artifacts from disk so
operators can review or re-export past scans without launching a new process.

## UX rules

- Prefer progressive disclosure over exposing every Nmap flag on day one.
- Show why an option is unavailable, especially when privileges are missing.
- Treat XML as the source of truth for completed scans.
- Keep human-readable previews visible to preserve operator trust.
- Separate validation errors from runtime scan errors.

## Accessibility and robustness

- Do not rely on color alone for state changes.
- Keep labels explicit and avoid icon-only primary actions.
- Use read-only previews for generated content to avoid accidental edits.
- Favor native controls where possible for keyboard navigation and platform fit.

## Phase boundaries

### Phase 2 complete when

- the main window reflects the planned workflow
- the key product panels exist as code and documentation
- the UI can guide future integration work without redesigning the shell

### Phase 3 starts with

- binding the Scan Builder to `ScanProfile`
- generating commands through `NmapExecutor`
- starting and stopping a subprocess safely
- collecting progress through process output and XML artifacts

### Phase 3 now covers

- composing scan profiles from UI state in the application layer
- validating and previewing exact Nmap commands before launch
- running scans in a background Qt worker
- surfacing environment diagnostics in the execution panel
- rendering typed XML results into the results table

### Phase 4 now covers

- organizing broader Nmap coverage into family-specific editors
- loading XML artifacts from disk through the application layer
- exporting current or latest available results to JSON and Markdown from the GUI

### Phase 5 now covers

- persisting operator preferences for binary path, output directories, and default execution options
- persisting a bilingual UI preference for English and Spanish
- applying saved preferences directly to diagnostics, execution, artifact loading, and report export
- hiding advanced Nmap families until the operator explicitly reveals them
- rendering per-selection detail panels for host, port, scripts, and scan metadata
