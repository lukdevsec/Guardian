# Guardian v0.9.3 - Endpoint Investigation and Domain Intelligence

This update builds on the supplied v0.9.2 project. It adds a dedicated Domain Intelligence navigation page, richer Endpoint process investigation, improved module statistics, and severity filtering. The existing Cloudflare Worker is unchanged; keep the currently deployed `guardian-cloud-api` Worker v0.4.0 and its existing Secrets.

## What's new

### Endpoint Explorer

- Best-effort process snapshot with PID, process name, working set and executable path.
- Established IPv4 TCP connections grouped by process ID.
- Search across process names, PIDs, paths and connection endpoints.
- Severity/category filter for process and TCP records.
- `Investigate process` opens a detail dialog with start time, file metadata, Authenticode verification result, parent-process information when captured in the current Guardian event log, and current established TCP connections for that PID.
- Process access restrictions are presented as missing metadata, not as suspicious behavior.
- Authenticode verification uses Windows WinVerifyTrust with no UI and cache-only URL retrieval. Revocation is not checked online; the UI states this explicitly.

### Domain Intelligence

- New sidebar entry and local hostname analysis page.
- Exact official-domain and subdomain-boundary matching for a small built-in registry.
- Punycode/IDN and selected common Cyrillic/Greek visual-confusable checks.
- Levenshtein lookalike candidates for common brand labels.
- Unknown domains remain UNKNOWN, not malicious. Lookalike and IDN findings are review leads, not automatic HIGH/CRITICAL alerts.
- No DNS, TLS, WHOIS, certificate reputation or external threat-intelligence lookup is performed by this page.

### Module UI

- Consistent page header and status panel.
- Compact statistic cards.
- Search plus severity/category filter on Endpoint, Alerts and History.
- Process detail cards include an explicit investigation action.

## Cloudflare Worker

No Worker code changed in v0.9.3. Do not redeploy a new Worker for this desktop-only update. Keep:

- `ANTHROPIC_API_KEY` as a Cloudflare Secret.
- `GUARDIAN_ACCESS_TOKEN` as a Cloudflare Secret.
- Existing Worker v0.4.0.

## Install into the existing repository

1. Close Guardian and Visual Studio.
2. Commit your current working tree or make a complete backup.
3. Extract this archive to a temporary folder.
4. Copy the contents of the archive's `Guardian` folder into your existing repository folder, preserving the existing `.git` directory. Merge folders and replace files when prompted.
5. Open `Guardian.slnx`.
6. Restore NuGet packages.
7. Set `Guardian.Desktop` as Startup Project.
8. Select `Debug` and `x64`.
9. Rebuild Solution and run with F5.

New `.cs` files are included automatically by the SDK-style project; no manual project-file inclusion is required.

## Validation and limitations

- The archive was checked for ZIP integrity and the XAML/XML files were parsed for well-formedness. Event-handler names were checked against code-behind.
- The Cloudflare Worker was not modified.
- This environment does not have the Windows SDK or .NET SDK, so a real WinUI 3 build could not be run here. Perform the final build in Visual Studio on Windows.
- Process enumeration is a best-effort snapshot. Windows may deny access to protected processes or a process may exit while being inspected.
- Parent-process information is shown only when Guardian recorded the process-start event during the current logging history. It is not reconstructed from an authoritative live parent-process API.
- TCP data is the established IPv4 connection table returned by Windows IP Helper. It is not packet capture, DNS telemetry or a full network history.
- Authenticode verification is performed without UI and without online revocation checking. A valid signature does not prove that software is harmless; an unsigned file is not automatically malicious.
- Domain Intelligence uses a small built-in registry and selected confusable mappings. It is a triage aid, not a public-suffix-list implementation or external reputation service. It can produce candidates that require manual review.
- Guardian remains detection-only. It does not terminate processes, block network connections or automatically block websites.
- The shared Cloud bearer token remains for private development only. Do not distribute a build containing a shared token until per-user/device enrollment, revocation and server-side quotas are implemented.
